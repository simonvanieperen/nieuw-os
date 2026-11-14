#!/usr/bin/env python3
"""Summarise open Dependabot and code-scanning alerts for public CI output.

Trust boundary: Actions logs and step summaries of this public repository are
publicly readable, while GitHub restricts the alert lists to maintainers.
SECURITY.md forbids publishing non-public vulnerability details, so the
summary prints only:

* Dependabot: one row per open alert, limited to fields that are derivable
  from the public lockfiles and the public GitHub Advisory Database
  (ecosystem, package, manifest path, advisory identifiers, severity,
  vulnerable range and first patched version).
* Code scanning: aggregate counts per tool and severity. Rule identifiers,
  file paths, line numbers and messages are never printed.

API free text is never printed. Every printed value must match a strict
allowlist pattern and is otherwise replaced by a placeholder; this also blocks
Markdown and workflow-command injection. An unreadable source makes the run
fail instead of being reported as zero alerts.
"""

import argparse
import http.client
import json
import os
import re
import sys
from collections import Counter
from urllib import error, request


API_ROOT = "https://api.github.com/"
API_VERSION = "2022-11-28"
PER_PAGE = 100
MAX_PAGES = 20
SOURCES = (
    ("dependabot", "dependabot/alerts"),
    ("code-scanning", "code-scanning/alerts"),
)
REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
SEVERITIES = ("critical", "high", "medium", "low")
RULE_SEVERITIES = ("error", "warning", "note", "none")
ABSENT = "-"
PLACEHOLDER = "(omitted)"
PUBLIC_NOTICE = ("This output is public: code-scanning details stay in the "
                 "Security tab (see SECURITY.md).")
DEPENDABOT_COLUMNS = ("#", "Severity", "Ecosystem", "Package", "Manifest",
                      "Advisory", "CVE", "Vulnerable", "First patched")
FIELD_PATTERNS = {
    "ecosystem": re.compile(r"[a-z0-9_-]{1,40}"),
    "package": re.compile(r"[A-Za-z0-9_.@/+-]{1,214}"),
    "manifest": re.compile(r"[A-Za-z0-9_./-]{1,300}"),
    "ghsa": re.compile(r"GHSA(?:-[a-z0-9]{4}){3}"),
    "cve": re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}"),
    "range": re.compile(r"[A-Za-z0-9_.,<>=~^* +-]{1,120}"),
    "version": re.compile(r"[A-Za-z0-9_.+-]{1,80}"),
    "tool": re.compile(r"[A-Za-z0-9_. -]{1,60}"),
}


class FetchError(RuntimeError):
    """A source could not be read completely; its count is unknown."""


class _ApiOnlyRedirects(request.HTTPRedirectHandler):
    """Refuse redirects that would carry the token outside the API root."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith(API_ROOT):
            raise FetchError("redirect left the GitHub API root")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def clean(kind, value):
    """Return an allowlisted value, a placeholder, or the absent marker."""
    if value is None or value == "":
        return ABSENT
    if not isinstance(value, str) or FIELD_PATTERNS[kind].fullmatch(value) is None:
        return PLACEHOLDER
    return value


def severity(value):
    """Map advisory severities to the fixed set; anything else is unknown."""
    if isinstance(value, str) and value.lower() in SEVERITIES:
        return value.lower()
    return "unknown"


def nested(container, key, source):
    """A nested alert object: absent is empty, any other non-object is malformed."""
    value = container.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise FetchError(f"unexpected {source} alert shape")
    return value


def is_next(parameters):
    """True if the first rel parameter lists "next" (RFC 8288: token or quoted, any case)."""
    for parameter in parameters:
        name, separator, value = parameter.partition("=")
        if separator and name.strip().lower() == "rel":
            return "next" in value.strip().strip('"').lower().split()
    return False


def next_link(header):
    """Return the rel="next" URL of a Link header, restricted to the API root."""
    if not header:
        return None
    for part in header.split(","):
        section = [piece.strip() for piece in part.split(";")]
        target = section[0]
        if not is_next(section[1:]):
            continue
        if not (target.startswith("<") and target.endswith(">")):
            raise FetchError("malformed pagination link")
        url = target[1:-1]
        if not url.startswith(API_ROOT):
            raise FetchError("pagination left the GitHub API root")
        return url
    return None


def fetch_all(url, token, opener=None):
    """Read every page of one alert list or raise FetchError."""
    if opener is None:
        opener = request.build_opener(_ApiOnlyRedirects).open
    items = []
    for _ in range(MAX_PAGES):
        req = request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "baryon-security-alert-summary",
        })
        try:
            with opener(req, timeout=30) as response:
                page = json.load(response)
                link = response.headers.get("Link")
        except error.HTTPError as exc:
            raise FetchError(f"HTTP {exc.code}") from None
        except (error.URLError, OSError, ValueError, http.client.HTTPException) as exc:
            raise FetchError(type(exc).__name__) from None
        if not isinstance(page, list):
            raise FetchError("unexpected response shape")
        items.extend(page)
        url = next_link(link)
        if url is None:
            return items
    raise FetchError(f"more than {MAX_PAGES} pages")


def dependabot_rows(alerts):
    """Publicly derivable fields per alert, most severe first."""
    rows = []
    for alert in alerts:
        if not isinstance(alert, dict):
            raise FetchError("unexpected Dependabot alert shape")
        dependency = nested(alert, "dependency", "Dependabot")
        package = nested(dependency, "package", "Dependabot")
        advisory = nested(alert, "security_advisory", "Dependabot")
        vulnerability = nested(alert, "security_vulnerability", "Dependabot")
        patched = nested(vulnerability, "first_patched_version", "Dependabot").get("identifier")
        number = alert.get("number")
        rows.append((
            str(number) if isinstance(number, int) and number > 0 else PLACEHOLDER,
            severity(advisory.get("severity")),
            clean("ecosystem", package.get("ecosystem")),
            clean("package", package.get("name")),
            clean("manifest", dependency.get("manifest_path")),
            clean("ghsa", advisory.get("ghsa_id")),
            clean("cve", advisory.get("cve_id")),
            clean("range", vulnerability.get("vulnerable_version_range")),
            clean("version", patched),
        ))
    order = {name: rank for rank, name in enumerate(SEVERITIES + ("unknown",))}
    return sorted(rows, key=lambda row: (order[row[1]], row[3], row[0]))


def code_scanning_counts(alerts):
    """Aggregate counts only; no rule, location or message leaves this function."""
    counts = Counter()
    for alert in alerts:
        if not isinstance(alert, dict):
            raise FetchError("unexpected code-scanning alert shape")
        tool = clean("tool", nested(alert, "tool", "code-scanning").get("name"))
        rule = nested(alert, "rule", "code-scanning")
        level = rule.get("security_severity_level")
        if isinstance(level, str) and level.lower() in SEVERITIES:
            label = level.lower()
        elif rule.get("severity") in RULE_SEVERITIES:
            label = "non-security " + rule["severity"]
        else:
            label = "unknown"
        counts[(tool, label)] += 1
    order = {name: rank for rank, name in enumerate(SEVERITIES)}
    return sorted(counts.items(), key=lambda item: (
        item[0][0], order.get(item[0][1], len(SEVERITIES)), item[0][1]))


def render(repository, dependabot, code_scanning):
    """Render Markdown; a FetchError result is shown as unread, never as zero."""
    lines = [
        "## Security alert summary",
        "",
        f"Repository `{repository}`; open alerts only. " + PUBLIC_NOTICE,
        "",
    ]
    if isinstance(dependabot, FetchError):
        lines += ["### Dependabot: not read", "",
                  f"Reading failed ({dependabot}). This is not evidence of zero alerts.", ""]
    else:
        rows = dependabot_rows(dependabot)
        lines += [f"### Dependabot: {len(rows)} open", ""]
        if rows:
            lines += [
                "| " + " | ".join(DEPENDABOT_COLUMNS) + " |",
                "|" + "---|" * len(DEPENDABOT_COLUMNS),
            ]
            for number, level, *fields in rows:
                cells = " | ".join(f"`{value}`" for value in fields)
                lines.append(f"| {number} | {level} | {cells} |")
            lines.append("")
    if isinstance(code_scanning, FetchError):
        lines += ["### Code scanning: not read", "",
                  f"Reading failed ({code_scanning}). This is not evidence of zero alerts."]
    else:
        counts = code_scanning_counts(code_scanning)
        total = sum(count for _, count in counts)
        lines += [f"### Code scanning: {total} open", ""]
        if counts:
            lines += ["| Tool | Severity | Open |", "|---|---|---|"]
            lines += [f"| {tool} | {label} | {count} |" for (tool, label), count in counts]
    return "\n".join(lines).rstrip("\n") + "\n"


def main(argv=None, fetch=fetch_all):
    """Read both sources, print the summary and fail if either was unreadable."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    args = parser.parse_args(argv)
    if REPOSITORY_PATTERN.fullmatch(args.repository or "") is None:
        parser.error("--repository must be owner/name")
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        parser.error("GITHUB_TOKEN is required")

    results = {}
    for source, path in SOURCES:
        url = f"{API_ROOT}repos/{args.repository}/{path}?state=open&per_page={PER_PAGE}"
        try:
            results[source] = fetch(url, token)
        except FetchError as exc:
            results[source] = exc
    try:
        text = render(args.repository, results["dependabot"], results["code-scanning"])
    except FetchError as exc:
        print(f"Security alert summary failed: {exc}", file=sys.stderr)
        return 1

    sys.stdout.write(text)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(text)
    failed = [f"{source} ({result})" for source, result in results.items()
              if isinstance(result, FetchError)]
    if failed:
        print("Security alert summary incomplete: " + ", ".join(failed), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
