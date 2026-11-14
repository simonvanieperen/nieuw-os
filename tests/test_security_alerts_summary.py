"""CI-HOSTED: disclosure and fail-closed rules of the security alert summary.

Invariants (ADR-CI-SECURITY-ALERTS-20261111, SECURITY.md):
- public output never contains code-scanning rules, paths or messages;
- every printed API value is allowlisted, so API data cannot inject Markdown
  or workflow commands;
- an unreadable source fails the run and is never reported as zero alerts;
- the token is never sent outside the GitHub API root;
- the workflow token may only read alerts, and fork pull requests get none.

These tests use local fakes and do not contact GitHub.
"""

import http.client
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib import error, request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import security_alerts_summary as summary  # noqa: E402

try:
    import yaml
except ImportError:  # host-quality installs PyYAML, so the contract runs there
    yaml = None

API = summary.API_ROOT + "repos/BaryonOS/BaryonOS/"


def dependabot_alert(number=7, name="hkdf", sev="high", **overrides):
    alert = {
        "number": number,
        "state": "open",
        "dependency": {
            "package": {"ecosystem": "rust", "name": name},
            "manifest_path": "sdk/app-management/Cargo.lock",
            "scope": "runtime",
        },
        "security_advisory": {
            "ghsa_id": "GHSA-abcd-2345-wxyz",
            "cve_id": "CVE-2026-12345",
            "severity": sev,
            "summary": "Free text that must never be printed",
            "description": "Long free text that must never be printed",
        },
        "security_vulnerability": {
            "vulnerable_version_range": ">= 0.12.0, < 0.12.5",
            "first_patched_version": {"identifier": "0.12.5"},
        },
        "html_url": "https://github.com/BaryonOS/BaryonOS/security/dependabot/7",
    }
    alert.update(overrides)
    return alert


def code_scanning_alert(level="high", rule_severity="error", tool="CodeQL"):
    return {
        "number": 3,
        "state": "open",
        "tool": {"name": tool, "version": "2.21.0"},
        "rule": {
            "id": "rust/hard-coded-cryptographic-value",
            "severity": rule_severity,
            "security_severity_level": level,
            "description": "Hard-coded cryptographic value",
        },
        "most_recent_instance": {
            "location": {"path": "kernel/src/secret_spot.rs", "start_line": 42},
            "message": {"text": "Sensitive message text"},
        },
    }


class FakeResponse(io.BytesIO):
    def __init__(self, payload, link=None):
        super().__init__(json.dumps(payload).encode("utf-8"))
        self.headers = {"Link": link} if link else {}


class FakeOpener:
    """Serve queued pages and record the requested URLs and headers."""

    def __init__(self, pages):
        self.pages = list(pages)
        self.requests = []

    def __call__(self, req, timeout):
        self.requests.append(req)
        page = self.pages.pop(0)
        if isinstance(page, Exception):
            raise page
        return page


class RenderingTests(unittest.TestCase):
    def test_dependabot_rows_publish_only_public_advisory_fields(self):
        text = summary.render("BaryonOS/BaryonOS", [dependabot_alert()], [])
        for expected in ("hkdf", "GHSA-abcd-2345-wxyz", "CVE-2026-12345",
                         "sdk/app-management/Cargo.lock", ">= 0.12.0, < 0.12.5",
                         "0.12.5", "| 7 | high |", "### Dependabot: 1 open"):
            self.assertIn(expected, text)
        self.assertNotIn("Free text", text)
        self.assertNotIn("security/dependabot", text)

    def test_code_scanning_publishes_aggregate_counts_only(self):
        alerts = [code_scanning_alert(), code_scanning_alert(),
                  code_scanning_alert(level=None, rule_severity="warning")]
        text = summary.render("BaryonOS/BaryonOS", [], alerts)
        self.assertIn("### Code scanning: 3 open", text)
        self.assertIn("| CodeQL | high | 2 |", text)
        self.assertIn("| CodeQL | non-security warning | 1 |", text)
        for secret in ("rust/hard-coded", "secret_spot", "kernel/src", "42",
                       "Sensitive message", "Hard-coded cryptographic"):
            self.assertNotIn(secret, text)

    def test_rows_are_sorted_most_severe_first(self):
        alerts = [dependabot_alert(1, "zlow", "low"),
                  dependabot_alert(2, "acrit", "critical"),
                  dependabot_alert(3, "mid", "MEDIUM")]
        rows = summary.dependabot_rows(alerts)
        self.assertEqual([row[1] for row in rows], ["critical", "medium", "low"])

    def test_untrusted_values_cannot_inject_markdown_or_workflow_commands(self):
        hostile = dependabot_alert(
            number="::error::x",
            dependency={"package": {"ecosystem": "rust\n::warning::pwned",
                                    "name": "::add-mask::pwned"},
                        "manifest_path": "a|b`c\nd"},
            security_advisory={"ghsa_id": "<script>", "cve_id": "CVE-1",
                               "severity": "catastrophic"},
            security_vulnerability={"vulnerable_version_range": "| pwned |",
                                    "first_patched_version": {"identifier": 5}},
        )
        text = summary.render("BaryonOS/BaryonOS", [hostile],
                              [code_scanning_alert(tool="Code`QL|\n::error::")])
        for line in text.splitlines():
            self.assertFalse(line.lstrip().startswith("::"), line)
        for forbidden in ("pwned", "<script>", "`CVE-1`", "a|b", "catastrophic"):
            self.assertNotIn(forbidden, text)
        self.assertIn(summary.PLACEHOLDER, text)
        self.assertIn("| (omitted) | unknown |", text)

    def test_absent_optional_fields_are_marked_not_invented(self):
        alert = dependabot_alert()
        alert["security_advisory"]["cve_id"] = None
        alert["security_vulnerability"]["first_patched_version"] = None
        rows = summary.dependabot_rows([alert])
        self.assertEqual(rows[0][6], summary.ABSENT)
        self.assertEqual(rows[0][8], summary.ABSENT)

    def test_malformed_nested_fields_fail_closed(self):
        dependabot = [
            dependabot_alert(dependency="SECRET-PATH/kernel.rs"),
            dependabot_alert(dependency={"package": ["rust", "hkdf"]}),
            dependabot_alert(security_advisory="GHSA text"),
            dependabot_alert(security_vulnerability=7),
            dependabot_alert(security_vulnerability={"first_patched_version": "0.12.5"}),
        ]
        for alert in dependabot:
            with self.subTest(alert=alert), \
                    self.assertRaisesRegex(summary.FetchError, "Dependabot alert shape"):
                summary.dependabot_rows([alert])
        broken_tool = code_scanning_alert()
        broken_tool["tool"] = "CodeQL"
        broken_rule = code_scanning_alert()
        broken_rule["rule"] = "rust/secret-rule"
        for alert in (broken_tool, broken_rule):
            with self.subTest(alert=alert), \
                    self.assertRaisesRegex(summary.FetchError, "code-scanning alert shape"):
                summary.code_scanning_counts([alert])

    def test_unread_source_is_never_rendered_as_zero(self):
        text = summary.render("BaryonOS/BaryonOS", summary.FetchError("HTTP 403"), [])
        self.assertIn("### Dependabot: not read", text)
        self.assertIn("not evidence of zero alerts", text)
        self.assertNotIn("Dependabot: 0 open", text)


class FetchTests(unittest.TestCase):
    def test_follows_next_links_and_sends_versioned_headers(self):
        opener = FakeOpener([
            FakeResponse([1, 2], link=f'<{API}dependabot/alerts?after=x>; rel="next"'),
            FakeResponse([3]),
        ])
        items = summary.fetch_all(API + "dependabot/alerts", "token-value", opener)
        self.assertEqual(items, [1, 2, 3])
        self.assertEqual(len(opener.requests), 2)
        first = opener.requests[0]
        self.assertEqual(first.get_header("Authorization"), "Bearer token-value")
        self.assertEqual(first.get_header("X-github-api-version"), summary.API_VERSION)

    def test_pagination_cannot_leave_the_api_root(self):
        opener = FakeOpener([
            FakeResponse([1], link='<https://evil.example/steal>; rel="next"'),
        ])
        with self.assertRaisesRegex(summary.FetchError, "API root"):
            summary.fetch_all(API + "dependabot/alerts", "token-value", opener)

    def test_redirects_cannot_leave_the_api_root(self):
        handler = summary._ApiOnlyRedirects()
        req = request.Request(API + "dependabot/alerts",
                              headers={"Authorization": "Bearer token-value"})
        with self.assertRaisesRegex(summary.FetchError, "API root"):
            handler.redirect_request(req, None, 302, "Found", {},
                                     "https://evil.example/steal")
        same_root = handler.redirect_request(req, None, 301, "Moved", {},
                                             summary.API_ROOT + "repositories/1/x")
        self.assertIsNotNone(same_root)

    def test_http_errors_report_status_only(self):
        opener = FakeOpener([error.HTTPError(
            API, 403, "Forbidden", {}, io.BytesIO(b"body with details"))])
        with self.assertRaises(summary.FetchError) as caught:
            summary.fetch_all(API + "code-scanning/alerts", "token-value", opener)
        self.assertEqual(str(caught.exception), "HTTP 403")

    def test_next_link_accepts_every_rfc_8288_form_of_rel_next(self):
        url = f"{API}x?page=2"
        for header in (f'<{url}>; rel=next', f'<{url}>; REL="Next"',
                       f'<{url}>; rel="prev next"', f'<{API}x?page=1>; rel="prev", <{url}>;rel=next'):
            with self.subTest(header=header):
                self.assertEqual(summary.next_link(header), url)
        for header in (f'<{url}>; rel="nextish"', f'<{url}>; rel=prev', f'<{url}>; title="next"'):
            with self.subTest(header=header):
                self.assertIsNone(summary.next_link(header))
        opener = FakeOpener([FakeResponse([1], link=f"<{url}>; rel=next"), FakeResponse([2])])
        self.assertEqual(summary.fetch_all(API + "x", "t", opener), [1, 2])

    def test_transport_errors_while_reading_the_body_fail_closed(self):
        class TruncatedResponse(FakeResponse):
            def read(self, *args):
                raise http.client.IncompleteRead(b"[", 99)

        with self.assertRaises(summary.FetchError) as caught:
            summary.fetch_all(API + "x", "t", FakeOpener([TruncatedResponse([1])]))
        self.assertEqual(str(caught.exception), "IncompleteRead")

    def test_non_list_payload_and_page_overflow_fail_closed(self):
        with self.assertRaisesRegex(summary.FetchError, "shape"):
            summary.fetch_all(API + "x", "t", FakeOpener([FakeResponse({"a": 1})]))
        link = f'<{API}x?page=2>; rel="next"'
        pages = [FakeResponse([0], link=link) for _ in range(summary.MAX_PAGES)]
        with self.assertRaisesRegex(summary.FetchError, "pages"):
            summary.fetch_all(API + "x", "t", FakeOpener(pages))


class MainTests(unittest.TestCase):
    def run_main(self, fetch, environ=None):
        env = {"GITHUB_TOKEN": "token-value"}
        env.update(environ or {})
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, env, clear=True), \
                patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            code = summary.main(["--repository", "BaryonOS/BaryonOS"], fetch=fetch)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_success_writes_log_and_step_summary(self):
        def fetch(url, token):
            self.assertEqual(token, "token-value")
            return [dependabot_alert()] if "dependabot" in url else []

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "summary.md"
            code, out, err = self.run_main(fetch, {"GITHUB_STEP_SUMMARY": str(path)})
            self.assertEqual(code, 0, err)
            self.assertEqual(path.read_text(encoding="utf-8"), out)
        self.assertIn("### Dependabot: 1 open", out)
        self.assertNotIn("token-value", out + err)

    def test_any_unreadable_source_fails_the_run(self):
        def fetch(url, token):
            if "code-scanning" in url:
                raise summary.FetchError("HTTP 404")
            return []

        code, out, err = self.run_main(fetch)
        self.assertEqual(code, 1)
        self.assertIn("### Code scanning: not read", out)
        self.assertIn("code-scanning (HTTP 404)", err)

    def test_malformed_alert_fails_without_partial_output(self):
        code, out, err = self.run_main(lambda url, token: ["not-an-alert"])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("unexpected", err)

    def test_malformed_nested_field_fails_without_traceback_or_partial_output(self):
        def fetch(url, token):
            return [dependabot_alert(dependency="SECRET-PATH/kernel.rs")] \
                if "dependabot" in url else [code_scanning_alert()]

        code, out, err = self.run_main(fetch)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("unexpected Dependabot alert shape", err)
        self.assertNotIn("SECRET-PATH", err)

    def test_missing_token_or_bad_repository_is_a_usage_error(self):
        with patch.dict(os.environ, {}, clear=True), \
                patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit):
                summary.main(["--repository", "BaryonOS/BaryonOS"])
            os.environ["GITHUB_TOKEN"] = "t"
            with self.assertRaises(SystemExit):
                summary.main(["--repository", "../etc/passwd"])


@unittest.skipIf(yaml is None, "PyYAML unavailable; enforced in ci.yml host-quality")
class WorkflowContractTests(unittest.TestCase):
    def setUp(self):
        self.path = ROOT / ".github/workflows/security-alerts.yml"
        self.workflow = yaml.load(self.path.read_text(encoding="utf-8"),
                                  Loader=yaml.BaseLoader)

    def test_token_can_only_read_alerts(self):
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        job = self.workflow["jobs"]["summarise"]
        self.assertEqual(job["permissions"], {
            "contents": "read",
            "security-events": "read",
            "vulnerability-alerts": "read",
        })
        text = self.path.read_text(encoding="utf-8")
        self.assertNotIn("secrets.", text)
        self.assertNotIn("pull_request_target", text)

    def test_fork_pull_requests_do_not_run(self):
        condition = self.workflow["jobs"]["summarise"]["if"]
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository",
                      condition)
        self.assertIn("github.event_name != 'pull_request'", condition)

    def test_actionlint_exception_is_one_message_in_one_file(self):
        config = yaml.load((ROOT / ".github/actionlint.yaml").read_text(encoding="utf-8"),
                           Loader=yaml.BaseLoader)
        # The runner-label entry belongs to the K06 matrix (tests/test_ci_workflows.py).
        self.assertEqual(config, {
            "self-hosted-runner": {"labels": ["ubuntu-26.04"]},
            "paths": {
                ".github/workflows/security-alerts.yml": {
                    "ignore": ['unknown permission scope "vulnerability-alerts"'],
                },
            },
        })


if __name__ == "__main__":
    unittest.main()
