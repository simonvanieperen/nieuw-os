# App package format — verification core (A02 sub-step)

Status: implemented `no_std` verification core and connection to existing
user-ELF policy; no installer, catalogue, dynamic app-image loading chain or
native acceptance.

`app-package-core` processes one package as a fixed manifest header of 3,584
bytes followed by exactly one application image. The manifest is versionable,
little-endian and uses `NOSAPP01` as a domain label. `verify_executable_package`
first verifies the package and then passes the image to
`kernel_core::user::parse`, the same existing ELF policy the kernel uses before
process construction. The returned fixed loading description contains no
allocated frames or process/launch capability and grants no launch right by
itself. Both existing standard verifications from ADR-049 are required:
Ed25519 and ML-DSA-65 over the same canonical metadata. The caller selects
publisher anchors from the explicitly chosen source; the bundle cannot
identify a trusted key itself. Verification binds the exact image length and
SHA-256 to the manifest.

Primary standards: Ed25519 is an EdDSA variant from NIST, *Digital Signature
Standard (DSS)*, FIPS 186-5, published on 2023-02-03,
https://csrc.nist.gov/pubs/fips/186-5/final. ML-DSA-65 is a parameterisation
from NIST, *Module-Lattice-Based Digital Signature Standard*, FIPS 204,
published on 2024-08-13,
https://csrc.nist.gov/pubs/fips/204/final. Both signatures are required over
the same canonical metadata; this demonstrates provenance under the chosen
key, not that the publisher or app is safe.

| Offset | Field |
|---|---|
| 0 | `NOSAPP01` |
| 8 | format version u32 = 1 |
| 12 | app ID [64], ASCII, zero-padded |
| 76 | minimum ABI u32 |
| 80 | maximum ABI u32 |
| 84 | app version u64 |
| 92 | image length u32 |
| 96 | image SHA-256 [32] |
| 128 | Ed25519 key ID [8] |
| 136 | ML-DSA-65 key ID [8] |
| 144 | Ed25519 signature [64] |
| 208 | ML-DSA-65 signature [3309] |
| 3517 | zero padding through 3584 |

Signature bytes cover exactly `manifest[0..144]`. ABI encodes major in the
high 16 bits and minor in the low 16 bits. The image starts at byte 3584,
and the package contains no trailing padding. The decoder checks framing and
ABI first, then selected key IDs and image hash, and only then performs the
two relatively expensive signature verifications.

Metadata contains only app ID, ABI interval, version number, image length,
digest and key IDs. There is deliberately no script, dependency resolver,
file location, capability/rights declaration or host output. The package ID
is a lowercase dot-separated identifier, not authority. A valid signature
proves only provenance under the selected key and integrity; it is not a
statement that an app is safe or trustworthy and grants no rights.

## Multiple app sources — policy core

`SourceRegistry` holds at most eight explicitly chosen sources. A 32-byte
`SourceId` comes from the trusted source manager and is absent from the
package; the caller selects the source for every verification. A source may
be added, rotated against an expected generation or revoked. Rotation and
revocation increment the generation; stale mutations fail without changing
state. Revoked slots remain tombstones and are not implicitly reused.

Revocation blocks new package verification and updates through that source.
Already installed apps remain launchable; data or apps are not silently
removed. This follows the decision of 30 October 2026. Managing source choice
and rotation requires separate user authorisation. This fixed array is only
an in-memory policy core: no consent UI, capability checking, durable source
registration or transactions. Eight sources is not a product limit.

ABI versions are two u16 values in one u32: major in the high 16 bits, minor
in the low bits. The verifier receives the actually negotiated ABI as an
argument; it does not infer a host or SDK version. The 2 MiB image limit is
solely this first fixture boundary, not an established product budget.
The manifest decoder rejects unknown versions, zero/oversized images,
non-canonical padding, invalid IDs and invalid ABI intervals.

## Streaming artefact store and app-management contract

The standalone `sdk/app-management` crate separates the immutable read-handle
contract from the write transaction. Both are host/target contracts; there is
not yet a persistent store adapter or native installer.

`ArtifactRef` contains `artifact_id[32]` and `immutable_generation:u64`.
`ArtifactDescriptor` combines that reference with `length:u64` and `sha256[32]`.
Publisher metadata (`source_id`, source generation, package version and app
identity) remains separate in package provenance; store generation is not a
publisher epoch. These are Rust records, not a fixed serialised storage ABI.
The `u64` capacity report gives total capacity, used bytes, reserved bytes and
quota; this contract has no global product cap. At `begin`, a provider must
atomically reserve the complete object length or fail before accepting chunks.

Since #109, the read side uses the shared `artifact-store-core` contract
(ADR-054, a contract proposal; native execution remains open); app management
no longer redefines read types. **Contract requirement, not yet implemented:**
there is no persistent store adapter yet. A future adapter implements
`ArtifactStore`, constructs the opaque handle type (neither serialisable nor
transferable), binds the handle to the kernel-authenticated client context
and current store epoch, and checks both on every read. Test adapter
`FakeStore` checks only `handle.epoch` and `handle.locator` on reads; it does
not model authenticated client context, so client binding has not been tested
anywhere. `open_checked` rejects a store-authoritative descriptor that differs
from the expected one (`Corrupt`); `read_bounded` uses the descriptor from the
opened handle, so a caller cannot supply a different descriptor. Each storage
operation is bounded to 4 KiB and errors are explicit: stale epoch, corruption,
truncation before declared length, overflow, EOF (`EndOfArtifact`) and an
offset outside the object (`OutOfRange`). This is a storage-layer boundary;
existing Message320 IPC retains a maximum of 256 payload bytes. The
app-management chunk request uses at most 224 data bytes per message.

The write transaction binds `caller`, `request_id` and `service_epoch` to the
store descriptor: immutable `ArtifactRef`, length and digest. `source_id`,
source generation and package version remain separate in `PackageIdentity`;
they are not bound to `InstallTransaction` and form no store or publisher
authority. Package policy must assess provenance and permissibility separately;
a persistent issuer/key lifecycle is still absent. Chunks are non-empty,
at most 4 KiB and strictly sequential at the expected offset. Commit is allowed
only after exactly the declared length and publishes atomically after complete
length/digest checking. Cancel is valid only before commit. `Unknown` blocks
replay and automatic recommit; an outcome may be queried only within the same
service epoch. After restart, old requests must become stale and recovery
must consult the durable catalogue. The current implementation is only an
in-memory transaction guard with fake-store tests: no durable journal or
proven cold recovery.

A digest is solely content-integrity metadata; it proves neither a publisher
nor model suitability. `SourceRegistry` remains in memory. Security/B02/B03
owners have released no existing issuer/trust-root lifecycle API, and B02 or
B03 anchors cannot be reused as app-publisher policy. Therefore no `verified`
boolean, artificial publisher epoch or claim of persistent signer trust is
added. Valid package verification under a temporary selected key does not by
itself establish persistent installer authority. The document-volume client
is not an authoritative app store while its current authentication/rollback
boundary is insufficient; this crate does not write to it.

### Install/update/remove catalogue (contract model)

`catalog::InstallCatalog<N>` is a bounded in-memory state model above the
artefact transaction. Every mutation is two-phase (`prepare` → `apply`/`abort`)
and bound to service epoch and expected catalogue generation; a stale,
repeated or concurrent intent fails without mutation. A private monotonically
increasing intent serial prevents a cancelled instruction from becoming valid
again when the same action is prepared anew. Exhaustion fails with `Overflow`
before a pending instruction exists; abort, restart and reconcile do not reuse
serials within this catalogue object. A real service must use a fresh service
epoch on reconstruction; the model does not provide that epoch authority.
The stored artefact must match the image in package identity in length and
SHA-256, and `apply` requires exactly the `ArtifactRef` committed by the store.
Update requires the same source, no lower source generation and a strictly
higher version; source change or downgrade is not an update. Remove requires
the exact installed entry. `released` reports only an old artefact no longer
used by any other entry in this catalogue. It is a cleanup candidate, not
erasure authority: durable catalogue mutation and the store lifetime check
(including other consumers and open read handles) remain necessary. The
catalogue removes no bytes and has no user-data or capability handle; removing
a package is not a request to erase user documents. Preservation of actual
user data and revocation of old task rights after update/removal still require
native integration and testing. Entries contain no capabilities: installation
grants nothing.

An `Unknown` store outcome makes the catalogue indeterminate: mutation and
lookup both fail closed, including after restart, until `reconcile` installs
a snapshot with a higher generation. That authoritative durable source does
not yet exist; this model therefore demonstrates neither persistence nor cold
recovery. `N` is a compile-time model bound, not a product limit.

#### Durable catalogue journal (host model, TASK-A02-J)

`sdk/app-management/src/journal.rs` adds a two-slot A/B journal over a
`JournalMedia` trait (read, write, flush). A commit writes only the inactive
slot, hashes header and entries with SHA-256 (torn-write and bit-rot detection,
not authentication) and flushes before the slot counts. `recover_into` picks the
valid slot with the highest generation and restores it only through
`InstallCatalog::reconcile`, so epoch, forward-only generation, duplicate and
artifact-binding checks are not duplicated or weakened. A media read error,
two valid slots with equal generation, or no valid slot fail closed
(`Media`, `Corrupt`); a failed write leaves the journal `Unknown` until the next
successful recovery. `released` artifacts may only be cleaned up after
`commit` returned `Ok`.

Host tests inject torn writes at every byte, flush and read failures, every
single-byte corruption of the newest slot, bad headers, ambiguous slots, stale
and indeterminate commits, and a forged digest-valid slot with duplicate app
ids. Not provided: a native storage adapter, power-cut or cold-boot trial,
protection against replacing the whole medium with an older valid copy (needs
a platform monotonic counter), or any change to A02 acceptance.

#### Targeted execution TASK-A02-CATALOG — 30 October 2026

Code source `05e658e58eb69d29a2a800660616308c4cecf2e3`, branch
`codex/app-management-catalog-leaf`, base `9d8a119` with initial catalogue commit
`c8c68ee`. SHA-256 of `sdk/app-management/src/catalog.rs`:
`1ecd0e45bdb7f8690c1784e75428acdcf3f767e4b669f5d709382c334f1e7582`.
The two regression tests for cancellation/repreparation and shared-image
cleanup first failed on the unchanged catalogue from `c8c68ee` (exit 101,
five existing catalogue tests passing, two new tests failing). On the code
source above, all 18 app-management tests pass, including eight catalogue tests.

Local environment for the following four commands:

```sh
export CC="$PWD/.tools/nieuw-os/dev/cc-wrapper"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$CC"
export CARGO_TARGET_DIR=/tmp/nieuw-os-app-management-target
python3 -B tools/dev.py cargo +1.90.0 test --offline --locked --manifest-path sdk/app-management/Cargo.toml
python3 -B tools/dev.py cargo +1.90.0 clippy --offline --locked --manifest-path sdk/app-management/Cargo.toml --all-targets -- -D warnings
python3 -B tools/dev.py cargo +1.90.0 fmt --manifest-path sdk/app-management/Cargo.toml --all -- --check
CARGO_ENCODED_RUSTFLAGS=$'--cfg\x1fcurve25519_dalek_backend="serial"' \
  python3 -B tools/dev.py cargo +1.90.0 build --offline --locked --release --manifest-path sdk/app-management/Cargo.toml --target x86_64-unknown-none
```

Every command exited 0. The complete host tests were executed, not inferred
from a build cache. Durations in this environment: test <1 s, Clippy <1 s,
fmt 1 s, target build <1 s; these are not runtime performance measurements.
Local logs: `/tmp/nieuw-os-app-catalog-05e658e-{test,clippy,fmt,none}.log`;
failing regression: `/tmp/nieuw-os-app-catalog-regression-before.log`.

Not performed: native installation/update/remove, actual I/O/power-cut trial,
user-data preservation on disk, rights revocation after update, cold recovery,
CI on this source, physical or human acceptance. The crate adds no engine,
dependency, persistence backend, publisher verifier or authority. A01 retains
its own historical SDK evidence; A02/A03/A04 remain open. This catalogue result
does not complete FR-A11/A12/A13 or other daily apps and compatibility tasks
from FULL-TEST-RELEASE-CONTEXT.

The shared read-only interface is also the intended entry point for consumers
such as a local AI model reader. Consumers must assess their own format/parser
boundaries and applicable model integrity; the artefact digest is neither
publisher trust nor a security statement. A dynamic launcher, single-use
`AuthorizedImage` handle, kernel copy/preflight path and app/catalogue
persistence are not implemented. The current launch message carries a package
identity, at most two capabilities reduced by the policy broker (zero by
default), and epochs; manifest rights create no capabilities.

## Testing and evidence boundary

```sh
cargo +1.90.0 test --offline --locked -p app-package-core
cargo +1.90.0 clippy --offline --locked -p app-package-core --all-targets -- -D warnings
CARGO_ENCODED_RUSTFLAGS=$'--cfg\x1fcurve25519_dalek_backend="serial"' \
  cargo +1.90.0 build --offline --locked -p app-package-core --target x86_64-unknown-none
cargo +1.90.0 test --offline --locked --manifest-path sdk/app-management/Cargo.toml
cargo +1.90.0 clippy --offline --locked --manifest-path sdk/app-management/Cargo.toml --all-targets -- -D warnings
cargo +1.90.0 fmt --manifest-path sdk/app-management/Cargo.toml --all -- --check
CARGO_ENCODED_RUSTFLAGS=$'--cfg\x1fcurve25519_dalek_backend="serial"' \
  cargo +1.90.0 build --offline --locked --release --manifest-path sdk/app-management/Cargo.toml --target x86_64-unknown-none
```

The first three commands test only the existing package core. App-management
tests check bounded wire decoding, zero-grant launch, capability/epoch binding,
read limits and transaction state with fake backends; they demonstrate no
actual provider, install/update/remove, trust persistence, native execution or
cold recovery. Cross-compilation proves only that the library compiles for
the freestanding target.

These package-core tests demonstrate only host/bare-metal library verification.
They do not show that an app can be installed, atomically managed on disk,
found after restart or launched through the kernel. The user-ELF parser uses
the same address/segment/quota policy as the current kernel loader. Tests show
that a correctly signed but W+X ELF image is not declared launch-ready.
SourceRegistry tests check independent source selection, generation-bound key
rotation, revocation, duplicate keys and fixed capacity; the registry is not
durable and grants no rights. The helper builds no mappings, process or
`LaunchImage`; A02 additionally requires on-disk source management, installer
transactions, update/removal policy, a dynamic image-loading chain and actual
native positive/negative tasks. When used, the loader service must account
for the approximately 200 KiB ML-DSA verification stack and have an appropriate
bounded stack.
