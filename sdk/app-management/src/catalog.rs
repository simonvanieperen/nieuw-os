#![forbid(unsafe_code)]

//! Bounded install/update/remove catalog state machine.
//!
//! This is an in-memory contract model, not a durable catalog. Entries carry
//! no capabilities: installation never grants launch rights or data access.
//! Every mutation is a two-phase `prepare` -> `apply`/`abort` bound to the
//! service epoch and an expected catalog generation, so a stale, replayed or
//! concurrent intent fails without mutation. An `Unknown` storage outcome
//! makes the catalog indeterminate; it then fails closed for both mutation
//! and lookup until `reconcile` installs state from an authoritative source.
//! `journal` is a host-tested durable model of that source; no native storage
//! adapter exists yet.

use crate::store::{ArtifactDescriptor, ArtifactRef};
use crate::PackageIdentity;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogError {
    Invalid,
    Stale,
    Busy,
    Full,
    NotFound,
    AlreadyInstalled,
    SourceMismatch,
    SourceGenerationRollback,
    VersionRollback,
    ArtifactMismatch,
    Overflow,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogEntry {
    pub identity: PackageIdentity,
    pub artifact: ArtifactDescriptor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogOp {
    Install,
    Update,
    Remove,
}

/// Prepared mutation. Holding one is not authority; `apply` re-checks epoch,
/// generation and the committed store reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogIntent {
    op: CatalogOp,
    service_epoch: u64,
    expected_generation: u64,
    serial: u64,
    entry: CatalogEntry,
}

impl CatalogIntent {
    pub const fn op(&self) -> CatalogOp {
        self.op
    }

    pub const fn entry(&self) -> &CatalogEntry {
        &self.entry
    }
}

/// Result of an applied mutation. `released` is a cleanup candidate with no
/// remaining reference in this catalog. Cleanup still requires a durable
/// catalog change and the store's lifetime checks; this is not delete authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogChange {
    pub generation: u64,
    pub released: Option<ArtifactRef>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Health {
    Consistent,
    Indeterminate,
}

pub struct InstallCatalog<const N: usize> {
    entries: [Option<CatalogEntry>; N],
    generation: u64,
    service_epoch: u64,
    last_intent_serial: u64,
    pending: Option<CatalogIntent>,
    health: Health,
}

/// The stored artifact is the verified application image; binding its length
/// and digest to the package identity prevents provenance/artifact mixups.
fn artifact_matches(identity: &PackageIdentity, artifact: &ArtifactDescriptor) -> bool {
    artifact.length == u64::from(identity.image_length())
        && artifact.sha256 == *identity.image_sha256()
        && artifact.reference.immutable_generation != 0
        && artifact.reference.artifact_id.iter().any(|byte| *byte != 0)
}

impl<const N: usize> InstallCatalog<N> {
    pub const fn new(service_epoch: u64) -> Self {
        Self {
            entries: [None; N],
            generation: 1,
            service_epoch,
            last_intent_serial: 0,
            pending: None,
            health: Health::Consistent,
        }
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn service_epoch(&self) -> u64 {
        self.service_epoch
    }

    /// Generation and committed entries for a durable snapshot. Fails closed
    /// while the catalog is indeterminate.
    pub fn snapshot(
        &self,
    ) -> Result<(u64, impl Iterator<Item = &CatalogEntry> + Clone), CatalogError> {
        self.check_consistent()?;
        Ok((self.generation, self.entries.iter().flatten()))
    }

    pub fn lookup(
        &self,
        app_id: &[u8; app_package_core::APP_ID_LEN],
    ) -> Result<Option<&CatalogEntry>, CatalogError> {
        self.check_consistent()?;
        Ok(self
            .position(app_id)
            .and_then(|index| self.entries[index].as_ref()))
    }

    pub fn prepare(
        &mut self,
        op: CatalogOp,
        service_epoch: u64,
        expected_generation: u64,
        entry: CatalogEntry,
    ) -> Result<CatalogIntent, CatalogError> {
        self.check_consistent()?;
        if self.service_epoch == 0 || service_epoch != self.service_epoch {
            return Err(CatalogError::Stale);
        }
        if expected_generation != self.generation {
            return Err(CatalogError::Stale);
        }
        if self.pending.is_some() {
            return Err(CatalogError::Busy);
        }
        if !artifact_matches(&entry.identity, &entry.artifact) {
            return Err(CatalogError::ArtifactMismatch);
        }
        let existing = self
            .position(entry.identity.app_id())
            .and_then(|index| self.entries[index]);
        match op {
            CatalogOp::Install => {
                if existing.is_some() {
                    return Err(CatalogError::AlreadyInstalled);
                }
                if !self.entries.iter().any(Option::is_none) {
                    return Err(CatalogError::Full);
                }
            }
            CatalogOp::Update => {
                let installed = existing.ok_or(CatalogError::NotFound)?;
                Self::check_update(&installed, &entry)?;
            }
            CatalogOp::Remove => {
                let installed = existing.ok_or(CatalogError::NotFound)?;
                if installed != entry {
                    return Err(CatalogError::Stale);
                }
            }
        }
        self.generation
            .checked_add(1)
            .ok_or(CatalogError::Overflow)?;
        let serial = self
            .last_intent_serial
            .checked_add(1)
            .ok_or(CatalogError::Overflow)?;
        let intent = CatalogIntent {
            op,
            service_epoch,
            expected_generation,
            serial,
            entry,
        };
        self.last_intent_serial = serial;
        self.pending = Some(intent);
        Ok(intent)
    }

    /// Applies a prepared intent. `committed` is the reference returned by the
    /// artifact store commit; it is required for install/update and ignored
    /// for remove.
    pub fn apply(
        &mut self,
        intent: &CatalogIntent,
        committed: Option<ArtifactRef>,
    ) -> Result<CatalogChange, CatalogError> {
        self.check_consistent()?;
        self.check_pending(intent)?;
        if intent.op != CatalogOp::Remove && committed != Some(intent.entry.artifact.reference) {
            return Err(CatalogError::ArtifactMismatch);
        }
        let next = self
            .generation
            .checked_add(1)
            .ok_or(CatalogError::Overflow)?;
        let app_id = intent.entry.identity.app_id();
        let released = match intent.op {
            CatalogOp::Install => {
                let slot = self
                    .entries
                    .iter()
                    .position(Option::is_none)
                    .ok_or(CatalogError::Full)?;
                self.entries[slot] = Some(intent.entry);
                None
            }
            CatalogOp::Update => {
                let index = self.position(app_id).ok_or(CatalogError::NotFound)?;
                let previous = self.entries[index].ok_or(CatalogError::NotFound)?;
                self.entries[index] = Some(intent.entry);
                Some(previous.artifact.reference)
            }
            CatalogOp::Remove => {
                let index = self.position(app_id).ok_or(CatalogError::NotFound)?;
                self.entries[index] = None;
                Some(intent.entry.artifact.reference)
            }
        };
        self.generation = next;
        self.pending = None;
        let released = released.filter(|reference| {
            !self
                .entries
                .iter()
                .flatten()
                .any(|entry| entry.artifact.reference == *reference)
        });
        Ok(CatalogChange {
            generation: next,
            released,
        })
    }

    /// Definitive abort: no catalog mutation happened.
    pub fn abort(&mut self, intent: &CatalogIntent) -> Result<(), CatalogError> {
        self.check_consistent()?;
        self.check_pending(intent)?;
        self.pending = None;
        Ok(())
    }

    /// The store reported `Unknown`; the catalog can no longer prove which
    /// state is current and refuses further use until reconciled.
    pub fn mark_unknown(&mut self, intent: &CatalogIntent) -> Result<(), CatalogError> {
        self.check_pending(intent)?;
        self.pending = None;
        self.health = Health::Indeterminate;
        Ok(())
    }

    /// Simulated service restart: in-flight intents become stale. In-memory
    /// entries are retained only in this model; a real service must reload
    /// them from a durable authoritative catalog, which does not exist yet.
    pub fn restart(&mut self, new_service_epoch: u64) -> Result<(), CatalogError> {
        if new_service_epoch <= self.service_epoch {
            return Err(CatalogError::Stale);
        }
        self.service_epoch = new_service_epoch;
        self.pending = None;
        Ok(())
    }

    /// Replaces state from an authoritative snapshot. The caller is
    /// responsible for that authority; the generation must move forward.
    pub fn reconcile(
        &mut self,
        service_epoch: u64,
        generation: u64,
        entries: &[CatalogEntry],
    ) -> Result<(), CatalogError> {
        if service_epoch != self.service_epoch || generation <= self.generation {
            return Err(CatalogError::Stale);
        }
        if entries.len() > N {
            return Err(CatalogError::Full);
        }
        for (index, entry) in entries.iter().enumerate() {
            if !artifact_matches(&entry.identity, &entry.artifact) {
                return Err(CatalogError::ArtifactMismatch);
            }
            if entries[..index]
                .iter()
                .any(|other| other.identity.app_id() == entry.identity.app_id())
            {
                return Err(CatalogError::Invalid);
            }
        }
        let mut next = [None; N];
        for (slot, entry) in next.iter_mut().zip(entries.iter()) {
            *slot = Some(*entry);
        }
        self.entries = next;
        self.generation = generation;
        self.pending = None;
        self.health = Health::Consistent;
        Ok(())
    }

    fn check_update(installed: &CatalogEntry, entry: &CatalogEntry) -> Result<(), CatalogError> {
        if installed.identity.source_id() != entry.identity.source_id() {
            return Err(CatalogError::SourceMismatch);
        }
        if entry.identity.source_generation() < installed.identity.source_generation() {
            return Err(CatalogError::SourceGenerationRollback);
        }
        if entry.identity.version() <= installed.identity.version() {
            return Err(CatalogError::VersionRollback);
        }
        if entry.artifact.reference == installed.artifact.reference {
            return Err(CatalogError::ArtifactMismatch);
        }
        Ok(())
    }

    fn check_consistent(&self) -> Result<(), CatalogError> {
        match self.health {
            Health::Consistent => Ok(()),
            Health::Indeterminate => Err(CatalogError::Unknown),
        }
    }

    fn check_pending(&self, intent: &CatalogIntent) -> Result<(), CatalogError> {
        if intent.service_epoch != self.service_epoch
            || intent.expected_generation != self.generation
        {
            return Err(CatalogError::Stale);
        }
        match self.pending {
            Some(pending) if pending == *intent => Ok(()),
            _ => Err(CatalogError::Stale),
        }
    }

    fn position(&self, app_id: &[u8; app_package_core::APP_ID_LEN]) -> Option<usize> {
        self.entries.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|entry| entry.identity.app_id() == app_id)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IDENTITY_LEN;

    const EPOCH: u64 = 7;

    fn identity(
        app: &[u8],
        source: u8,
        source_generation: u32,
        version: u64,
        tag: u8,
    ) -> PackageIdentity {
        let mut bytes = [0u8; IDENTITY_LEN];
        bytes[..app.len()].copy_from_slice(app);
        bytes[64..96].fill(source);
        bytes[96..100].copy_from_slice(&source_generation.to_le_bytes());
        bytes[100..108].copy_from_slice(&version.to_le_bytes());
        bytes[108..112].copy_from_slice(&(64u32 + u32::from(tag)).to_le_bytes());
        bytes[112..144].fill(tag);
        PackageIdentity::decode(&bytes).unwrap()
    }

    fn entry(
        app: &[u8],
        source: u8,
        source_generation: u32,
        version: u64,
        tag: u8,
    ) -> CatalogEntry {
        let identity = identity(app, source, source_generation, version, tag);
        CatalogEntry {
            identity,
            artifact: ArtifactDescriptor {
                reference: ArtifactRef {
                    artifact_id: [tag; 32],
                    immutable_generation: u64::from(tag),
                },
                length: u64::from(identity.image_length()),
                sha256: *identity.image_sha256(),
            },
        }
    }

    fn installed(catalog: &mut InstallCatalog<2>, value: CatalogEntry) {
        let intent = catalog
            .prepare(CatalogOp::Install, EPOCH, catalog.generation(), value)
            .unwrap();
        catalog
            .apply(&intent, Some(value.artifact.reference))
            .unwrap();
    }

    #[test]
    fn install_update_remove_are_generation_bound_and_grant_nothing() {
        let mut catalog = InstallCatalog::<2>::new(EPOCH);
        let first = entry(b"org.example.notes", 1, 1, 1, 1);
        installed(&mut catalog, first);
        assert_eq!(catalog.generation(), 2);
        assert_eq!(
            catalog.lookup(first.identity.app_id()).unwrap(),
            Some(&first)
        );

        let newer = entry(b"org.example.notes", 1, 2, 2, 2);
        let update = catalog.prepare(CatalogOp::Update, EPOCH, 2, newer).unwrap();
        let change = catalog
            .apply(&update, Some(newer.artifact.reference))
            .unwrap();
        assert_eq!(change.generation, 3);
        assert_eq!(change.released, Some(first.artifact.reference));

        let remove = catalog.prepare(CatalogOp::Remove, EPOCH, 3, newer).unwrap();
        let change = catalog.apply(&remove, None).unwrap();
        assert_eq!(change.released, Some(newer.artifact.reference));
        assert_eq!(catalog.lookup(newer.identity.app_id()).unwrap(), None);
    }

    #[test]
    fn rollback_source_switch_and_artifact_mixups_are_rejected() {
        let mut catalog = InstallCatalog::<2>::new(EPOCH);
        let current = entry(b"org.example.notes", 1, 2, 5, 1);
        installed(&mut catalog, current);
        let generation = catalog.generation();

        let cases = [
            (
                entry(b"org.example.notes", 1, 2, 5, 2),
                CatalogError::VersionRollback,
            ),
            (
                entry(b"org.example.notes", 1, 2, 4, 2),
                CatalogError::VersionRollback,
            ),
            (
                entry(b"org.example.notes", 1, 1, 6, 2),
                CatalogError::SourceGenerationRollback,
            ),
            (
                entry(b"org.example.notes", 2, 2, 6, 2),
                CatalogError::SourceMismatch,
            ),
        ];
        for (candidate, expected) in cases {
            assert_eq!(
                catalog.prepare(CatalogOp::Update, EPOCH, generation, candidate),
                Err(expected)
            );
        }

        let mut wrong_digest = entry(b"org.example.notes", 1, 2, 6, 2);
        wrong_digest.artifact.sha256[0] ^= 1;
        assert_eq!(
            catalog.prepare(CatalogOp::Update, EPOCH, generation, wrong_digest),
            Err(CatalogError::ArtifactMismatch)
        );
        let mut wrong_length = entry(b"org.example.notes", 1, 2, 6, 2);
        wrong_length.artifact.length += 1;
        assert_eq!(
            catalog.prepare(CatalogOp::Update, EPOCH, generation, wrong_length),
            Err(CatalogError::ArtifactMismatch)
        );
        assert_eq!(
            catalog.prepare(CatalogOp::Install, EPOCH, generation, current),
            Err(CatalogError::AlreadyInstalled)
        );
        assert_eq!(
            catalog.prepare(
                CatalogOp::Remove,
                EPOCH,
                generation,
                entry(b"org.example.notes", 1, 2, 6, 2)
            ),
            Err(CatalogError::Stale)
        );
        assert_eq!(
            catalog.prepare(
                CatalogOp::Update,
                EPOCH,
                generation,
                entry(b"org.example.other", 1, 1, 1, 3)
            ),
            Err(CatalogError::NotFound)
        );
        assert_eq!(catalog.generation(), generation);
        assert_eq!(
            catalog.lookup(current.identity.app_id()).unwrap(),
            Some(&current)
        );
    }

    #[test]
    fn full_busy_stale_and_wrong_commit_fail_without_mutation() {
        let mut catalog = InstallCatalog::<2>::new(EPOCH);
        installed(&mut catalog, entry(b"org.example.one", 1, 1, 1, 1));
        installed(&mut catalog, entry(b"org.example.two", 1, 1, 1, 2));
        let generation = catalog.generation();
        let third = entry(b"org.example.three", 1, 1, 1, 3);
        assert_eq!(
            catalog.prepare(CatalogOp::Install, EPOCH, generation, third),
            Err(CatalogError::Full)
        );
        assert_eq!(
            catalog.prepare(
                CatalogOp::Remove,
                EPOCH,
                generation - 1,
                entry(b"org.example.one", 1, 1, 1, 1)
            ),
            Err(CatalogError::Stale)
        );
        assert_eq!(
            catalog.prepare(
                CatalogOp::Remove,
                EPOCH + 1,
                generation,
                entry(b"org.example.one", 1, 1, 1, 1)
            ),
            Err(CatalogError::Stale)
        );

        let update = entry(b"org.example.one", 1, 1, 2, 4);
        let intent = catalog
            .prepare(CatalogOp::Update, EPOCH, generation, update)
            .unwrap();
        assert_eq!(
            catalog.prepare(
                CatalogOp::Update,
                EPOCH,
                generation,
                entry(b"org.example.two", 1, 1, 2, 5)
            ),
            Err(CatalogError::Busy)
        );
        assert_eq!(
            catalog.apply(&intent, None),
            Err(CatalogError::ArtifactMismatch)
        );
        let mut other_ref = update.artifact.reference;
        other_ref.immutable_generation += 1;
        assert_eq!(
            catalog.apply(&intent, Some(other_ref)),
            Err(CatalogError::ArtifactMismatch)
        );
        catalog.abort(&intent).unwrap();
        assert_eq!(
            catalog.apply(&intent, Some(update.artifact.reference)),
            Err(CatalogError::Stale)
        );
        assert_eq!(catalog.abort(&intent), Err(CatalogError::Stale));
        assert_eq!(catalog.generation(), generation);
        assert_eq!(
            catalog.lookup(b"org.example.one\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")
                .unwrap()
                .map(|value| value.identity.version()),
            Some(1)
        );
    }

    #[test]
    fn applied_intent_cannot_be_replayed_and_restart_stales_pending() {
        let mut catalog = InstallCatalog::<2>::new(EPOCH);
        let first = entry(b"org.example.notes", 1, 1, 1, 1);
        let intent = catalog
            .prepare(CatalogOp::Install, EPOCH, 1, first)
            .unwrap();
        catalog
            .apply(&intent, Some(first.artifact.reference))
            .unwrap();
        assert_eq!(
            catalog.apply(&intent, Some(first.artifact.reference)),
            Err(CatalogError::Stale)
        );

        let newer = entry(b"org.example.notes", 1, 1, 2, 2);
        let pending = catalog.prepare(CatalogOp::Update, EPOCH, 2, newer).unwrap();
        assert_eq!(catalog.restart(EPOCH), Err(CatalogError::Stale));
        catalog.restart(EPOCH + 1).unwrap();
        assert_eq!(
            catalog.apply(&pending, Some(newer.artifact.reference)),
            Err(CatalogError::Stale)
        );
        assert_eq!(
            catalog.prepare(CatalogOp::Update, EPOCH, 2, newer),
            Err(CatalogError::Stale)
        );
        let fresh = catalog
            .prepare(CatalogOp::Update, EPOCH + 1, 2, newer)
            .unwrap();
        catalog
            .apply(&fresh, Some(newer.artifact.reference))
            .unwrap();
        assert_eq!(catalog.generation(), 3);
    }

    #[test]
    fn cancelled_intent_stays_stale_after_identical_prepare() {
        for op in [CatalogOp::Install, CatalogOp::Update, CatalogOp::Remove] {
            let mut catalog = InstallCatalog::<2>::new(EPOCH);
            let first = entry(b"org.example.notes", 1, 1, 1, 1);
            if op != CatalogOp::Install {
                installed(&mut catalog, first);
            }
            let candidate = if op == CatalogOp::Update {
                entry(b"org.example.notes", 1, 1, 2, 2)
            } else {
                first
            };
            let generation = catalog.generation();
            let cancelled = catalog.prepare(op, EPOCH, generation, candidate).unwrap();
            catalog.abort(&cancelled).unwrap();
            let fresh = catalog.prepare(op, EPOCH, generation, candidate).unwrap();

            assert_ne!(cancelled, fresh);
            assert_eq!(
                catalog.apply(&cancelled, Some(candidate.artifact.reference)),
                Err(CatalogError::Stale)
            );
            assert_eq!(catalog.abort(&cancelled), Err(CatalogError::Stale));
            assert_eq!(catalog.mark_unknown(&cancelled), Err(CatalogError::Stale));
            assert_eq!(catalog.generation(), generation);
            assert_eq!(
                catalog.lookup(first.identity.app_id()).unwrap().copied(),
                (op != CatalogOp::Install).then_some(first)
            );
            catalog
                .apply(&fresh, Some(candidate.artifact.reference))
                .unwrap();
            assert_eq!(catalog.generation(), generation + 1);
        }
    }

    #[test]
    fn shared_image_is_released_only_after_last_catalog_reference() {
        for op in [CatalogOp::Update, CatalogOp::Remove] {
            let mut catalog = InstallCatalog::<2>::new(EPOCH);
            let first = entry(b"org.example.notes", 1, 1, 1, 1);
            let other = entry(b"org.example.reader", 1, 1, 1, 1);
            installed(&mut catalog, first);
            installed(&mut catalog, other);
            let candidate = if op == CatalogOp::Update {
                entry(b"org.example.notes", 1, 1, 2, 2)
            } else {
                first
            };
            let intent = catalog
                .prepare(op, EPOCH, catalog.generation(), candidate)
                .unwrap();
            let change = catalog
                .apply(&intent, Some(candidate.artifact.reference))
                .unwrap();
            assert_eq!(change.released, None);
            assert_eq!(
                catalog.lookup(other.identity.app_id()).unwrap(),
                Some(&other)
            );
            let remove = catalog
                .prepare(CatalogOp::Remove, EPOCH, catalog.generation(), other)
                .unwrap();
            assert_eq!(
                catalog.apply(&remove, None).unwrap().released,
                Some(first.artifact.reference)
            );
        }
    }

    #[test]
    fn exhausted_intent_serial_fails_without_pending_or_catalog_mutation() {
        let mut catalog = InstallCatalog::<2>::new(EPOCH);
        let first = entry(b"org.example.notes", 1, 1, 1, 1);
        catalog.last_intent_serial = u64::MAX - 1;
        let last = catalog
            .prepare(CatalogOp::Install, EPOCH, 1, first)
            .unwrap();
        catalog.abort(&last).unwrap();
        for _ in 0..2 {
            assert_eq!(
                catalog.prepare(CatalogOp::Install, EPOCH, 1, first),
                Err(CatalogError::Overflow)
            );
            assert_eq!(catalog.pending, None);
            assert_eq!(catalog.generation(), 1);
            assert_eq!(catalog.lookup(first.identity.app_id()).unwrap(), None);
            assert_eq!(catalog.abort(&last), Err(CatalogError::Stale));
        }
        catalog.restart(EPOCH + 1).unwrap();
        assert_eq!(
            catalog.prepare(CatalogOp::Install, EPOCH + 1, 1, first),
            Err(CatalogError::Overflow)
        );
    }

    #[test]
    fn unknown_outcome_fails_closed_until_authoritative_reconcile() {
        let mut catalog = InstallCatalog::<2>::new(EPOCH);
        let first = entry(b"org.example.notes", 1, 1, 1, 1);
        installed(&mut catalog, first);
        let newer = entry(b"org.example.notes", 1, 1, 2, 2);
        let intent = catalog.prepare(CatalogOp::Update, EPOCH, 2, newer).unwrap();
        catalog.mark_unknown(&intent).unwrap();

        assert_eq!(
            catalog.lookup(first.identity.app_id()),
            Err(CatalogError::Unknown)
        );
        assert_eq!(
            catalog.apply(&intent, Some(newer.artifact.reference)),
            Err(CatalogError::Unknown)
        );
        assert_eq!(
            catalog.prepare(
                CatalogOp::Install,
                EPOCH,
                2,
                entry(b"org.example.other", 1, 1, 1, 3)
            ),
            Err(CatalogError::Unknown)
        );
        catalog.restart(EPOCH + 1).unwrap();
        assert_eq!(
            catalog.lookup(first.identity.app_id()),
            Err(CatalogError::Unknown)
        );

        assert_eq!(
            catalog.reconcile(EPOCH, 3, &[newer]),
            Err(CatalogError::Stale)
        );
        assert_eq!(
            catalog.reconcile(EPOCH + 1, 2, &[newer]),
            Err(CatalogError::Stale)
        );
        let mut corrupt = newer;
        corrupt.artifact.sha256[0] ^= 1;
        assert_eq!(
            catalog.reconcile(EPOCH + 1, 3, &[corrupt]),
            Err(CatalogError::ArtifactMismatch)
        );
        assert_eq!(
            catalog.reconcile(EPOCH + 1, 3, &[newer, newer]),
            Err(CatalogError::Invalid)
        );
        assert_eq!(
            catalog.reconcile(EPOCH + 1, 3, &[first, newer, newer]),
            Err(CatalogError::Full)
        );
        assert_eq!(
            catalog.lookup(first.identity.app_id()),
            Err(CatalogError::Unknown)
        );

        catalog.reconcile(EPOCH + 1, 3, &[newer]).unwrap();
        assert_eq!(
            catalog
                .lookup(newer.identity.app_id())
                .unwrap()
                .map(|value| value.identity.version()),
            Some(2)
        );
        assert_eq!(catalog.generation(), 3);
    }
}
