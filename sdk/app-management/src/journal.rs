#![forbid(unsafe_code)]

//! Durable A/B journal model for the install catalogue.
//!
//! Host-tested contract only: no native storage adapter, power-cut trial or
//! cold-boot acceptance exists. The digest detects torn writes and bit rot; it
//! is not authentication and cannot detect replacement of the whole medium by
//! an older valid copy (that needs a monotonic counter from the platform).
//!
//! Order for a mutation: store commit -> `InstallCatalog::apply` ->
//! `Journal::commit`. `CatalogChange::released` may only be cleaned up after
//! `commit` returned `Ok`. If `commit` fails the in-memory catalog is ahead of
//! durable state: discard it and rebuild with `recover_into` on a new catalog.
//!
//! Two slots; a commit writes only the inactive one, then flushes, so a torn
//! write leaves the previous generation intact. Recovery picks the valid slot
//! with the highest generation. A media read error fails recovery instead of
//! falling back, because an unreadable newer slot must not look like rollback.

use crate::catalog::{CatalogEntry, CatalogError, InstallCatalog};
use crate::store::{ArtifactDescriptor, ArtifactRef};
use crate::{PackageIdentity, IDENTITY_LEN};
use sha2::{Digest, Sha256};

const MAGIC: [u8; 8] = *b"NOSAPPJ1";
const VERSION: u32 = 1;
const HEADER_LEN: usize = 32;
const ENTRY_LEN: usize = IDENTITY_LEN + 32 + 8 + 8 + 32;
const DIGEST_LEN: usize = 32;

/// Bytes a medium must provide per slot for a catalogue of `entries` entries.
pub const fn slot_len(entries: usize) -> usize {
    HEADER_LEN + entries * ENTRY_LEN + DIGEST_LEN
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MediaError;

/// Two slots of at least `slot_len(N)` bytes. `flush` returning `Ok` means all
/// earlier writes are durable; anything else leaves their state unknown.
pub trait JournalMedia {
    fn read(&mut self, slot: usize, offset: usize, out: &mut [u8]) -> Result<(), MediaError>;
    fn write(&mut self, slot: usize, offset: usize, data: &[u8]) -> Result<(), MediaError>;
    fn flush(&mut self) -> Result<(), MediaError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalError {
    Media,
    /// Neither slot was ever written.
    NotFormatted,
    /// No usable slot, or two slots claim the same generation.
    Corrupt,
    /// Not recovered yet, or a previous write left durable state unknown.
    Unknown,
    /// Catalogue generation does not exceed the durable generation.
    Stale,
    Catalog(CatalogError),
}

impl From<CatalogError> for JournalError {
    fn from(error: CatalogError) -> Self {
        Self::Catalog(error)
    }
}

pub struct Journal {
    slot: usize,
    generation: u64,
    ready: bool,
}

impl Default for Journal {
    fn default() -> Self {
        Self::new()
    }
}

struct Recovered<const N: usize> {
    slot: usize,
    generation: u64,
    count: usize,
    entries: [Option<CatalogEntry>; N],
}

enum Probe<const N: usize> {
    Blank,
    Bad,
    Good(Recovered<N>),
}

impl Journal {
    /// Not usable until `format` or `recover_into` succeeded.
    pub const fn new() -> Self {
        Self {
            slot: 0,
            generation: 0,
            ready: false,
        }
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Initialises the medium with an empty generation-1 catalogue and blanks
    /// the other slot. Destroys existing journal content: call only after
    /// `recover_into` returned `NotFormatted`.
    pub fn format<M: JournalMedia>(&mut self, media: &mut M) -> Result<(), JournalError> {
        self.ready = false;
        media
            .write(1, 0, &[0; HEADER_LEN])
            .map_err(|_| JournalError::Media)?;
        write_slot(media, 0, 1, core::iter::empty::<&CatalogEntry>())
            .map_err(|_| JournalError::Media)?;
        *self = Self {
            slot: 0,
            generation: 1,
            ready: true,
        };
        Ok(())
    }

    /// Loads the newest valid durable state into `catalog` through the
    /// catalogue's own `reconcile` checks (epoch, forward-only generation,
    /// duplicates, artifact binding). On error `catalog` is unchanged.
    pub fn recover_into<M: JournalMedia, const N: usize>(
        &mut self,
        media: &mut M,
        catalog: &mut InstallCatalog<N>,
    ) -> Result<(), JournalError> {
        self.ready = false;
        let found = read_best::<M, N>(media)?;
        let fresh_empty = found.count == 0
            && matches!(catalog.snapshot(), Ok((g, it)) if g == found.generation && it.clone().count() == 0);
        if !fresh_empty {
            let epoch = catalog.service_epoch();
            match found.entries.first().copied().flatten() {
                None => catalog.reconcile(epoch, found.generation, &[])?,
                Some(first) => {
                    let mut flat = [first; N];
                    for (dst, src) in flat.iter_mut().zip(found.entries.iter().take(found.count)) {
                        if let Some(entry) = src {
                            *dst = *entry;
                        }
                    }
                    catalog.reconcile(epoch, found.generation, &flat[..found.count])?;
                }
            }
        }
        *self = Self {
            slot: found.slot,
            generation: found.generation,
            ready: true,
        };
        Ok(())
    }

    /// Persists the catalogue snapshot into the inactive slot. Any media error
    /// makes the journal `Unknown` until `recover_into` succeeds again.
    pub fn commit<M: JournalMedia, const N: usize>(
        &mut self,
        media: &mut M,
        catalog: &InstallCatalog<N>,
    ) -> Result<(), JournalError> {
        if !self.ready {
            return Err(JournalError::Unknown);
        }
        let (generation, entries) = catalog.snapshot()?;
        if generation <= self.generation {
            return Err(JournalError::Stale);
        }
        let target = 1 - self.slot;
        if write_slot(media, target, generation, entries).is_err() {
            self.ready = false;
            return Err(JournalError::Media);
        }
        self.slot = target;
        self.generation = generation;
        Ok(())
    }
}

fn encode_entry(entry: &CatalogEntry) -> [u8; ENTRY_LEN] {
    let mut out = [0u8; ENTRY_LEN];
    entry.identity.encode(&mut out[..IDENTITY_LEN]);
    let artifact = &entry.artifact;
    out[IDENTITY_LEN..IDENTITY_LEN + 32].copy_from_slice(&artifact.reference.artifact_id);
    out[IDENTITY_LEN + 32..IDENTITY_LEN + 40]
        .copy_from_slice(&artifact.reference.immutable_generation.to_le_bytes());
    out[IDENTITY_LEN + 40..IDENTITY_LEN + 48].copy_from_slice(&artifact.length.to_le_bytes());
    out[IDENTITY_LEN + 48..].copy_from_slice(&artifact.sha256);
    out
}

fn decode_entry(bytes: &[u8; ENTRY_LEN]) -> Option<CatalogEntry> {
    let identity = PackageIdentity::decode(&bytes[..IDENTITY_LEN]).ok()?;
    let o = IDENTITY_LEN;
    Some(CatalogEntry {
        identity,
        artifact: ArtifactDescriptor {
            reference: ArtifactRef {
                artifact_id: bytes[o..o + 32].try_into().ok()?,
                immutable_generation: u64::from_le_bytes(bytes[o + 32..o + 40].try_into().ok()?),
            },
            length: u64::from_le_bytes(bytes[o + 40..o + 48].try_into().ok()?),
            sha256: bytes[o + 48..].try_into().ok()?,
        },
    })
}

fn write_slot<'a, M: JournalMedia>(
    media: &mut M,
    slot: usize,
    generation: u64,
    entries: impl Iterator<Item = &'a CatalogEntry> + Clone,
) -> Result<(), MediaError> {
    let mut header = [0u8; HEADER_LEN];
    header[..8].copy_from_slice(&MAGIC);
    header[8..12].copy_from_slice(&VERSION.to_le_bytes());
    header[12..16].copy_from_slice(&(entries.clone().count() as u32).to_le_bytes());
    header[16..24].copy_from_slice(&generation.to_le_bytes());
    let mut hasher = Sha256::new();
    hasher.update(header);
    media.write(slot, 0, &header)?;
    let mut offset = HEADER_LEN;
    for entry in entries {
        let bytes = encode_entry(entry);
        hasher.update(bytes);
        media.write(slot, offset, &bytes)?;
        offset += ENTRY_LEN;
    }
    media.write(slot, offset, &hasher.finalize())?;
    media.flush()
}

fn probe<M: JournalMedia, const N: usize>(
    media: &mut M,
    slot: usize,
) -> Result<Probe<N>, MediaError> {
    let mut header = [0u8; HEADER_LEN];
    media.read(slot, 0, &mut header)?;
    if header.iter().all(|byte| *byte == 0) {
        return Ok(Probe::Blank);
    }
    let count = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
    let generation = u64::from_le_bytes(header[16..24].try_into().unwrap());
    if header[..8] != MAGIC
        || u32::from_le_bytes(header[8..12].try_into().unwrap()) != VERSION
        || header[24..].iter().any(|byte| *byte != 0)
        || count > N
        || generation == 0
    {
        return Ok(Probe::Bad);
    }
    let mut hasher = Sha256::new();
    hasher.update(header);
    let mut entries = [None; N];
    let mut decoded = true;
    for (index, slot_entry) in entries.iter_mut().take(count).enumerate() {
        let mut bytes = [0u8; ENTRY_LEN];
        media.read(slot, HEADER_LEN + index * ENTRY_LEN, &mut bytes)?;
        hasher.update(bytes);
        *slot_entry = decode_entry(&bytes);
        decoded &= slot_entry.is_some();
    }
    let mut stored = [0u8; DIGEST_LEN];
    media.read(slot, HEADER_LEN + count * ENTRY_LEN, &mut stored)?;
    if !decoded || stored[..] != hasher.finalize()[..] {
        return Ok(Probe::Bad);
    }
    Ok(Probe::Good(Recovered {
        slot,
        generation,
        count,
        entries,
    }))
}

fn read_best<M: JournalMedia, const N: usize>(media: &mut M) -> Result<Recovered<N>, JournalError> {
    let first = probe::<M, N>(media, 0).map_err(|_| JournalError::Media)?;
    let second = probe::<M, N>(media, 1).map_err(|_| JournalError::Media)?;
    match (first, second) {
        (Probe::Blank, Probe::Blank) => Err(JournalError::NotFormatted),
        (Probe::Good(a), Probe::Good(b)) if a.generation == b.generation => {
            Err(JournalError::Corrupt)
        }
        (Probe::Good(a), Probe::Good(b)) => Ok(if a.generation > b.generation { a } else { b }),
        (Probe::Good(a), _) | (_, Probe::Good(a)) => Ok(a),
        _ => Err(JournalError::Corrupt),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::CatalogOp;
    use std::vec::Vec;

    const N: usize = 3;
    const EPOCH: u64 = 7;
    const LEN: usize = slot_len(N);

    struct Media {
        slots: [Vec<u8>; 2],
        /// Bytes still writable before a write fails midway (torn write).
        budget: Option<usize>,
        fail_flush: bool,
        fail_read: bool,
    }

    impl Media {
        fn new() -> Self {
            Self {
                slots: [std::vec![0; LEN], std::vec![0; LEN]],
                budget: None,
                fail_flush: false,
                fail_read: false,
            }
        }
    }

    impl JournalMedia for Media {
        fn read(&mut self, slot: usize, offset: usize, out: &mut [u8]) -> Result<(), MediaError> {
            if self.fail_read {
                return Err(MediaError);
            }
            out.copy_from_slice(
                self.slots[slot]
                    .get(offset..offset + out.len())
                    .ok_or(MediaError)?,
            );
            Ok(())
        }

        fn write(&mut self, slot: usize, offset: usize, data: &[u8]) -> Result<(), MediaError> {
            let target = self.slots[slot]
                .get_mut(offset..offset + data.len())
                .ok_or(MediaError)?;
            let allowed = self.budget.map_or(data.len(), |left| left.min(data.len()));
            target[..allowed].copy_from_slice(&data[..allowed]);
            if let Some(left) = self.budget.as_mut() {
                *left -= allowed;
            }
            if allowed < data.len() {
                return Err(MediaError);
            }
            Ok(())
        }

        fn flush(&mut self) -> Result<(), MediaError> {
            if self.fail_flush {
                Err(MediaError)
            } else {
                Ok(())
            }
        }
    }

    fn entry(app: &[u8], version: u64, tag: u8) -> CatalogEntry {
        let mut bytes = [0u8; IDENTITY_LEN];
        bytes[..app.len()].copy_from_slice(app);
        bytes[64..96].fill(1);
        bytes[96..100].copy_from_slice(&1u32.to_le_bytes());
        bytes[100..108].copy_from_slice(&version.to_le_bytes());
        bytes[108..112].copy_from_slice(&(64u32 + u32::from(tag)).to_le_bytes());
        bytes[112..144].fill(tag);
        let identity = PackageIdentity::decode(&bytes).unwrap();
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

    fn apply(catalog: &mut InstallCatalog<N>, op: CatalogOp, value: CatalogEntry) {
        let intent = catalog
            .prepare(op, catalog.service_epoch(), catalog.generation(), value)
            .unwrap();
        catalog
            .apply(&intent, Some(value.artifact.reference))
            .unwrap();
    }

    fn formatted() -> (Media, Journal) {
        let mut media = Media::new();
        let mut journal = Journal::new();
        journal.format(&mut media).unwrap();
        (media, journal)
    }

    fn cold_boot(
        media: &mut Media,
        epoch: u64,
    ) -> Result<(InstallCatalog<N>, Journal), JournalError> {
        let mut catalog = InstallCatalog::<N>::new(epoch);
        let mut journal = Journal::new();
        journal.recover_into(media, &mut catalog)?;
        Ok((catalog, journal))
    }

    #[test]
    fn commit_survives_cold_restart_and_continues() {
        let (mut media, mut journal) = formatted();
        let mut catalog = InstallCatalog::<N>::new(EPOCH);
        let a = entry(b"org.example.a", 1, 1);
        apply(&mut catalog, CatalogOp::Install, a);
        journal.commit(&mut media, &catalog).unwrap();
        let a2 = entry(b"org.example.a", 2, 2);
        apply(&mut catalog, CatalogOp::Update, a2);
        journal.commit(&mut media, &catalog).unwrap();

        let (mut booted, mut journal) = cold_boot(&mut media, EPOCH + 1).unwrap();
        assert_eq!(booted.generation(), catalog.generation());
        assert_eq!(booted.lookup(a.identity.app_id()).unwrap(), Some(&a2));
        let b = entry(b"org.example.b", 1, 3);
        apply(&mut booted, CatalogOp::Install, b);
        journal.commit(&mut media, &booted).unwrap();
        let (again, _) = cold_boot(&mut media, EPOCH + 2).unwrap();
        assert_eq!(again.lookup(b.identity.app_id()).unwrap(), Some(&b));
    }

    #[test]
    fn fresh_format_recovers_as_empty_catalog() {
        let (mut media, _) = formatted();
        let (catalog, journal) = cold_boot(&mut media, EPOCH).unwrap();
        assert_eq!(catalog.generation(), 1);
        assert_eq!(journal.generation(), 1);
        assert_eq!(
            cold_boot(&mut Media::new(), EPOCH).err(),
            Some(JournalError::NotFormatted)
        );
    }

    #[test]
    fn torn_write_at_every_byte_keeps_a_whole_generation() {
        let a = entry(b"org.example.a", 1, 1);
        let b = entry(b"org.example.b", 1, 2);
        for cut in 0..=LEN {
            let (mut media, mut journal) = formatted();
            let mut catalog = InstallCatalog::<N>::new(EPOCH);
            apply(&mut catalog, CatalogOp::Install, a);
            journal.commit(&mut media, &catalog).unwrap();
            apply(&mut catalog, CatalogOp::Install, b);
            media.budget = Some(cut);
            let committed = journal.commit(&mut media, &catalog).is_ok();
            media.budget = None;
            let (booted, _) = cold_boot(&mut media, EPOCH + 1).unwrap();
            let has_b = booted.lookup(b.identity.app_id()).unwrap().is_some();
            assert_eq!(
                booted.lookup(a.identity.app_id()).unwrap(),
                Some(&a),
                "cut {cut}"
            );
            assert_eq!(booted.generation(), if has_b { 3 } else { 2 }, "cut {cut}");
            assert!(has_b || !committed, "acknowledged commit lost at cut {cut}");
        }
    }

    #[test]
    fn flush_failure_taints_until_recovery() {
        let (mut media, mut journal) = formatted();
        let mut catalog = InstallCatalog::<N>::new(EPOCH);
        apply(
            &mut catalog,
            CatalogOp::Install,
            entry(b"org.example.a", 1, 1),
        );
        media.fail_flush = true;
        assert_eq!(
            journal.commit(&mut media, &catalog),
            Err(JournalError::Media)
        );
        media.fail_flush = false;
        assert_eq!(
            journal.commit(&mut media, &catalog),
            Err(JournalError::Unknown)
        );
        let (booted, mut journal) = cold_boot(&mut media, EPOCH + 1).unwrap();
        assert!(booted.generation() == 1 || booted.generation() == 2);
        assert_eq!(journal.generation(), booted.generation());
        let mut next = booted;
        apply(&mut next, CatalogOp::Install, entry(b"org.example.c", 1, 5));
        journal.commit(&mut media, &next).unwrap();
    }

    #[test]
    fn any_single_byte_corruption_never_yields_wrong_state() {
        let (mut media, mut journal) = formatted();
        let mut catalog = InstallCatalog::<N>::new(EPOCH);
        let a = entry(b"org.example.a", 1, 1);
        apply(&mut catalog, CatalogOp::Install, a);
        journal.commit(&mut media, &catalog).unwrap(); // generation 2 in slot 1
        let used = HEADER_LEN + ENTRY_LEN + DIGEST_LEN;
        for byte in 0..used {
            let mut damaged = Media::new();
            damaged.slots = media.slots.clone();
            damaged.slots[1][byte] ^= 0x01;
            match cold_boot(&mut damaged, EPOCH + 1) {
                Ok((booted, _)) => match booted.generation() {
                    // Falls back to the intact empty generation 1.
                    1 => assert_eq!(booted.lookup(a.identity.app_id()).unwrap(), None),
                    2 => assert_eq!(booted.lookup(a.identity.app_id()).unwrap(), Some(&a)),
                    other => panic!("byte {byte}: generation {other}"),
                },
                Err(error) => panic!("byte {byte}: {error:?}"),
            }
        }
        // Flipping a byte that is covered by the digest must reject slot 1.
        let mut damaged = Media::new();
        damaged.slots = media.slots.clone();
        damaged.slots[1][HEADER_LEN + 5] ^= 0x01;
        assert_eq!(
            cold_boot(&mut damaged, EPOCH + 1).unwrap().0.generation(),
            1
        );
    }

    #[test]
    fn unusable_media_fails_closed() {
        let (mut media, mut journal) = formatted();
        let mut catalog = InstallCatalog::<N>::new(EPOCH);
        apply(
            &mut catalog,
            CatalogOp::Install,
            entry(b"org.example.a", 1, 1),
        );
        journal.commit(&mut media, &catalog).unwrap();
        let healthy = media.slots.clone();

        for slot in 0..2 {
            media.slots[slot][3] ^= 0xff;
        }
        assert_eq!(
            cold_boot(&mut media, EPOCH + 1).err(),
            Some(JournalError::Corrupt)
        );

        media.slots = healthy.clone();
        media.fail_read = true;
        assert_eq!(
            cold_boot(&mut media, EPOCH + 1).err(),
            Some(JournalError::Media)
        );

        // Same generation in both slots is ambiguous.
        media.fail_read = false;
        media.slots[0] = healthy[1].clone();
        assert_eq!(
            cold_boot(&mut media, EPOCH + 1).err(),
            Some(JournalError::Corrupt)
        );
    }

    #[test]
    fn bad_headers_and_counts_are_rejected() {
        let (mut media, mut journal) = formatted();
        let mut catalog = InstallCatalog::<N>::new(EPOCH);
        apply(
            &mut catalog,
            CatalogOp::Install,
            entry(b"org.example.a", 1, 1),
        );
        journal.commit(&mut media, &catalog).unwrap();
        let healthy = media.slots.clone();
        for (offset, value) in [(8, 2u8), (12, N as u8 + 1), (24, 1), (0, b'X'), (16, 0)] {
            media.slots = healthy.clone();
            media.slots[1][offset] = value;
            if offset == 16 {
                media.slots[1][17..24].fill(0);
            }
            let booted = cold_boot(&mut media, EPOCH + 1).unwrap().0;
            assert_eq!(booted.generation(), 1, "offset {offset}");
        }
    }

    #[test]
    fn stale_and_indeterminate_commits_write_nothing() {
        let (mut media, mut journal) = formatted();
        let mut catalog = InstallCatalog::<N>::new(EPOCH);
        assert_eq!(
            journal.commit(&mut media, &catalog),
            Err(JournalError::Stale)
        );
        let value = entry(b"org.example.a", 1, 1);
        let intent = catalog
            .prepare(CatalogOp::Install, EPOCH, 1, value)
            .unwrap();
        catalog.mark_unknown(&intent).unwrap();
        let before = media.slots.clone();
        assert_eq!(
            journal.commit(&mut media, &catalog),
            Err(JournalError::Catalog(CatalogError::Unknown))
        );
        assert_eq!(media.slots, before);
        assert_eq!(
            Journal::new().commit(&mut media, &catalog),
            Err(JournalError::Unknown)
        );
    }

    #[test]
    fn recovery_does_not_mutate_a_catalog_that_is_ahead() {
        let (mut media, mut journal) = formatted();
        let mut catalog = InstallCatalog::<N>::new(EPOCH);
        apply(
            &mut catalog,
            CatalogOp::Install,
            entry(b"org.example.a", 1, 1),
        );
        journal.commit(&mut media, &catalog).unwrap();
        let mut ahead = InstallCatalog::<N>::new(EPOCH);
        apply(
            &mut ahead,
            CatalogOp::Install,
            entry(b"org.example.z", 1, 9),
        );
        apply(&mut ahead, CatalogOp::Remove, entry(b"org.example.z", 1, 9));
        let generation = ahead.generation();
        assert_eq!(
            Journal::new().recover_into(&mut media, &mut ahead),
            Err(JournalError::Catalog(CatalogError::Stale))
        );
        assert_eq!(ahead.generation(), generation);
    }

    #[test]
    fn restored_entries_still_pass_catalog_validation() {
        let (mut media, mut journal) = formatted();
        let mut catalog = InstallCatalog::<N>::new(EPOCH);
        let a = entry(b"org.example.a", 1, 1);
        apply(&mut catalog, CatalogOp::Install, a);
        apply(
            &mut catalog,
            CatalogOp::Install,
            entry(b"org.example.b", 1, 2),
        );
        journal.commit(&mut media, &catalog).unwrap();
        // Re-seal slot 1 with a duplicated app id and a valid digest.
        let mut forged = Media::new();
        let dup = [a, a];
        write_slot(&mut forged, 0, 5, dup.iter()).unwrap();
        assert_eq!(
            cold_boot(&mut forged, EPOCH + 1).err(),
            Some(JournalError::Catalog(CatalogError::Invalid))
        );
    }
}
