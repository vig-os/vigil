//! Internal durable writer; the public trail surface follows in #11 B3.
use super::{
    format::{Kind, request},
    storage::{Head, State, TrailReader, existing, scan},
    *,
};
use crate::rotate::{self, Directory};
use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
use rustix::fs::{self as rfs, AtFlags, Mode, OFlags};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub(crate) struct Config {
    pub(crate) service: String,
    pub(crate) checkpoint_every: u64,
    pub(crate) checkpoint_interval: Duration,
    pub(crate) max_bytes: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            service: "vigil".into(),
            checkpoint_every: 1000,
            checkpoint_interval: Duration::from_secs(60),
            max_bytes: 50 * 1024 * 1024,
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Recorded {
    pub(crate) head: Head,
    pub(crate) unsigned_records: u64,
}
impl std::ops::Deref for Recorded {
    type Target = Head;
    fn deref(&self) -> &Head {
        &self.head
    }
}
pub(crate) struct Sink {
    reader: TrailReader,
    trail: [u8; 16],
    signer: Arc<dyn Signer>,
    config: Config,
    poisoned: AtomicBool,
    reported: AtomicBool,
    unsigned_records: AtomicU64,
    closed: bool,
}
fn error(kind: AuditErrorKind, text: impl Into<String>) -> AuditError {
    AuditError::new(kind, text)
}
fn io_error(e: impl std::fmt::Display) -> AuditError {
    error(AuditErrorKind::Io, e.to_string())
}
fn corrupt(text: &str) -> AuditError {
    error(AuditErrorKind::CorruptTrail, text)
}
fn exists(dir: &File, name: &str) -> Result<bool, AuditError> {
    match rfs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(e) => Err(io_error(e)),
    }
}
fn poison_check(dir: &File) -> Result<(), AuditError> {
    if exists(dir, "audit.poison")? {
        Err(error(AuditErrorKind::Poisoned, "audit.poison exists"))
    } else {
        Ok(())
    }
}
fn new_file(dir: &File, name: &str, mode: Mode) -> Result<File, AuditError> {
    #[cfg(test)]
    hooks::event(name_to_create_site(name)).map_err(io_error)?;
    rfs::openat(
        dir,
        name,
        OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::APPEND
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW,
        mode,
    )
    .map(File::from)
    .map_err(io_error)
}
fn marker(dir: &File) -> Result<[u8; 16], AuditError> {
    if !exists(dir, "audit.trail")? {
        return Err(error(AuditErrorKind::MissingTrail, "missing audit.trail"));
    }
    let file = existing(dir, Path::new("audit.trail"), false)?;
    let mut bytes = Vec::new();
    file.take(34).read_to_end(&mut bytes).map_err(io_error)?;
    if bytes.len() != 33
        || bytes[32] != b'\n'
        || !bytes[..32]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(corrupt("noncanonical trail marker"));
    }
    let mut trail = [0; 16];
    let digit = |b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    for (byte, pair) in trail.iter_mut().zip(bytes[..32].chunks_exact(2)) {
        *byte = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(trail)
}
fn clock() -> Result<u64, AuditError> {
    #[cfg(test)]
    if let Some(time) = hooks::TIME.with(std::cell::Cell::get) {
        hooks::CHECK_CLOCK.with(|check| {
            if let Some(check) = check.borrow().as_ref() {
                check();
            }
        });
        hooks::event("clock").map_err(io_error)?;
        return Ok(time);
    }
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io_error)?
            .as_nanos(),
    )
    .map_err(io_error)
}
pub(super) fn line(record: &Record) -> Result<Vec<u8>, AuditError> {
    let context = AnyValue {
        value: Some(any_value::Value::StringValue("vigil".into())),
    };
    let request = request(record, context)?;
    let mut bytes = crate::logs::encode_line(&request)
        .map_err(io_error)?
        .into_bytes();
    bytes.push(b'\n');
    Ok(bytes)
}
fn sync_io(file: &File, site: &'static str) -> std::io::Result<()> {
    #[cfg(test)]
    hooks::event(site)?;
    if site.ends_with("dir") || site == "marker" {
        file.sync_all()?;
    } else {
        file.sync_data()?;
    }
    #[cfg(test)]
    hooks::durable(file)?;
    Ok(())
}
fn sync(file: &File, site: &'static str, poisoned: &AtomicBool) -> Result<(), AuditError> {
    sync_io(file, site).map_err(|e| {
        poisoned.store(true, Ordering::Relaxed);
        io_error(e)
    })
}
fn write_io(file: &File, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(test)]
    {
        hooks::event("write")?;
        if let Some(cap) = hooks::SHORT.with(std::cell::Cell::take) {
            (&*file).write_all(&bytes[..cap.min(bytes.len())])?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "injected short write",
            ));
        }
    }
    #[cfg(test)]
    if hooks::HALF.with(std::cell::Cell::take) {
        (&*file).write_all(&bytes[..bytes.len() / 2])?;
        hooks::point("partial-write");
        panic!("partial-write hook must end the process");
    }
    rotate::write_once(&mut &*file, bytes)?;
    #[cfg(test)]
    hooks::point("after-write");
    Ok(())
}
fn truncate_io(file: &File, length: u64) -> std::io::Result<()> {
    #[cfg(test)]
    hooks::event("truncate")?;
    file.set_len(length)
}
fn append(
    dir: &File,
    file: &File,
    bytes: &[u8],
    site: &'static str,
    poisoned: &AtomicBool,
) -> Result<(), AuditError> {
    let length = file.metadata().map_err(io_error)?.len();
    let write = write_io(file, bytes).map_err(io_error);
    let result = write.and_then(|()| sync(file, site, poisoned));
    if let Err(original) = result {
        let rollback = truncate_io(file, length);
        if let Err(truncate) = rollback {
            // Persist the barrier before releasing the directory lock (d6).
            poison(dir, &format!("{original}; rollback: {truncate}"));
        }
        return Err(original);
    }
    Ok(())
}
fn poison(dir: &File, cause: &str) {
    if let Ok(file) = new_file(dir, "audit.poison", Mode::RUSR | Mode::WUSR) {
        let _ = write_io(&file, cause.as_bytes());
    }
}
fn sync_renamed(
    dir: &File,
    site: &'static str,
    staging: &str,
    poisoned: &AtomicBool,
) -> Result<(), AuditError> {
    sync(dir, site, poisoned).inspect_err(|error| {
        let segments = match rotate::rotated_names_at(dir, "audit") {
            Ok(names) => format!("{names:?}"),
            Err(cause) => format!("segment names unavailable: {cause}"),
        };
        poison(
            dir,
            &format!("{error}; directory fsync after rename: audit.jsonl, {staging}, {segments}"),
        );
    })
}
#[cfg(test)]
fn name_to_create_site(name: &str) -> &'static str {
    match name {
        "audit.poison" => "create-poison",
        "audit.trail" => "create-marker",
        _ => "create-staging",
    }
}
fn linked_live(dir: &File) -> Result<bool, AuditError> {
    let live = existing(dir, Path::new("audit.jsonl"), false)?;
    rotate::has_segment_link(dir, "audit", &rfs::fstat(&live).map_err(io_error)?).map_err(io_error)
}
fn predecessor(dir: &File, trail: [u8; 16]) -> Result<Option<State>, AuditError> {
    let mut state = None;
    for name in rotate::rotated_names_at(dir, "audit").map_err(io_error)? {
        state = Some(scan(
            &existing(dir, &name, false)?,
            trail,
            state,
            true,
            None,
            &mut false,
            false,
        )?);
    }
    if exists(dir, "audit.jsonl")? && !linked_live(dir)? {
        state = Some(scan(
            &existing(dir, Path::new("audit.jsonl"), false)?,
            trail,
            state,
            true,
            None,
            &mut false,
            false,
        )?);
    }
    Ok(state)
}
fn settle(dir: &File, trail: [u8; 16], poisoned: &AtomicBool) -> Result<(), AuditError> {
    for (name, count) in [(".audit-next.jsonl", 1), (".audit-resume.jsonl", 2)] {
        if !exists(dir, name)? {
            continue;
        }
        let staged = existing(dir, Path::new(name), false)?;
        let mut bytes = Vec::new();
        (&staged)
            .take(2_000_003)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        let records: Option<Vec<Record>> = bytes.strip_suffix(b"\n").and_then(|payload| {
            payload
                .split(|b| *b == b'\n')
                .map(|part| {
                    let mut records = Record::parse_line(part).ok()?;
                    if records.len() == 1 {
                        records.pop()
                    } else {
                        None
                    }
                })
                .collect()
        });
        let prior = predecessor(dir, trail)?;
        let valid = records.as_ref().is_some_and(|records| {
            if records.len() != count {
                return false;
            }
            let first = &records[0];
            if !matches!(first.kind, Kind::Checkpoint(_)) {
                return false;
            }
            let seq = prior.as_ref().map_or(0, |s| s.head.seq.saturating_add(1));
            if count == 1 && first.context.seq != seq {
                return false;
            }
            // Scan enforces predecessor/genesis links, forward sequence and immediate resume action.
            scan(&staged, trail, prior.clone(), true, None, &mut false, true).is_ok()
        });
        if valid {
            if exists(dir, "audit.jsonl")? {
                #[cfg(test)]
                hooks::event("seal-rename").map_err(io_error)?;
                if linked_live(dir)? {
                    rfs::unlinkat(dir, "audit.jsonl", AtFlags::empty()).map_err(io_error)?;
                } else {
                    rotate::rotate(dir, "audit", Path::new("audit.jsonl")).map_err(io_error)?;
                }
            }
            #[cfg(test)]
            hooks::event("promote").map_err(io_error)?;
            rotate::rename_no_replace(dir, Path::new(name), Path::new("audit.jsonl"))
                .map_err(io_error)?;
            sync_renamed(dir, "settle-promote-dir", name, poisoned)?;
        } else {
            #[cfg(test)]
            hooks::event("unlink").map_err(io_error)?;
            rfs::unlinkat(dir, name, AtFlags::empty()).map_err(io_error)?;
            sync(dir, "settle-discard-dir", poisoned)?;
        }
    }
    Ok(())
}
impl Sink {
    pub(super) fn trail(&self) -> [u8; 16] {
        self.trail
    }

    pub(crate) fn create(
        path: &Path,
        signer: Arc<dyn Signer>,
        config: Config,
    ) -> Result<Self, AuditError> {
        let directory = Directory::open(path).map_err(io_error)?;
        let head = directory
            .with_lock(|dir| {
                if [
                    "audit.trail",
                    "audit.jsonl",
                    ".audit-next.jsonl",
                    ".audit-resume.jsonl",
                    "audit.poison",
                ]
                .into_iter()
                .map(|name| exists(dir, name))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .any(|v| v)
                    || !rotate::rotated_names_at(dir, "audit")
                        .map_err(io_error)?
                        .is_empty()
                {
                    return Err(error(AuditErrorKind::TrailExists, "audit data exists"));
                }
                let mut trail = [0; 16];
                getrandom::fill(&mut trail).map_err(io_error)?;
                #[cfg(test)]
                hooks::point("create-1");
                let poisoned = AtomicBool::new(false);
                let marker = new_file(dir, "audit.trail", Mode::RUSR)?;
                write_io(&marker, format!("{}\n", hex(&trail)).as_bytes()).map_err(io_error)?;
                sync(&marker, "marker", &poisoned)?;
                sync(dir, "marker-dir", &poisoned)?;
                #[cfg(test)]
                hooks::point("create-2");
                let context = RecordContext::new(
                    trail,
                    0,
                    clock()?,
                    &config.service,
                    Record::genesis(&trail),
                );
                let cp = Self::signed(&*signer, context, &Mmr::new())?;
                Self::stage(dir, &line(&cp)?, &poisoned)?;
                #[cfg(test)]
                hooks::event("promote").map_err(io_error)?;
                rotate::rename_no_replace(
                    dir,
                    Path::new(".audit-next.jsonl"),
                    Path::new("audit.jsonl"),
                )
                .map_err(io_error)?;
                sync_renamed(dir, "promote-dir", ".audit-next.jsonl", &poisoned)?;
                #[cfg(test)]
                hooks::point("create-3");
                Ok(Head {
                    seq: 0,
                    hash: cp.hash(),
                })
            })
            .map_err(io_error)??;
        let sink = Self::open(path, signer, config, Some(head))?;
        #[cfg(test)]
        hooks::point("create-4");
        Ok(sink)
    }
    pub(crate) fn open(
        path: &Path,
        signer: Arc<dyn Signer>,
        config: Config,
        expected: Option<Head>,
    ) -> Result<Self, AuditError> {
        let poisoned = AtomicBool::new(false);
        let mut trail = None;
        // Read the marker under the same lock that settles and scans.
        let reader = TrailReader::open_marked(path, expected, |dir| {
            poison_check(dir)?;
            let id = marker(dir)?;
            settle(dir, id, &poisoned)?;
            trail = Some(id);
            Ok(id)
        })?;
        Ok(Self {
            reader,
            trail: trail.ok_or_else(|| corrupt("missing marker identity"))?,
            signer,
            config,
            poisoned,
            reported: AtomicBool::new(false),
            unsigned_records: AtomicU64::new(0),
            closed: false,
        })
    }
    fn signed(
        signer: &dyn Signer,
        context: RecordContext,
        mmr: &Mmr,
    ) -> Result<Record, AuditError> {
        let key = signer.public_key();
        let fields =
            CheckpointFields::new(mmr.size(), mmr.root(), mmr.peaks().to_vec(), key, [0; 64])?;
        let unsigned = Record::checkpoint(context.clone(), fields)?;
        let message = unsigned
            .signing_message()
            .ok_or_else(|| corrupt("checkpoint without signing message"))?;
        let signature = signer
            .sign(&message)
            .map_err(|e| error(AuditErrorKind::Signer, e.to_string()))?;
        Record::checkpoint(
            context,
            CheckpointFields::new(mmr.size(), mmr.root(), mmr.peaks().to_vec(), key, signature)?,
        )
    }
    fn context(&self, state: &State, time: u64) -> Result<RecordContext, AuditError> {
        let seq = state
            .head
            .seq
            .checked_add(1)
            .ok_or_else(|| error(AuditErrorKind::InvalidConfig, "sequence overflow"))?;
        let mut context =
            RecordContext::new(self.trail, seq, time, &self.config.service, state.head.hash);
        context.repaired = state.repair_digest();
        Ok(context)
    }
    fn checkpoint_record(&self, state: &State, time: u64) -> Result<Record, AuditError> {
        Self::signed(&*self.signer, self.context(state, time)?, &state.mmr)
    }
    fn stage(dir: &File, bytes: &[u8], poisoned: &AtomicBool) -> Result<(), AuditError> {
        let file = new_file(dir, ".audit-next.jsonl", Mode::RUSR | Mode::WUSR)?;
        let result = write_io(&file, bytes)
            .map_err(io_error)
            .and_then(|()| sync(&file, "staging", poisoned))
            .and_then(|()| sync(dir, "staging-dir", poisoned));
        if let Err(original) = result {
            if let Err(truncate) = truncate_io(&file, 0)
                && poisoned.load(Ordering::Relaxed)
            {
                poison(
                    dir,
                    &format!("{original}; .audit-next.jsonl rollback: {truncate}"),
                );
            }
            return Err(original);
        }
        Ok(())
    }
    fn healthy(&self) -> Result<(), AuditError> {
        if self.poisoned.load(Ordering::Relaxed) {
            Err(error(AuditErrorKind::Poisoned, "handle durability failure"))
        } else {
            Ok(())
        }
    }
    fn prepare(&self, dir: &File) -> Result<(), AuditError> {
        self.healthy()?;
        poison_check(dir)?;
        settle(dir, self.trail, &self.poisoned)
    }
    fn signer_failed(&self) {
        if !self.reported.swap(true, Ordering::Relaxed) {
            let message = "vigil audit: checkpoint signer unavailable; retrying on next append";
            #[cfg(test)]
            hooks::stderr(message);
            let _ = writeln!(std::io::stderr().lock(), "{message}");
        }
    }
    pub(crate) fn record(&self, entry: &Entry) -> Result<Recorded, AuditError> {
        self.record_impl(entry, false)
    }
    /// One internal path for all reserved actions, including resume and key rotation (B3).
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "operator writes follow in #11 B3c/B3d")
    )]
    pub(crate) fn record_internal(&self, entry: &Entry) -> Result<Recorded, AuditError> {
        self.record_impl(entry, true)
    }
    fn record_impl(&self, entry: &Entry, internal: bool) -> Result<Recorded, AuditError> {
        if self.poisoned.load(Ordering::Relaxed) {
            return Err(error(AuditErrorKind::Poisoned, "handle durability failure"));
        }
        self.reader.with_current(
            |dir| {
                if self.poisoned.load(Ordering::Relaxed) {
                    return Err(error(AuditErrorKind::Poisoned, "handle durability failure"));
                }
                self.prepare(dir)
            },
            |dir, live, state| {
                let time = clock()?;
                let mut record = if internal {
                    Record::new_internal(self.context(state, time)?, entry.clone())?
                } else {
                    Record::new(self.context(state, time)?, entry.clone())?
                };
                let mut bytes = line(&record)?; // Validate before rotation changes disk.
                let mut file = live.try_clone().map_err(io_error)?;
                let mut current = state.clone();
                let mut signer_down = false;
                if state
                    .length
                    .saturating_add(bytes.len() as u64)
                    .saturating_add(u64::from(state.needs_newline()))
                    > self.config.max_bytes
                {
                    match self.rotate(dir, live, state, time) {
                        Ok(()) => {
                            file = live.try_clone().map_err(io_error)?;
                            current = state.clone();
                            record = if internal {
                                Record::new_internal(self.context(&current, time)?, entry.clone())?
                            } else {
                                Record::new(self.context(&current, time)?, entry.clone())?
                            };
                            bytes = line(&record)?;
                        }
                        Err(e) if e.kind() == AuditErrorKind::Signer => {
                            self.signer_failed();
                            signer_down = true;
                        }
                        Err(e) => return Err(e),
                    }
                }
                let receipt = Head {
                    seq: record.context.seq,
                    hash: record.hash(),
                };
                let due = current.since_checkpoint.saturating_add(1)
                    >= self.config.checkpoint_every
                    || time < current.checkpoint_time
                    || u128::from(time - current.checkpoint_time.min(time))
                        >= self.config.checkpoint_interval.as_nanos();
                let mut checkpoint = None;
                if due || signer_down {
                    let mut mmr = current.mmr.clone();
                    mmr.push(record.hash())?;
                    let context = RecordContext::new(
                        self.trail,
                        receipt.seq + 1,
                        time,
                        &self.config.service,
                        receipt.hash,
                    );
                    match Self::signed(&*self.signer, context, &mmr) {
                        Ok(cp) => {
                            bytes.extend(line(&cp)?);
                            checkpoint = Some(cp);
                            signer_down = false;
                        }
                        Err(e) if e.kind() == AuditErrorKind::Signer => {
                            self.signer_failed();
                            signer_down = true;
                        }
                        Err(e) => return Err(e),
                    }
                }
                if current.needs_newline() {
                    bytes.insert(0, b'\n');
                }
                let length = current.length + bytes.len() as u64;
                let mut next = current.after(&record, length)?;
                if let Some(cp) = checkpoint {
                    next = next.after(&cp, length)?;
                }
                append(dir, &file, &bytes, "record-data", &self.poisoned)?;
                *live = file;
                *state = next;
                if signer_down {
                    self.unsigned_records.fetch_add(1, Ordering::Relaxed);
                }
                Ok(Recorded {
                    head: receipt,
                    unsigned_records: self.unsigned_records.load(Ordering::Relaxed),
                })
            },
        )
    }
    fn rotate(
        &self,
        dir: &File,
        live: &mut File,
        state: &mut State,
        time: u64,
    ) -> Result<(), AuditError> {
        let closing = self.checkpoint_record(state, time)?;
        let mut mmr = state.mmr.clone();
        mmr.push(closing.hash())?;
        let opening = Self::signed(
            &*self.signer,
            RecordContext::new(
                self.trail,
                closing.context.seq + 1,
                time,
                &self.config.service,
                closing.hash(),
            ),
            &mmr,
        )?;
        #[cfg(test)]
        hooks::point("seal-1");
        let opening_bytes = line(&opening)?;
        Self::stage(dir, &opening_bytes, &self.poisoned)?;
        #[cfg(test)]
        hooks::point("seal-2");
        let mut bytes = line(&closing)?;
        if state.needs_newline() {
            bytes.insert(0, b'\n');
        }
        let closed = state.after(&closing, state.length + bytes.len() as u64)?;
        let opened = closed.after(&opening, opening_bytes.len() as u64)?;
        append(dir, live, &bytes, "closing-data", &self.poisoned)?;
        *state = closed;
        #[cfg(test)]
        hooks::point("seal-3");
        #[cfg(test)]
        hooks::event("seal-rename").map_err(io_error)?;
        rotate::rotate(dir, "audit", Path::new("audit.jsonl")).map_err(io_error)?;
        #[cfg(test)]
        hooks::point("seal-4");
        #[cfg(test)]
        hooks::event("promote").map_err(io_error)?;
        rotate::rename_no_replace(
            dir,
            Path::new(".audit-next.jsonl"),
            Path::new("audit.jsonl"),
        )
        .map_err(io_error)?;
        #[cfg(test)]
        hooks::point("seal-5");
        sync_renamed(dir, "promote-dir", ".audit-next.jsonl", &self.poisoned)?;
        #[cfg(test)]
        hooks::point("seal-6");
        *live = existing(dir, Path::new("audit.jsonl"), true)?;
        *state = opened;
        Ok(())
    }
    pub(crate) fn checkpoint(&self) -> Result<Record, AuditError> {
        self.healthy()?;
        self.reader.with_current(
            |dir| self.prepare(dir),
            |dir, file, state| {
                let cp = self.checkpoint_record(state, clock()?)?;
                let mut bytes = line(&cp)?;
                if state.needs_newline() {
                    bytes.insert(0, b'\n');
                }
                let next = state.after(&cp, state.length + bytes.len() as u64)?;
                append(dir, file, &bytes, "checkpoint-data", &self.poisoned)?;
                *state = next;
                Ok(cp)
            },
        )
    }
    pub(crate) fn close(mut self) -> Result<Record, AuditError> {
        // Consumed even on signer failure: Drop must never retry a failed close.
        self.closed = true;
        self.checkpoint()
    }
}
impl Drop for Sink {
    fn drop(&mut self) {
        if !self.closed
            && !self.poisoned.load(Ordering::Relaxed)
            && let Err(error) = self.checkpoint()
        {
            let message = format!(
                "vigil audit: best-effort checkpoint failed: {}",
                error.to_string().escape_debug()
            );
            #[cfg(test)]
            hooks::stderr(&message);
            // A failed stderr write must not turn best-effort Drop into a panic.
            let _ = writeln!(std::io::stderr().lock(), "{message}");
        }
    }
}
#[cfg(test)]
mod hooks {
    use std::{
        cell::{Cell, RefCell},
        io,
    };
    thread_local! {
        pub(super) static CHECK_CLOCK: RefCell<Option<Box<dyn Fn()>>> = const { RefCell::new(None) };
        pub(super) static TIME: Cell<Option<u64>> = const { Cell::new(None) };
        pub(super) static HALF: Cell<bool> = const { Cell::new(false) };
        pub(super) static SHORT: Cell<Option<usize>> = const { Cell::new(None) };
        pub(super) static FAIL: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
        pub(super) static EVENTS: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
    }
    pub(super) fn stderr(message: &str) {
        STDERR.with(|lines| lines.borrow_mut().push(message.to_owned()));
    }
    thread_local! {
        pub(super) static STDERR: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }
    pub(super) fn durable(file: &std::fs::File) -> io::Result<()> {
        super::durability::sync(file)
    }
    type Observer = Box<dyn Fn(&str)>;
    thread_local! {
        pub(super) static OBSERVE: RefCell<Option<Observer>> = const { RefCell::new(None) };
    }
    // Crash observers park or terminate; they cannot inject an error rollback.
    pub(super) fn point(site: &'static str) {
        OBSERVE.with(|observe| {
            if let Some(observe) = observe.borrow().as_ref() {
                observe(site);
            }
        });
    }
    pub(super) fn event(site: &'static str) -> io::Result<()> {
        OBSERVE.with(|observe| {
            if let Some(observe) = observe.borrow().as_ref() {
                observe(site);
            }
        });
        EVENTS.with(|events| events.borrow_mut().push(site));
        FAIL.with(|fail| {
            let mut fail = fail.borrow_mut();
            if fail.first() == Some(&site) {
                fail.remove(0);
                Err(io::Error::other(format!("injected {site}")))
            } else {
                Ok(())
            }
        })
    }
}
#[cfg(test)]
#[path = "durability_tests.rs"]
mod durability;
#[cfg(test)]
#[path = "sink_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "crash_tests.rs"]
mod crashes;

#[cfg(test)]
#[path = "crash_fixtures.rs"]
pub(crate) mod crash_fixtures;
