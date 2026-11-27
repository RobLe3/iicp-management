//! Private Unix serving-boundary custody. No stale recovery or unlinking Drop.
//! The namespace must be trusted: this is not a defence against root, malicious
//! same-UID actors, or an unpatched controller ignoring the claim protocol.
use sha2::{Digest, Sha256};
use std::ffi::{CString, OsString};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

const SUFFIX: &str = ".iicp-controller-owner";
const MAX_CLAIM_BYTES: u64 = 4096;

// MetadataExt uses u32; libc mode bits are u16 on Darwin and u32 on Linux.
fn mode_bits(mode: impl Into<u32>) -> u32 {
    mode.into()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    uid: u32,
    kind: u32,
}
impl Identity {
    fn of(meta: &Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            uid: meta.uid(),
            kind: meta.mode() & mode_bits(libc::S_IFMT),
        }
    }
}
fn fail(message: impl std::fmt::Display) -> String {
    format!("CONTROLLER_OWNERSHIP: {message}")
}
fn uid() -> u32 {
    unsafe { libc::geteuid() }
}
fn safe_directory(meta: &Metadata) -> bool {
    meta.is_dir()
        && (meta.uid() == uid() || meta.uid() == 0)
        && (meta.mode() & 0o022 == 0
            || (meta.uid() == 0 && meta.mode() & mode_bits(libc::S_ISVTX) != 0))
}

struct Entry {
    identity: Identity,
    mode: libc::mode_t,
    links: libc::nlink_t,
    length: u64,
}
impl Entry {
    fn is_file(&self) -> bool {
        self.identity.kind == mode_bits(libc::S_IFREG)
    }
    fn uid(&self) -> u32 {
        self.identity.uid
    }
    fn nlink(&self) -> libc::nlink_t {
        self.links
    }
    fn mode(&self) -> libc::mode_t {
        self.mode
    }
    fn len(&self) -> u64 {
        self.length
    }
}

struct Parent {
    path: PathBuf,
    handle: File,
    identity: Identity,
    owned_resource: bool,
}
impl Parent {
    fn open(path: &Path) -> Result<Self, String> {
        let path = fs::canonicalize(path).map_err(fail)?;
        // A private leaf directory under an attacker-replaceable ancestor is
        // insufficient. Root-owned sticky temporary ancestors are allowed.
        for ancestor in path.ancestors() {
            let meta = fs::symlink_metadata(ancestor).map_err(fail)?;
            if !safe_directory(&meta) {
                return Err(fail("untrusted parent namespace"));
            }
        }
        let handle = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(fail)?;
        let identity = Identity::of(&handle.metadata().map_err(fail)?);
        let parent = Self {
            path,
            handle,
            identity,
            owned_resource: false,
        };
        parent.check()?;
        Ok(parent)
    }
    fn check(&self) -> Result<(), String> {
        let held = self.handle.metadata().map_err(fail)?;
        let named = fs::symlink_metadata(&self.path).map_err(fail)?;
        if !safe_directory(&held)
            || !safe_directory(&named)
            || Identity::of(&held) != self.identity
            || Identity::of(&named) != self.identity
        {
            return Err(fail("parent identity or permissions changed"));
        }
        // Mutable DB/socket namespaces must be owner-controlled at the
        // immediate parent, not merely sticky. SQLite can create WAL/SHM and
        // transitional siblings here; separate leaf claims cannot reserve all
        // those names in a directory writable by another UID.
        if self.owned_resource
            && (held.uid() != uid()
                || named.uid() != uid()
                || held.mode() & 0o022 != 0
                || named.mode() & 0o022 != 0)
        {
            return Err(fail(
                "owned resource requires an existing owner-controlled immediate directory",
            ));
        }
        // Recheck ancestors before path-based SQLite/socket operations too.
        for ancestor in self.path.ancestors() {
            if !safe_directory(&fs::symlink_metadata(ancestor).map_err(fail)?) {
                return Err(fail("ancestor namespace changed"));
            }
        }
        Ok(())
    }
    fn name(name: &std::ffi::OsStr) -> Result<CString, String> {
        CString::new(name.as_bytes()).map_err(fail)
    }
    fn metadata(&self, name: &std::ffi::OsStr) -> Result<Option<Entry>, String> {
        self.check()?;
        let name = Self::name(name)?;
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                self.handle.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(fail(error));
        }
        let stat = unsafe { stat.assume_init() };
        // Match MetadataExt::dev(), including the signed dev_t on Darwin.
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        let device = stat.st_dev;
        #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
        let device = stat.st_dev as u64;
        Ok(Some(Entry {
            identity: Identity {
                dev: device,
                ino: stat.st_ino,
                uid: stat.st_uid,
                kind: mode_bits(stat.st_mode & libc::S_IFMT),
            },
            mode: stat.st_mode,
            links: stat.st_nlink,
            length: stat.st_size as u64,
        }))
    }
    fn unlink(&self, name: &std::ffi::OsStr) -> Result<(), String> {
        self.unlink_with_sync(name, File::sync_all)
    }
    fn unlink_with_sync(
        &self,
        name: &std::ffi::OsStr,
        sync: impl FnOnce(&File) -> std::io::Result<()>,
    ) -> Result<(), String> {
        self.check()?;
        let name = Self::name(name)?;
        if unsafe { libc::unlinkat(self.handle.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(fail(std::io::Error::last_os_error()));
        }
        sync(&self.handle)
            .map_err(|e| fail(format!("name removed; directory sync unconfirmed: {e}")))
    }
}

struct Resource {
    parent: Parent,
    name: OsString,
    path: PathBuf,
}
impl Resource {
    fn resolve(path: &Path) -> Result<Self, String> {
        let name = path
            .file_name()
            .ok_or_else(|| fail("resource basename required"))?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = Parent::open(parent)?;
        let path = parent.path.join(name);
        Ok(Self {
            parent,
            name: name.to_os_string(),
            path,
        })
    }
    fn resolve_owned(path: &Path) -> Result<Self, String> {
        let mut resource = Self::resolve(path)?;
        // Read-only verification-key resolution intentionally does not opt in.
        // No directory is created, chowned or chmodded by this check.
        resource.parent.owned_resource = true;
        resource.parent.check()?;
        Ok(resource)
    }
    fn claim_path(&self) -> PathBuf {
        let mut name = self.name.clone();
        name.push(SUFFIX);
        self.parent.path.join(name)
    }
    fn check_database(&self) -> Result<(), String> {
        if let Some(meta) = self.parent.metadata(&self.name)? {
            if !meta.is_file()
                || meta.uid() != uid()
                || meta.nlink() != 1
                || meta.mode() & 0o022 != 0
            {
                return Err(fail(
                    "database must be an owned single-link regular file without group/other writes",
                ));
            }
        }
        Ok(())
    }
    fn check_endpoint_absent(&self) -> Result<(), String> {
        self.parent.check()?;
        // lstat detects even dangling symlinks and sockets (which cannot be
        // opened using openat O_RDONLY). An existing endpoint is never removed.
        match fs::symlink_metadata(&self.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(fail(e)),
            Ok(_) => Err(fail(
                "endpoint already exists; recovery requires separate authority",
            )),
        }
    }
}

struct Claim {
    resource: Resource,
    handle: File,
    identity: Identity,
    digest: Vec<u8>,
    content: Vec<u8>,
}
impl Claim {
    fn create(path: &Path, binding: &[u8]) -> Result<Self, String> {
        let resource = Resource::resolve_owned(path)?;
        resource.parent.check()?;
        let name = Parent::name(&resource.name)?;
        let fd = unsafe {
            libc::openat(
                resource.parent.handle.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(fail(std::io::Error::last_os_error()));
        }
        let mut handle = unsafe { File::from_raw_fd(fd) };
        let meta = handle
            .metadata()
            .map_err(|e| fail(format!("new claim retained; fstat failed: {e}")))?;
        if !meta.is_file()
            || meta.uid() != uid()
            || meta.nlink() != 1
            || meta.mode() & 0o777 != 0o600
        {
            return Err(fail("new claim retained; private identity not established"));
        }
        let identity = Identity::of(&meta);
        let content = serde_json::to_vec(&serde_json::json!({
            "schema": "iicp.management-unix-owner.v1",
            "binding_sha256": hex::encode(Sha256::digest(binding)),
            "pid_diagnostic_only": std::process::id(),
            "device": identity.dev, "inode": identity.ino
        }))
        .map_err(fail)?;
        if content.len() as u64 > MAX_CLAIM_BYTES {
            return Err(fail("new claim retained; content exceeds bound"));
        }
        handle
            .write_all(&content)
            .and_then(|_| handle.sync_all())
            .map_err(|e| fail(format!("new partial claim retained; write failed: {e}")))?;
        let digest = Sha256::digest(&content).to_vec();
        let claim = Self {
            resource,
            handle,
            identity,
            digest,
            content,
        };
        claim.check()?;
        Ok(claim)
    }
    fn check(&self) -> Result<(), String> {
        self.resource.parent.check()?;
        let meta = self
            .resource
            .parent
            .metadata(&self.resource.name)?
            .ok_or_else(|| fail("claim name disappeared"))?;
        let held = self.handle.metadata().map_err(fail)?;
        if meta.identity != self.identity
            || Identity::of(&held) != self.identity
            || meta.nlink() != 1
            || meta.mode() & 0o777 != 0o600
            || held.nlink() != 1
            || held.mode() & 0o777 != 0o600
            || meta.len() != self.content.len() as u64
        {
            return Err(fail("claim identity or mode changed; retained"));
        }
        let mut reader = self.handle.try_clone().map_err(fail)?;
        reader.seek(SeekFrom::Start(0)).map_err(fail)?;
        let mut bytes = Vec::new();
        reader
            .take(MAX_CLAIM_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(fail)?;
        if bytes != self.content || Sha256::digest(&bytes).as_slice() != self.digest.as_slice() {
            return Err(fail("claim contents changed; retained"));
        }
        Ok(())
    }
    fn finish(self) -> Result<(), String> {
        self.finish_with_sync(File::sync_all)
    }
    fn finish_with_sync(
        self,
        sync: impl FnOnce(&File) -> std::io::Result<()>,
    ) -> Result<(), String> {
        self.check()?;
        self.resource
            .parent
            .unlink_with_sync(&self.resource.name, sync)
    }
}

/// Resolve the verification-key name without reading key bytes or allocating
/// anything. A symlink to an existing key is resolved once and the returned
/// canonical name is the only name subsequently read.
pub(super) fn checked_public_key_path(
    database: &Path,
    endpoint: &Path,
    key: &Path,
) -> Result<PathBuf, String> {
    let database = Resource::resolve_owned(database)?;
    let endpoint = Resource::resolve_owned(endpoint)?;
    let key = match fs::symlink_metadata(key) {
        Ok(meta) if meta.file_type().is_symlink() => fs::canonicalize(key).map_err(fail)?,
        Ok(_) => Resource::resolve(key)?.path,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Resource::resolve(key)?.path,
        Err(e) => return Err(fail(e)),
    };
    let keys = [
        database.path.clone(),
        endpoint.path.clone(),
        database.claim_path(),
        endpoint.claim_path(),
    ];
    if keys.iter().any(|resource| resource == &key) {
        return Err(fail(
            "verification key collides with a resource or owner claim",
        ));
    }
    // A distinct name must not alias the same existing DB inode either.
    let key_resource = Resource::resolve(&key)?;
    if let Some(key_meta) = key_resource.parent.metadata(&key_resource.name)? {
        if !key_meta.is_file() {
            return Err(fail("verification key is not a regular file"));
        }
        for resource in [&database, &endpoint] {
            if let Some(meta) = resource.parent.metadata(&resource.name)? {
                if meta.identity == key_meta.identity {
                    return Err(fail("verification key aliases a resource inode"));
                }
            }
        }
    }
    Ok(key)
}

/// Retains both claims and the exact bound endpoint until explicit finish.
/// Field/handle Drop closes descriptors only; it deliberately never unlinks.
pub(super) struct ControllerOwnership {
    database: Resource,
    endpoint: Resource,
    claims: Vec<Claim>,
    listener: Option<UnixListener>,
    socket_identity: Option<Identity>,
    database_handle: Option<File>,
    database_identity: Option<Identity>,
}
impl ControllerOwnership {
    pub(super) fn acquire(database: &Path, endpoint: &Path) -> Result<Self, String> {
        let database = Resource::resolve_owned(database)?;
        let endpoint = Resource::resolve_owned(endpoint)?;
        database.check_database()?;
        endpoint.check_endpoint_absent()?;
        let mut names = [
            database.path.clone(),
            endpoint.path.clone(),
            database.claim_path(),
            endpoint.claim_path(),
        ];
        names.sort();
        if names.windows(2).any(|p| p[0] == p[1]) {
            return Err(fail("resource and claim names collide"));
        }
        let binding = serde_json::to_vec(&(
            hex::encode(database.path.as_os_str().as_bytes()),
            hex::encode(endpoint.path.as_os_str().as_bytes()),
        ))
        .map_err(fail)?;
        let mut paths = [database.claim_path(), endpoint.claim_path()];
        paths.sort();
        let first = Claim::create(&paths[0], &binding)?;
        let second = match Claim::create(&paths[1], &binding) {
            Ok(claim) => claim,
            Err(error) => {
                return match first.finish() {
                    Ok(()) => Err(error),
                    Err(release) => {
                        Err(format!("{error}; first claim release uncertain: {release}"))
                    }
                };
            }
        };
        Ok(Self {
            database,
            endpoint,
            claims: vec![first, second],
            listener: None,
            socket_identity: None,
            database_handle: None,
            database_identity: None,
        })
    }
    pub(super) fn database(&self) -> &Path {
        &self.database.path
    }
    pub(super) fn listener(&self) -> Result<&UnixListener, String> {
        self.listener
            .as_ref()
            .ok_or_else(|| fail("listener not bound"))
    }
    pub(super) fn bind(&mut self) -> Result<(), String> {
        self.check_claims()?;
        self.database.check_database()?;
        self.endpoint.check_endpoint_absent()?;
        struct UmaskGuard(libc::mode_t);
        impl Drop for UmaskGuard {
            fn drop(&mut self) {
                unsafe { libc::umask(self.0) };
            }
        }
        let umask = UmaskGuard(unsafe { libc::umask(0o177) });
        let listener = UnixListener::bind(&self.endpoint.path).map_err(fail);
        drop(umask);
        self.listener = Some(listener?);
        // Record identity before any subsequent fallible operation. If identity
        // cannot be collected, finish retains claims and reports uncertainty.
        let meta = fs::symlink_metadata(&self.endpoint.path).map_err(fail)?;
        if !meta.file_type().is_socket() || meta.uid() != uid() || meta.nlink() != 1 {
            return Err(fail("bound endpoint identity unknown; retained"));
        }
        self.socket_identity = Some(Identity::of(&meta));
        self.endpoint.parent.check()?;
        fs::set_permissions(&self.endpoint.path, fs::Permissions::from_mode(0o600))
            .map_err(fail)?;
        self.check_socket()?;
        Ok(())
    }
    // Database allocation is persistent, not temporary cleanup. This is after
    // both claims, listener and verification-key intake, never before them.
    pub(super) fn prepare_database(&mut self) -> Result<(), String> {
        self.check_before_initialization()?;
        let existing = self.database.parent.metadata(&self.database.name)?;
        let name = Parent::name(&self.database.name)?;
        let flags = libc::O_RDWR
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | if existing.is_none() {
                libc::O_CREAT | libc::O_EXCL
            } else {
                0
            };
        let fd = unsafe {
            libc::openat(
                self.database.parent.handle.as_raw_fd(),
                name.as_ptr(),
                flags,
                0o600,
            )
        };
        if fd < 0 {
            return Err(fail(std::io::Error::last_os_error()));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let identity = Identity::of(&file.metadata().map_err(fail)?);
        self.database_handle = Some(file);
        self.database_identity = Some(identity);
        self.check_database_identity()
    }
    pub(super) fn check_database_identity(&self) -> Result<(), String> {
        self.database.check_database()?;
        let named = self
            .database
            .parent
            .metadata(&self.database.name)?
            .ok_or_else(|| fail("database name disappeared; retained"))?;
        let held = self
            .database_handle
            .as_ref()
            .ok_or_else(|| fail("database handle missing"))?
            .metadata()
            .map_err(fail)?;
        if Some(named.identity) != self.database_identity
            || Some(Identity::of(&held)) != self.database_identity
            || !held.is_file()
            || held.uid() != uid()
            || held.nlink() != 1
            || held.mode() & 0o022 != 0
        {
            return Err(fail("database identity changed; retained"));
        }
        Ok(())
    }
    fn check_claims(&self) -> Result<(), String> {
        for claim in &self.claims {
            claim.check()?;
        }
        Ok(())
    }
    fn check_socket(&self) -> Result<(), String> {
        self.endpoint.parent.check()?;
        let meta = fs::symlink_metadata(&self.endpoint.path).map_err(fail)?;
        if Some(Identity::of(&meta)) != self.socket_identity
            || !meta.file_type().is_socket()
            || meta.nlink() != 1
            || meta.mode() & 0o777 != 0o600
        {
            return Err(fail("endpoint identity or mode changed; retained"));
        }
        Ok(())
    }
    pub(super) fn check_before_initialization(&self) -> Result<(), String> {
        self.check_claims()?;
        self.database.check_database()?;
        self.check_socket()
    }
    /// Independent readback after the serving connection has closed. Never
    /// checkpoint, erase a journal, repair permissions or reclaim a stale name.
    pub(super) fn verify_closed_store(&self, expected_generation: u64) -> Result<(), String> {
        self.check_before_initialization()?;
        self.check_database_identity()?;
        let db = rusqlite::Connection::open_with_flags(
            self.database(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(fail)?;
        let (generation, unsettled): (u64, bool) = db.query_row(
            "SELECT generation, EXISTS (SELECT 1 FROM execution_journal WHERE phase != 'complete' OR lifecycle_receipt_json IS NULL) FROM state WHERE id = 1",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        ).map_err(fail)?;
        db.close().map_err(|(_, e)| fail(e))?;
        if generation != expected_generation || unsettled {
            return Err(fail(
                "generation or execution journal is not settled; claims retained",
            ));
        }
        // A nonempty uncheckpointed WAL cannot be certified by syncing only
        // the main file. Do not remove sidecars or force a checkpoint here.
        let mut wal = self.database.name.clone();
        wal.push("-wal");
        if self
            .database
            .parent
            .metadata(&wal)?
            .is_some_and(|m| !m.is_file() || m.len() != 0)
        {
            return Err(fail("database WAL writeback unconfirmed; claims retained"));
        }
        self.check_database_identity()?;
        self.database_handle
            .as_ref()
            .ok_or_else(|| fail("database handle missing"))?
            .sync_all()
            .map_err(fail)?;
        self.database.parent.handle.sync_all().map_err(fail)?;
        Ok(())
    }

    /// Call only after Controller and AdapterHost have been dropped. A failed
    /// release is never a successful service/cleanup result. No DB/sidecar data
    /// are treated as temporary resources.
    pub(super) fn finish(self) -> Result<(), String> {
        self.finish_with(|_, dir| dir.sync_all())
    }

    fn finish_with(
        mut self,
        sync_claim_parent: impl Fn(bool, &File) -> std::io::Result<()>,
    ) -> Result<(), String> {
        self.check_claims()?;
        if self.database_handle.is_some() {
            self.check_database_identity()?;
        }
        if self.listener.is_some() {
            self.check_socket()?;
            drop(self.listener.take());
            self.endpoint.parent.unlink(&self.endpoint.name)?;
        }
        drop(self.database_handle.take());
        // Keep the database claim behind socket and endpoint-claim cleanup,
        // irrespective of the lexicographic order used for acquisition.
        let database_claim = self.database.claim_path();
        self.claims
            .sort_by_key(|c| c.resource.path != database_claim);
        while let Some(claim) = self.claims.pop() {
            let last = claim.resource.path == database_claim;
            let role = if last { "database" } else { "endpoint" };
            // The final verified unlink makes handoff visible, not durable.
            // If sync fails, report non-success; never recreate a claim over
            // a legitimate successor after the original owner has quiesced.
            claim
                .finish_with_sync(|dir| sync_claim_parent(last, dir))
                .map_err(|e| format!("{role} claim retirement: {e}"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod release_tests {
    use super::*;

    #[test]
    fn incomplete_retirement_keeps_database_gate_closed() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        // DB sorts after the endpoint: release order must not depend on names.
        let database = dir.path().join("z-db");
        let endpoint = dir.path().join("a-sock");
        let mut owner = ControllerOwnership::acquire(&database, &endpoint).unwrap();
        owner.bind().unwrap();
        let result = owner.finish_with(|last, _dir| {
            assert!(!last, "database claim retired before the endpoint claim");
            Err(std::io::Error::other("fixture: sync unconfirmed"))
        });
        let reason = result.unwrap_err();
        assert!(
            reason.contains("endpoint claim retirement")
                && reason.contains("directory sync unconfirmed")
        );
        assert!(dir.path().join("z-db.iicp-controller-owner").is_file());
        assert!(ControllerOwnership::acquire(&database, &dir.path().join("fresh")).is_err());
    }

    #[test]
    fn final_claim_removal_allows_handoff_but_failed_sync_is_not_clean_success() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let database = dir.path().join("db");
        let endpoint = dir.path().join("endpoint");
        let mut owner = ControllerOwnership::acquire(&database, &endpoint).unwrap();
        owner.bind().unwrap();
        let result = owner.finish_with(|last, parent| {
            if last {
                Err(std::io::Error::other("fixture: final sync failed"))
            } else {
                parent.sync_all()
            }
        });
        let reason = result.unwrap_err();
        assert!(
            reason.contains("database claim retirement")
                && reason.contains("name removed; directory sync unconfirmed")
        );
        // Only the sync result was injected. Both the unlink and subsequent
        // acquisition operate on real, private fixture names.
        ControllerOwnership::acquire(&database, &endpoint)
            .unwrap()
            .finish()
            .unwrap();
    }

    #[test]
    fn unproved_endpoint_identity_retains_names_and_claims() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let database = dir.path().join("db");
        let socket = dir.path().join("endpoint");
        let unrelated = dir.path().join("unrelated");
        fs::write(&unrelated, b"untouched").unwrap();
        let mut owner = ControllerOwnership::acquire(&database, &socket).unwrap();
        owner.bind().unwrap();
        // Inject a foreign identity into the in-memory proof, not the namespace.
        owner.socket_identity = Some(Identity::of(&fs::metadata(&unrelated).unwrap()));
        assert!(owner.finish().unwrap_err().contains("endpoint identity"));
        assert!(fs::symlink_metadata(&socket)
            .unwrap()
            .file_type()
            .is_socket());
        assert_eq!(fs::read(&unrelated).unwrap(), b"untouched");
        assert!(dir.path().join("db.iicp-controller-owner").is_file());
        assert!(dir.path().join("endpoint.iicp-controller-owner").is_file());
        assert!(ControllerOwnership::acquire(&database, &dir.path().join("new")).is_err());
    }
}
