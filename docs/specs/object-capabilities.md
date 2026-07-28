# Handle-Backed Object Capabilities

Status: Proposed
Target release: `0.3.0`
Tracking issue: [#62](https://github.com/auths-dev/capsec/issues/62)

## Summary

Add first-class, handle-backed object capabilities for filesystem and network
access across `capsec-std` and `capsec-tokio`.

The existing `Cap<P>` remains the authority to acquire resources of permission
class `P`. The new object-capability layer turns that broad authority into
unforgeable values representing specific filesystem namespaces, files, network
endpoint sets, listeners, and connected sockets.

Filesystem operations are performed relative to open directory handles.
Network operations are performed through immutable pools of authorized socket
addresses. Neither API performs an authorization check followed by an ambient
path or address operation.

The implementation uses `cap-std` and `cap-net-ext` as the OS-facing backend.
Capsec wraps those types and never exposes the backend handles or pools through
safe public APIs.

## Goals

- Bind filesystem authority to open directory and file handles.
- Bind network authority to immutable sets of concrete socket addresses.
- Prevent path traversal, symlink escape, check/open races, and DNS rebinding.
- Preserve compile-time distinctions between read, write, connect, and bind
  permissions.
- Provide equivalent synchronous and Tokio APIs.
- Support delegation and attenuation without recovering an ambient `Cap<P>`.
- Cover every filesystem and network operation currently exposed by
  `capsec-std` and `capsec-tokio`.
- Preserve existing path-plus-token APIs for compatibility while making the
  object-capability APIs the recommended interface.
- Make direct ambient acquisition and backend escape visible to
  `cargo capsec audit`.

## Non-goals

- This specification does not add OS sandboxing to code that directly calls
  `std`, `tokio`, FFI, inline assembly, or raw syscalls. `cargo capsec audit`
  remains responsible for detecting those bypasses.
- Environment variables and process spawning are not filesystem or network
  objects and have no portable handle-relative equivalents. They retain their
  existing scoped-token APIs.
- The API does not expose raw file descriptors, raw handles, `cap_std::fs::Dir`,
  or `cap_std::net::Pool`.
- The API does not make revocation retroactive. Revoking the authority used to
  acquire an object does not invalidate an already-issued OS handle.

## Terminology

- **Class capability**: `Cap<P>` or another `CapProvider<P>`. It authorizes
  acquisition of objects in permission class `P`.
- **Object capability**: an unforgeable value holding an OS handle or an
  immutable authority set.
- **Bootstrap**: the explicit conversion of ambient process authority into the
  first object capability.
- **Attenuation**: deriving a capability with equal or narrower authority.
- **Relative path**: a path resolved from a directory capability, never from
  the process working directory.

## Security model

The following invariants are mandatory:

1. Safe code cannot construct an object capability without an existing
   `CapProvider<P>` or another object capability with sufficient authority.
2. Safe code cannot extract a `Cap<P>` from an object capability.
3. Safe code cannot extract the backend directory, pool, file descriptor,
   socket, or raw OS handle.
4. `DirCap<FsRead>` exposes no operation that mutates its namespace.
5. `DirCap<FsWrite>` exposes no operation that reads file contents.
6. `DirCap<FsAll>` exposes both sets of operations and can be irreversibly
   attenuated to either subset.
7. All paths used after bootstrap are relative to an open directory handle.
8. Absolute paths, platform prefixes, and parent traversal components are
   rejected before reaching the backend.
9. Symlinks cannot resolve outside the directory capability.
10. Creating a nonexistent file or directory remains confined to the directory
    capability.
11. A network pool cannot gain addresses after construction.
12. Hostnames are resolved during trusted construction. Delegated capabilities
    contain concrete socket addresses and never re-resolve a hostname.
13. Unconnected UDP sends re-check the destination against the pool on every
    send.
14. Connected streams, listeners, and connected UDP sockets derive authority
    from the pool that created them and no longer require a class capability.
15. Object capabilities are `Send + Sync` when their underlying OS object is
    `Send + Sync`. The existing local-by-default behavior of `Cap<P>` continues
    to control authority acquisition; acquired OS objects are transferable.
16. No safe conversion broadens a permission. Narrowing conversions consume
    the source capability unless the API explicitly duplicates the underlying
    handle.

The confinement guarantee begins at bootstrap. `open_ambient` and network-pool
construction are the only APIs allowed to consult process-global namespaces.
Applications must call them in trusted initialization code and delegate only
the resulting object capabilities.

## Developer UX

### Filesystem

```rust
use capsec::prelude::*;
use capsec::fs::DirCap;

fn main() -> Result<(), CapSecError> {
    let root = capsec::root();

    // Trusted bootstrap: ambient path becomes an open directory authority.
    let app = DirCap::<FsAll>::open_ambient("/srv/my-app", &root.fs_all())?;

    // Strong attenuation: this is a new directory handle rooted at "config".
    let config = app.open_dir("config")?.into_read();

    // No absolute path and no unrelated capability argument.
    let settings = config.read_to_string("settings.toml")?;

    // The destination may not escape `app`, including through symlinks.
    app.write("cache/settings.snapshot", settings)?;
    Ok(())
}
```

An untrusted function receives only the namespace it needs:

```rust
fn render_templates(templates: &DirCap<FsRead>) -> Result<String, CapSecError> {
    let source = templates.read_to_string("page.html")?;
    Ok(source)
}
```

There is no API on `templates` that can access `/etc`, its parent directory,
or a sibling of its directory handle.

### Tokio filesystem

```rust
use capsec::prelude::*;
use capsec::tokio::fs::AsyncDirCap;

async fn load(root: &CapRoot) -> Result<String, CapSecError> {
    let config =
        AsyncDirCap::<FsRead>::open_ambient("/srv/my-app/config", &root.fs_read()).await?;

    config.read_to_string("settings.toml").await
}
```

### Network

```rust
use capsec::net::{ConnectPoolCap, Endpoint};
use capsec::prelude::*;

fn fetch(root: &CapRoot) -> Result<(), CapSecError> {
    // DNS is resolved once during trusted construction.
    let api = ConnectPoolCap::resolve(
        [Endpoint::host("api.example.com", 443)],
        &root.net_connect(),
    )?;

    // The pool can connect only to the resolved, authorized addresses.
    let mut stream = api.connect_any()?;
    // use stream ...
    Ok(())
}
```

Tokio uses the same immutable endpoint semantics:

```rust
let api = capsec::tokio::net::AsyncConnectPoolCap::resolve(
    [Endpoint::host("api.example.com", 443)],
    &root.net_connect(),
).await?;

let stream = api.connect_any().await?;
```

## Architecture

```text
+------------------------- trusted bootstrap --------------------------+
|                                                                      |
|  CapRoot / CapProvider<P>                                            |
|             |                                                        |
|             +-------------------+-------------------+                |
|             v                   v                   v                |
|      open_ambient()       resolve endpoints     bind addresses       |
+-------------|-------------------|-------------------|----------------+
              v                   v                   v
       +-------------+     +----------------+   +----------------+
       | DirCap<P>   |     | ConnectPoolCap |   | BindPoolCap    |
       | open handle |     | immutable pool |   | immutable pool |
       +------+------+     +-------+--------+   +--------+-------+
              |                    |                     |
      relative operations          |                     |
              v                    v                     v
       +-------------+      +-------------+       +-------------+
       | FileCap<P>  |      | TcpStream  |       | TcpListener |
       | OS handle   |      | OS socket  |       | OS socket   |
       +-------------+      +-------------+       +-------------+
              |
              +---- open_dir("child") ----> narrower DirCap<P>

  capsec-objects
  +---------------------------------------------------------------+
  | private cap-std/cap-net-ext backend and permission invariants |
  +-----------------------------+---------------------------------+
                                |
                 +--------------+--------------+
                 v                             v
          capsec-std                     capsec-tokio
          sync facade                    async facade
```

### Crate layout

Add a workspace crate named `capsec-objects`.

`capsec-objects` owns all backend types and security invariants. It depends on:

- `capsec-core`
- `cap-std = "4"`
- `cap-net-ext = "4"`
- optional `tokio = "1"` behind a `tokio` feature

`capsec-std` depends on `capsec-objects` without async features.
`capsec-tokio` depends on `capsec-objects` with the `tokio` feature.

This crate boundary prevents duplicated security-sensitive path and address
resolution logic. It also allows sync and async wrappers to construct their
respective file and socket types without exposing backend handles publicly.

The `capsec` facade re-exports the synchronous types from `capsec::fs` and
`capsec::net`, and asynchronous types from `capsec::tokio::fs` and
`capsec::tokio::net`.

### Backend rules

- `cap_std::ambient_authority()` is called only inside audited bootstrap and
  network-pool construction functions in `capsec-objects`.
- All filesystem operations after bootstrap call methods on `cap_std::fs::Dir`.
- All network operations call methods on `cap_std::net::Pool` or capabilities
  derived from `cap-net-ext`.
- Backend types remain in private fields.
- No public `AsFd`, `AsHandle`, `AsRawFd`, `AsRawHandle`, `IntoRawFd`,
  `IntoRawHandle`, or `into_inner` implementation is provided.
- Platform-specific conversion to Tokio types remains private and uses owned
  handle conversions, not duplicated ambient lookups.

## Typed authorization targets

The current `CapProvider<P>` accepts `&str`, which loses non-UTF-8 path data and
mixes filesystem, network, environment, and process targets. Version `0.3.0`
replaces that argument with a typed target:

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub enum CapTarget<'a> {
    Path(&'a std::path::Path),
    SocketAddr(std::net::SocketAddr),
    HostPort {
        host: &'a str,
        port: u16,
    },
    EnvKey(&'a std::ffi::OsStr),
    Program(&'a std::ffi::OsStr),
    Opaque(&'a str),
}

pub trait CapProvider<P: Permission> {
    fn provide_cap(&self, target: CapTarget<'_>) -> Result<Cap<P>, CapSecError>;
}

pub trait Scope: 'static {
    fn check(&self, target: CapTarget<'_>) -> Result<(), CapSecError>;
}
```

Rules:

- `DirScope` accepts only `CapTarget::Path`.
- `HostScope` accepts `HostPort` and `SocketAddr`.
- Receiving an incompatible target returns
  `CapSecError::TargetTypeMismatch`.
- Unscoped providers continue to ignore the target.
- Generated context implementations change mechanically from `_target: &str`
  to `_target: CapTarget<'_>`.
- Custom providers receive a migration error with the complete replacement
  signature in the `0.3.0` release notes.

Object operations do not call `provide_cap` repeatedly. Authorization occurs
when an object capability is acquired; the OS handle or immutable pool performs
subsequent mediation.

## Filesystem API

### Permission marker bounds

```rust
pub struct DirCap<P: Permission> {
    // private cap_std::fs::Dir
    // private PhantomData<P>
}

pub struct FileCap<P: Permission> {
    // private permission-restricted file handle
    // private PhantomData<P>
}

pub type ReadDirCap = DirCap<FsRead>;
pub type WriteDirCap = DirCap<FsWrite>;
pub type ReadWriteDirCap = DirCap<FsAll>;

pub type ReadFile = FileCap<FsRead>;
pub type WriteFile = FileCap<FsWrite>;
pub type ReadWriteFile = FileCap<FsAll>;
```

Private sealed traits define the operation sets:

- `AllowsFsRead`: `FsRead`, `FsAll`
- `AllowsFsWrite`: `FsWrite`, `FsAll`

External crates cannot implement these traits.

### Bootstrap

```rust
impl DirCap<FsRead> {
    pub fn open_ambient(
        path: impl AsRef<Path>,
        cap: &impl CapProvider<FsRead>,
    ) -> Result<Self, CapSecError>;
}

impl DirCap<FsWrite> {
    pub fn open_ambient(
        path: impl AsRef<Path>,
        cap: &impl CapProvider<FsWrite>,
    ) -> Result<Self, CapSecError>;
}

impl DirCap<FsAll> {
    pub fn open_ambient(
        path: impl AsRef<Path>,
        cap: &impl CapProvider<FsAll>,
    ) -> Result<Self, CapSecError>;

    pub fn open_ambient_with(
        path: impl AsRef<Path>,
        read: &impl CapProvider<FsRead>,
        write: &impl CapProvider<FsWrite>,
    ) -> Result<Self, CapSecError>;
}
```

Each constructor:

1. calls `provide_cap(CapTarget::Path(path))`;
2. opens the directory once with `cap_std::fs::Dir::open_ambient_dir`;
3. stores only the open handle and permission marker;
4. does not store or return the proof token.

### Relative path validation

All relative-path methods use one shared validator before the backend call.

The validator rejects:

- absolute paths;
- Windows drive, UNC, and verbatim prefixes;
- `ParentDir` (`..`) components;
- empty paths where the operation requires a named child;
- platform-specific paths that cannot be represented by the backend without
  changing their bytes.

It accepts:

- normal relative components;
- `.` components, which are normalized away;
- non-UTF-8 path components on supported platforms.

The original `Path` is passed to the backend without conversion through UTF-8.

### Directory attenuation and delegation

```rust
impl<P: Permission> DirCap<P> {
    pub fn open_dir(&self, relative: impl AsRef<Path>)
        -> Result<DirCap<P>, CapSecError>;

    pub fn try_clone(&self) -> Result<DirCap<P>, CapSecError>;
}

impl DirCap<FsAll> {
    pub fn into_read(self) -> DirCap<FsRead>;
    pub fn into_write(self) -> DirCap<FsWrite>;

    pub fn try_split(
        self,
    ) -> Result<(DirCap<FsRead>, DirCap<FsWrite>), CapSecError>;
}
```

`open_dir` is the primary attenuation operation. It returns a new open handle
whose namespace root is the selected child directory. The child cannot name or
reopen its parent.

`into_read` and `into_write` consume the broad capability.
`try_split` explicitly duplicates the directory handle and consumes the
original.

`DirCap<P>` does not implement `CapProvider<P>`. Such an implementation would
allow the object capability to authorize an unrelated ambient path through the
legacy APIs.

### File operations

The complete synchronous method set is:

| Method | Required permission | Result |
|---|---|---|
| `read` | `AllowsFsRead` | `Vec<u8>` |
| `read_to_string` | `AllowsFsRead` | `String` |
| `read_dir` | `AllowsFsRead` | capability-safe `ReadDir` |
| `metadata` | `AllowsFsRead` | metadata |
| `symlink_metadata` | `AllowsFsRead` | metadata |
| `try_exists` | `AllowsFsRead` | `bool` |
| `open_file` | `AllowsFsRead` | `FileCap<FsRead>` |
| `write` | `AllowsFsWrite` | `()` |
| `create_file` | `AllowsFsWrite` | `FileCap<FsWrite>` |
| `create_new_file` | `AllowsFsWrite` | `FileCap<FsWrite>` |
| `create_dir` | `AllowsFsWrite` | `()` |
| `create_dir_all` | `AllowsFsWrite` | `()` |
| `remove_file` | `AllowsFsWrite` | `()` |
| `remove_dir` | `AllowsFsWrite` | `()` |
| `remove_dir_all` | `AllowsFsWrite` | `()` |
| `rename` | source and destination `AllowsFsWrite` | `()` |
| `copy` | source `AllowsFsRead`, destination `AllowsFsWrite` | `u64` |
| `open_with` | derived from options | matching `FileCap<P>` |

`rename` and `copy` accept separate source and destination directory
capabilities:

```rust
source.rename("old", &destination, "new")?;
source.copy("input", &destination, "output")?;
```

Both sides are mediated by their respective open directory handles.

### Open options

Raw `std::fs::OpenOptions` and `cap_std::fs::OpenOptions` are not accepted.
Expose permission-specific builders:

```rust
pub struct ReadOpenOptions { /* private */ }
pub struct WriteOpenOptions { /* private */ }
pub struct ReadWriteOpenOptions { /* private */ }
```

- `ReadOpenOptions` cannot enable write, append, truncate, or create.
- `WriteOpenOptions` cannot enable read.
- `ReadWriteOpenOptions` is accepted only by `DirCap<FsAll>`.
- `create_new(true)` is supported and remains atomic.
- Platform extension flags are exposed only when they do not broaden the
  permission represented by the builder.

### File capabilities

`FileCap<FsRead>` implements `Read + Seek`.
`FileCap<FsWrite>` implements `Write + Seek`.
`FileCap<FsAll>` implements `Read + Write + Seek`.

All variants provide:

- handle-based `metadata`;
- `sync_all` and `sync_data` where meaningful;
- `try_clone`, preserving the same permission marker.

`FileCap<FsAll>` additionally provides consuming `into_read`, `into_write`, and
fallible `try_split`.

No variant exposes the underlying file or raw handle.

### Directory iteration

The object-capability `ReadDir` and `DirEntry` wrappers expose:

- `file_name`;
- `file_type`;
- metadata relative to the originating directory;
- `open_file` and `open_dir` methods that derive new object capabilities.

They do not expose an ambient absolute path. Any diagnostic display path is
non-authoritative and cannot be passed back into object-capability operations
without its originating directory capability.

## Tokio filesystem API

Tokio exposes:

```rust
pub struct AsyncDirCap<P: Permission> { /* private */ }
pub struct AsyncFileCap<P: Permission> { /* private */ }
```

The async operation set has one-for-one parity with the synchronous operation
matrix. Method names are identical and return futures.

Implementation rules:

- `AsyncDirCap` holds the same handle-relative backend authority as `DirCap`.
- Opening files occurs through the directory handle before conversion to
  `tokio::fs::File`.
- `AsyncFileCap<FsRead>` implements `AsyncRead + AsyncSeek`.
- `AsyncFileCap<FsWrite>` implements `AsyncWrite + AsyncSeek`.
- `AsyncFileCap<FsAll>` implements all three traits.
- Blocking metadata and namespace mutations execute through
  `tokio::task::spawn_blocking`.
- Whole-file reads and writes open a confined handle first, then perform data
  transfer through Tokio.
- Dropping a future backed by `spawn_blocking` does not imply cancellation.
  Documentation states which namespace mutations may complete after the
  waiting future is dropped.

Conversions consume the source:

```rust
impl<P: Permission> DirCap<P> {
    pub fn into_async(self) -> AsyncDirCap<P>;
}

impl<P: Permission> AsyncDirCap<P> {
    pub fn into_sync(self) -> DirCap<P>;
}
```

No ambient namespace lookup occurs during conversion.

## Network API

### Immutable authority pools

```rust
pub struct NetPoolCap<P: Permission> {
    // private cap_std::net::Pool
    // private normalized grants
    // private PhantomData<P>
}

pub type ConnectPoolCap = NetPoolCap<NetConnect>;
pub type BindPoolCap = NetPoolCap<NetBind>;
pub type FullNetPoolCap = NetPoolCap<NetAll>;
```

Private sealed traits define:

- `AllowsNetConnect`: `NetConnect`, `NetAll`
- `AllowsNetBind`: `NetBind`, `NetAll`

Pools have no mutation method after construction.

### Endpoint grants

```rust
#[derive(Clone, Debug)]
pub enum Endpoint {
    SocketAddr(SocketAddr),
    Host { host: String, port: u16 },
    IpNet {
        network: IpNet,
        ports: RangeInclusive<u16>,
    },
}
```

Construction APIs:

```rust
impl NetPoolCap<NetConnect> {
    pub fn from_endpoints(
        endpoints: impl IntoIterator<Item = Endpoint>,
        cap: &impl CapProvider<NetConnect>,
    ) -> Result<Self, CapSecError>;

    pub fn resolve(
        endpoints: impl IntoIterator<Item = Endpoint>,
        cap: &impl CapProvider<NetConnect>,
    ) -> Result<Self, CapSecError>;
}
```

Equivalent constructors exist for `NetBind` and `NetAll`.

Construction rules:

- Every grant is checked through the corresponding typed `CapTarget`.
- `Host` entries are resolved once and replaced by concrete `SocketAddr`
  entries.
- Resolution failure fails construction; partially built pools are discarded.
- The normalized grant set is stored for deterministic subset checks and
  diagnostics.
- Duplicate and overlapping grants are normalized.
- An empty endpoint list creates a deny-all pool.

`restrict` derives an immutable subset and fails if any requested grant is not
contained by the parent:

```rust
pub fn restrict(
    &self,
    endpoints: impl IntoIterator<Item = Endpoint>,
) -> Result<Self, CapSecError>;
```

No class capability or ambient authority is consulted during restriction.

### TCP

`ConnectPoolCap` provides:

```rust
pub fn connect(&self, addr: SocketAddr) -> Result<TcpStreamCap, CapSecError>;
pub fn connect_any(&self) -> Result<TcpStreamCap, CapSecError>;
```

`BindPoolCap` provides:

```rust
pub fn bind_tcp(&self, addr: SocketAddr) -> Result<TcpListenerCap, CapSecError>;
```

`TcpListenerCap::accept` returns a `TcpStreamCap`.
`TcpStreamCap` implements `Read + Write` and exposes safe socket configuration
and address inspection methods. It has no reconnect or retarget method.

### UDP

`BindPoolCap::bind_udp` returns `UdpSocketCap`.

An unconnected `UdpSocketCap` cannot call unrestricted `send_to`. Sending to a
destination requires a `ConnectPoolCap`:

```rust
socket.send_to(&destinations, bytes, destination)?;
```

`destinations` checks every datagram destination.

Connecting a UDP socket consumes it and returns `ConnectedUdpSocketCap`:

```rust
let connected = socket.connect(&destinations, destination)?;
connected.send(bytes)?;
```

The connected variant has no `send_to` method.

### Tokio network

Tokio exposes async counterparts:

- `AsyncConnectPoolCap`
- `AsyncBindPoolCap`
- `AsyncTcpStreamCap`
- `AsyncTcpListenerCap`
- `AsyncUdpSocketCap`
- `AsyncConnectedUdpSocketCap`

Network object construction uses nonblocking sockets from `cap-net-ext`, then
registers those sockets with the active Tokio runtime. It does not perform a
blocking `std::net::TcpStream::connect` on a Tokio worker thread.

Dropping an in-progress connect future closes the unconnected socket and
cancels the attempt.

Pool conversion between sync and async variants consumes the source and
preserves the exact normalized grant set.

## Errors

Extend `CapSecError` with structured variants:

```rust
InvalidRelativePath {
    path: PathBuf,
    reason: RelativePathError,
}

TargetTypeMismatch {
    expected: &'static str,
    actual: &'static str,
}

NetworkTargetDenied {
    target: SocketAddr,
}

NoAuthorizedAddress

DnsResolution {
    host: String,
    port: u16,
    source: io::Error,
}

Backend {
    operation: &'static str,
    source: io::Error,
}
```

Requirements:

- Errors preserve `io::Error::kind` through `source`.
- Errors never reveal directory paths outside the capability.
- Network denial is distinguishable from connection failure.
- Path validation failure is distinguishable from backend I/O failure.
- Existing `Io` and `OutOfScope` variants remain for compatibility.

## Legacy API and migration

The existing APIs remain available:

```rust
capsec::fs::read(path, &cap)
capsec::tokio::fs::read(path, &cap).await
capsec::net::tcp_connect(addr, &cap)
```

They are documented as class-capability compatibility APIs. The new object
APIs are the default in the README, crate-level documentation, and examples.

No deprecation warning is introduced in `0.3.0`. The compatibility APIs remain
useful at trusted application boundaries and for incremental adoption.

Existing `ReadFile`, `WriteFile`, `AsyncReadFile`, and `AsyncWriteFile` become
type aliases or compatible wrappers around `FileCap<P>` and
`AsyncFileCap<P>`. Existing trait behavior remains unchanged.

`DirScope` and `HostScope` remain supported for compatibility APIs and for
controlling object-capability bootstrap. Documentation distinguishes them from
handle-backed confinement.

## Audit integration

`cargo capsec audit` adds the following rules:

- Flag direct calls to `cap_std::ambient_authority`.
- Flag direct `cap_std::fs::Dir::open_ambient_dir` and ambient network-pool
  insertion outside `capsec-objects`.
- Flag direct construction or use of `cap_std`, `cap_primitives`, and
  `cap-net-ext` authority types in application crates.
- Continue flagging direct `std` and `tokio` filesystem/network operations.
- Treat object-capability methods as authorized sinks tied to the receiver
  object rather than requiring a nearby `CapProvider<P>` argument.
- Include object-capability acquisition and delegation edges in shallow and
  deep audit reports.

The audit report distinguishes:

- class-capability acquisition;
- ambient bootstrap;
- object attenuation;
- object delegation;
- actual I/O operations.

## Testing

### Compile-fail tests

Tests must prove:

- `DirCap<FsRead>` cannot call write, create, remove, rename, or destination-copy
  methods.
- `DirCap<FsWrite>` cannot read contents or open a readable file.
- `FileCap<FsRead>` does not implement `Write`.
- `FileCap<FsWrite>` does not implement `Read`.
- `NetPoolCap<NetConnect>` cannot bind.
- `NetPoolCap<NetBind>` cannot connect.
- `DirCap<P>` does not implement `CapProvider<P>`.
- Backend and raw-handle fields are inaccessible.
- Safe code cannot convert a narrow object capability into `FsAll` or `NetAll`.
- Async permission boundaries match synchronous boundaries.

### Filesystem runtime tests

Run equivalent sync and Tokio tests for:

- normal reads and writes;
- nonexistent-file creation;
- recursive directory creation;
- source/destination copy across two capabilities;
- source/destination rename across two capabilities;
- absolute-path rejection;
- every platform prefix form;
- `..` traversal rejection;
- symlink to a file outside the root;
- symlink to a directory outside the root;
- nested symlink chains;
- dangling symlinks;
- concurrent symlink replacement during open;
- concurrent directory rename during open;
- removal and recreation of a pathname after a file handle is acquired;
- non-UTF-8 filenames on Unix;
- permission attenuation and `try_split`;
- directory iteration without ambient-path escape;
- no access to parent or sibling directories;
- capability transfer across threads/tasks.

The concurrent race tests run enough iterations to exercise the check/open
window that exists in the compatibility API and demonstrate that the
handle-relative API never escapes.

### Network runtime tests

Run equivalent sync and Tokio tests for:

- connect to an exact allowed address;
- reject a different IP;
- reject a different port;
- CIDR and port-range boundaries;
- bind only to allowed local addresses;
- deny-all empty pool;
- subset restriction;
- reject attempted authority expansion;
- hostname resolution pinned to its construction-time addresses;
- no DNS lookup during delegated `connect`;
- TCP listener acceptance;
- UDP destination check on every `send_to`;
- connected UDP cannot retarget;
- async connect cancellation;
- object transfer across threads/tasks.

### Platform matrix

Required CI targets:

- Linux
- macOS
- Windows

WASI builds cover the filesystem API supported by `cap-std`. Network APIs are
compiled only where the backend and standard library expose the required
socket facilities.

### Audit tests

Add fixtures proving:

- direct backend ambient acquisition is reported;
- object-capability I/O is not reported as an ambient bypass;
- delegation appears in the authority graph;
- legacy direct `std` and `tokio` bypasses remain detected.

## Documentation

Update:

- root `README.md`;
- `SECURITY.md`;
- `crates/capsec-core/README.md`;
- `crates/capsec-std/README.md`;
- `crates/capsec-tokio/README.md`;
- crate-level rustdoc for all affected crates;
- examples for sync filesystem, Tokio filesystem, sync network, and Tokio
  network;
- the comparison with `cap-std` to state that capsec now uses it as the
  handle-backed enforcement layer.

Documentation must use “class capability,” “scoped capability,” and “object
capability” consistently and must not describe name-based `DirScope` checks as
equivalent to handle-backed confinement.

## Implementation sequence

1. Add typed `CapTarget` and migrate `CapProvider`, `Scope`, macros, wrappers,
   and tests.
2. Add `capsec-objects` with private backend wrappers and relative-path
   validation.
3. Implement synchronous directory and file capabilities with the complete
   operation matrix.
4. Implement Tokio directory and file capabilities with parity tests.
5. Implement immutable network pools and synchronous TCP/UDP objects.
6. Implement nonblocking Tokio TCP/UDP objects.
7. Re-export the APIs through `capsec-std`, `capsec-tokio`, and `capsec`.
8. Extend audit discovery, call classification, and reports.
9. Update compile-fail, adversarial, cross-platform, documentation, and example
   coverage.

Each step lands with tests. No step weakens an existing capability invariant.

## Acceptance criteria

The implementation is complete when:

- all security invariants in this specification have automated tests;
- every current filesystem and network wrapper has an object-capability
  equivalent in sync and Tokio APIs;
- filesystem access after bootstrap is exclusively handle-relative;
- network access after pool construction is exclusively pool-mediated;
- no safe public API exposes or broadens backend authority;
- typed targets eliminate lossy path conversion;
- Linux, macOS, Windows, and applicable WASI checks pass;
- compile-fail snapshots prove permission separation;
- `cargo capsec audit` detects direct ambient/backend bypasses;
- README and rustdoc examples use object capabilities as the recommended
  interface;
- the legacy API remains source-compatible except for the documented
  `CapProvider`/`Scope` signature migration required by `0.3.0`.
