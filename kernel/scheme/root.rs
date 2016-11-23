use alloc::arc::Arc;
use alloc::boxed::Box;
use collections::BTreeMap;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;

use context;
use syscall::error::*;
use syscall::scheme::Scheme;
use scheme::{self, AtomicSchemeId, ATOMIC_SCHEMEID_INIT, SchemeNamespace};
use scheme::user::{UserInner, UserScheme};

pub static ROOT_SCHEME_ID: AtomicSchemeId = ATOMIC_SCHEMEID_INIT;

#[repr(usize)]
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub enum Capabilities {
    Top = 0,
    Reg = 1,
    Unreg = 2,
    Last,
}
impl Capabilities {
    fn new(value: usize) -> Capabilities {
        match value {
            0 => Capabilities::Top,
            1 => Capabilities::Reg,
            2 => Capabilities::Unreg,
            _ => Capabilities::Last,
        }
    }
}

pub struct RootScheme {
    scheme_ns: SchemeNamespace,
    scheme_id: SchemeId,
    next_id: AtomicUsize,
    handles: RwLock<BTreeMap<usize, Arc<UserInner>>>
}

impl RootScheme {
    pub fn new(scheme_ns: SchemeNamespace, scheme_id: SchemeId) -> RootScheme {
        RootScheme {
            scheme_ns: scheme_ns,
            scheme_id: scheme_id,
            next_id: AtomicUsize::new(Capabilities::Last as usize),
            handles: RwLock::new(BTreeMap::new())
        }
    }
}

impl RootScheme {
    fn register(&self, path: &[u8], flags: usize) -> Result<usize> {
        let context = {
            let contexts = context::contexts();
            let context = contexts.current().ok_or(Error::new(ESRCH))?;
            Arc::downgrade(&context)
        };

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        debug_assert!(id >= Capabilities::Last as usize);

        let inner = {
            let mut schemes = scheme::schemes_mut();
            let inner = Arc::new(UserInner::new(self.scheme_id, id, flags, context));
            schemes.insert(self.scheme_ns, path.to_vec().into_boxed_slice(), |scheme_id| {
                inner.scheme_id.store(scheme_id, Ordering::SeqCst);
                Arc::new(Box::new(UserScheme::new(Arc::downgrade(&inner))))
            })?;
            inner
        };

        self.handles.write().insert(id, inner);

        Ok(id)
    }
}

impl Scheme for RootScheme {
    /// Request a weaker capability.
    ///
    /// # Arguments
    ///
    /// If `path` is a valid path (i.e. if it doesn't start with `:`), it is
    /// taken as the name of a scheme that should be registered. The root scheme
    /// will attempt to register it.
    ///
    /// Otherwise, it is taken as the name of a pure capability. The root scheme
    /// will attempt to downgrade capability `proof` to match this capability.
    /// The only capability name recognized by the root scheme is `":reg"`, the
    /// authorization to register schemes.
    ///
    /// # Access policy
    ///
    /// This scheme has the following capabilities:
    /// - `:*`, provides full access;
    /// - `:reg`, gives clients the ability to register new schemes;
    /// - `:unreg`, gives clients the ability to unregister schemes;
    /// - other capabilities map each to one specific scheme and grant the
    ///   to send a message to said scheme.
    fn open_at(&self, path: &[u8], proof: usize) -> Result<usize> {
        match (path, Capabilities::new(proof)) {
            (b":*", Capabilities::Top) => {
                Ok(Capabilities::Top as usize)
            }
            (b":reg", Capabilities::Top) |
            (b":reg", Capabilities::Reg) => {
                // Downgrade to Capabilities::Reg.
                // FIXME: What's the semantics if we return twice the same fd?
                Ok(Capabilities::Reg as usize)
            }
            (b":unreg", Capabilities::Top) |
            (b":unreg", Capabilities::Unreg) => {
                // Downgrade to Capabilities::Unreg.
                // FIXME: What's the semantics if we return twice the same fd?
                Ok(Capabilities::Unreg as usize)
            }
            (_, Capabilities::Top) |
            (_, Capabilities::Reg) => {
                self.register(path, 0) // FIXME: Check the semantics of flags here.
            }
            _ => Err(Error::new(EACCES))
        }
    }

    /// Register a new scheme.
    ///
    /// Return the file descriptor for the new scheme.
    ///
    /// # Access policy
    ///
    /// This method may only be called by the root user.
    fn open(&self, path: &[u8], flags: usize, uid: u32, _gid: u32) -> Result<usize> {
        if uid == 0 {
            self.register(path, flags)
        } else {
            Err(Error::new(EACCES))
        }
    }

    fn dup(&self, file: usize, _buf: &[u8]) -> Result<usize> {
        let mut handles = self.handles.write();
        let inner = {
            let inner = handles.get(&file).ok_or(Error::new(EBADF))?;
            inner.clone()
        };

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        handles.insert(id, inner);

        Ok(id)
    }

    fn read(&self, file: usize, buf: &mut [u8]) -> Result<usize> {
        let inner = {
            let handles = self.handles.read();
            let inner = handles.get(&file).ok_or(Error::new(EBADF))?;
            inner.clone()
        };

        inner.read(buf)
    }

    fn write(&self, file: usize, buf: &[u8]) -> Result<usize> {
        let inner = {
            let handles = self.handles.read();
            let inner = handles.get(&file).ok_or(Error::new(EBADF))?;
            inner.clone()
        };

        inner.write(buf)
    }

    fn fevent(&self, file: usize, flags: usize) -> Result<usize> {
        let inner = {
            let handles = self.handles.read();
            let inner = handles.get(&file).ok_or(Error::new(EBADF))?;
            inner.clone()
        };

        inner.fevent(flags)
    }

    fn fsync(&self, file: usize) -> Result<usize> {
        let inner = {
            let handles = self.handles.read();
            let inner = handles.get(&file).ok_or(Error::new(EBADF))?;
            inner.clone()
        };

        inner.fsync()
    }

    fn close(&self, file: usize) -> Result<usize> {
        self.handles.write().remove(&file).ok_or(Error::new(EBADF)).and(Ok(0))
    }
}
