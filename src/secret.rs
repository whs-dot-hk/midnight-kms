//! Page-aligned, `mlock`ed, volatile-zeroed buffer for key material.
//!
//! # Why not `Zeroizing<Vec<u8>>`?
//!
//! `zeroize`'s own `Vec` impl carries this caveat:
//!
//! > Ensures the entire capacity of the `Vec` is zeroed. Cannot ensure that
//! > previous reallocations did not leave values on the heap.
//!
//! That caveat is the whole problem. A `Vec` that grows copies its bytes to a
//! new allocation and frees the old one *without* zeroing it, so every
//! reallocation leaves a plaintext copy of the seed loose on the heap. Reading
//! an HTTP body into a `Vec` does exactly that, repeatedly.
//!
//! `SecretBuffer` therefore has a **fixed capacity that is never reallocated**.
//! Writes past capacity are a hard error, never a silent regrow.
//!
//! On top of that it applies three protections a plain heap allocation lacks:
//!
//! * `mlock(2)`      — the pages cannot be written to swap.
//! * `MADV_DONTDUMP` — the pages are excluded from any core dump.
//! * volatile zeroing on drop, via `zeroize`, *before* the pages are freed.
//!
//! # What this cannot protect
//!
//! Only bytes we own. Once a secret has been through rustls' TLS record
//! buffers, hyper's body buffers or a kernel socket buffer, copies exist that
//! we have no handle on and cannot zero. See the "Residual exposure" section of
//! the README — the honest short version is that zeroization here is
//! defence-in-depth against *post-hoc* disclosure (a heap-overread bug, a
//! stray dump), and the primary protection for key material at rest in RAM is
//! SEV-SNP memory encryption plus the absence of swap.

use core::alloc::Layout;
use core::fmt;
use core::ptr::NonNull;
use core::slice;
use std::sync::OnceLock;

use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Hard ceiling on a single secret allocation. Nothing we handle (a 32-byte
/// seed, a SURI, a Confidential Space JWT, an OAuth access token) comes close;
/// the cap exists so a hostile `Content-Length` cannot make us try to `mlock`
/// an unbounded amount of unswappable memory.
pub const MAX_SECRET_CAPACITY: usize = 1 << 20; // 1 MiB

fn page_size() -> usize {
    static PAGE: OnceLock<usize> = OnceLock::new();
    *PAGE.get_or_init(|| {
        // SAFETY: `sysconf` is thread-safe and has no preconditions.
        let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        // A non-positive answer means the platform lied; 4 KiB is a safe
        // fallback because over-aligning is always sound.
        if raw > 0 { raw as usize } else { 4096 }
    })
}

/// Records which hardening steps actually took effect, so startup can log the
/// truth instead of an aspiration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protections {
    /// `mlock(2)` succeeded: these pages will not reach swap.
    pub locked: bool,
    /// `MADV_DONTDUMP` succeeded: these pages are excluded from core dumps.
    pub no_dump: bool,
}

/// A fixed-capacity buffer for secret bytes.
///
/// Deliberately implements neither `Clone` (a copy is another thing to zero)
/// nor `Deref` (which would make it trivially easy to hand the bytes to
/// something that keeps them).
pub struct SecretBuffer {
    ptr: NonNull<u8>,
    layout: Layout,
    len: usize,
    protections: Protections,
}

// SAFETY: `SecretBuffer` uniquely owns its allocation — the pointer is never
// copied out and there is no interior mutability — so moving it between
// threads is sound. It is deliberately not `Sync`.
unsafe impl Send for SecretBuffer {}

impl SecretBuffer {
    /// Allocate at least `capacity` bytes, rounded up to a page boundary,
    /// zero-filled, locked into RAM and excluded from core dumps.
    pub fn new(capacity: usize) -> Result<Self> {
        if capacity > MAX_SECRET_CAPACITY {
            return Err(Error::SecretTooLarge {
                requested: capacity,
                max: MAX_SECRET_CAPACITY,
            });
        }
        let page = page_size();
        // Round up to a whole number of pages: mlock and madvise operate at
        // page granularity, so a partial page would either fail or silently
        // pull in a neighbouring allocation.
        let size = capacity.max(1).next_multiple_of(page);
        let layout = Layout::from_size_align(size, page).map_err(|_| Error::Alloc)?;

        // SAFETY: `layout` has non-zero size (>= one page).
        let raw = unsafe { std::alloc::alloc_zeroed(layout) };
        let ptr = NonNull::new(raw).ok_or(Error::Alloc)?;

        // Both calls are advisory — failure is reported, not fatal, because
        // mlock needs RLIMIT_MEMLOCK headroom that we may not have.
        //
        // SAFETY: `ptr` is a live, page-aligned allocation of exactly `size`
        // bytes.
        let locked = unsafe { libc::mlock(ptr.as_ptr().cast(), size) } == 0;
        // SAFETY: as above.
        let no_dump = unsafe { Self::exclude_from_core_dump(ptr, size) };

        Ok(Self {
            ptr,
            layout,
            len: 0,
            protections: Protections { locked, no_dump },
        })
    }

    /// # Safety
    /// `ptr` must be a live page-aligned allocation of `size` bytes.
    #[cfg(target_os = "linux")]
    unsafe fn exclude_from_core_dump(ptr: NonNull<u8>, size: usize) -> bool {
        // SAFETY: guaranteed by the caller's contract.
        unsafe { libc::madvise(ptr.as_ptr().cast(), size, libc::MADV_DONTDUMP) == 0 }
    }

    /// # Safety
    /// Same contract as the Linux variant; this is the no-op fallback.
    #[cfg(not(target_os = "linux"))]
    unsafe fn exclude_from_core_dump(_ptr: NonNull<u8>, _size: usize) -> bool {
        false
    }

    /// Allocate a buffer holding a copy of `bytes`.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let mut buf = Self::new(bytes.len())?;
        buf.push(bytes)?;
        Ok(buf)
    }

    pub fn capacity(&self) -> usize {
        self.layout.size()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn protections(&self) -> Protections {
        self.protections
    }

    /// The initialised bytes.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `0..len` is initialised by construction and the allocation
        // outlives the borrow.
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// The uninitialised (but zero-filled) tail, for writing into.
    pub fn spare_mut(&mut self) -> &mut [u8] {
        let spare = self.capacity() - self.len;
        // SAFETY: the whole allocation was zero-filled at creation, so every
        // byte is initialised; `len..capacity` is in bounds.
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr().add(self.len), spare) }
    }

    /// Append `bytes`. Errors rather than reallocating, which is the entire
    /// point of this type.
    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        let spare = self.capacity() - self.len;
        if bytes.len() > spare {
            return Err(Error::SecretCapacityExceeded {
                capacity: self.capacity(),
            });
        }
        self.spare_mut()[..bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }

    /// Declare `additional` bytes of the spare region initialised, after
    /// writing into the slice from [`Self::spare_mut`].
    pub fn commit(&mut self, additional: usize) -> Result<()> {
        if additional > self.capacity() - self.len {
            return Err(Error::SecretCapacityExceeded {
                capacity: self.capacity(),
            });
        }
        self.len += additional;
        Ok(())
    }

    /// Interpret the contents as UTF-8 without copying.
    pub fn as_str(&self) -> Result<&str> {
        core::str::from_utf8(self.as_slice()).map_err(|_| Error::NotUtf8)
    }

    /// Fill from `reader` until EOF, into our own locked pages.
    ///
    /// Used instead of `Response::text()`/`bytes()` so that the response body
    /// lands in a buffer we can actually zero, rather than in an internal
    /// `Bytes` we have no way to reach. Exceeding capacity is an error: a
    /// truncated ciphertext or token must never be silently accepted.
    pub fn fill_from<R: std::io::Read>(&mut self, reader: &mut R) -> Result<()> {
        loop {
            if self.len == self.capacity() {
                // At capacity. Distinguish "exactly full" from "truncated" by
                // asking for one more byte.
                let mut probe = [0u8; 1];
                return match reader.read(&mut probe) {
                    Ok(0) => Ok(()),
                    Ok(_) => {
                        probe.zeroize();
                        Err(Error::SecretCapacityExceeded {
                            capacity: self.capacity(),
                        })
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => Err(Error::Io(e.to_string())),
                };
            }
            match reader.read(self.spare_mut()) {
                Ok(0) => return Ok(()),
                Ok(n) => self.len += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::Io(e.to_string())),
            }
        }
    }

    /// Append `bytes` as lowercase hex.
    ///
    /// Hand-rolled rather than using `hex::encode`, which returns a `String`
    /// on the normal heap that we could not lock or reliably zero.
    pub fn push_hex(&mut self, bytes: &[u8]) -> Result<()> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let needed = bytes.len().checked_mul(2).ok_or(Error::Alloc)?;
        if needed > self.capacity() - self.len {
            return Err(Error::SecretCapacityExceeded {
                capacity: self.capacity(),
            });
        }
        for &b in bytes {
            let pair = [HEX[(b >> 4) as usize], HEX[(b & 0x0f) as usize]];
            self.spare_mut()[..2].copy_from_slice(&pair);
            self.len += 2;
        }
        Ok(())
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        let size = self.layout.size();
        // SAFETY: the whole allocation is initialised (zero-filled at
        // creation) and uniquely borrowed here.
        let all = unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), size) };
        // Volatile write + compiler fence, via zeroize. This must happen
        // before `dealloc` hands the pages back to the allocator, which may
        // reuse them for anything.
        all.zeroize();

        if self.protections.locked {
            // SAFETY: matches the `mlock` in `new` exactly.
            unsafe { libc::munlock(self.ptr.as_ptr().cast(), size) };
        }
        // SAFETY: allocated by `alloc_zeroed` with this same layout.
        unsafe { std::alloc::dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

/// Lets a `SecretBuffer` be wrapped in `std::io::Cursor` and streamed as a
/// request body straight out of its locked pages. Exposes nothing that
/// [`SecretBuffer::as_slice`] does not.
impl AsRef<[u8]> for SecretBuffer {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// Redacted. A derived `Debug` on any struct holding a `SecretBuffer` stays
/// safe to log, which is why this prints a shape instead of refusing to exist.
impl fmt::Debug for SecretBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SecretBuffer(<redacted; {} of {} bytes>)",
            self.len,
            self.capacity()
        )
    }
}

/// Reject bytes that cannot appear in a JWT, an OAuth token or a base64 blob.
///
/// Two jobs, both structural rather than cryptographic:
///
/// * A credential is interpolated into a JSON request body and into an HTTP
///   header. Refusing quotes, backslashes, CR and LF means neither
///   interpolation can be broken out of, so we never need an escaping routine
///   on a secret value.
/// * It catches the common failure of a token file containing an error message
///   or HTML, which would otherwise fail much later with a confusing error.
pub fn is_credential_safe(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.iter().all(|&b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'+' | b'/' | b'=')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_is_page_rounded_and_never_reallocates() {
        let mut b = SecretBuffer::new(10).unwrap();
        assert_eq!(b.capacity(), page_size());
        assert!(b.is_empty());
        b.push(b"abc").unwrap();
        assert_eq!(b.as_slice(), b"abc");
        // The address must be stable across writes: no realloc, ever.
        let addr = b.as_slice().as_ptr();
        b.push(b"def").unwrap();
        assert_eq!(b.as_slice(), b"abcdef");
        assert_eq!(b.as_slice().as_ptr(), addr);
    }

    #[test]
    fn overflow_is_an_error_not_a_regrow() {
        let mut b = SecretBuffer::new(1).unwrap();
        let cap = b.capacity();
        b.push(&vec![7u8; cap]).unwrap();
        assert!(matches!(
            b.push(b"x"),
            Err(Error::SecretCapacityExceeded { .. })
        ));
    }

    #[test]
    fn fill_from_rejects_truncation() {
        let mut b = SecretBuffer::new(1).unwrap();
        let cap = b.capacity();
        let src = vec![1u8; cap + 1];
        assert!(matches!(
            b.fill_from(&mut src.as_slice()),
            Err(Error::SecretCapacityExceeded { .. })
        ));
        // Exactly-full must succeed rather than trip the probe.
        let mut b2 = SecretBuffer::new(1).unwrap();
        b2.fill_from(&mut vec![1u8; cap].as_slice()).unwrap();
        assert_eq!(b2.len(), cap);
    }

    #[test]
    fn push_hex_matches_expected_encoding() {
        let mut b = SecretBuffer::new(64).unwrap();
        b.push(b"0x").unwrap();
        b.push_hex(&[0x00, 0x0f, 0xa5, 0xff]).unwrap();
        assert_eq!(b.as_str().unwrap(), "0x000fa5ff");
    }

    #[test]
    fn debug_never_prints_contents() {
        let b = SecretBuffer::from_slice(b"topsecret").unwrap();
        let rendered = format!("{b:?}");
        assert!(!rendered.contains("topsecret"), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    #[test]
    fn credential_charset_blocks_header_and_json_injection() {
        assert!(is_credential_safe(b"eyJhbGciOiJSUzI1NiJ9.eyJhIjoxfQ.c2ln"));
        assert!(is_credential_safe(b"ya29.a0Ae-w=="));
        assert!(!is_credential_safe(b""));
        assert!(!is_credential_safe(b"tok\r\nX-Evil: 1")); // header injection
        assert!(!is_credential_safe(br#"tok","scope":"x"#)); // JSON breakout
        assert!(!is_credential_safe(b"<html>error</html>"));
        assert!(!is_credential_safe(b"tok en"));
    }
}
