use libc::{mlock, munlock};

pub(crate) struct SecureBuffer(*mut u8, usize);
impl SecureBuffer {
    pub fn new(size: usize) -> Result<Self, &'static str> {
        let layout =
            std::alloc::Layout::from_size_align(size, 4096).map_err(|_| "Invalid layout")?;
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err("Allocation failed");
        }
        if unsafe { mlock(ptr as *const libc::c_void, size) } != 0 {
            unsafe { std::alloc::dealloc(ptr, layout) };
            return Err("mlock failed");
        }
        Ok(Self(ptr, size))
    }

    pub fn from_slice(data: &[u8]) -> Result<Self, &'static str> {
        let mut buf = Self::new(data.len())?;
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), buf.0, data.len());
        }
        Ok(buf)
    }

    pub fn expose(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.0, self.1) }
    }

    pub fn expose_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.0, self.1) }
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        let layout = std::alloc::Layout::from_size_align(self.1, 4096).expect("Valid layout");

        unsafe {
            std::ptr::write_bytes(self.0, 0, self.1);
            munlock(self.0 as *const libc::c_void, self.1);
            std::alloc::dealloc(self.0, layout);
        }
    }
}
unsafe impl Send for SecureBuffer {}
unsafe impl Sync for SecureBuffer {}
impl Clone for SecureBuffer {
    fn clone(&self) -> Self {
        panic!("Attempted clone of secure buffer not allowed.")
    }
}
