pub(crate) struct SecureBuffer(*mut u8, usize);
unsafe impl Send for SecureBuffer {}
unsafe impl Sync for SecureBuffer {}
impl Clone for SecureBuffer {
    fn clone(&self) -> Self {
        panic!("Attempted clone of secure buffer not allowed.")
    }
}
impl Drop for SecureBuffer {
    fn drop(&mut self) {
        panic!("Drop")
    }
}