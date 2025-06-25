pub(crate) struct WrappedKek {}

impl Drop for WrappedKek {
    fn drop(&mut self) {
        panic!("KeK dropped")
    }
}
