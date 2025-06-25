pub(crate) struct Dek {}

impl Drop for Dek {
    fn drop(&mut self) {
        panic!("DeK dropped")
    }
}
