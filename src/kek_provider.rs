use crate::secure_buf::SecureBuffer;

pub mod fs;
#[async_trait::async_trait]
pub trait KekProvider {
    fn init() -> Self
    where
        Self: Sized,
    {
        unimplemented!()
    }
    async fn unwrap_dek(&self, dek: SecureBuffer) -> () {
        return ();
    }
    async fn wrap_dek<'a>(&self, dek: &'a SecureBuffer) -> Result<(Vec<u8>, [u8; 12]), String> {
        unimplemented!()
    }
}
