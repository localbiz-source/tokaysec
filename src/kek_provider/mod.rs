use crate::secure_buf::SecureBuffer;

pub mod fs;
pub mod tokaykms;

#[async_trait::async_trait]
pub trait KekProvider: Sync {
    fn init() -> Self
    where
        Self: Sized,
    {
        unimplemented!()
    }
    async fn unwrap_dek<'a>(
        &self,
        _dek: &'a [u8],
        _nonce: [u8; 12],
        _tag: [u8; 16],
        _secret_name: &'a str,
    ) -> SecureBuffer {
        unimplemented!()
    }
    async fn wrap_dek<'a>(
        &self,
        _dek: SecureBuffer,
        _secret_name: &'a str,
    ) -> Result<(Vec<u8>, [u8; 12], [u8; 16]), String> {
        unimplemented!()
    }
}
