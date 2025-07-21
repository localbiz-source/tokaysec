use crate::{dek::Dek, secure_buf::SecureBuffer};

pub mod fs;
pub mod tokaykms;

// Init function not defined on trait because
// it is not called by the dynamic trait objects
// and only called in app.rs to setup the provider.
// indiviudal providers choose the structure of
// their init fn and get called individually at
// startup. Same idea for the stores as well.
#[async_trait::async_trait]
pub trait KekProvider: Send + Sync {
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
        _dek: Dek,
        _secret_name: &'a str,
    ) -> Result<(Vec<u8>, [u8; 12], [u8; 16]), String> {
        unimplemented!()
    }
    async fn init_new_kek(&self) -> Result<String, String> {
        unimplemented!()
    }
}
