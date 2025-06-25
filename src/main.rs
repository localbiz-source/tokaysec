use openssl::provider::Provider;

mod dek;
mod kek;
mod secure_buf;
use std::mem;

use crate::secure_buf::SecureBuffer;

fn main() {
    // Enable OpenSSL fips mode. We want to use FIPS approved modules
    // only and in specific AES-256-GCM amongst others.
    mem::forget(Provider::load(None, "fips").unwrap());
    let secure_buffer: SecureBuffer =
        SecureBuffer::from_slice(b"Hello, World!".as_slice()).unwrap();

    println!(
        "{:?}",
        String::from_utf8(secure_buffer.expose().to_vec()).unwrap()
    );
    drop(secure_buffer);
}
