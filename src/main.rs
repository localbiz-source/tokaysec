use openssl::provider::Provider;

mod dek;
mod kek;
mod secure_buf;
use std::mem;

fn main() {
    // Enable OpenSSL fips mode. We want to use FIPS approved modules 
    // only and in specific AES-256-GCM amongst others.
    mem::forget(Provider::load(None, "fips").unwrap());
    println!("Hello, world!");
}
