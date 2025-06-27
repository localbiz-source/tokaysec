use bitflags::bitflags;

bitflags! {
    pub struct UserPerms: i64 {}
    pub struct GroupPerms: i64 {}
    pub struct SecretFlgas: i64 {}
    pub struct ProjectFlags: i64 {}
}
