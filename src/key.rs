/// Information available to identify keys
pub trait KeyMetadata<C> {
    /// Timestamp when the key was generated
    fn created_at(&self) -> i64;

    /// Timestamp when the key is supposed to expire
    fn expired_at(&self) -> Option<i64>;

    /// Key identifier
    fn keynum(&self) -> libsignify::KeyNumber;

    /// Comment helping to identifing the key
    fn comment(&self) -> Option<&C>;

    /// What is the purpose of the key
    fn usage(&self) -> KeyUsage;
}

/// What is the purpose of a key
pub enum KeyUsage {
    /// Generate signatures
    Signing,

    /// Verify signatures
    Verifying,
}
