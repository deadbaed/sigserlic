use crate::error::TimestampError;
use jiff::Timestamp;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct Metadata<T> {
    #[serde(with = "crate::timestamp::required")]
    pub(crate) created_at: Timestamp,

    #[serde(with = "crate::timestamp::optional")]
    pub(crate) expired_at: Option<Timestamp>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) comment: Option<T>,
}

impl<T> Default for Metadata<T> {
    fn default() -> Self {
        Self {
            created_at: Timestamp::now(),
            expired_at: None,
            comment: None,
        }
    }
}

impl<T> Metadata<T> {
    pub fn with_comment(mut self, comment: T) -> Self {
        self.comment = Some(comment);
        self
    }

    pub fn with_expiration(mut self, timestamp: i64) -> Result<Self, TimestampError> {
        let timestamp = crate::timestamp::parse_timestamp(timestamp)?;
        self.expired_at = Some(timestamp);
        Ok(self)
    }
}
