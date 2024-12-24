use jiff::Timestamp;
use serde::{Deserialize, Deserializer, Serializer};
use snafu::{ResultExt, Snafu};
use std::str::FromStr;

pub(crate) mod required {
    use super::*;

    pub fn serialize<S>(timestamp: &Timestamp, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let str = timestamp.to_string();
        serializer.serialize_str(&str)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Timestamp, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string: String = Deserialize::deserialize(deserializer)?;
        Timestamp::from_str(&string).map_err(serde::de::Error::custom)
    }
}

pub(crate) mod optional {
    use super::*;

    pub fn serialize<S>(optional: &Option<Timestamp>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match optional {
            Some(ref value) => serializer.serialize_some(&value.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Timestamp>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::deserialize(deserializer)?;

        // If there is a value, attempt to parse it in a timestamp, return error if parsing fails
        let timestamp = value
            .map(|v| Timestamp::from_str(v).map_err(serde::de::Error::custom))
            .transpose()?;

        Ok(timestamp)
    }
}

#[derive(Debug, Snafu)]
#[snafu(display("Failed to parse timestamp {timestamp}"))]
pub struct TimestampError {
    timestamp: i64,
    source: jiff::Error,
}

pub(crate) fn parse_timestamp(timestamp: i64) -> Result<Timestamp, TimestampError> {
    Timestamp::from_second(timestamp).context(TimestampSnafu { timestamp })
}
