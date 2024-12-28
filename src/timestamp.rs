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
        serializer.collect_str(timestamp)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Timestamp, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Make sure value is an owned string, some serde implementations will fail on a slice (ex: `ciborium`)
        let string = String::deserialize(deserializer)?;
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
        // Make sure value is an owned string, some serde implementations will fail on a slice (ex: `ciborium`)
        let string = Option::<String>::deserialize(deserializer)?;

        // If there is a value, attempt to parse it in a timestamp, return error if parsing fails
        let timestamp = string
            .map(|string| Timestamp::from_str(&string).map_err(serde::de::Error::custom))
            .transpose()?;

        Ok(timestamp)
    }
}

#[derive(Debug, Snafu)]
#[snafu(display("Failed to parse timestamp {timestamp}"))]
/// Error while parsing a timestamp from an integer
pub struct TimestampError {
    timestamp: i64,
    source: jiff::Error,
}

pub(crate) fn parse_timestamp(timestamp: i64) -> Result<Timestamp, TimestampError> {
    Timestamp::from_second(timestamp).context(TimestampSnafu { timestamp })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_required_timestamp_string() {
        #[derive(Deserialize)]
        struct Test {
            #[serde(rename = "timestamp")]
            #[serde(with = "crate::timestamp::required")]
            timestamp: Timestamp,
        }

        let json = r#"{"timestamp": "toto mange du gateau"}"#;
        let test: Result<Test, _> = serde_json::from_str(json);
        assert!(test.is_err());

        let json = r#"{"timestamp": "2024-12-24T10:44:58Z"}"#;
        let test: Result<Test, _> = serde_json::from_str(json);
        assert_eq!(test.unwrap().timestamp.as_second(), 1735037098);
    }

    #[test]
    fn deserialize_optional_timestamp_string() {
        #[derive(Deserialize)]
        struct Test {
            #[serde(rename = "timestamp")]
            #[serde(with = "crate::timestamp::optional")]
            timestamp: Option<Timestamp>,
        }

        let json = r#"{"timestamp": null}"#;
        let test: Result<Test, _> = serde_json::from_str(json);
        assert!(test.is_ok());

        let json = r#"{"timestamp": "toto mange du gateau"}"#;
        let test: Result<Test, _> = serde_json::from_str(json);
        assert!(test.is_err());

        let json = r#"{"timestamp": "2024-12-24T10:44:58Z"}"#;
        let test: Result<Test, _> = serde_json::from_str(json);
        assert_eq!(
            test.unwrap().timestamp.map(|t| t.as_second()),
            Some(1735037098)
        );
    }
}
