use bindings::protocol;
use serde::{Deserialize, Serialize};
struct Component;
pub mod operator;
pub mod package;
mod proto_envelope;
pub mod registry;
mod serde_envelope;

pub use semver::{Version, VersionReq};

pub use proto_envelope::{ProtoEnvelope, ProtoEnvelopeBody};
pub use serde_envelope::SerdeEnvelope;
use warg_crypto::signing;

/// Represents information about a registry package.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageInfo {
    /// The name of the package.
    pub name: String,
    /// The last known checkpoint of the package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<SerdeEnvelope<bindings::protocol::MapCheckpoint>>,
    // pub checkpoint: Option<String>,
    /// The current validation state of the package.
    #[serde(default)]
    pub state: package::Validator,
}

impl PackageInfo {
    /// Creates a new package info for the given package name and url.
    pub fn new(name: impl Into<String>, checkpoint: bindings::protocol::MapCheckpoint) -> Self {
        Self {
            name: name.into(),
            checkpoint: Some(checkpoint),
            state: package::Validator::default(),
        }
    }
}

/// Types for converting to and from protobuf
pub mod protobuf {
    #![allow(clippy::all)]
    // Generated by [`prost-build`]
    include!(concat!(env!("OUT_DIR"), "/warg.rs"));
    // Generated by [`pbjson-build`]
    include!(concat!(env!("OUT_DIR"), "/warg.serde.rs"));

    pub fn prost_to_pbjson_timestamp(timestamp: prost_types::Timestamp) -> pbjson_types::Timestamp {
        pbjson_types::Timestamp {
            seconds: timestamp.seconds,
            nanos: timestamp.nanos,
        }
    }

    pub fn pbjson_to_prost_timestamp(timestamp: pbjson_types::Timestamp) -> prost_types::Timestamp {
        prost_types::Timestamp {
            seconds: timestamp.seconds,
            nanos: timestamp.nanos,
        }
    }
}

/// Helper module for serializing and deserializing timestamps.
///
/// This is used over serde's built-in implementation to produce cleaner timestamps
/// in serialized output.
mod timestamp {
    use serde::Deserializer;
    use serde::{Deserialize, Serializer};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub fn serialize<S>(timestamp: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::Error;

        let duration_since_epoch = match timestamp.duration_since(UNIX_EPOCH) {
            Ok(duration_since_epoch) => duration_since_epoch,
            Err(_) => return Err(S::Error::custom("timestamp must be later than UNIX_EPOCH")),
        };

        serializer.serialize_str(&format!(
            "{secs}.{nsecs}",
            secs = duration_since_epoch.as_secs(),
            nsecs = duration_since_epoch.subsec_nanos()
        ))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let s = String::deserialize(deserializer)?;
        let (secs, nsecs) = s
            .split_once('.')
            .ok_or_else(|| D::Error::custom("timestamp must be in the format <secs>.<nsecs>"))?;

        Ok(SystemTime::UNIX_EPOCH
            + Duration::new(
                secs.parse::<u64>().map_err(D::Error::custom)?,
                nsecs.parse::<u32>().map_err(D::Error::custom)?,
            ))
    }
}

impl bindings::Component for Component {
    fn hello_world() -> String {
        "Hello, World!".to_string()
    }
}

impl protocol::Protocol for Component {
  fn validate(private_key: String, contents: bindings::protocol::MapCheckpoint) {
    println!("THIS IS THE CONTENTS {:?}", contents);
    let package = PackageInfo::new("foo", contents);
  }
}

bindings::export!(Component);
