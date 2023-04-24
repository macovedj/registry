use chrono::{DateTime, Utc};
use base64::{Engine as _, engine::{self, general_purpose}};
use std::str::FromStr; // 0.4.15
use std::collections::HashMap;

use bindings::protocol as protocolbindings;
struct Component {
  validators: HashMap<u32, package::Validator>
}

pub use semver::{Version, VersionReq};

use anyhow::Error;
use anyhow::anyhow;

use warg_protocol::{
  package,
  proto_envelope::{ProtoEnvelope, ProtoEnvelopeBody}, 
  SerdeEnvelope,
  registry::{MapCheckpoint, RecordId, LogId, LogLeaf, MapLeaf},
};
use warg_crypto::{signing, Decode, hash::{Hash, Sha256, HashAlgorithm, DynHash}};
use warg_transparency::{log::LogProofBundle, map::MapProofBundle};
use warg_api::proof::ProofError;

bindings::export!(Component);

// #[macro_use]
// extern crate lazy_static;
// lazy_static! {
//   static ref validators: HashMap<u32, &'static package::Validator> = {
//       let mut m = HashMap::new();
//       m
//   };
//   static ref COUNT: usize = validators.len();
// }

 
/// Represents information about a registry package.
#[derive(Debug, Clone)]
// #[serde(rename_all = "camelCase")]
pub struct PackageInfo {
    /// The name of the package.
    pub name: String,
    /// The last known checkpoint of the package.
    // #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<String>,
    // pub checkpoint: Option<String>,
    /// The current validation state of the package.
    // #[serde(default)]
    pub state: u32,
}

impl PackageInfo {
    /// Creates a new package info for the given package name and url.
    pub fn new(name: impl Into<String>, 
    ) -> Self {
      let key = validators.len();
      let validator = package::Validator::default();
      validators.insert(key.try_into().unwrap(), &validator);
      Self {
          name: name.into(),
          checkpoint: None,
          state: key.try_into().unwrap(),
      }
    }
}

#[derive(Debug)]
struct ProtoBody(protocolbindings::ProtoEnvelopeBody);

impl<Content> TryFrom<ProtoBody> for ProtoEnvelope<Content>
where
    Content: Decode,
{
    type Error = Error;

    fn try_from(value: ProtoBody) -> Result<Self, Self::Error> {
        let contents = Content::decode(&value.0.content_bytes)?;
        let envelope = ProtoEnvelope {
            contents,
            content_bytes: value.0.content_bytes,
            key_id: value.0.key_id.into(),
            signature: signing::Signature::from_str(&value.0.signature).unwrap(),
        };
        Ok(envelope)
    }
}

fn perm_binding(permission: &package::model::Permission) -> protocolbindings::Permission {
    match permission {
        &package::Permission::Release => protocolbindings::Permission::Release,
        &package::Permission::Yank => protocolbindings::Permission::Yank,
        &_ => protocolbindings::Permission::Release,
    }
}

struct HeadBindings(protocolbindings::Head);
impl From<package::Head> for HeadBindings {
  fn from(head: package::Head) -> Self {
    let t: DateTime<Utc> = head.timestamp.into();
    Self(protocolbindings::Head {
      digest: RecordIdBindings::from(head.digest).0,
      timestamp: Some(t.to_rfc3339())
   })
  }
}

struct RecordIdBindings(protocolbindings::RecordId);
impl From<RecordId> for RecordIdBindings {
  fn from(record_id: RecordId) -> Self {
    Self(protocolbindings::RecordId::DynHash(DynHashBindings::from(record_id.0).0))
  }
}

struct DynHashBindings(protocolbindings::DynHash);
impl From<DynHash> for DynHashBindings {
  fn from(dyn_hash: DynHash) -> Self {
    Self(protocolbindings::DynHash {
      algo: protocolbindings::HashAlgorithm::Sha256,
      bytes: dyn_hash.bytes().to_vec()
    })
  }
}
impl protocolbindings::Protocol for Component {
    fn get_algorithm(_this: protocolbindings::Validator) -> Option<protocolbindings::HashAlgorithm> {
      Some(protocolbindings::HashAlgorithm::Sha256)
    }
    fn get_head(this: protocolbindings::Validator) -> Option<protocolbindings::Head> {
      let head = validators.get(&this).unwrap().head().unwrap();
      Some(HeadBindings::from(head).0)
    }
    fn get_permissions(this: protocolbindings::Validator) -> Vec<protocolbindings::PermissionEntry> {
      let permissions = validators.get(&this).unwrap().permissions();
      let mut output = Vec::new();
      for (keyID, permission_set) in permissions {
        let mut cur = Vec::new();
        for permission in permission_set {
          match permission {
            package::Permission::Release => {
              cur.push(protocolbindings::Permission::Release);
            }
            package::Permission::Yank => {
              cur.push(protocolbindings::Permission::Yank);
            }
            &_ => {}
          }
        }
        output.push(protocolbindings::PermissionEntry {
          key_id: keyID.to_string(),
          permissions: cur
        });
      }
      output
    }
    fn get_releases(this: protocolbindings::Validator) -> Vec<protocolbindings::Release> {
      let mut releases = Vec::new();
      for release in validators.get(&this).unwrap().releases() {
        let t: DateTime<Utc> = release.timestamp.into();
        let state = match release.state {
          package::ReleaseState::Released {content} => {
            let released = DynHashBindings::from(content);
            protocolbindings::ReleaseState::Released(protocolbindings::Released {content: released.0})
          }
          package::ReleaseState::Yanked {by, timestamp} => {
            let cur_t: DateTime<Utc> = release.timestamp.into(); 
            protocolbindings::ReleaseState::Yanked(protocolbindings::Yanked{by: by.to_string(), timestamp: cur_t.to_rfc3339()})
          }
        };
        releases.push(protocolbindings::Release {
          version: release.version.to_string(),
          by: release.by.to_string(),
          timestamp: t.to_rfc3339(),
          state
        })
      }
      releases
    }
    fn get_keys(this: protocolbindings::Validator) -> Option<Vec<protocolbindings::KeyEntry>> {
      let mut keys = Vec::new();
      for (key_id, public_key) in validators.get(&this).unwrap().keys() {
        keys.push(protocolbindings::KeyEntry {
          key_id: key_id.to_string(),
          public_key: public_key.to_string()
        });
      }
      Some(keys)
    }
    fn prove_inclusion(input: protocolbindings::Inclusion, checkpoint: protocolbindings::MapCheckpoint, heads: Vec<protocolbindings::LogLeaf>) {
      let bytes = general_purpose::STANDARD.decode(&input.log).unwrap();
      let log_proof_bundle: LogProofBundle<Sha256, LogLeaf> =
            LogProofBundle::decode(general_purpose::STANDARD
              .decode(&input.log).unwrap().as_slice()).unwrap();
        let (log_data, _, log_inclusions) = log_proof_bundle.unbundle();
        for (leaf, proof) in heads.iter().zip(log_inclusions.iter()) {
          let leaf = &LogLeaf {
            log_id: LogId(DynHash::from_str(&leaf.log_id).unwrap()),
            record_id: RecordId(DynHash::from_str(&leaf.record_id).unwrap())
          };
            let found = proof.evaluate_value(
              &log_data,
              &leaf).unwrap();
            let log_root: Hash<Sha256> = DynHash::from_str(&checkpoint.log_root).expect("expected a dynamic hash to exist").clone().try_into().unwrap();
            if found != log_root {
                println!("ERR: {:?}", Err::<ProofError, anyhow::Error>(anyhow!(ProofError::IncorrectProof { root: log_root, found })));
            }
        }
        let map_proof_bundle: MapProofBundle<Sha256, MapLeaf> =
        MapProofBundle::decode(general_purpose::STANDARD
          .decode(&input.map).unwrap().as_slice()).unwrap();
        let map_inclusions = map_proof_bundle.unbundle();
        for (leaf, proof) in heads.iter().zip(map_inclusions.iter()) {
            let map_found = proof.evaluate(
                &LogId(DynHash::from_str(&leaf.log_id).unwrap()),
                &MapLeaf {
                    record_id: RecordId(DynHash::from_str(&leaf.record_id).unwrap()) 
                },
              );
            let map_root: Hash<Sha256> = DynHash::from_str(&checkpoint.map_root).expect("expected dynamic hash to exist").clone().try_into().unwrap();
            if map_found != map_root {
                println!("ERR {:?}", Err::<ProofError, anyhow::Error>(anyhow!(ProofError::IncorrectProof { root: map_root, found: map_found })));
            }
        }
    }
    fn validate(
        package_records: Vec<protocolbindings::ProtoEnvelopeBody>,
    ) -> protocolbindings::PackageInfo {
        let mut package = PackageInfo::new("funny");
        let mut permissions = Vec::new();
        let mut releases = Vec::new();
        let mut keys = Vec::new();
        let mut heads = Vec::with_capacity(1);
        let validator: &package::Validator = validators.get(&package.state).unwrap();
        for package_record in package_records {
          let rec: ProtoBody = ProtoBody(package_record);
          let record: Result<ProtoEnvelope<package::model::PackageRecord>, Error> = rec.try_into();
          let record = record.unwrap();
          let res = validator.validate(&record);
          for (key, value) in validator.permissions() {
              permissions.push(protocolbindings::PermissionEntry {
                  key_id: key.to_string(),
                  permissions: value
                      .into_iter()
                      .map(|p: &package::model::Permission| perm_binding(p))
                      .collect(),
              })
          }
          for release in validator.releases() {
            let t: DateTime<Utc> = release.timestamp.into();
            releases.push(protocolbindings::Release {
              version: release.version.to_string(),
              by: release.by.to_string(),
              timestamp: t.to_rfc3339(),
              state: match &release.state {
                package::ReleaseState::Released{ content } => protocolbindings::ReleaseState::Released(protocolbindings::Released {
                  content: protocolbindings::DynHash {
                    algo: protocolbindings::HashAlgorithm::Sha256,
                    bytes: content.bytes().to_vec()
                  }
                }),
                package::ReleaseState::Yanked{ by, timestamp } => {
                  let ts: DateTime<Utc> = (*timestamp).into();
                  protocolbindings::ReleaseState::Yanked(protocolbindings::Yanked {
                    by: by.to_string(),
                    timestamp: ts.to_string()
                  })
                }
              }
            })
          }
          for (key, value) in validator.keys() {
              keys.push(protocolbindings::KeyEntry {
                  key_id: key.to_string(),
                  public_key: value.to_string(),
              })
          }
        }
        if let Some(head) = &validator.head() {
          heads.push(protocolbindings::LogLeaf {
              log_id: LogId::package_log::<Sha256>("funny").to_string(),
              record_id: head.digest.clone().to_string(),
          });
        } 
        return protocolbindings::PackageInfo {
            name: package.name,
            checkpoint: package.checkpoint,
            state: package.state,
            heads
        };
    }
}

fn main() {
  
}