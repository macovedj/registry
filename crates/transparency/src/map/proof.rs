use alloc::vec::Vec;
use core::marker::PhantomData;

use warg_crypto::{
    hash::{Hash, SupportedDigest},
    VisitBytes,
};

use super::{
    map::{hash_branch, hash_leaf},
    path::{ReversePath, Side},
};

/// An inclusion proof of the specified value in a map
///
/// # Compression
///
/// Since the depth of a tree is always `n` and a proof needs to contain all
/// branch node peers from the leaf to the root, a proof should contain `n`
/// hashes. However, several strategies can be used to compress a proof;
/// saving both memory and bytes on the wire.
///
/// First, the hash of the item and the root are known by both sides and can
/// be omitted.
///
/// Second, sparse peers can be represented by `None`. Since we take references
/// to the hashes, Rust null-optimization is used.
///
/// Third, since sparse peers are more likely at the bottom of the tree, we
/// can omit all leading sparse peers. The verifier can dynamically reconstruct
pub struct Proof<D, V>
where
    D: SupportedDigest,
    V: VisitBytes,
{
    value: PhantomData<V>,
    peers: Vec<Hash<D>>,
}

impl<D, V> Proof<D, V>
where
    D: SupportedDigest,
    V: VisitBytes,
{
    pub(crate) fn new(peers: Vec<Hash<D>>) -> Self {
        Self {
            value: PhantomData,
            peers,
        }
    }

    pub(crate) fn push(&mut self, peer: &Hash<D>) {
        self.peers.push(peer.clone());
    }

    /// Computes the root obtained by evaluating this inclusion proof with the given leaf
    pub fn evaluate<K: ?Sized + VisitBytes>(&self, key: &K, value: &V) -> Hash<D> {
        // Get the path from bottom to top.
        let path = ReversePath::<D>::new(key);

        // Calculate the leaf hash.
        let mut hash = hash_leaf(key, value);

        // // Loop over each side and peer.
        for (side, peer) in path.zip(self.peers.clone()) {
            hash = match side {
                Side::Left => hash_branch(&hash, &peer),
                Side::Right => hash_branch(&peer, &hash),
            };
        }

        hash
    }
}

impl<D, V> From<Proof<D, V>> for Vec<Hash<D>>
where
    D: SupportedDigest,
    V: VisitBytes,
{
    fn from(value: Proof<D, V>) -> Self {
        value.peers
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_proof_evaluate() {
        use warg_crypto::hash::Sha256;

        let a = crate::map::Map::<Sha256, &str, &[u8]>::default();
        let b = a.insert("foo", b"bar");
        let c = b.insert("baz", b"bat");

        let root = c.root().clone();

        let p = c.prove(&"baz").unwrap();

        assert_eq!(root, p.evaluate(&"baz", &b"bat".as_slice()));
        assert_ne!(root, p.evaluate(&"other", &b"bar".as_slice()));
    }
}
