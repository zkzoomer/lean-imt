use serde::{Deserialize, Serialize};

/// Represents a Merkle proof for a leaf in the tree.
///
/// This struct contains all the necessary information to verify the inclusion
/// of a specific `leaf` in the Merkle tree defined by the `root`.
#[derive(Serialize, Deserialize)]
pub struct LeanImtProof {
    /// The leaf hash for which the proof is generated.
    pub leaf: [u8; 32],
    /// The index of the leaf in the tree.
    pub index: usize,
    /// The sibling hashes needed to reconstruct the path to the root.
    siblings: Vec<[u8; 32]>,
}

impl LeanImtProof {
    /// Creates a new `LeanImtProof` from a leaf, index, and siblings.
    ///
    /// # Arguments
    ///
    /// * `leaf` - The leaf hash for which the proof is generated.
    /// * `index` - The index of the leaf in the tree.
    /// * `siblings` - The sibling hashes needed to reconstruct the path to the root.
    ///
    /// # Returns
    ///
    /// A new `LeanImtProof` instance.
    pub fn from(leaf: [u8; 32], index: usize, siblings: Vec<[u8; 32]>) -> Self {
        Self {
            leaf,
            index,
            siblings,
        }
    }

    /// Verifies a `LeanImtProof` Merkle proof.
    ///
    /// This method checks if the provided proof correctly demonstrates that the
    /// leaf is part of the Merkle tree with the given `root` specified in the proof.
    /// The method **does not** check if the proof is valid for *current* tree, it only
    /// verifies the proof itself as being valid.
    ///
    /// # Arguments
    ///
    /// * `root` - The root of the tree the Merkle proof is being verified against.
    /// * `hash` - The hash function being used to derive the root.
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, `false` otherwise.
    pub fn verify(&self, root: &[u8; 32], hash: fn(&[u8]) -> [u8; 32]) -> bool {
        let mut node: [u8; 32] = self.leaf;

        for (i, &sibling) in self.siblings.iter().enumerate() {
            if (self.index >> i) & 1 == 1 {
                node = hash(&[sibling, node].concat());
            } else {
                node = hash(&[node, sibling].concat());
            }
        }

        node == *root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_random_leaf() -> [u8; 32] {
        (0..32)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap()
    }

    #[test]
    fn test_from() {
        let leaf = get_random_leaf();
        let index = rand::random::<usize>() % (1 << 32);
        let siblings = (0..rand::random::<usize>() % 32)
            .map(|_| get_random_leaf())
            .collect::<Vec<_>>();
        let proof = LeanImtProof::from(leaf, index, siblings.clone());
        assert_eq!(proof.leaf, leaf);
        assert_eq!(proof.index, index);
        assert_eq!(proof.siblings, siblings);
    }
}
