use serde::{Deserialize, Serialize};

/// The state representing an append-only lean incremental Merkle tree.
///
/// We only store the siblings needed to reconstruct the path to the root and append new leaves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppendOnlyLeanImtState {
    /// The number of leaves in the tree
    size: usize,
    /// The siblings needed to reconstruct the path to the root and append new leaves
    siblings: Vec<[u8; 32]>,
}

impl Default for AppendOnlyLeanImtState {
    /// Creates a new, empty `AppendOnlyLeanImtState`.
    ///
    /// # Returns
    ///
    /// A new `AppendOnlyLeanImtState` instance with a size of 0 and an empty siblings vector.
    fn default() -> Self {
        Self {
            size: 0,
            siblings: vec![],
        }
    }
}

impl AppendOnlyLeanImtState {
    /// Creates a new, empty `AppendOnlyLeanImtState`.
    ///
    /// # Returns
    ///
    /// A new `AppendOnlyLeanImtState` instance with a size of 0 and an empty siblings vector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new `AppendOnlyLeanImtState` from a given size and siblings.
    ///
    /// # Arguments
    ///
    /// * `size` - The number of leaves in the tree.
    /// * `siblings` - The siblings needed to reconstruct the path to the root and append new leaves.
    ///
    /// # Returns
    ///
    /// A new `AppendOnlyLeanImtState` instance with the given size and siblings.
    ///
    /// # Example
    ///
    /// ```
    /// use lean_imt::AppendOnlyLeanImtState;
    ///
    /// let state = AppendOnlyLeanImtState::from(10, vec![[0u8; 32], [1u8; 32]]);
    /// ```
    pub fn from(size: usize, siblings: Vec<[u8; 32]>) -> Self {
        Self { size, siblings }
    }
}

/// A lean incremental Merkle tree is an append-only merkle which minimizes the number of hash calculations
pub struct AppendOnlyLeanImt {
    /// The state of the tree.
    state: AppendOnlyLeanImtState,
    /// The hash function to use.
    hash: fn(&[u8]) -> [u8; 32],
}

impl AppendOnlyLeanImt {
    /// Creates a new empty lean incremental Merkle.
    ///
    /// # Examples
    ///
    /// ```
    /// use lean_imt::AppendOnlyLeanImt;
    ///
    /// let hash = |data: &[u8]| -> [u8; 32] { [0u8; 32] };  // dummy hash function
    /// let tree = AppendOnlyLeanImt::new(hash);
    /// assert_eq!(tree.size(), 0);
    /// ```
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash function to use.
    ///
    /// # Returns
    ///
    /// A new empty `AppendOnlyLeanImt` instance.
    pub fn new(hash: fn(&[u8]) -> [u8; 32]) -> Self {
        Self {
            state: AppendOnlyLeanImtState::default(),
            hash,
        }
    }

    /// Creates a new lean incremental Merkle from a given state and hash function.
    ///
    /// # Arguments
    ///
    /// * `state` - The state of the tree.
    /// * `hash` - The hash function to use.
    ///
    /// # Returns
    ///
    /// A new `AppendOnlyLeanImt` instance.
    pub fn from(state: AppendOnlyLeanImtState, hash: fn(&[u8]) -> [u8; 32]) -> Self {
        Self { state, hash }
    }

    /// Returns the root of the Merkle tree
    ///
    /// If the tree is empty, the root will be the [0u8; 32] value.
    ///
    /// # Returns
    ///
    /// The root of the tree.
    pub fn root(&self) -> [u8; 32] {
        self.state.siblings.first().map_or([0u8; 32], |&first| {
            self.state
                .siblings
                .iter()
                .skip(1)
                .fold(first, |root, &sibling| {
                    (self.hash)(&[sibling, root].concat())
                })
        })
    }

    /// Returns the size (number of leaves) of the Merkle tree.
    ///
    /// # Returns
    ///
    /// The size of the tree.
    pub fn size(&self) -> usize {
        self.state.size
    }

    /// Inserts a leaf into the Merkle tree.
    ///
    /// # Arguments
    ///
    /// * `leaf` - A leaf hash to insert into the tree.
    pub fn insert(&mut self, leaf: &[u8; 32]) {
        let mut old_siblings = self.state.siblings.clone().into_iter();
        self.state.siblings.clear();
        let mut root: [u8; 32] = *leaf;

        let mut old_size: usize = self.size();
        let mut new_size: usize = old_size + 1;
        let new_levels: usize = (new_size as f64).log2().ceil() as usize + 1;

        (0..new_levels).for_each(|_| {
            if old_size & 1 == 1 {
                let sibling: [u8; 32] = old_siblings.next().unwrap();
                // Keep the existing sibling for future insertions if the new size is also odd
                if new_size & 1 == 1 {
                    self.state.siblings.push(sibling);
                }
                root = (self.hash)(&[sibling, root].concat());
            } else if new_size & 1 == 1 {
                self.state.siblings.push(root);
            }

            old_size >>= 1;
            new_size >>= 1;
        });

        self.state.size += 1;
    }

    /// Exports the state of the tree.
    ///
    /// # Returns
    ///
    /// The state of the tree.
    pub fn export_state(&self) -> AppendOnlyLeanImtState {
        self.state.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lean_imt::LeanImt;
    use crate::proof::tests::{get_random_leaf, hash};

    #[test]
    fn test_default_state() {
        let state: AppendOnlyLeanImtState = AppendOnlyLeanImtState::default();
        assert_eq!(state.size, 0);
        assert_eq!(state.siblings, Vec::<[u8; 32]>::new());
    }

    #[test]
    fn test_new_state() {
        let state: AppendOnlyLeanImtState = AppendOnlyLeanImtState::new();
        assert_eq!(state.size, 0);
        assert_eq!(state.siblings, Vec::<[u8; 32]>::new());
    }

    #[test]
    fn test_state_from() {
        let siblings: Vec<[u8; 32]> = (0..32).map(|_| get_random_leaf()).collect();
        let size: usize = rand::random::<usize>() % (1 << 32);
        let state: AppendOnlyLeanImtState = AppendOnlyLeanImtState::from(size, siblings.clone());
        assert_eq!(state.size, size);
        assert_eq!(state.siblings, siblings);
    }

    #[test]
    fn test_new_tree() {
        let tree: AppendOnlyLeanImt = AppendOnlyLeanImt::new(hash);
        assert_tree_properties(&tree, [0; 32], 0);
    }

    #[test]
    fn test_tree_from() {
        let size: usize = rand::random::<usize>() % (1 << 32);
        let siblings: Vec<[u8; 32]> = (0..32).map(|_| get_random_leaf()).collect();
        let state: AppendOnlyLeanImtState = AppendOnlyLeanImtState::from(size, siblings.clone());
        let tree: AppendOnlyLeanImt = AppendOnlyLeanImt::from(state, hash);
        let expected_root: [u8; 32] =
            siblings.iter().skip(1).fold(siblings[0], |root, &sibling| {
                (hash)(&[sibling, root].concat())
            });
        assert_tree_properties(&tree, expected_root, size);
    }

    #[test]
    fn test_insert() {
        let size: usize = rand::random::<u16>() as usize;
        let leaves: Vec<[u8; 32]> = (0..size).map(|_| get_random_leaf()).collect();
        let mut lean_imt: LeanImt = LeanImt::from_leaves(&leaves, hash);

        let state: AppendOnlyLeanImtState = AppendOnlyLeanImtState::from(size, lean_imt.siblings());
        let mut append_only_imt: AppendOnlyLeanImt = AppendOnlyLeanImt::from(state, hash);

        let new_leaf: [u8; 32] = get_random_leaf();
        lean_imt.insert(&new_leaf);
        append_only_imt.insert(&new_leaf);

        assert_tree_properties(&append_only_imt, *lean_imt.root(), lean_imt.size());
    }

    #[test]
    fn test_export_state() {
        let size: usize = rand::random::<usize>() % (1 << 32);
        let siblings: Vec<[u8; 32]> = (0..32).map(|_| get_random_leaf()).collect();
        let state: AppendOnlyLeanImtState = AppendOnlyLeanImtState::from(size, siblings.clone());
        let tree: AppendOnlyLeanImt = AppendOnlyLeanImt::from(state, hash);
        let tree_from_state: AppendOnlyLeanImt = AppendOnlyLeanImt::from(tree.export_state(), hash);
        assert_tree_properties(&tree_from_state, tree.root(), tree.size());
    }

    fn assert_tree_properties(
        tree: &AppendOnlyLeanImt,
        expected_root: [u8; 32],
        expected_size: usize,
    ) {
        assert_eq!(tree.root(), expected_root);
        assert_eq!(tree.size(), expected_size);
    }
}
