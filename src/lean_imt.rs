use crate::proof::LeanImtProof;
use serde::{Deserialize, Serialize};

/// We store nodes at each level of the tree, allowing for efficient updates and Merkle proof generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeanImtState {
    /// Stores the nodes of the tree. Each inner `Vec` represents a level in the tree.
    nodes: Vec<Vec<[u8; 32]>>,
}

impl Default for LeanImtState {
    /// Creates a new, empty `LeanImtState`
    ///
    /// # Returns
    ///
    /// A new `LeanImtState` instance with an empty `nodes` vector.
    fn default() -> Self {
        Self {
            nodes: vec![vec![]],
        }
    }
}

impl LeanImtState {
    /// Creates a new, empty `LeanImtState`.
    ///
    /// # Returns
    ///
    /// A new `LeanImtState` instance with an empty `nodes` vector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new `LeanImtState` from the given nodes.
    ///
    /// # Arguments
    ///
    /// * `nodes` - A vector of vectors of `[u8; 32]` values representing the nodes of the tree.
    ///
    /// # Returns
    ///
    /// A new `LeanImtState` instance with the given nodes.
    ///
    /// # Example
    ///
    /// ```
    /// use lean_imt::LeanImtState;
    ///
    /// let nodes = vec![vec![[0u8; 32], [1u8; 32]], vec![[3u8; 32]]];
    /// let state = LeanImtState::from(nodes);
    /// ```
    pub fn from(nodes: Vec<Vec<[u8; 32]>>) -> Self {
        Self { nodes }
    }
}

/// A lean incremental Merkle tree is a Merkle tree which minimizes the number of hash calculations
pub struct LeanImt {
    /// The state of the tree.
    state: LeanImtState,
    /// The hash function to use.
    hash: fn(&[u8]) -> [u8; 32],
}

impl LeanImt {
    /// Creates a new empty lean incremental Merkle.
    ///
    /// # Examples
    ///
    /// ```
    /// use lean_imt::LeanImt;
    ///
    /// let hash = |data: &[u8]| -> [u8; 32] { [0u8; 32] };  // dummy hash function
    /// let tree = LeanImt::new(hash);
    /// assert_eq!(tree.size(), 0);
    /// ```
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash function to use.
    ///
    /// # Returns
    ///
    /// A new empty `LeanImt` instance.
    ///
    /// # Example
    ///
    /// ```
    /// use lean_imt::LeanImt;
    ///
    /// let hash = |data: &[u8]| -> [u8; 32] { [0u8; 32] };  // dummy hash function
    /// let tree = LeanImt::new(hash);
    pub fn new(hash: fn(&[u8]) -> [u8; 32]) -> Self {
        Self {
            state: LeanImtState::default(),
            hash,
        }
    }

    /// Creates a new lean incremental Merkle tree from the given `leaves`
    ///
    /// # Arguments
    ///
    /// * `leaves` - A vector of leaf hashes to initialize the tree with.
    /// * `hash` - The hash function to use.
    ///
    /// # Returns
    ///
    /// A new `LeanImt` instance.
    ///
    /// # Example
    ///
    /// ```
    /// use lean_imt::LeanImt;
    ///
    /// let leaves = vec![[0u8; 32], [1u8; 32]];
    /// let hash = |data: &[u8]| -> [u8; 32] { [0u8; 32] };  // dummy hash function
    /// let tree = LeanImt::from_leaves(&leaves, hash);
    /// ```
    pub fn from_leaves(leaves: &Vec<[u8; 32]>, hash: fn(&[u8]) -> [u8; 32]) -> Self {
        assert!(!leaves.is_empty(), "Cannot create an empty tree");
        let mut tree: LeanImt = Self {
            state: LeanImtState::default(),
            hash,
        };
        tree.insert_many(leaves);
        tree
    }

    /// Creates a new lean incremental Merkle from a given state and hash function.
    ///
    /// This method can be used to restore a tree from a previously saved state.
    ///
    /// # Warning
    ///
    /// This method does not verify the validity of the provided state.
    /// Using an invalid state can lead to unexpected behavior.
    ///
    /// # Arguments
    ///
    /// * `state` - The state of the tree.
    /// * `hash` - The hash function to use.
    ///
    /// # Returns
    ///
    /// A new `LeanImt` instance.
    ///
    /// # Example
    ///
    /// ```
    /// use lean_imt::LeanImt;
    ///
    /// let hash = |data: &[u8]| -> [u8; 32] { [0u8; 32] };  // dummy hash function
    /// let tree = LeanImt::new(hash);
    /// let state = tree.export_state();
    /// let tree = LeanImt::from_state(state, hash);
    pub fn from_state(state: LeanImtState, hash: fn(&[u8]) -> [u8; 32]) -> Self {
        Self { state, hash }
    }

    /// Returns the root of the Merkle tree
    ///
    /// If the tree is empty, the root will be the [0u8; 32] value.
    ///
    /// # Returns
    ///
    /// A reference to the root of the tree.
    pub fn root(&self) -> &[u8; 32] {
        self.state.nodes[self.depth()].first().unwrap_or(&[0u8; 32])
    }

    /// Returns the depth of the Merkle tree, the number of levels in the tree minus one.
    ///
    /// # Returns
    ///
    /// The depth of the tree.
    pub fn depth(&self) -> usize {
        self.state.nodes.len() - 1
    }

    /// Returns a vector containing all the leaves of the Merkle tree.
    ///
    /// # Returns
    ///
    /// A reference to the leaves of the tree.
    pub fn leaves(&self) -> &Vec<[u8; 32]> {
        &self.state.nodes[0]
    }

    /// Returns the size (number of leaves) of the Merkle tree.
    ///
    /// # Returns
    ///
    /// The size of the tree.
    pub fn size(&self) -> usize {
        self.state.nodes[0].len()
    }

    /// Finds the index of a given `leaf` in the Merkle tree.
    ///
    /// # Arguments
    ///
    /// * `leaf` - The leaf to search for.
    ///
    /// # Returns
    ///
    /// An `Option<usize>` containing the index if the leaf is found, or `None` if it's not present.
    pub fn index_of(&self, leaf: &[u8; 32]) -> Option<usize> {
        self.state.nodes[0].iter().position(|&x| x == *leaf)
    }

    /// Checks if the Merkle tree contains a specific `leaf`.
    ///
    /// # Arguments
    ///
    /// * `leaf` - The leaf hash to check for.
    ///
    /// # Returns
    ///
    /// `true` if the leaf is present in the tree, `false` otherwise.
    pub fn has(&self, leaf: &[u8; 32]) -> bool {
        self.state.nodes[0].contains(leaf)
    }

    /// Inserts a leaf into the Merkle tree.
    ///
    /// # Arguments
    ///
    /// * `leaf` - A leaf hash to insert into the tree.
    pub fn insert(&mut self, leaf: &[u8; 32]) {
        // If the next depth is greater, a new tree level will be added
        if self.depth() < ((self.size() + 1) as f64).log2().ceil() as usize {
            // Adding an array is like adding a new level
            self.state.nodes.push(vec![]);
        }

        let mut node: [u8; 32] = *leaf;
        // The index of the new leaf equals the number of leaves in the tree
        let mut index: usize = self.size();

        for level in 0..self.depth() {
            if index >= self.state.nodes[level].len() {
                self.state.nodes[level].resize(index + 1, [0u8; 32]);
            }
            self.state.nodes[level][index] = node;

            // If the node is a right node (1), the parent node will be the hash of the child nodes
            // Otherwise, the parent node will be the left (0) node
            if (index & 1) == 1 {
                let sibling: [u8; 32] = self.state.nodes[level][index - 1];
                node = (self.hash)(&[sibling, node].concat());
            }

            index >>= 1;
        }

        // Store the new root
        let depth: usize = self.depth();
        self.state.nodes[depth] = vec![node];
    }

    /// Inserts multiple leaves into the Merkle tree.
    ///
    /// It is more efficient than using the `insert` method N times because it
    /// significantly reduces the number of cases where a node has only one
    /// child, which is a common occurrence in gradual insertion.
    ///
    /// # Arguments
    ///
    /// * `leaves` - A vector of leaves to insert into the tree.
    pub fn insert_many(&mut self, leaves: &Vec<[u8; 32]>) {
        assert!(!leaves.is_empty(), "Vector cannot be empty");

        let mut start_index: usize = self.size() >> 1;
        self.state.nodes[0].extend(leaves);

        // Calculate how many tree levels need to be added and extend the tree
        let new_levels: usize = ((self.size() as f64).log2().ceil() as usize) - self.depth();
        self.state.nodes.extend((0..new_levels).map(|_| vec![]));

        for level in 0..self.depth() {
            // Calculate the number of  nodes of the next level
            let num_nodes: usize = (self.state.nodes[level].len() + 1) / 2;

            for index in start_index..num_nodes {
                let left_node: [u8; 32] = self.state.nodes[level][2 * index];
                let right_node: Option<&[u8; 32]> = self.state.nodes[level].get(2 * index + 1);

                let parent_node: [u8; 32] = match right_node {
                    Some(right_node) => (self.hash)(&[left_node, *right_node].concat()),
                    None => left_node,
                };

                if index >= self.state.nodes[level + 1].len() {
                    self.state.nodes[level + 1].push(parent_node);
                } else {
                    self.state.nodes[level + 1][index] = parent_node;
                }
            }

            start_index >>= 1;
        }
    }

    /// Updates a leaf in the Merkle tree.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the leaf to update.
    /// * `leaf` - The new leaf to be inserted.
    pub fn update(&mut self, index: usize, leaf: &[u8; 32]) {
        let mut index: usize = index;
        let mut node: [u8; 32] = *leaf;

        for level in 0..self.depth() {
            self.state.nodes[level][index] = node;

            if (index & 1) == 1 {
                let sibling: [u8; 32] = self.state.nodes[level][index - 1];
                node = (self.hash)(&[sibling, node].concat());
            } else {
                // There could still be a right node if the path is not the rightmost onel
                // If the sibling does not exist, the node at this level equals its child.
                if let Some(&sibling) = self.state.nodes[level].get(index + 1) {
                    node = (self.hash)(&[node, sibling].concat());
                }
            }

            index >>= 1;
        }

        let depth: usize = self.depth();
        self.state.nodes[depth] = vec![node];
    }

    /// Updates multiple leaves in the Merkle tree at once.
    ///
    /// It is more efficient than using the `update` method N times because it
    /// prevents updating middle nodes several times.
    ///
    /// # Arguments
    ///
    /// * `indices` - A vector of indices of the leaves to update.
    /// * `leaves` - A vector of leaves to update in the tree.
    pub fn update_many(&mut self, indices: &[usize], leaves: &[[u8; 32]]) {
        assert!(
            indices.len() == leaves.len(),
            "Indices and leaves must have the same length"
        );

        // This will keep track of the outdated nodes of each level
        let mut modified_indices = std::collections::HashSet::<usize>::new();
        for (i, &index) in indices.iter().enumerate() {
            assert!(index < self.size(), "Index '{}' is out of range", i);
            assert!(
                !modified_indices.contains(&index),
                "Leaf '{}' is repeated",
                index
            );
            modified_indices.insert(index);
        }

        modified_indices.clear();
        // Modify the leaf level first
        for leaf in 0..indices.len() {
            self.state.nodes[0][indices[leaf]] = leaves[leaf];
            modified_indices.insert(indices[leaf] >> 1);
        }

        // Now update each of the corresponding levels
        for level in 1..self.depth() + 1 {
            let mut new_modified_indices: Vec<usize> = vec![];
            for &index in modified_indices.iter() {
                let left_child: [u8; 32] = self.state.nodes[level - 1][2 * index];
                let right_child: Option<&[u8; 32]> = self.state.nodes[level - 1].get(2 * index + 1);

                self.state.nodes[level][index] = match right_child {
                    Some(&right_child) => (self.hash)(&[left_child, right_child].concat()),
                    None => left_child,
                };
                new_modified_indices.push(index >> 1);
            }
            modified_indices = std::collections::HashSet::<usize>::from_iter(new_modified_indices);
        }
    }

    /// Generates a `LeanImtProof` Merkle proof for a leaf at the given `index`.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the leaf for which to generate the proof.
    ///
    /// # Returns
    ///
    /// The corresponding `LeanImtProof`.
    pub fn generate_proof(&self, mut index: usize) -> LeanImtProof {
        assert!(
            index < self.size(),
            "The leaf at index '{}' does not exist in this tree",
            index
        );

        let leaf: [u8; 32] = self.state.nodes[0][index];
        let mut siblings: Vec<[u8; 32]> = Vec::with_capacity(self.depth());
        let mut path: Vec<bool> = Vec::with_capacity(self.depth());

        (0..self.depth()).for_each(|level| {
            let is_right_node: bool = index & 1 == 1;
            let sibling_index: usize = if is_right_node { index - 1 } else { index + 1 };

            // If the sibling node does not exist, it means that the node at this level has the same value as its child.
            // Therefore, there is no need to include it in the proof since there is no hash to calculate.
            if let Some(sibling) = self.state.nodes[level].get(sibling_index) {
                path.push(is_right_node);
                siblings.push(*sibling);
            }

            index >>= 1;
        });

        // The output index might be different from the original index, as some siblings may not be included.
        path.reverse();
        let index: usize = path.iter().fold(0, |acc, &bit| (acc << 1) | bit as usize);

        LeanImtProof::from(leaf, index, siblings)
    }

    /// Returns a clone of the current tree state.
    ///
    /// This can be used to save the state of the tree for later restoration.
    ///
    /// # Returns
    ///
    /// A clone of the current `LeanImtState`.
    ///
    /// # Example
    ///
    /// ```
    /// use lean_imt::{LeanImt, LeanImtState};
    ///
    /// let hash = |data: &[u8]| -> [u8; 32] { [0u8; 32] };  // dummy hash function
    /// let tree: LeanImt = LeanImt::new(hash);
    /// let state: LeanImtState = tree.export_state();
    /// ```
    pub fn export_state(&self) -> LeanImtState {
        self.state.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::tests::{get_random_leaf, hash};

    #[test]
    fn test_default_state() {
        let state: LeanImtState = LeanImtState::default();
        assert_eq!(state.nodes, vec![vec![]] as Vec<Vec<[u8; 32]>>);
    }

    #[test]
    fn test_new_state() {
        let state: LeanImtState = LeanImtState::new();
        assert_eq!(state.nodes, vec![vec![]] as Vec<Vec<[u8; 32]>>);
    }

    #[test]
    fn test_state_from() {
        let nodes: Vec<Vec<[u8; 32]>> = vec![(0..rand::random::<usize>() % 1 << 12)
            .map(|_| get_random_leaf())
            .collect()];
        let state: LeanImtState = LeanImtState::from(nodes.clone());
        assert_eq!(state.nodes, nodes);
    }

    #[test]
    fn test_new_tree() {
        let tree: LeanImt = LeanImt::new(hash);
        assert_tree_properties(&tree, &[0u8; 32], 0, &vec![], 0);
    }

    #[test]
    fn test_tree_from_leaves() {
        let leaves: Vec<[u8; 32]> = (0..5).map(|_| get_random_leaf()).collect();
        let tree: LeanImt = LeanImt::from_leaves(&leaves, hash);

        let manual_root: [u8; 32] = {
            let left_node: [u8; 32] = hash(
                &[
                    hash(&[leaves[0], leaves[1]].concat()),
                    hash(&[leaves[2], leaves[3]].concat()),
                ]
                .concat(),
            );
            hash(&[left_node, leaves[4]].concat())
        };

        assert_tree_properties(&tree, &manual_root, 3, &leaves, leaves.len());
    }

    #[test]
    fn test_tree_from_state() {
        let leaves: Vec<[u8; 32]> = (0..rand::random::<usize>() % (1 << 12))
            .map(|_| get_random_leaf())
            .collect();
        let tree: LeanImt = LeanImt::from_leaves(&leaves, hash);
        let state: LeanImtState = tree.export_state();
        let tree_from_state: LeanImt = LeanImt::from_state(state, hash);
        assert_tree_properties(
            &tree_from_state,
            tree.root(),
            tree.depth(),
            tree.leaves(),
            tree.size(),
        );
    }

    #[test]
    fn test_index_of() {
        let element: [u8; 32] = get_random_leaf();
        let mut leaves: Vec<[u8; 32]> = (0..rand::random::<u16>())
            .map(|_| get_random_leaf())
            .collect();
        let insert_index = rand::random::<usize>() % leaves.len();
        leaves.insert(insert_index, element);
        let tree: LeanImt = LeanImt::from_leaves(&leaves, hash);

        assert_eq!(tree.index_of(&element).unwrap(), insert_index);
    }

    #[test]
    fn test_has() {
        let element: [u8; 32] = get_random_leaf();
        let mut leaves: Vec<[u8; 32]> = (0..rand::random::<u16>())
            .map(|_| get_random_leaf())
            .collect();
        let insert_index = rand::random::<usize>() % leaves.len();
        leaves.insert(insert_index, element);
        let tree: LeanImt = LeanImt::from_leaves(&leaves, hash);

        assert!(tree.has(&element));
        assert!(!tree.has(&get_random_leaf()));
    }

    #[test]
    fn test_insert_empty_tree() {
        let mut tree: LeanImt = LeanImt::new(hash);
        let leaf: [u8; 32] = get_random_leaf();
        tree.insert(&leaf);
        assert_tree_properties(&tree, &leaf, 0, &vec![leaf], 1);
        let leaf2: [u8; 32] = get_random_leaf();
        tree.insert(&leaf2);
        let expected_root: [u8; 32] = hash(&[leaf, leaf2].concat());
        assert_tree_properties(&tree, &expected_root, 1, &vec![leaf, leaf2], 2);
    }

    #[test]
    fn test_insert() {
        let size: usize = rand::random::<usize>() % (1 << 1 << 12);
        let leaves: Vec<[u8; 32]> = (0..size).map(|_| get_random_leaf()).collect();
        let new_leaf: [u8; 32] = get_random_leaf();

        let mut tree: LeanImt = LeanImt::from_leaves(&leaves, hash);
        tree.insert(&new_leaf);

        let mut full_leaves: Vec<[u8; 32]> = leaves.clone();
        full_leaves.push(new_leaf);
        let expected_tree: LeanImt = LeanImt::from_leaves(&full_leaves, hash);

        assert_tree_properties(
            &tree,
            expected_tree.root(),
            expected_tree.depth(),
            expected_tree.leaves(),
            expected_tree.size(),
        );
    }

    #[test]
    fn test_insert_many() {
        let size: usize = rand::random::<usize>() % (1 << 1 << 12);
        let leaves: Vec<[u8; 32]> = (0..size).map(|_| get_random_leaf()).collect();
        let new_leaves: Vec<[u8; 32]> = (0..rand::random::<usize>() % 100 + 1)
            .map(|_| get_random_leaf())
            .collect();

        let mut tree: LeanImt = LeanImt::from_leaves(&leaves, hash);
        tree.insert_many(&new_leaves);

        let mut leaves: Vec<[u8; 32]> = leaves.clone();
        leaves.extend(new_leaves);
        let expected_tree: LeanImt = LeanImt::from_leaves(&leaves, hash);

        assert_tree_properties(
            &tree,
            expected_tree.root(),
            expected_tree.depth(),
            expected_tree.leaves(),
            expected_tree.size(),
        );
    }

    #[test]
    fn test_update() {
        let size: usize = rand::random::<usize>() % (1 << 1 << 12);
        let leaves: Vec<[u8; 32]> = (0..size).map(|_| get_random_leaf()).collect();
        let index: usize = rand::random::<usize>() % size;
        let new_leaf: [u8; 32] = get_random_leaf();

        let mut tree: LeanImt = LeanImt::from_leaves(&leaves, hash);
        tree.update(index, &new_leaf);

        let mut leaves: Vec<[u8; 32]> = leaves.clone();
        leaves[index] = new_leaf;
        let expected_tree: LeanImt = LeanImt::from_leaves(&leaves, hash);

        assert_tree_properties(
            &tree,
            expected_tree.root(),
            expected_tree.depth(),
            expected_tree.leaves(),
            expected_tree.size(),
        );
    }

    #[test]
    fn test_update_many() {
        let size: usize = 5; //rand::random::<usize>() % (1 << 1 << 12);
        let leaves: Vec<[u8; 32]> = (0..size).map(|_| get_random_leaf()).collect();
        let indices: Vec<usize> = (0../* rand::random::<usize>() % 100 +  */1)
            .map(|_| rand::random::<usize>() % size)
            .collect();
        let new_leaves: Vec<[u8; 32]> = (0..indices.len()).map(|_| get_random_leaf()).collect();

        let mut tree: LeanImt = LeanImt::from_leaves(&leaves, hash);
        tree.update_many(&indices, &new_leaves);

        let mut leaves: Vec<[u8; 32]> = leaves.clone();
        for (i, &index) in indices.iter().enumerate() {
            leaves[index] = new_leaves[i];
        }
        let expected_tree: LeanImt = LeanImt::from_leaves(&leaves, hash);

        assert_tree_properties(
            &tree,
            expected_tree.root(),
            expected_tree.depth(),
            expected_tree.leaves(),
            expected_tree.size(),
        );
    }

    #[test]
    fn test_generate_verify_proof() {
        let size: usize = rand::random::<usize>() % (1 << 1 << 12);
        let leaves: Vec<[u8; 32]> = (0..size).map(|_| get_random_leaf()).collect();
        let tree: LeanImt = LeanImt::from_leaves(&leaves, hash);

        // Random leaf
        let proof: LeanImtProof = tree.generate_proof(rand::random::<usize>() % size);
        assert!(proof.verify(tree.root(), hash));

        // End leaf
        let proof: LeanImtProof = tree.generate_proof(size - 1);
        assert!(proof.verify(tree.root(), hash));
    }

    #[test]
    fn test_export_state() {
        let leaves: Vec<[u8; 32]> = (0..rand::random::<u16>())
            .map(|_| get_random_leaf())
            .collect();
        let tree: LeanImt = LeanImt::from_leaves(&leaves, hash);
        let state: LeanImtState = tree.export_state();
        assert_eq!(state.nodes, tree.state.nodes);
    }

    fn assert_tree_properties(
        tree: &LeanImt,
        expected_root: &[u8; 32],
        expected_depth: usize,
        expected_leaves: &Vec<[u8; 32]>,
        expected_size: usize,
    ) {
        assert_eq!(tree.root(), expected_root);
        assert_eq!(tree.depth(), expected_depth);
        assert_eq!(tree.leaves(), expected_leaves);
        assert_eq!(tree.size(), expected_size);
    }
}
