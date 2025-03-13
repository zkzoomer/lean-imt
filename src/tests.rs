#[cfg(test)]
mod test {
    use crate::*;
    use sha2::{Digest, Sha256};

    fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    #[test]
    #[cfg(not(feature = "append-only"))]
    fn test_initializes_empty_tree() {
        let tree: LeanImt = LeanImt::new(hash);
        assert_eq!(tree.root(), [0; 32]);
        assert_eq!(tree.depth(), 0);
        assert_eq!(tree.leaves(), &Vec::<[u8; 32]>::new());
        assert_eq!(tree.size(), 0);
    }

    #[test]
    #[cfg(feature = "append-only")]
    fn test_initializes_empty_tree() {
        let tree: LeanImt = LeanImt::new(hash);
        assert_eq!(tree.root(), [0; 32]);
        assert_eq!(tree.size(), 0);
    }
}
