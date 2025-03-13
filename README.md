# LeanIMT

A [lean incremental Merkle tree](https://hackmd.io/@vplasencia/S1whLBN16) is a Merkle tree designed to be updated efficiently by minimizing the number of hash calculations. Such construction is useful both for onchain applications and zkVMs, where hash functions can be quite expensive to prove.

This library contains a binary lean incremental Merkle tree implementation in Rust, based on [Semaphore's implementation](https://github.com/privacy-scaling-explorations/zk-kit/blob/main/packages/lean-imt/src/lean-imt.ts). The library is designed to be used both inside and outside zkVM programs.
