include "../node_modules/circomlib/circuits/poseidon.circom";
include "./sparseMerkleTree.circom";

template ProveNotBlacklisted(TREE_DEPTH) {
  signal private input IMEI;
  signal private input path_elements[TREE_DEPTH];
  signal output root;

  component hasher = Poseidon(1);
  hasher.inputs[0] <== IMEI;

  component smt_proof = SMTInclusionProof(TREE_DEPTH);
  // prove that the leaf is empty, e.g. not blacklisted
  smt_proof.leaf <== 0;
  // leaf index is hash of the secret value
  smt_proof.leaf_index <== hasher.out;
  for (var x = 0; x < TREE_DEPTH; x++) {
    smt_proof.path_elements[x] <== path_elements[x];
  }
  root <== smt_proof.root;
}
