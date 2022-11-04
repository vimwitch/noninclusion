pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "./sparseMerkleTree.circom";

template ProofOfPayment(TREE_DEPTH, PAYMENT_NULLIFIER_CONST) {
  signal input rid;
  signal input payId;
  signal input payCycle;
  signal input merkleProof[TREE_DEPTH];
  signal input idNullifier;
  signal input idTrapdoor;
  signal input leafIndex;

  signal output paymentRoot;
  signal output semaphoreIdentity;
  signal output paymentLeafNullifier;

  // Generate semaphore identity
  component pubKeyHasher = Poseidon(1);
  component secretHasher = Poseidon(2);

  secretHasher.inputs[0] <== idNullifier;
  secretHasher.inputs[1] <== idTrapdoor;

  pubKeyHasher.inputs[0] <== secretHasher.out;

  semaphoreIdentity <== pubKeyHasher.out;

  // Generate payment leaf nullifier
  component paymentHasher = Poseidon(4);

  paymentHasher.inputs[0] <== rid;
  paymentHasher.inputs[1] <== payId;
  paymentHasher.inputs[2] <== payCycle;
  paymentHasher.inputs[3] <== PAYMENT_NULLIFIER_CONST;

  paymentLeafNullifier <== paymentHasher.out;

  // Generate payment root
  component smt_proof = SMTInclusionProof(TREE_DEPTH);

  component paymentLeafHasher = Poseidon(3);

  paymentLeafHasher.inputs[0] <== rid;
  paymentLeafHasher.inputs[1] <== payId;
  paymentLeafHasher.inputs[2] <== payCycle;

  smt_proof.leaf <== paymentLeafHasher.out;
  smt_proof.leaf_index <== leafIndex;
  for (var x = 0; x < TREE_DEPTH; x++) {
    smt_proof.path_elements[x] <== merkleProof[x];
  }
  paymentRoot <== smt_proof.root;
}

