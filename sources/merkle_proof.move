// SPDX-License-Identifier: MIT

/// ZKP verification for merkle proof.
module zkp_verifier::merkle_proof {
    use std::vector;

    use sui::transfer;
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::groth16::{Self, PreparedVerifyingKey};

    /// Error for invalid proof.
    const EInvalidProof: u64 = 0;

    /// OwnerCap is the capacity to operate on the globle resources.
    struct OwnerCap has key, store {
        id: UID
    }

    /// MerkleRoot represents the serialized merkle root.
    struct MerkleRoot has key {
        id: UID,
        /// The value of the merkle root
        value: vector<u8>
    }

    /// VerifyingKey represents the verifying key.
    struct VerifyingKey has key {
        id: UID,
        /// The underlying verifying key
        value: PreparedVerifyingKey
    }
    
    // Construct a new MerkleRoot instance.
    fun new_merkle_root(ctx: &mut TxContext): MerkleRoot {
        MerkleRoot {
            id: object::new(ctx),
            value: vector::empty()
        }
    }

    // Construct a new VerifyingKey instance.
    fun new_verifying_key(ctx: &mut TxContext): VerifyingKey {
        let empty_bytes = vector::empty();

        VerifyingKey {
            id: object::new(ctx),
            value: groth16::pvk_from_bytes(empty_bytes, empty_bytes, empty_bytes, empty_bytes)
        }
    }

    /// Initializer.
    fun init(ctx: &mut TxContext) {
        transfer::transfer(OwnerCap { id: object::new(ctx) }, tx_context::sender(ctx));
        transfer::share_object(new_merkle_root(ctx));
        transfer::share_object(new_verifying_key(ctx))
    }

    /// Set the merkle root.
    public entry fun set_merkle_root(
        _: &OwnerCap,
        root: &mut MerkleRoot,
        new_root: vector<u8>,
        _ctx: &mut TxContext
    ) {
        root.value = new_root
    }

    /// Set the verifying key.
    public entry fun set_verifying_key(
        _: &OwnerCap,
        vk: &mut VerifyingKey,
        new_vk: vector<u8>,
        _ctx: &mut TxContext
    ) {
        vk.value = groth16::prepare_verifying_key(&groth16::bls12381(), &new_vk)
    }

    /// Verify the given zk proof against the verifying key.
    public entry fun verify(
        proof: vector<u8>,
        root: &MerkleRoot,
        vk: &VerifyingKey,
        _ctx: &mut TxContext
    ) {
        let public_inputs = groth16::public_proof_inputs_from_bytes(root.value);
        let proof_points = groth16::proof_points_from_bytes(proof);

        assert!(groth16::verify_groth16_proof(&groth16::bls12381(), &vk.value, &public_inputs, &proof_points), EInvalidProof)
    }
}
