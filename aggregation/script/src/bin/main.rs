use sp1_sdk::{
    HashableKey, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
};

use lib::{load_image_from_file, Context};

/// ELF that aggregates the proofs
const AGGREGATION_ELF: &[u8] = include_bytes!("../../../program/elf/riscv32im-succinct-zkvm-elf");

/// ELF that resizs images
const RESIZING_ELF: &[u8] =
    include_bytes!("../../../../video-resizing/elf/riscv32im-succinct-zkvm-elf");

const INPUT_WIDTH: i32 = 192;
const INPUT_HEIGHT: i32 = 108;
const OUTPUT_WIDTH: i32 = 48;
const OUTPUT_HEIGHT: i32 = 27;

/// An input to the aggregation program.
///
/// Consists of a proof and a verification key.
struct AggregationInput {
    pub proof: SP1ProofWithPublicValues,
    pub vk: SP1VerifyingKey,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Initialize the proving client.
    let client = ProverClient::new();

    // Setup the proving and verifying keys.
    let (aggregation_pk, aggregation_vk) = client.setup(AGGREGATION_ELF);
    let (resizing_pk, resizing_vk) = client.setup(RESIZING_ELF);

    let input_file = "../../resources/fake_original_image.txt";
    let target_file = "../../resources/fake_target_image.txt";
    let context = Context::new(INPUT_WIDTH, INPUT_HEIGHT, OUTPUT_WIDTH, OUTPUT_HEIGHT).unwrap();
    let image: Vec<u8> = load_image_from_file(input_file);
    let target_image: Vec<u8> = load_image_from_file(target_file);

    // TODO(jianfeng): Nested for loop to deal with series of imges and their RGB channel data
    let proof_1 = tracing::info_span!("generate proof for the R").in_scope(|| {
        let mut stdin = SP1Stdin::new();
        stdin.write(&context);
        stdin.write(&image);
        stdin.write(&target_image);
        client
            .prove(&resizing_pk, stdin)
            .compressed()
            .run()
            .expect("proving failed")
    });

    print!("proof_1 generated");
    
    let proof_2 = tracing::info_span!("generate proof for the G").in_scope(|| {
        let mut stdin = SP1Stdin::new();
        stdin.write(&context);
        stdin.write(&image);
        stdin.write(&target_image);
        client
            .prove(&resizing_pk, stdin)
            .compressed()
            .run()
            .expect("proving failed")
    });
    print!("proof_2 generated");

    let proof_3 = tracing::info_span!("generate proof for the B").in_scope(|| {
        let mut stdin = SP1Stdin::new();
        stdin.write(&context);
        stdin.write(&image);
        stdin.write(&target_image);
        client
            .prove(&resizing_pk, stdin)
            .compressed()
            .run()
            .expect("proving failed")
    });
    print!("proof_3 generated");

    // Setup the inputs to the aggregation program.
    let input_1 = AggregationInput {
        proof: proof_1,
        vk: resizing_vk.clone(),
    };
    let input_2 = AggregationInput {
        proof: proof_2,
        vk: resizing_vk.clone(),
    };
    let input_3 = AggregationInput {
        proof: proof_3,
        vk: resizing_vk.clone(),
    };
    let inputs = vec![input_1, input_2, input_3];

    // Aggregate the proofs.
    print!("proof aggregation started");
    tracing::info_span!("aggregate the proofs").in_scope(|| {
        let mut stdin = SP1Stdin::new();

        // Write the verification keys.
        let vkeys = inputs
            .iter()
            .map(|input| input.vk.hash_u32())
            .collect::<Vec<_>>();
        stdin.write::<Vec<[u32; 8]>>(&vkeys);

        // Write the public values.
        let public_values = inputs
            .iter()
            .map(|input| input.proof.public_values.to_vec())
            .collect::<Vec<_>>();
        stdin.write::<Vec<Vec<u8>>>(&public_values);

        // Write the proofs.
        //
        // Note: this data will not actually be read by the aggregation program, instead it will be
        // witnessed by the prover during the recursive aggregation process inside SP1 itself.
        for input in inputs {
            let SP1Proof::Compressed(proof) = input.proof.proof else {
                panic!()
            };
            stdin.write_proof(proof, input.vk.vk);
        }

        // Generate the plonk bn254 proof.
        client
            .prove(&aggregation_pk, stdin)
            .plonk()
            .run()
            .expect("proving failed");
    });
    print!("proof aggregation finished");
}
