use lib::{
    freivalds_gblur::freivalds_prover, freivalds_gblur::freivalds_verifier,
    freivalds_gblur::u64_to_u8_vec, load_image_from_file, BlurContext
};
use sp1_sdk::{utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey, SP1Proof,HashableKey};
use sp1_sdk::include_elf;

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("fibonacci-program");
const AGGREGATION_ELF: &[u8] = include_elf!("aggregation-program");

struct AggregationInput {
    pub proof: SP1ProofWithPublicValues,
    pub vk: SP1VerifyingKey,
}

const _FRAME_NUM: usize = 10;
const DEBUGGING: bool = false;


fn main() {
    // Setup logging.
    utils::setup_logger();

    //fake example
    let config_file = std::fs::File::open("config.json").expect("Failed to open config file");
    let config: serde_json::Value = serde_json::from_reader(config_file).expect("Failed to parse JSON");
    
    let INPUT_WIDTH= config["input_width"].as_i64().expect("Missing input_width") as i32;
    let INPUT_HEIGHT = config["input_height"].as_i64().expect("Missing input_height") as i32;
    // let OUTPUT_WIDTH = config["output_width"].as_i64().expect("Missing output_width") as i32;
    // let OUTPUT_HEIGHT = config["output_height"].as_i64().expect("Missing output_height") as i32;
    let input_file = config["input_file"].as_str().expect("Missing input_file");
    let target_file = config["target_file"].as_str().expect("Missing target_file");
    let target_prove_file = config["target_prove_file"].as_str().expect("Missing target_prove_file");
    let target_pk_file = config["target_pk_file"].as_str().expect("Missing target_pk_file");


    let image: Vec<u8> = load_image_from_file(input_file);
    let target_image: Vec<u8> = load_image_from_file(target_file);

    use std::time::Instant;
    let start = Instant::now();
    let (
        freivalds_randomness_left,
        freivalds_randomness_right,
        r_left_t_b,
        b_r_right,
        channel_blurred,
    ) = freivalds_prover(10, 30, INPUT_WIDTH as usize, INPUT_HEIGHT as usize, &image);
    let duration = start.elapsed();
    println!("Time elapsed: {:?}", duration);

    let mut stdin = SP1Stdin::new();
    // stdin.write(&context);
    stdin.write_vec(image);
    stdin.write_vec(target_image);
    stdin.write_vec(u64_to_u8_vec(freivalds_randomness_left));
    stdin.write_vec(u64_to_u8_vec(freivalds_randomness_right));
    stdin.write_vec(u64_to_u8_vec(r_left_t_b));
    stdin.write_vec(u64_to_u8_vec(b_r_right));
    stdin.write_vec(u64_to_u8_vec(channel_blurred));
    stdin.write(&(INPUT_HEIGHT as usize));
    stdin.write(&(INPUT_WIDTH as usize));

    // Create a `ProverClient` method.
    let client = ProverClient::from_env();
    if DEBUGGING == false {
        let pk = serde_cbor::from_slice(&std::fs::read(target_pk_file).expect("reading pk failed")).expect("deserializing pk failed");
        let mut proof = client.prove(&pk, &stdin).compressed().run().expect("proving failed");

        proof
            .save(target_prove_file)
            .expect("saving proof failed");
        

        // let hash_target_image = proof.public_values.read::<blake3::Hash>();
        // println!("hash_target_image: {:?}", hash_target_image);
        println!("successfully generated proof for the program!");

    } else {
        let (pk, vk) = client.setup(ELF);
        let (aggregation_pk, aggregation_vk) = client.setup(AGGREGATION_ELF);
        let proof = tracing::info_span!("generate Proof").in_scope(|| {
            client.prove(&pk, &stdin).compressed().run().expect("proving failed")
        });
        println!("generated proof");

        let input_1 =  AggregationInput { proof: proof.clone(), vk: vk.clone() };
        let inputs = vec![input_1];

        tracing::info_span!("aggregate the proofs").in_scope(|| {
            println!("Aggregate the Proofs");
            let mut full_stdin = SP1Stdin::new();
    
            // Write the verification keys.
            let vkeys = inputs.iter().map(|input| input.vk.hash_u32()).collect::<Vec<_>>();
            full_stdin.write::<Vec<[u32; 8]>>(&vkeys);
    
            // Write the public values.
            let public_values =
                inputs.iter().map(|input| input.proof.public_values.to_vec()).collect::<Vec<_>>();
            full_stdin.write::<Vec<Vec<u8>>>(&public_values);
    
            // Write the proofs.
            //
            // Note: this data will not actually be read by the aggregation program, instead it will be
            // witnessed by the prover during the recursive aggregation process inside SP1 itself.
            for input in inputs {
                let SP1Proof::Compressed(proof) = input.proof.proof else { panic!() };
                full_stdin.write_proof(*proof, input.vk.vk);
            }
    
            // Generate the plonk bn254 proof.
            let proof_final = client.prove(&aggregation_pk, &full_stdin).plonk().run().expect("proving failed");
            proof_final
            .save(target_prove_file)
            .expect("saving proof failed");
        });
    }

    // // Create a `ProverClient` method.
    // let client = ProverClient::new();

    // // Execute the program using the `ProverClient.execute` method, without generating a proof.
    // // let (_, report) = client.execute(ELF, stdin.clone()).run().unwrap();
    // // println!(
    // //     "executed program with {} cycles",
    // //     report.total_instruction_count()
    // // );

    // // Generate the proof for the given program and input.
    // let (pk, vk) = client.setup(ELF);
    // let mut proof = client.prove(&pk, stdin).run().unwrap();

    // //client
    // // .prove(&resizing_pk, stdin)
    // // .compressed()
    // // .run()
    // // .expect("proving failed")
    // println!("generated proof");


    // let within_limit: bool = proof.public_values.read::<bool>();

    // assert!(within_limit, "within_limit = {}", within_limit);
    // // Verify proof and public values
    // client.verify(&proof, &vk).expect("verification failed");

    // // Test a round trip of proof serialization and deserialization.
    // proof
    //     .save("proof-with-pis.bin")
    //     .expect("saving proof failed");
    // let deserialized_proof =
    //     SP1ProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    // // Verify the deserialized proof.
    // client
    //     .verify(&deserialized_proof, &vk)
    //     .expect("verification failed");

    // println!("successfully generated and verified proof for the program!")
}


