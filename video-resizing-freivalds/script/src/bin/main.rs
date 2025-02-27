use lib::{load_image_from_file};
use sp1_sdk::{utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey, SP1Proof};
use sp1_sdk::include_elf;
use rand::Rng;
use blake3::{hash};
use sp1_sdk::HashableKey;

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("fibonacci-program");
const AGGREGATION_ELF: &[u8] = include_elf!("aggregation-program");

struct AggregationInput {
    pub proof: SP1ProofWithPublicValues,
    pub vk: SP1VerifyingKey,
}


// const _FRAME_NUM: usize = 10;
// const INPUT_WIDTH: i32 = 240;
// const INPUT_HEIGHT: i32 = 320;
// const OUTPUT_WIDTH: i32 = 120; // Hardcoded value, will be overridden by config
// const OUTPUT_HEIGHT: i32 = 160;
const DEBUGGING: bool = false;

fn main() {
    // Setup logging.
    utils::setup_logger();
    let config_file = std::fs::File::open("config.json").expect("Failed to open config file");
    let config: serde_json::Value = serde_json::from_reader(config_file).expect("Failed to parse JSON");
    
    let INPUT_WIDTH= config["input_width"].as_i64().expect("Missing input_width") as i32;
    let INPUT_HEIGHT = config["input_height"].as_i64().expect("Missing input_height") as i32;
    let OUTPUT_WIDTH = config["output_width"].as_i64().expect("Missing output_width") as i32;
    let OUTPUT_HEIGHT = config["output_height"].as_i64().expect("Missing output_height") as i32;
    let input_file = config["input_file"].as_str().expect("Missing input_file");
    let target_file = config["target_file"].as_str().expect("Missing target_file");
    let target_prove_file = config["target_prove_file"].as_str().expect("Missing target_prove_file");
    let target_pk_file = config["target_pk_file"].as_str().expect("Missing target_pk_file");

    // Reading the input image and target image
    let image: Vec<u8> = load_image_from_file(input_file);
    let target_image: Vec<u8> = load_image_from_file(target_file);

    // Build the full matrices
    let h_matrix = lib::build_vertical_matrix(INPUT_HEIGHT, OUTPUT_HEIGHT);
    let w_matrix = lib::build_horizontal_matrix(INPUT_WIDTH, OUTPUT_WIDTH);
    
    /*Debugging*/
    /*
    let mut file = std::fs::File::create("h_matrix.txt").expect("Failed to create file");
    for row in &h_matrix {
        for &value in row {
            writeln!(file, "{}", value).expect("Failed to write to file");
        }
    }
    
    let mut file = std::fs::File::create("w_matrix.txt").expect("Failed to create file");
    for row in &w_matrix {
        for &value in row {
            writeln!(file, "{}", value).expect("Failed to write to file");
        }
    }
    */

    // Calculate the middle image: H @ R @ W
    let mut target_middle_image: Vec<u32> = vec![0; target_image.len()];
    let mut temp = vec![0u32; INPUT_HEIGHT as usize * OUTPUT_WIDTH as usize];
    for i in 0..INPUT_HEIGHT as usize {
        for j in 0..OUTPUT_WIDTH as usize {
            let mut sum = 0u32;
            for k in 0..INPUT_WIDTH as usize {
                // println!("{} {} {}", i * INPUT_WIDTH as usize + k, k, j);
                sum = sum + image[i * INPUT_WIDTH as usize + k] as u32 * w_matrix[k][j] as u32;
            }
            temp[i * OUTPUT_WIDTH as usize + j] = sum;
        }
    }

    for i in 0..OUTPUT_HEIGHT as usize {
        for j in 0..OUTPUT_WIDTH as usize {
            let mut sum = 0u32;
            for k in 0..INPUT_HEIGHT as usize {
                sum = sum + temp[k * OUTPUT_WIDTH as usize + j] as u32 * h_matrix[i][k] as u32;
            }
            target_middle_image[i * OUTPUT_WIDTH as usize + j] = sum;
        }
    }

    /*for debugging*/
    /*
    let mut file = std::fs::File::create("df.txt").expect("Failed to create file");
    for i in 0..target_middle_image.len() {
        let middle_val = target_middle_image[i]/(1<<22) as u32;
        let target_val = target_image[i].clone() as u32;
        let difference = if middle_val > target_val {
            middle_val - target_val 
        } else {
            target_val - middle_val
        };
        writeln!(file, "{}", difference).expect("Failed to write to file");
    }
    */

    /* For the proof generation */
    // Generate random values for Freivalds' algorithm
    let mut rng = rand::thread_rng();
    let babybear_prime: u64 = 2013265921 as u64; //u64::pow(2, 31) - u64::pow(2, 27) + 1;
    
    let mut freivalds_left = Vec::<u32>::with_capacity(OUTPUT_HEIGHT as usize);
    let mut freivalds_right = Vec::<u32>::with_capacity(OUTPUT_WIDTH as usize);

    for _ in 0..OUTPUT_HEIGHT {
        freivalds_left.push(rng.gen_range(0..(babybear_prime as u32)));
    }

    for _ in 0..OUTPUT_WIDTH {
        freivalds_right.push(rng.gen_range(0..(babybear_prime as u32)));
    }

    // Calculate r_left * H and W * r_right
    let mut r_left_h = vec![0u32; INPUT_HEIGHT as usize];
    for i in 0..OUTPUT_HEIGHT as usize {
        for j in 0..INPUT_HEIGHT as usize {
            let product = freivalds_left[i] as u32 * h_matrix[i][j] as u32;
            r_left_h[j] = ((r_left_h[j] as u32 + product)) as u32;
        }
    }
    let mut w_r_right = vec![0u32; INPUT_WIDTH as usize];
    for i in 0..INPUT_WIDTH as usize {
        for j in 0..OUTPUT_WIDTH as usize {
            let product = w_matrix[i][j] as u32 * freivalds_right[j] as u32;
            w_r_right[i] = (w_r_right[i] as u32 + product) as u32;
        }
    }

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(image);
    stdin.write_vec(target_image);

    stdin.write(&target_middle_image);
    stdin.write(&r_left_h);
    stdin.write(&w_r_right);
    stdin.write(&freivalds_left);
    stdin.write(&freivalds_right);

    // Create a `ProverClient` method.
    let client = ProverClient::from_env();
    if DEBUGGING == false {
        let pk = serde_cbor::from_slice(&std::fs::read(target_pk_file).expect("reading pk failed")).expect("deserializing pk failed");
        let mut proof = client.prove(&pk, &stdin).compressed().run().expect("proving failed");

        proof
            .save(target_prove_file)
            .expect("saving proof failed");
        
        let equal_sum: bool = proof.public_values.read::<bool>();
        println!("equal_sum: {}", equal_sum);

        let exceed_limit_20: u32 = proof.public_values.read::<u32>();
        println!("exceed_limit_20: {}", exceed_limit_20);

        let exceed_limit_50: u32 = proof.public_values.read::<u32>();
        println!("exceed_limit_50: {}", exceed_limit_50);

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

        // let equal_sum: bool = proof.public_values.read::<bool>();
        // println!("equal_sum: {}", equal_sum);

        // let exceed_limit_20: u32 = proof.public_values.read::<u32>();
        // println!("exceed_limit_20: {}", exceed_limit_20);

        // let exceed_limit_50: u32 = proof.public_values.read::<u32>();
        // println!("exceed_limit_50: {}", exceed_limit_50);

        // let hash_target_image = proof.public_values.read::<blake3::Hash>();
        // println!("hash_target_image: {:?}", hash_target_image);

        //     // Verify proof and public values
        // client.verify(&proof, &vk).expect("verification failed");

        // // Test a round trip of proof serialization and deserialization.
        // proof
        //     .save(target_prove_file)
        //     .expect("saving proof failed");
        
        // let deserialized_proof =
        //     SP1ProofWithPublicValues::load(target_prove_file).expect("loading proof failed");
        
        // client
        //     .verify(&deserialized_proof, &vk)
        //     .expect("verification failed");

        // println!("successfully generated and verified proof for the program!");
    }
}