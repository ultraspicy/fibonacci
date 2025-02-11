use lib::{generate_horizontal_filter, generate_vertical_filter, load_image_from_file};
use sp1_sdk::{utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey};
use sp1_sdk::include_elf;
use rand::Rng;
use clap::Parser;
use std::io::Write;

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("fibonacci-program");

// const _FRAME_NUM: usize = 10;
// const INPUT_WIDTH: i32 = 240;
// const INPUT_HEIGHT: i32 = 320;
// const OUTPUT_WIDTH: i32 = 120; // Hardcoded value, will be overridden by config
// const OUTPUT_HEIGHT: i32 = 180;

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
    let target_vk_file = config["target_vk_file"].as_str().expect("Missing target_vk_file");

    // Build the full matrices
    let h_matrix = lib::build_horizontal_matrix(INPUT_WIDTH, OUTPUT_WIDTH);
    let v_matrix = lib::build_vertical_matrix(INPUT_HEIGHT, OUTPUT_HEIGHT);
    // V @ R @ H
    
    // Generate random values for Freivalds' algorithm
    let mut rng = rand::thread_rng();
    let babybear_prime: u64 = u64::pow(2, 32) - u64::pow(2, 16) + 1;
    
    let mut freivalds_left = Vec::<u32>::with_capacity(OUTPUT_HEIGHT as usize);
    let mut freivalds_right = Vec::<u32>::with_capacity(OUTPUT_WIDTH as usize);

    for _ in 0..OUTPUT_HEIGHT {
        freivalds_left.push(rng.gen_range(0..(babybear_prime as u32)));
    }

    for _ in 0..OUTPUT_WIDTH {
        freivalds_right.push(rng.gen_range(0..(babybear_prime as u32)));
    }
    
    // Calculate r_left * H and W * r_right
    let mut r_left_h = vec![0u32; v_matrix[0].len()];
    for i in 0..OUTPUT_HEIGHT as usize {
        for j in 0..v_matrix[0].len() {
            let product = (freivalds_left[i] as u32).wrapping_mul(v_matrix[i][j] as u32);
            r_left_h[j] = ((r_left_h[j] as u32).wrapping_add(product) % babybear_prime as u32) as u32;
        }
    }

    let mut w_r_right = vec![0u32; h_matrix.len()];
    for i in 0..h_matrix.len() {
        for j in 0..OUTPUT_WIDTH as usize {
            let product = (h_matrix[i][j] as u32).wrapping_mul(freivalds_right[j] as u32);
            w_r_right[i] = ((w_r_right[i] as u32).wrapping_add(product) % babybear_prime as u32) as u32;
        }
    }

    let image: Vec<u8> = load_image_from_file(input_file);
    let target_image: Vec<u8> = load_image_from_file(target_file);
    let mut target_middle_image: Vec<u32> = vec![0; target_image.len()];

    println!("image: {:?}", image.len());
    println!("INPUT_WIDTH: {:?}", INPUT_WIDTH);
    println!("INPUT_HEIGHT: {:?}", INPUT_HEIGHT);
    println!("target_image: {:?}", target_image.len());

    // Calculate target_middle_image = v @ image @ h
    // First multiply image with h matrix
    let mut temp = vec![0u32; INPUT_HEIGHT as usize * OUTPUT_WIDTH as usize];
    for i in 0..INPUT_HEIGHT as usize {
        for j in 0..OUTPUT_WIDTH as usize {
            let mut sum = 0u32;
            for k in 0..INPUT_WIDTH as usize {
                // println!("{} {} {}", i * INPUT_WIDTH as usize + k, k, j);
                let product = ((image[i * INPUT_WIDTH as usize + k] as u64) * (h_matrix[k][j] as u64)) % (babybear_prime as u64);
                sum = ((sum as u64 + product) % babybear_prime as u64) as u32;
            }
            temp[i * OUTPUT_WIDTH as usize + j] = sum;
        }
    }

    // Then multiply v matrix with the result
    for i in 0..OUTPUT_HEIGHT as usize {
        for j in 0..OUTPUT_WIDTH as usize {
            let mut sum = 0u32;
            for k in 0..INPUT_HEIGHT as usize {
                let product = ((temp[k * OUTPUT_WIDTH as usize + j] as u64) * (v_matrix[i][k] as u64)) % (babybear_prime as u64);
                sum = ((sum as u64 + product) % (babybear_prime as u64)) as u32;
            }
            target_middle_image[i * OUTPUT_WIDTH as usize + j] = sum;
        }
    }
    // Calculate freivalds_left @ target_image @ freivalds_right
    // First multiply target_image (OUTPUT_HEIGHT x OUTPUT_WIDTH) with freivalds_right (OUTPUT_WIDTH x 1)
    let mut temp = vec![0u32; OUTPUT_HEIGHT as usize];
    for i in 0..OUTPUT_HEIGHT as usize {
        for j in 0..OUTPUT_WIDTH as usize {
            let product = (target_image[i * OUTPUT_WIDTH as usize + j] as u64)
                .wrapping_mul(freivalds_right[j] as u64);
            temp[i] = ((temp[i] as u64).wrapping_add(product) % babybear_prime as u64) as u32;
        }
    }

    // Then multiply freivalds_left (1 x OUTPUT_HEIGHT) with the result (OUTPUT_HEIGHT x 1)
    let mut sum = 0u32;
    for i in 0..OUTPUT_HEIGHT as usize {
        let product = (freivalds_left[i] as u64).wrapping_mul(temp[i] as u64);
        sum = ((sum as u64).wrapping_add(product) % babybear_prime as u64) as u32;
    }
    println!("sum: {}",sum);
    // The input stream that the program will read from using `sp1_zkvm::io::read`.
    // Note that the types of the elements in the input stream must match the types being
    // read in the program.
    // Output differences between scaled target_middle_image and target_image

    /*for debugging*/
    // let mut file = std::fs::File::create("differences.txt").expect("Failed to create file");
    // for i in 0..target_middle_image.len() {
    //     let middle_val = target_middle_image[i]/(1<<22) as u32;
    //     let target_val = target_image[i].clone() as u32;
    //     let difference = if middle_val > target_val {
    //         middle_val - target_val
    //     } else {
    //         target_val - middle_val
    //     };
    //     writeln!(file, "{}", difference).expect("Failed to write to file");
    // }
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(image);
    stdin.write_vec(target_image);

    stdin.write(&target_middle_image);
    stdin.write(&r_left_h);
    stdin.write(&w_r_right);
    stdin.write(&freivalds_left);
    stdin.write(&freivalds_right);

    // Save target_middle_image values divided by 2^22 to a file
    let mut file = std::fs::File::create("target_middle_image.txt").expect("Failed to create file");
    for value in target_middle_image.iter() {
        let scaled_value = value / (1 << 22);
        writeln!(file, "{}", scaled_value).expect("Failed to write to file");
    }

    // Create a `ProverClient` method.
    let client = ProverClient::new();

    // Generate the proof for the given program and input.
    let (pk, vk) = client.setup(ELF);
    println!("pk type: {}", std::any::type_name_of_val(&pk));
    println!("vk type: {}", std::any::type_name_of_val(&vk));
    let mut proof = client.prove(&pk, &stdin).run().unwrap();

    println!("generated proof");
    let equal_sum: bool = proof.public_values.read::<bool>();
    println!("equal_sum: {}", equal_sum);

    let within_limit: bool = proof.public_values.read::<bool>();
    println!("within_limit: {}", within_limit);

    // Verify proof and public values
    client.verify(&proof, &vk).expect("verification failed");

    // Test a round trip of proof serialization and deserialization.
    proof
        .save(target_prove_file)
        .expect("saving proof failed");
    
    let deserialized_proof =
        SP1ProofWithPublicValues::load(target_prove_file).expect("loading proof failed");
    
    let serialized_vk = serde_cbor::to_vec(&vk).expect("serializing vk failed");
    std::fs::write(target_vk_file, serialized_vk).expect("saving serialized vk failed");
    //vk.save(target_vk_file).expect("saving verifying key failed");
    println!("Saved verifying key to {}", target_vk_file);
    let deserialized_vk = serde_cbor::from_slice(&std::fs::read(target_vk_file).expect("reading vk failed")).expect("deserializing vk failed");
    // let deserialized_vk = SP1VerifyingKey::load(target_vk_file).expect("loading verifying key failed");
    client
        .verify(&deserialized_proof, &deserialized_vk)
        .expect("verification failed");

    println!("successfully generated and verified proof for the program!");
}
