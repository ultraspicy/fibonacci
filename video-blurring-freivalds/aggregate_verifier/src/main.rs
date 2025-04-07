use sp1_sdk::{utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey};

// const _FRAME_NUM: usize = 10;
// const INPUT_WIDTH: i32 = 240;
// const INPUT_HEIGHT: i32 = 320;
// const OUTPUT_WIDTH: i32 = 120; // Hardcoded value, will be overridden by config
// const OUTPUT_HEIGHT: i32 = 160;

fn main() {
    // Setup logging.
    let _start_time = std::time::Instant::now();
    utils::setup_logger();
    let client = ProverClient::from_env();
    let _end_time = std::time::Instant::now();
    println!("Time taken to setup logging: {:?}", _end_time.duration_since(_start_time));
    let config_file = std::fs::File::open("config.json").expect("Failed to open config file");
    let config: serde_json::Value = serde_json::from_reader(config_file).expect("Failed to parse JSON");
    let target_vk_file = config["target_vk_file"].as_str().expect("Missing target_vk_file");
    let target_prove_file = config["target_prove_file"].as_str().expect("Missing target_prove_file");

    let start_time = std::time::Instant::now();

    let vk =  serde_cbor::from_slice(&std::fs::read(target_vk_file).expect("reading vk failed")).expect("deserializing vk failed");
    let mut proof =  SP1ProofWithPublicValues::load(target_prove_file).expect("loading proof failed");

    client.verify(&proof, &vk).expect("verification failed");
    let end_time = std::time::Instant::now();
    println!("Time taken to verify proof: {:?}", end_time.duration_since(start_time));

    // for i in 0..10{
    //     println!("The {}th public value is:", i);
    //     let public_value = proof.public_values.read::<Vec<u8>>();
    // }

    // let equal_sum: bool = proof.public_values.read::<bool>();
    // println!("equal_sum: {}", equal_sum);

    // let exceed_limit_20: u32 = proof.public_values.read::<u32>();
    // println!("exceed_limit_20: {}", exceed_limit_20);

    // let exceed_limit_50: u32 = proof.public_values.read::<u32>();
    // println!("exceed_limit_50: {}", exceed_limit_50);


}