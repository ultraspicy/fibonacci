use lib::{load_image_from_file};
use sp1_sdk::{utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey, SP1Proof};
use sp1_sdk::include_elf;
use rand::Rng;
use blake3::{hash};
use sp1_sdk::HashableKey;
use serde_json::Value;

const AGGREGATION_ELF: &[u8] = include_elf!("aggregation-program");

struct AggregationInput {
    pub proof: SP1ProofWithPublicValues,
    pub vk: SP1VerifyingKey,
}

fn main() {
    // Setup logging.
    utils::setup_logger();
    let client = ProverClient::from_env();
    let config_file = std::fs::File::open("config.json").expect("Failed to open config file");
    let config: serde_json::Value = serde_json::from_reader(config_file).expect("Failed to parse JSON");

   // let target_pk_file = config["target_pk_file"].as_str().expect("Missing target_pk_file");
    let target_vk_file = config["vk"].as_str().expect("Missing target_vk_file");
    let aggregation_pk_file = config["aggregation_pk"].as_str().expect("Missing aggregation_pk_file");
    let target_prove_file = config["target_prove_file"].as_str().expect("missing target prove file");
    let proof_files: Vec<String> = match &config["proof_files"] {
        Value::Array(arr) => arr.iter()
            .map(|v| v.as_str().unwrap_or("").to_string())
            .collect(),
        Value::String(s) => vec![s.clone()],
        _ => panic!("proof_file should be a list or a string"),
    };    

 //   let pk = serde_cbor::from_slice(&std::fs::read(target_pk_file).expect("reading pk failed")).expect("deserializing pk failed");
    let vk:SP1VerifyingKey = serde_cbor::from_slice(&std::fs::read(target_vk_file).expect("reading pk failed")).expect("deserializing pk failed");
    //println!("{}", std::any::type_name_of_val(&vk));
    let aggregation_pk = serde_cbor::from_slice(&std::fs::read(aggregation_pk_file).expect("reading aggregation pk failed")).expect("deserializing pk failed");

    let mut inputs = vec![];
    for proof_file in proof_files{
        let mut proof =  SP1ProofWithPublicValues::load(proof_file).expect("loading proof failed");
        inputs.push(AggregationInput { proof: proof.clone(), vk: vk.clone() });
    }
    
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