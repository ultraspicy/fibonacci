use sp1_sdk::{utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin};
use fibonacci_lib::{Context, load_image_from_file, scale_image};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup logging.
    utils::setup_logger();

    // Todo: how to input from the 
    // let args: Vec<String> = std::env::args().collect();

    // if args.len() != 7 {
    //     println!("Usage: {} <input_file> <input_width> <input_height> <output_file> <output_width> <output_height>", args[0]);
    //     //  sand_19201080_R_channel.txt 1920 1080 custom_bilinear_r.txt 480 270
    //     return;
    // }

    // let input_file = "../resources/sand_19201080_R_channel.txt";
    // let input_width = 1920;
    // let input_height = 1080;
    // let output_file = "custom_bilinear_r.txt";
    // let output_width = 480;
    // let output_height = 270;

    //fake example
    let input_file = "../resources/fake_image.txt";
    let input_width = 120;
    let input_height = 100;
    let target_file = "../resources/fake_real_image.txt";
    let output_width = 60;
    let output_height = 50;
    let output_file = "image_output.txt";

    let c = Context::new(input_width, input_height, output_width, output_height).unwrap();

    // Get the Image
    let image: Vec<u8> =load_image_from_file(input_file);
    let target_image: Vec<u8> = load_image_from_file(target_file);

    // For test only, generate output file 
    // let mut output = vec![0u8; (output_width * output_height) as usize];
    // scale_image(&c, &image, input_width, &mut output, output_width);
    // let output_path = Path::new(output_file);
    // let mut output_file = File::create(&output_path).expect("Failed to open output file");

    // for i in 0..output_height {
    //     for j in 0..output_width {
    //         write!(output_file, "{} ", output[(i * output_width + j) as usize]).unwrap();
    //     }
    //     writeln!(output_file).unwrap();
    // }

    // The input stream that the program will read from using `sp1_zkvm::io::read`.
    // Note that the types of the elements in the input stream must match the types being
    // read in the program.
    let mut stdin = SP1Stdin::new();
    stdin.write(&c);
    stdin.write(&image);
    stdin.write(&target_image);

    // Create a `ProverClient` method.
    let client = ProverClient::new();

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(ELF, stdin.clone()).run().unwrap();
    println!(
        "executed program with {} cycles",
        report.total_instruction_count()
    );

    // Generate the proof for the given program and input.
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).run().unwrap();

    println!("generated proof");

    // Read and verify the output.
    //
    // Note that this output is read from values commited to in the program using
    // `sp1_zkvm::io::commit`.
    //let _ = proof.public_values.read::<u32>();

    // Calculate the L1 norm here 
    // Todo: change to range check & speed up
    let difference: u8 = proof.public_values.read::<u8>();

    println!("difference: {}", difference);

    // Verify proof and public values
    client.verify(&proof, &vk).expect("verification failed");

    // Test a round trip of proof serialization and deserialization.
    proof
        .save("proof-with-pis.bin")
        .expect("saving proof failed");
    let deserialized_proof =
        SP1ProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    // Verify the deserialized proof.
    client
        .verify(&deserialized_proof, &vk)
        .expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}
