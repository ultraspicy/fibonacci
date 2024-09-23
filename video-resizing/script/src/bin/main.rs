use lib::{load_image_from_file, Context};
use sp1_sdk::{utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");

const FRAME_NUM: usize = 10;
const input_width: i32 = 192;
const input_height: i32 = 108;
const output_width: i32 = 96;
const output_height: i32 = 54;

fn main() {
    // Setup logging.
    utils::setup_logger();

    for i in 1..=FRAME_NUM {
        let filename = format!("../resources/ffmpeg_bilinear_output/output_{:03}.png", i);
    }

    //fake example
    let input_file = "../resources/fake_image.txt";
    let target_file = "../resources/fake_real_image.txt";
    let output_file = "image_output.txt";

    let context = Context::new(input_width, input_height, output_width, output_height).unwrap();

    // Get the Image
    let image: Vec<u8> = load_image_from_file(input_file);
    let target_image: Vec<u8> = load_image_from_file(target_file);

    // The input stream that the program will read from using `sp1_zkvm::io::read`.
    // Note that the types of the elements in the input stream must match the types being
    // read in the program.
    let mut stdin = SP1Stdin::new();
    stdin.write(&context);
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

    // Note: if commit a Vec<> the proof time will be very long
    // for quick verification, use a usize to sum it up
    // TODO: investigate why commit to Vec<> will hurt the performance
    let difference: Vec<usize> = proof.public_values.read::<Vec<usize>>();
    println!("difference: {}", difference[0]);
    // let difference: usize = proof.public_values.read::<usize>();

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
