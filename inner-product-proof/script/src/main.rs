use rand::Rng;
use sp1_sdk::{include_elf, utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin};

const ELF: &[u8] = include_elf!("inner-product-proof");

fn main() {
    utils::setup_logger();

    let p: u32 = 0xFFF5001; // babybear

    let mut rng = rand::rng();
    let mut a: Vec<u32> = vec![1024];
    a.extend((0..1024).map(|_| rng.gen_range(1..=255)));
    let mut b: Vec<u32> = vec![1024];
    b.extend((0..1024).map(|_| rng.gen_range(1..=255)));

    let mut stdin = SP1Stdin::new();
    stdin.write(&a);
    stdin.write(&b);
    stdin.write(&p);

    // Create a `ProverClient` method.
    let client = ProverClient::from_env();
    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(ELF, &stdin).run().unwrap();
    println!(
        "executed program with {} cycles",
        report.total_instruction_count()
    );
}
