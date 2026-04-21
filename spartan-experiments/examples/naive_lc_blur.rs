//! Baseline circuit to show the performance of the naive approach
//! for linear transformation-based edits. This has configurable parameters
//! for the bitlengths of the kernel/pixel values and the kernel size, since
//! both affect the performance.
//!
//! Command: `RUST_LOG=info cargo run --release --example naive_lc_blur`
#![allow(non_snake_case)]
use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError, num::AllocatedNum};
use ff::{Field, PrimeField, PrimeFieldBits};
use rand::RngCore;
use spartan2::{
  provider::T256HyraxEngine,
  spartan::SpartanSNARK,
  traits::{Engine, circuit::SpartanCircuit, snark::R1CSSNARKTrait},
};
use std::{ops::Add, time::Instant};
use tracing::{info, info_span};
use tracing_subscriber::EnvFilter;

type E = T256HyraxEngine;

const KERNEL_SIZE: usize = 5;
const RADIUS: usize = KERNEL_SIZE / 2;
const BITLENGTH: usize = 64;

// Generates a random scalar with only the lowest `bitlength` bits randomized.
fn random_scalar_with_bitlength<Scalar: PrimeField>(
  rng: &mut impl RngCore,
  bitlength: usize,
) -> Scalar {
  loop {
    let mut repr = Scalar::Repr::default();
    let bytes = repr.as_mut();
    let full_bytes = bitlength / 8;
    let partial_bits = bitlength % 8;
    let len = full_bytes.min(bytes.len());
    rng.fill_bytes(&mut bytes[..len]);
    if partial_bits > 0 && full_bytes < bytes.len() {
      bytes[full_bytes] = (rng.next_u32() as u8) & ((1u8 << partial_bits) - 1);
    }
    if let Some(s) = Scalar::from_repr(repr).into_option() {
      return s;
    }
  }
}

// Generate random image/kernel for the program. This is meant to simulate using fixed point
// arithmetic for this stuff.
fn generate_random_image<Scalar: PrimeField>(
  dimensions: (usize, usize),
  bitlength: usize,
) -> Vec<Vec<Scalar>> {
  let (height, width) = dimensions;
  let mut rng = rand::thread_rng();
  (0..height)
    .map(|_| {
      (0..width)
        .map(|_| random_scalar_with_bitlength(&mut rng, bitlength))
        .collect()
    })
    .collect()
}

fn generate_random_kernel<Scalar: PrimeField>(bitlength: usize) -> Vec<Vec<Scalar>> {
  let mut rng = rand::thread_rng();
  (0..KERNEL_SIZE)
    .map(|_| {
      (0..KERNEL_SIZE)
        .map(|_| random_scalar_with_bitlength(&mut rng, bitlength))
        .collect()
    })
    .collect()
}

#[derive(Clone, Debug)]
struct BlurCircuit<Scalar: PrimeField> {
  image: Vec<Vec<Scalar>>,
  kernel: Vec<Vec<Scalar>>,
}

impl<Scalar: PrimeField + PrimeFieldBits> BlurCircuit<Scalar> {
  fn new(image: Vec<Vec<Scalar>>, kernel: Vec<Vec<Scalar>>) -> Self {
    Self { image, kernel }
  }
}

impl<E: Engine> SpartanCircuit<E> for BlurCircuit<E::Scalar> {
  fn public_values(&self) -> Result<Vec<<E as Engine>::Scalar>, SynthesisError> {
    let height = self.image.len();
    assert!(height > 0);
    let width = self.image[0].len();
    assert!(width > 0);

    let mut convolved_values = vec![vec![<E as Engine>::Scalar::ZERO; width]; height];
    for y in 0..height {
      for x in 0..width {
        let mut sum = <E as Engine>::Scalar::ZERO;

        let y_min = y.saturating_sub(RADIUS);
        let y_max = (y + RADIUS).min(height - 1);
        let x_min = x.saturating_sub(RADIUS);
        let x_max = (x + RADIUS).min(width - 1);

        for yy in y_min..=y_max {
          for xx in x_min..=x_max {
            let ky = yy + RADIUS - y;
            let kx = xx + RADIUS - x;
            sum += self.kernel[ky][kx] * self.image[yy][xx];
          }
        }

        convolved_values[y][x] = sum;
      }
    }

    let flat: Vec<<E as Engine>::Scalar> = convolved_values.into_iter().flatten().collect();
    Ok(flat)
  }

  fn shared<CS: ConstraintSystem<E::Scalar>>(
    &self,
    _: &mut CS,
  ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
    Ok(vec![])
  }

  fn precommitted<CS: ConstraintSystem<E::Scalar>>(
    &self,
    _: &mut CS,
    _: &[AllocatedNum<E::Scalar>],
  ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
    Ok(vec![])
  }

  fn num_challenges(&self) -> usize {
    0
  }

  fn synthesize<CS: ConstraintSystem<E::Scalar>>(
    &self,
    cs: &mut CS,
    _: &[AllocatedNum<E::Scalar>],
    _: &[AllocatedNum<E::Scalar>],
    _: Option<&[E::Scalar]>,
  ) -> Result<(), SynthesisError> {
    // 1. Allocate input field elements.
    let input_vars = self
      .image
      .clone()
      .into_iter()
      .enumerate()
      .map(|(i, row)| {
        row
          .into_iter()
          .enumerate()
          .map(|(j, val)| {
            AllocatedNum::alloc(
              cs.namespace(|| format!("Input image pixel {i},{j}")),
              || Ok(val),
            )
          })
          .collect::<Result<Vec<_>, _>>()
      })
      .collect::<Result<Vec<Vec<_>>, _>>()?;

    // 2. Get expected convolution.
    let height = self.image.len();
    let width = self.image[0].len();
    let expected_convolution_flat: Vec<<E as Engine>::Scalar> =
      <BlurCircuit<<E as Engine>::Scalar> as SpartanCircuit<E>>::public_values(self)?;

    let expected_convolution: Vec<Vec<<E as Engine>::Scalar>> = expected_convolution_flat
      .chunks(width)
      .map(|chunk| chunk.to_vec())
      .collect();

    // 3. Allocate expected result and enforce equality.
    for i in 0..height {
      for j in 0..width {
        let n = AllocatedNum::alloc_input(
          cs.namespace(|| format!("Output image pixel {i}, {j}")),
          || Ok(expected_convolution[i][j]),
        )?;

        let mut sum_lc = LinearCombination::zero();

        let y_min = i.saturating_sub(RADIUS);
        let y_max = (i + RADIUS).min(height - 1);
        let x_min = j.saturating_sub(RADIUS);
        let x_max = (j + RADIUS).min(width - 1);

        for ii in y_min..=y_max {
          for jj in x_min..=x_max {
            let ky = ii + RADIUS - i;
            let kx = jj + RADIUS - j;
            sum_lc = sum_lc
              .clone()
              .add((self.kernel[ky][kx], input_vars[ii][jj].get_variable()));
          }
        }

        cs.enforce(
          || format!("Output pixel {i}, {j} validity check"),
          |lc| lc + CS::one(),
          |lc| lc + &sum_lc,
          |lc| lc + n.get_variable(),
        );
      }
    }

    Ok(())
  }
}

fn main() {
  tracing_subscriber::fmt()
    .with_target(false)
    .with_ansi(true)
    .with_env_filter(EnvFilter::from_default_env())
    .init();

  // let image_dimensions_list = vec![(240, 320), (720, 1280)];
  let image_dims = (720usize, 1280usize);

  let test_image = generate_random_image::<<E as Engine>::Scalar>(image_dims, BITLENGTH);
  let kernel = generate_random_kernel::<<E as Engine>::Scalar>(BITLENGTH);

  let circuit = BlurCircuit::<<E as Engine>::Scalar>::new(test_image, kernel);

  let root_span = info_span!("bench", "image").entered();
  info!(
    "======= Image size is = {} x {} pixels =======",
    image_dims.0, image_dims.1
  );

  let t0 = Instant::now();
  let (pk, vk) = SpartanSNARK::<E>::setup(circuit.clone()).expect("setup failed");
  let setup_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = setup_ms, "setup");
  info!("Constraint count is: {}", pk.sizes()[0]);

  let t0 = Instant::now();
  let prep_snark =
    SpartanSNARK::<E>::prep_prove(&pk, circuit.clone(), false).expect("prep_prove failed");
  let prep_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = prep_ms, "prep_prove");

  let t0 = Instant::now();
  let proof =
    SpartanSNARK::<E>::prove(&pk, circuit.clone(), &prep_snark, false).expect("prove failed");
  let prove_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = prove_ms, "prove");

  let t0 = Instant::now();
  proof.verify(&vk).expect("verification failed");
  let verify_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = verify_ms, "verify");

  info!(
    "SUMMARY dims={}x{}, setup={} ms, prep_prove={} ms, prove={} ms, verify={} ms",
    image_dims.0, image_dims.1, setup_ms, prep_ms, prove_ms, verify_ms
  );
  drop(root_span);
}
