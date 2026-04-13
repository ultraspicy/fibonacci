//! examples/naive_lc_blur.rs
//! Baseline circuit to show the performance of the naive approach
//! for linear transformation-based edits.
//!
//! Run with: `RUST_LOG=info cargo run --release --example naive_lc_blur`
#![allow(non_snake_case)]
use bellpepper_core::{
  num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError
};
use ff::{Field, PrimeField, PrimeFieldBits};
use spartan2::{
  provider::T256HyraxEngine,
  spartan::SpartanSNARK,
  traits::{Engine, circuit::SpartanCircuit, snark::R1CSSNARKTrait},
};
use rand::{RngCore};
use std::{marker::PhantomData, time::Instant, ops::Add};
use tracing::{info, info_span};
use tracing_subscriber::EnvFilter;

type E = T256HyraxEngine;

const KERNEL_SIZE: usize = 9;
const RADIUS: usize = KERNEL_SIZE / 2;
const FIXED_POINT_SCALE: u128 = 1 << 30; // 2^30

fn generate_random_image(dimensions: (usize, usize)) -> Vec<Vec<u8>> {
    let (height, width) = dimensions;
    let mut rng = rand::thread_rng();
    
    (0..height)
        .map(|_| (0..width).map(|_| rng.next_u32() as u8).collect())
        .collect()
}

#[derive(Clone, Debug)]
struct BlurCircuit<Scalar: PrimeField> {
  image: Vec<Vec<u8>>,
  _p: PhantomData<Scalar>,
}

impl<Scalar: PrimeField + PrimeFieldBits> BlurCircuit<Scalar> {
  fn new(image: Vec<Vec<u8>>) -> Self {
    Self {
      image,
      _p: PhantomData,
    }
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
          let mut sum = 0u128;

          // region boundaries (clipped to edges)
          let y_min = y.saturating_sub(RADIUS);
          let y_max = (y + RADIUS).min(height - 1);
          let x_min = x.saturating_sub(RADIUS);
          let x_max = (x + RADIUS).min(width - 1);

          for yy in y_min..=y_max {
              for xx in x_min..=x_max {
                  // Convert pixel value to fixed point before accumulating
                  sum += (self.image[yy][xx] as u128) * FIXED_POINT_SCALE;
              }
          }

          convolved_values[y][x] = <E as Engine>::Scalar::from_u128(sum);
      }
    }

    let flat: Vec<<E as Engine>::Scalar> = convolved_values.into_iter().flatten().collect();
    Ok(flat)
  }

  fn shared<CS: ConstraintSystem<E::Scalar>>(
    &self,
    _: &mut CS,
  ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
    // No shared variables in this circuit
    Ok(vec![])
  }

  fn precommitted<CS: ConstraintSystem<E::Scalar>>(
    &self,
    _: &mut CS,
    _: &[AllocatedNum<E::Scalar>], // shared variables, if any
  ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
    // No precommitted variables in this circuit
    Ok(vec![])
  }

  fn num_challenges(&self) -> usize {
    // Circuit does not expect any challenges
    0
  }

  fn synthesize<CS: ConstraintSystem<E::Scalar>>(
    &self,
    cs: &mut CS,
    _: &[AllocatedNum<E::Scalar>],
    _: &[AllocatedNum<E::Scalar>],
    _: Option<&[E::Scalar]>,
  ) -> Result<(), SynthesisError> {
    // 1. Allocate inputs to circuit with fixed point scaling.
    let input_vars = self.image.clone()
      .into_iter()
      .enumerate()
      .map(|(i, row)| 
        row.into_iter()
          .enumerate()
          .map(|(j, val)| {
            // Convert u8 pixel value to fixed point (val * 2^30)
            let fixed_point_val = (val as u128) * FIXED_POINT_SCALE;
            AllocatedNum::alloc(
              cs.namespace(|| format!("Input image pixel {i},{j}")), 
              || Ok(E::Scalar::from_u128(fixed_point_val))
            )
          })
          .collect::<Result<Vec<_>, _>>()
      )
      .collect::<Result<Vec<Vec<_>>, _>>()?;

    // 2. Compute expected convolution.
    let height = self.image.len();
    let width = self.image[0].len();
    // Rust compiler was being weird here, almost certainly a better way to do this.
    let expected_convolution_flat: Vec<<E as Engine>::Scalar> = <BlurCircuit<<E as Engine>::Scalar> as SpartanCircuit<E>>::public_values(self)?;

    let expected_convolution : Vec<Vec<<E as Engine>::Scalar>> = expected_convolution_flat.chunks(width)
      .map(|chunk| chunk.to_vec())
      .collect();

    // 3. Allocate expected result and enforce equality.
    for i in 0..height {
      for j in 0..width {
          let n = AllocatedNum::alloc_input(cs.namespace(|| format!("Output image pixel {i}, {j}")), || {
            Ok(expected_convolution[i][j])
          })?;


         let mut sum_lc = LinearCombination::zero();

          // region boundaries (clipped to edges)
          let y_min = i.saturating_sub(RADIUS);
          let y_max = (i + RADIUS).min(height - 1);
          let x_min = j.saturating_sub(RADIUS);
          let x_max = (j + RADIUS).min(width - 1);

          for ii in y_min..=y_max {
              for jj in x_min..=x_max {
                  sum_lc = sum_lc.clone().add((<E as Engine>::Scalar::ONE, input_vars[ii][jj].get_variable()));
              }
          }

          // Single equality constraint is enough
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
    .with_ansi(true)                // no bold colour codes
    .with_env_filter(EnvFilter::from_default_env())
    .init();

  // let image_dimensions_list = vec![(240, 320), (720, 1280)];
  let image_dims = (720usize, 1280usize);

  let test_image = generate_random_image(image_dims);

  // Message lengths: 2^10 … 2^11 bytes.
  let circuit = BlurCircuit::<<E as Engine>::Scalar>::new(test_image);

  let root_span = info_span!("bench", "image").entered();
  info!("======= image_size is = {} x {} pixels =======", image_dims.0, image_dims.1);

  // SETUP
  let t0 = Instant::now();
  let (pk, vk) = SpartanSNARK::<E>::setup(circuit.clone()).expect("setup failed");
  let setup_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = setup_ms, "setup");
  info!("Constraint count is: {}", pk.sizes()[0]);

  // PREPARE
  let t0 = Instant::now();
  let prep_snark =
    SpartanSNARK::<E>::prep_prove(&pk, circuit.clone(), false).expect("prep_prove failed");
  let prep_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = prep_ms, "prep_prove");

  // PROVE
  let t0 = Instant::now();
  let proof =
    SpartanSNARK::<E>::prove(&pk, circuit.clone(), &prep_snark, false).expect("prove failed");
  let prove_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = prove_ms, "prove");

  // VERIFY
  let t0 = Instant::now();
  proof.verify(&vk).expect("verify errored");
  let verify_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = verify_ms, "verify");

  // Summary
  info!(
    "SUMMARY dims={}x{}, setup={} ms, prep_prove={} ms, prove={} ms, verify={} ms",
    image_dims.0, image_dims.1, setup_ms, prep_ms, prove_ms, verify_ms
  );
  drop(root_span);
}