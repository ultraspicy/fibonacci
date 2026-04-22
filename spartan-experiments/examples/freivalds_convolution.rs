//! examples/freivalds_convolution.rs
//! Generic circuit for verifying the performance of implementing convolution-
//! type transforms using Freivald's algorithm.
//!
//! Run with: `RUST_LOG=info cargo run --release --example naive_lc_blur`
#![allow(non_snake_case)]
use bellpepper_core::{ConstraintSystem, SynthesisError, num::AllocatedNum};
use ff::{Field, PrimeField, PrimeFieldBits};
use rand::{Rng, RngCore};
use spartan2::{
  provider::T256HyraxEngine,
  spartan::SpartanSNARK,
  traits::{Engine, circuit::SpartanCircuit, snark::R1CSSNARKTrait},
};
use std::{marker::PhantomData, time::Instant};
use tracing::{info, info_span};
use tracing_subscriber::EnvFilter;

type E = T256HyraxEngine;

const KERNEL_SIZE: usize = 9;
const RADIUS: usize = KERNEL_SIZE / 2;

fn generate_random_vector<Scalar: PrimeField + PrimeFieldBits>(length: usize) -> Vec<Scalar> {
  let mut rng = rand::thread_rng();

  (0..length)
    .map(|_| Scalar::from_u128(rng.gen_range(0..((1u128 << 127) as u128))))
    .collect()
}

fn generate_random_image(dimensions: (usize, usize)) -> Vec<Vec<u8>> {
  let (height, width) = dimensions;
  let mut rng = rand::thread_rng();

  (0..height)
    .map(|_| (0..width).map(|_| rng.next_u32() as u8).collect())
    .collect()
}

#[derive(Clone, Debug)]
struct FreivaldsConvCircuit<Scalar: PrimeField> {
  image: Vec<Vec<u8>>,
  edited_image: Vec<Vec<u8>>,
  r: Vec<Scalar>,
  s: Vec<Scalar>,
  rTA: Vec<Scalar>,
  As: Vec<Scalar>,
  _p: PhantomData<Scalar>,
}

impl<Scalar: PrimeField + PrimeFieldBits> FreivaldsConvCircuit<Scalar> {
  // This circuit verifies the convolution: A_{left}IA_{right} = J.
  // It does so by verifying that r^TA_{left}IA_{right}s = r^TJs.
  fn new(image: Vec<Vec<u8>>) -> Self {
    let height = image.len();
    assert!(height > 0);
    let width = image[0].len();
    assert!(width > 0);

    let r = generate_random_vector(height);
    let s = generate_random_vector(width);

    // For now, A_{left} and A_{right} are the identity matrix for respective
    // transformations, will swap these out when the zk part is ready.
    let edited_image = image.clone();
    let rTA = r.clone();
    let As = s.clone();

    Self {
      image,
      edited_image,
      r,
      s,
      rTA,
      As,
      _p: PhantomData,
    }
  }
}

impl<E: Engine> SpartanCircuit<E> for FreivaldsConvCircuit<E::Scalar> {
  fn public_values(&self) -> Result<Vec<<E as Engine>::Scalar>, SynthesisError> {
    let height = self.image.len();
    assert!(height > 0);
    let width = self.image[0].len();
    assert!(width > 0);

    let mut public_vals = Vec::new();

    let flattened_edited_image: Vec<<E as Engine>::Scalar> = self
      .edited_image
      .clone()
      .into_iter()
      .map(|v| {
        v.into_iter()
          .map(|pixel| <E as Engine>::Scalar::from_u128(pixel as u128))
          .collect::<Vec<<E as Engine>::Scalar>>()
      })
      .flatten()
      .collect();

    public_vals.extend(flattened_edited_image);
    public_vals.extend(self.r.clone());
    public_vals.extend(self.s.clone());
    public_vals.extend(self.rTA.clone());
    public_vals.extend(self.As.clone());

    Ok(public_vals)
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
    // 1. Allocate private input for the image
    let image_input_vars = self
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
              || Ok(E::Scalar::from_u128(val as u128)),
            )
          })
          .collect::<Result<Vec<_>, _>>()
      })
      .collect::<Result<Vec<Vec<_>>, _>>()?;

    // 2. Allocate public inputs.
    let mut allocated_edited_image = Vec::new();
    for (i, row) in self.edited_image.clone().into_iter().enumerate() {
      let mut row_vars = Vec::new();
      for (j, pixel) in row.into_iter().enumerate() {
        let n = AllocatedNum::alloc_input(
          cs.namespace(|| format!("edited image entry {i} {j}")),
          || Ok(E::Scalar::from_u128(pixel as u128)),
        )?;
        row_vars.push(n);
      }
      allocated_edited_image.push(row_vars);
    }

    let mut allocated_r = Vec::new();
    for (i, val) in self.r.clone().into_iter().enumerate() {
      let n = AllocatedNum::alloc_input(cs.namespace(|| format!("r entry {i}")), || Ok(val))?;
      allocated_r.push(n);
    }

    let mut allocated_s = Vec::new();
    for (i, val) in self.s.clone().into_iter().enumerate() {
      let n = AllocatedNum::alloc_input(cs.namespace(|| format!("s entry {i}")), || Ok(val))?;
      allocated_s.push(n);
    }

    let mut allocated_rTA = Vec::new();
    for (i, val) in self.rTA.clone().into_iter().enumerate() {
      let n = AllocatedNum::alloc_input(cs.namespace(|| format!("rTA entry {i}")), || Ok(val))?;
      allocated_rTA.push(n);
    }

    let mut allocated_As = Vec::new();
    for (i, val) in self.As.clone().into_iter().enumerate() {
      let n = AllocatedNum::alloc_input(cs.namespace(|| format!("As entry {i}")), || Ok(val))?;
      allocated_As.push(n);
    }

    // 3. Compute LHS convolution (r^TA)I(As).
    // Compute I(As)
    // 2D for loop computing the matrix vector product I(As)
    let mut IAs = Vec::new();
    let mut IAs_felts = Vec::new();
    for (i, row) in image_input_vars.iter().enumerate() {
      let mut row_partial_sums: Vec<AllocatedNum<E::Scalar>> = Vec::new();
      let mut running_sum = E::Scalar::ZERO;

      for ((j, x), y) in row.iter().enumerate().zip(allocated_As.iter()) {
        running_sum = running_sum + E::Scalar::from_u128(self.image[i][j] as u128) * self.As[j];

        let partial_sum_var = AllocatedNum::alloc(
          cs.namespace(|| format!("Row {i} IAs partial sum {j}")),
          || Ok(running_sum),
        )?;

        if j == 0 {
          cs.enforce(
            || format!("Row {i} IAs partial sum constraint {j}"),
            |lc| lc + x.get_variable(),
            |lc| lc + y.get_variable(),
            |lc| lc + partial_sum_var.get_variable(),
          );
        } else {
          cs.enforce(
            || format!("Row {i} IAs partial sum constraint {j}"),
            |lc| lc + x.get_variable(),
            |lc| lc + y.get_variable(),
            |lc| lc + partial_sum_var.get_variable() - row_partial_sums[j - 1].get_variable(),
          );
        }

        row_partial_sums.push(partial_sum_var);
      }

      IAs_felts.push(running_sum);
      IAs.push(row_partial_sums.pop().unwrap());
    }

    // 1D for loop computing the vector vector product (r^TA)(I(As))
    let mut lhs_partial_sums: Vec<AllocatedNum<E::Scalar>> = Vec::new();
    let mut lhs_running_sum = E::Scalar::ZERO;
    for (i, (x, y)) in IAs.iter().zip(allocated_rTA.iter()).enumerate() {
      lhs_running_sum = lhs_running_sum + self.rTA[i] * IAs_felts[i];
      let partial_sum_var = AllocatedNum::alloc(
        cs.namespace(|| format!("LHS partial sum {i}")),
        || Ok(lhs_running_sum),
      )?;
      if i == 0 {
        cs.enforce(
          || format!("LHS partial sum constraint {i}"),
          |lc| lc + x.get_variable(),
          |lc| lc + y.get_variable(),
          |lc| lc + partial_sum_var.get_variable(),
        );
      } else {
        cs.enforce(
          || format!("LHS partial sum constraint {i}"),
          |lc| lc + x.get_variable(),
          |lc| lc + y.get_variable(),
          |lc| lc + partial_sum_var.get_variable() - lhs_partial_sums[i - 1].get_variable(),
        );
      }
      lhs_partial_sums.push(partial_sum_var);
    }
    let rTAIAs = lhs_partial_sums.pop().unwrap();

    // 4. Compute RHS convolution (r^T)F(s).
    let mut Fs = Vec::new();
    let mut Fs_felts = Vec::new();
    for (i, row) in allocated_edited_image.iter().enumerate() {
      let mut row_partial_sums: Vec<AllocatedNum<E::Scalar>> = Vec::new();
      let mut running_sum = E::Scalar::ZERO;

      for ((j, x), y) in row.iter().enumerate().zip(allocated_s.iter()) {
        running_sum = running_sum + E::Scalar::from_u128(self.edited_image[i][j] as u128) * self.As[j];

        let partial_sum_var = AllocatedNum::alloc(
          cs.namespace(|| format!("Row {i} Fs partial sum {j}")),
          || Ok(running_sum),
        )?;

        if j == 0 {
          cs.enforce(
            || format!("Row {i} Fs partial sum constraint {j}"),
            |lc| lc + x.get_variable(),
            |lc| lc + y.get_variable(),
            |lc| lc + partial_sum_var.get_variable(),
          );
        } else {
          cs.enforce(
            || format!("Row {i} Fs partial sum constraint {j}"),
            |lc| lc + x.get_variable(),
            |lc| lc + y.get_variable(),
            |lc| lc + partial_sum_var.get_variable() - row_partial_sums[j - 1].get_variable(),
          );
        }

        row_partial_sums.push(partial_sum_var);
      }

      Fs_felts.push(running_sum);
      Fs.push(row_partial_sums.pop().unwrap());
    }

    let mut rhs_partial_sums: Vec<AllocatedNum<E::Scalar>> = Vec::new();
    let mut rhs_running_sum = E::Scalar::ZERO;
    for (i, (x, y)) in Fs.iter().zip(allocated_r.iter()).enumerate() {
      rhs_running_sum = rhs_running_sum + Fs_felts[i] * self.r[i];
      let partial_sum_var = AllocatedNum::alloc(
        cs.namespace(|| format!("RHS partial sum {i}")),
        || Ok(rhs_running_sum),
      )?;
      if i == 0 {
        cs.enforce(
          || format!("RHS partial sum constraint {i}"),
          |lc| lc + x.get_variable(),
          |lc| lc + y.get_variable(),
          |lc| lc + partial_sum_var.get_variable(),
        );
      } else {
        cs.enforce(
          || format!("RHS partial sum constraint {i}"),
          |lc| lc + x.get_variable(),
          |lc| lc + y.get_variable(),
          |lc| lc + partial_sum_var.get_variable() - rhs_partial_sums[i - 1].get_variable(),
        );
      }
      rhs_partial_sums.push(partial_sum_var);
    }
    let rTFs = rhs_partial_sums.pop().unwrap();

    // 5. Enforce equality among the two convolved values.
    cs.enforce(
      || format!("OutpFinal Freivalds validity check"),
      |lc| lc + CS::one(),
      |lc| lc + rTFs.get_variable(),
      |lc| lc + rTAIAs.get_variable(),
    );

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

  let test_image = generate_random_image(image_dims);

  let circuit = FreivaldsConvCircuit::<<E as Engine>::Scalar>::new(test_image);

  let root_span = info_span!("bench", "image").entered();
  info!(
    "======= image_size is = {} x {} pixels =======",
    image_dims.0, image_dims.1
  );

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
