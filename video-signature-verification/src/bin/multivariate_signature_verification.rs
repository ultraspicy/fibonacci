// This code is also adapted from: https://github.com/Pratyush/hekaton-system/blob/main/cp-groth16/benches/bench.rs

use ark_bls12_381::{Bls12_381 as E, Fr as F};
use ark_cp_groth16::{
    committer::CommitmentBuilder,
    generator::generate_parameters,
    verifier::{prepare_verifying_key, verify_proof},
    MultiStageConstraintSynthesizer, MultiStageConstraintSystem,
};
use ark_ff::{Field, One, PrimeField, UniformRand};
use ark_groth16::r1cs_to_qap::LibsnarkReduction as QAP;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension, Polynomial};
use ark_poly_commit::multilinear_pc::MultilinearPC;
use ark_r1cs_std::{
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::{AllocVar, FieldVar},
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::log2;
use ark_std::rand::Rng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};

const MESSAGE_LENGTH: usize = 1 << 16;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

/// A multistage circuit
/// Stage 1. Witness the evaluations on Boolean Hypercube of polynomial.
/// Stage 2. Prove evaluation at a random point chosen in a Fiat-Shamir way.
#[derive(Clone)]
struct PolyEvalCircuit {
    // A polynomial that is committed in stage 0.
    pub polynomial: Vec<F>,

    // The variable corresponding to `polynomial` that is generated after stage 0.
    pub polynomial_var: Option<Vec<FpVar<F>>>,

    // The evaluation point for the polynomial (a vector of log N points in multilinear case).
    pub point: Option<Vec<F>>,

    // The evaluation of `self.polynomial` at `self.root`.
    pub evaluation: Option<F>,
}

impl PolyEvalCircuit {
    fn new(polynomial: Vec<F>) -> Self {
        Self {
            polynomial,
            polynomial_var: None,
            point: None,
            evaluation: None,
        }
    }

    fn rand(mut rng: impl Rng) -> Self {
        // Sample a random multilinear polynomial of the correct degree.
        let degree = MESSAGE_LENGTH;
        let polynomial = (0..degree).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
        Self::new(polynomial)
    }

    fn add_point(&mut self, point: Vec<F>) {
        use ark_std::Zero;
        self.point = Some(point.clone());
        let mle =
            DenseMultilinearExtension::from_evaluations_vec(point.len(), self.polynomial.clone());

        self.evaluation = mle.evaluate(&point);
    }

    fn stage_0(&mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let polynomial_var = self
            .polynomial
            .iter()
            .map(|c| FpVar::new_witness(ns!(cs, "evaluation"), || Ok(c)))
            .collect::<Result<Vec<_>, _>>()?;
        self.polynomial_var = Some(polynomial_var);

        Ok(())
    }

    fn stage_1(&mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let num_vars = log2(self.polynomial.len()) as usize;
        let mut point = Vec::new();
        for i in 0..num_vars {
            point.push(FpVar::new_input(ns!(cs, "point"), || {
                Ok(self.point.as_ref().unwrap()[i])
            })?);
        }

        let evaluation = FpVar::new_input(ns!(cs, "point"), || Ok(self.evaluation.unwrap()))?;

        let mut eq_polynomial_evaluation_stages = vec![vec![FpVar::one()]];
        // Progressively build up eq polynomial evaluations.
        for p in point {
            let mut next_stage = Vec::new();
            for e in eq_polynomial_evaluation_stages.last().unwrap() {
                next_stage.push((FpVar::one() - &p) * e);
            }
            for e in eq_polynomial_evaluation_stages.last().unwrap() {
                next_stage.push(&p * e);
            }
            eq_polynomial_evaluation_stages.push(next_stage);
        }

        let claimed_eval = eq_polynomial_evaluation_stages
            .last()
            .unwrap()
            .iter()
            .zip(self.polynomial_var.as_ref().unwrap())
            .fold(FpVar::zero(), |acc, (x, y)| acc + x * y);

        // Assert that it's a root
        claimed_eval.enforce_equal(&evaluation)?;
        Ok(())
    }
}

impl MultiStageConstraintSynthesizer<F> for PolyEvalCircuit {
    fn total_num_stages(&self) -> usize {
        2
    }

    fn generate_constraints(
        &mut self,
        stage: usize,
        cs: &mut MultiStageConstraintSystem<F>,
    ) -> Result<(), SynthesisError> {
        let out = match stage {
            0 => cs.synthesize_with(|c| self.stage_0(c)),
            1 => cs.synthesize_with(|c| self.stage_1(c)),
            _ => panic!("unexpected stage stage {}", stage),
        };

        out
    }
}

fn main() {
    assert!(
        MESSAGE_LENGTH.is_power_of_two(),
        "Circuit does not yet support non-power of 2 messages",
    );
    let num_vars = log2(MESSAGE_LENGTH) as usize;

    let mut rng = ark_std::test_rng();
    let circuit = PolyEvalCircuit::rand(&mut rng);

    // Sanity check the circuit/get constraint counts
    {
        let mut circuit = circuit.clone();
        let mut cs = MultiStageConstraintSystem::default();
        circuit.generate_constraints(0, &mut cs).unwrap();
        let point = (0..num_vars).map(|_| F::rand(&mut rng)).collect();
        circuit.add_point(point);
        circuit.generate_constraints(1, &mut cs).unwrap();
        println!("Num constraints: {:?}", cs.num_constraints());
        println!(
            "Constraints per byte: {:?}",
            cs.num_constraints() as f64 / MESSAGE_LENGTH as f64
        );
    }

    // Setup
    let start = ark_std::time::Instant::now();
    let pk = generate_parameters::<_, E, QAP>(circuit.clone(), &mut rng).unwrap();
    println!("Groth16 setup: {} s", start.elapsed().as_secs_f64());

    let mut rng = ark_std::test_rng();
    let mut cb = CommitmentBuilder::<_, E, QAP>::new(circuit, &pk);

    let start = ark_std::time::Instant::now();
    let mpc_params = MultilinearPC::<E>::setup(num_vars, &mut rng);
    let (mpc_ck, mpc_vk) = MultilinearPC::<E>::trim(&mpc_params, num_vars);
    println!("PCS setup: {} s", start.elapsed().as_secs_f64());

    // Commit
    let start = ark_std::time::Instant::now();
    let (comm, rand) = cb.commit(&mut rng).unwrap();
    println!("Groth16 commit: {} s", start.elapsed().as_secs_f64());
    println!("Groth16 Commitment value is: {:?}", comm);

    // Build the MLE polynomial for commitment
    let mle_poly =
        DenseMultilinearExtension::from_evaluations_vec(num_vars, cb.circuit.polynomial.clone());
    let start = ark_std::time::Instant::now();
    let mpc_comm = MultilinearPC::<E>::commit(&mpc_ck, &mle_poly);
    println!("PCS commit: {} s", start.elapsed().as_secs_f64());

    // Derive challenge point (Fiat-Shamir)
    let point = {
        let mut hasher = Sha256::new();
        let mut buf = Vec::new();
        comm.serialize_compressed(&mut buf).unwrap();
        hasher.update(&buf);
        buf.clear();
        mpc_comm.serialize_compressed(&mut buf).unwrap();
        hasher.update(&buf);
        let seed = hasher.finalize();
        let mut cp_rng = rand::rngs::StdRng::from_seed(seed.into());
        (0..num_vars)
            .map(|_| F::rand(&mut cp_rng))
            .collect::<Vec<_>>()
    };
    let start = ark_std::time::Instant::now();
    cb.circuit.add_point(point.clone());
    println!(
        "Point derivation (add_point): {} s",
        start.elapsed().as_secs_f64()
    );

    // Prove / Open
    let mut inputs = point.clone();
    inputs.push(cb.circuit.evaluation.unwrap());
    let evaluation = cb.circuit.evaluation.unwrap();

    let start = ark_std::time::Instant::now();
    let proof = cb.prove(&[comm], &[rand], &mut rng).unwrap();
    println!("Groth16 prove: {} s", start.elapsed().as_secs_f64());

    let start = ark_std::time::Instant::now();
    let mpc_proof = MultilinearPC::<E>::open(&mpc_ck, &mle_poly, &point);
    println!("PCS open: {} s", start.elapsed().as_secs_f64());

    // Verify
    let start = ark_std::time::Instant::now();
    let pvk = prepare_verifying_key(&pk.vk());
    assert!(verify_proof(&pvk, &proof, &inputs).unwrap());

    // Re-derive point from the commitment embedded in the proof and the
    // MultilinearPC commitment to confirm the challenge was formed correctly.
    let claimed_point = {
        let mut hasher = Sha256::new();
        let mut buf = Vec::new();
        proof.ds[0].serialize_compressed(&mut buf).unwrap();
        hasher.update(&buf);
        buf.clear();
        mpc_comm.serialize_compressed(&mut buf).unwrap();
        hasher.update(&buf);
        let seed = hasher.finalize();
        let mut cp_rng = rand::rngs::StdRng::from_seed(seed.into());
        (0..num_vars)
            .map(|_| F::rand(&mut cp_rng))
            .collect::<Vec<_>>()
    };
    assert_eq!(claimed_point, inputs[0..num_vars]);
    println!("CP-Groth16 verify: {} s", start.elapsed().as_secs_f64());

    let start = ark_std::time::Instant::now();
    assert!(
        MultilinearPC::<E>::check(&mpc_vk, &mpc_comm, &point, evaluation, &mpc_proof),
        "MultilinearPC verification failed"
    );
    println!("MultilinearPC verify: {} s", start.elapsed().as_secs_f64());
}
