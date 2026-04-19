// Code adapted from: https://github.com/Pratyush/hekaton-system/blob/main/cp-groth16/benches/bench.rs

use ark_bls12_381::{Bls12_381 as E, Fr as F};
use ark_cp_groth16::{
    committer::CommitmentBuilder,
    generator::generate_parameters,
    verifier::{prepare_verifying_key, verify_proof},
    MultiStageConstraintSynthesizer, MultiStageConstraintSystem,
};
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_ff::{FftField, Field, One, PrimeField, UniformRand};
use ark_groth16::r1cs_to_qap::LibsnarkReduction as QAP;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{
    DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain,
};
use ark_poly_commit::{
    challenge::ChallengeGenerator, marlin::marlin_pc::MarlinKZG10, LabeledPolynomial,
    PolynomialCommitment,
};
use ark_r1cs_std::{
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::{AllocVar, FieldVar},
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use ark_serialize::CanonicalSerialize;
use ark_std::log2;
use ark_std::rand::Rng;
use ark_std::Zero;
use sha2::{Digest, Sha256};

type KZG = MarlinKZG10<E, DensePolynomial<F>, PoseidonSponge<F>>;

const MESSAGE_LENGTH: usize = 1 << 16;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

/// A multistage circuit
/// Stage 1. Witness the coefficients of the polynomial.
/// Stage 2. Prove that the polynomial evaluates to a given value at a random point derived in an F-S way from the coefficients.
#[derive(Clone)]
struct BarycentricEvalCircuit {
    // Evaluations of the polynomial over a two-adic subgroup (I do not like that term)
    pub evaluations: Vec<F>,

    // The variable corresponding to `evaluations` that is generated after stage 0.
    pub evaluations_var: Option<Vec<FpVar<F>>>,

    // The evaluation point for the polynomial. Derived via Fiat-Shamir + Commit and Prove.
    pub point: Option<F>,

    // The evaluation of the interpolated polynomial at `self.root`.
    pub result: Option<F>,
}

impl BarycentricEvalCircuit {
    fn new(evaluations: Vec<F>) -> Self {
        Self {
            evaluations,
            evaluations_var: None,
            point: None,
            result: None,
        }
    }

    fn rand(mut rng: impl Rng) -> Self {
        // Sample a random polynomial of degree MESSAGE_LENGTH - 1
        let evals_length = MESSAGE_LENGTH;
        let evaluations = (0..evals_length)
            .map(|_| F::rand(&mut rng))
            .collect::<Vec<_>>();
        Self::new(evaluations)
    }

    fn add_point(&mut self, point: F) {
        use ark_std::Zero;
        self.point = Some(point);

        let degree = self.evaluations.len().next_power_of_two();
        let degree_bits = log2(degree);

        let mut omega = F::TWO_ADIC_ROOT_OF_UNITY;
        for _ in degree_bits..F::TWO_ADICITY {
            omega = omega.square();
        }

        // Will contain powers of omega needed for sum
        let mut omega_acc = F::one();
        // Running sum:
        let mut sum = F::zero();

        // Simple version: compute each term individually
        for i in 0..self.evaluations.len() {
            let numerator = self.evaluations[i] * omega_acc;
            let denominator = point - omega_acc;

            // Direct inversion for each denominator (no batching)
            let inverted_denominator = denominator.inverse().unwrap();
            sum += numerator * inverted_denominator;

            omega_acc *= omega;
        }

        let front_quantity = (&point.pow(&[degree as u64]) - &F::one()) / &F::from(degree as u64);

        self.result = Some(front_quantity * sum);
    }

    fn stage_0(&mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let evaluations_var = self
            .evaluations
            .iter()
            .map(|c| FpVar::new_witness(ns!(cs, "eval"), || Ok(c)))
            .collect::<Result<Vec<_>, _>>()?;
        self.evaluations_var = Some(evaluations_var);

        Ok(())
    }

    fn stage_1(&mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let point = FpVar::new_input(ns!(cs, "point"), || Ok(self.point.unwrap()))?;
        let result = FpVar::new_input(ns!(cs, "point"), || Ok(self.result.unwrap()))?;

        let degree = self.evaluations.len().next_power_of_two();
        let degree_bits = log2(degree);
        let mut omega = F::TWO_ADIC_ROOT_OF_UNITY;
        for _ in degree_bits..F::TWO_ADICITY {
            omega = omega.square();
        }
        let omega_var = FpVar::new_constant(ns!(cs, "eval"), omega)?;

        // Will contain powers of omega needed for sum
        let mut omega_acc = FpVar::new_constant(ns!(cs, "eval"), F::one())?;
        // Running sum:
        let mut sum = FpVar::new_constant(ns!(cs, "eval"), F::zero())?;

        // Simple version: compute each term individually
        for i in 0..self.evaluations.len() {
            let numerator = &self.evaluations_var.as_ref().unwrap()[i] * &omega_acc;
            let denominator = &point - &omega_acc;

            // Direct inversion for each denominator (no batching)
            let inverted_denominator = &denominator.inverse().unwrap();
            sum += &numerator * inverted_denominator;

            omega_acc *= &omega_var;
        }

        let front_quantity = (point.pow_by_constant(&[degree as u64])? - F::one())
            * FpVar::new_constant(ns!(cs, "eval"), F::from(degree as u64))
                .unwrap()
                .inverse()
                .unwrap();

        let claimed_eval = front_quantity * sum;

        // // Assert that it's a root
        claimed_eval.enforce_equal(&result)?;
        Ok(())
    }
}

impl MultiStageConstraintSynthesizer<F> for BarycentricEvalCircuit {
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
    let mut rng = ark_std::test_rng();
    let circuit = BarycentricEvalCircuit::rand(&mut rng);

    // Sanity-check the circuit/get constraint counts
    {
        let mut circuit = circuit.clone();
        let mut cs = MultiStageConstraintSystem::default();
        circuit.generate_constraints(0, &mut cs).unwrap();
        let point = F::rand(&mut rng);
        circuit.add_point(point);
        circuit.generate_constraints(1, &mut cs).unwrap();
        println!("Num constraints: {:?}", cs.num_constraints());
        println!(
            "Constraints per field element: {:?}",
            cs.num_constraints() / MESSAGE_LENGTH
        );
    }

    // Setup
    let start = ark_std::time::Instant::now();
    let pk = generate_parameters::<_, E, QAP>(circuit.clone(), &mut rng).unwrap();
    println!("Groth16 setup: {} s", start.elapsed().as_secs_f64());

    let mut rng = ark_std::test_rng();
    let mut cb = CommitmentBuilder::<_, E, QAP>::new(circuit, &pk);

    let domain = Radix2EvaluationDomain::<F>::new(cb.circuit.evaluations.len()).unwrap();
    let degree = domain.size() - 1;
    let start = ark_std::time::Instant::now();
    let pp = KZG::setup(degree, None, &mut rng).unwrap();
    let (ck, vk) = KZG::trim(&pp, degree, 1, None).unwrap();
    println!("KZG setup: {} s", start.elapsed().as_secs_f64());

    // ── Commit ───────────────────────────────────────────────────────────────

    let start = ark_std::time::Instant::now();
    let (comm, rand) = cb.commit(&mut rng).unwrap();
    println!("Groth16 commit: {} s", start.elapsed().as_secs_f64());
    println!("Groth16 Commitment value is: {:?}", comm);

    // Interpolate via IFFT to get the coefficient-form polynomial for KZG.
    let kzg_poly =
        Evaluations::from_vec_and_domain(cb.circuit.evaluations.clone(), domain).interpolate();
    let labeled_poly = LabeledPolynomial::new("poly".to_string(), kzg_poly, None, None);
    let start = ark_std::time::Instant::now();
    let (kzg_comms, kzg_rands) = KZG::commit(&ck, &[labeled_poly.clone()], Some(&mut rng)).unwrap();
    println!("KZG commit: {} s", start.elapsed().as_secs_f64());

    // Derive point from both commitments (Fiat-Shamir)
    // Binding the challenge to both commitments prevents a prover from using
    // different polynomials in the two schemes.
    let point = {
        let mut hasher = Sha256::new();
        let mut buf = Vec::new();
        comm.serialize_compressed(&mut buf).unwrap();
        hasher.update(&buf);
        buf.clear();
        kzg_comms[0]
            .commitment()
            .serialize_compressed(&mut buf)
            .unwrap();
        hasher.update(&buf);
        F::from_be_bytes_mod_order(&hasher.finalize())
    };
    let start = ark_std::time::Instant::now();
    cb.circuit.add_point(point);
    println!(
        "Point derivation (add_point): {} s",
        start.elapsed().as_secs_f64()
    );

    // Prove / Open

    let inputs = [point, cb.circuit.result.unwrap()];
    let start = ark_std::time::Instant::now();
    let proof = cb.prove(&[comm], &[rand], &mut rng).unwrap();
    println!("Groth16 prove: {} s", start.elapsed().as_secs_f64());

    let challenge_gen_seed = F::rand(&mut rng);
    // This challenge generator has to do with batched openings, not super important.
    let mut open_cgen = ChallengeGenerator::<F, PoseidonSponge<F>>::Univariate(
        challenge_gen_seed,
        challenge_gen_seed,
    );
    let start = ark_std::time::Instant::now();
    let kzg_proof = KZG::open(
        &ck,
        &[labeled_poly],
        &kzg_comms,
        &point,
        &mut open_cgen,
        &kzg_rands,
        None,
    )
    .unwrap();
    println!("KZG open: {} s", start.elapsed().as_secs_f64());

    // Verify

    let start = ark_std::time::Instant::now();
    let pvk = prepare_verifying_key(&pk.vk());
    assert!(verify_proof(&pvk, &proof, &inputs).unwrap());

    // Re-derive point from the commitment embedded in the proof and the KZG
    // commitment to confirm the challenge was formed correctly.
    let claimed_point = {
        let mut hasher = Sha256::new();
        let mut buf = Vec::new();
        proof.ds[0].serialize_compressed(&mut buf).unwrap();
        hasher.update(&buf);
        buf.clear();
        kzg_comms[0]
            .commitment()
            .serialize_compressed(&mut buf)
            .unwrap();
        hasher.update(&buf);
        F::from_be_bytes_mod_order(&hasher.finalize())
    };
    assert_eq!(claimed_point, inputs[0]);
    println!("CP-Groth16 verify: {} s", start.elapsed().as_secs_f64());

    let mut check_cgen = ChallengeGenerator::<F, PoseidonSponge<F>>::Univariate(
        challenge_gen_seed,
        challenge_gen_seed,
    );
    let start = ark_std::time::Instant::now();
    assert!(
        KZG::check(
            &vk,
            &kzg_comms,
            &point,
            std::iter::once(inputs[1]),
            &kzg_proof,
            &mut check_cgen,
            Some(&mut rng),
        )
        .unwrap(),
        "KZG verification failed"
    );
    println!("KZG verify: {} s", start.elapsed().as_secs_f64());
}
