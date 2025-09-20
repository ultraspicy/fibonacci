


//! Prover inputs for Alignment Circuits

use fxhash::FxHashMap as HashMap;
use crate::ir::term::Value;
use rug::Integer;
use crate::bignat::bignatwithlimbmax::{BigNatWithLimbMax, BigNatbWithLimbMax, BigNatModMultWithLimbMax}; //, BigNatExponWithLimbMax};

use crate::commitment::{Poseidon};


#[cfg(feature = "spartan")]
use crate::right_field_arithmetic::alloc::{map_field, map_field_vec, map_field_double_vec};
#[cfg(feature = "spartan")]
use std::sync::Arc;

#[cfg(feature = "spartan")]
use core::ops::Mul;
use std::path::PathBuf;

use std::time::Instant;
use crate::util::timer::print_time;
use crate::bignat::bignat_adv::BigNatInit;


const FRAME_HEIGHT: usize = 24;
const FRAME_WIDTH: usize = 32;

#[cfg(feature = "spartan")]
/// Prover input for basic freivalds (1 matrix multiplication) variant.
pub fn prover_input_for_freivalds(modulus: &Arc<Integer>) -> HashMap<String, Value>{
    let mut original_frame = vec![vec![Integer::from(0); FRAME_WIDTH]; FRAME_HEIGHT];
    let mut result_frame = vec![vec![Integer::from(0); FRAME_WIDTH]; FRAME_HEIGHT];

    let mut r = vec![Integer::from(0); FRAME_HEIGHT];
    let mut r_transpose_a = vec![Integer::from(0); FRAME_HEIGHT];

    let mut input_map = HashMap::<String, Value>::default();
    map_field_double_vec(&original_frame, modulus, "original_frame", &mut input_map);
    map_field_vec(&r_transpose_a, modulus, "rta", &mut input_map);
    map_field_double_vec(&result_frame, modulus, "result_frame", &mut input_map);
    map_field_vec(&r, modulus, "r", &mut input_map);

    input_map
}


#[cfg(feature = "spartan")]
pub fn verifier_input_for_freivalds(modulus: &Arc<Integer>) -> HashMap<String, Value>{
    let mut input_map = HashMap::<String, Value>::default();

    map_field(&Integer::from(0), modulus, "return", &mut input_map);

    input_map
}