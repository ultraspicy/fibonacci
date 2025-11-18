This directory contains the code for the polynomial commitment-based signatures described in Section 6
of our paper. This directory contains files implementing different variants of the signature scheme 
for multilinear and univariate polynomials.

`outsourced_signature_benchmarks` produces the data for Figure 5 in the paper.
These 4 files produce the data for Tables 3 and 4 in the paper:
- `video_trimming_demo.rs`
- `video_trimming_demo_multi.rs`
- `sumcheck_redactable_signatures.rs`
- `merkle_tree_redactable_signatures.rs`

Run the benchmarks for this section with `./run_benchmarks.sh`. Note that this may require Rust nightly.