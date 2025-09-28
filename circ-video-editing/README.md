# Examples for CirC based alignment circuits:

## Examples

### Basic Freivald's video editing:

Build:
    cargo run --release --example circ -- zok_src/video/freivalds_editing.zok r1cs --action setup --proof-impl dorian --pfcurve curve25519
Prove:
    cargo run --release --example run_zk -- --compute freivalds-video-edit --proof-impl dorian --pfcurve curve25519 --action prove
Verify:
    cargo run --release --example run_zk -- --compute freivalds-video-edit --proof-impl dorian --pfcurve curve25519 --action verify
