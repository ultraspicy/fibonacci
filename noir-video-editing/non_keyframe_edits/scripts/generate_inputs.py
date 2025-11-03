#!/usr/bin/env python3
import pathlib
import random
import sys
import tomllib
import tomli_w

def main():
    # Path to Prover.toml
    config_path = pathlib.Path("Prover.toml")

    if not config_path.exists():
        sys.stderr.write(f"Error: {config_path} does not exist.\n")
        sys.exit(1)

    # Open TOML file
    with config_path.open("rb") as f:
        prover_inputs = tomllib.load(f)

    image_height = len(prover_inputs['rTA'])
    image_width = len(prover_inputs['As'])
    delta_len = len(prover_inputs['delta'][0])
    # Reflects the empirical distribution of deltas we found.
    random_deltas = [str(random.randint(0, 7)) for _ in range(delta_len)]
    random_i_indices = [str(random.randint(0, image_height - 1)) for _ in range(delta_len)]
    random_j_indices = [str(random.randint(0, image_width - 1)) for _ in range(delta_len)]
    delta = [random_deltas, random_i_indices, random_j_indices]
    transformed_delta = delta.copy()
    r = [str(random.randint(0, 2**250-1)) for _ in range(image_height)]
    rTA = r.copy()
    s = [str(random.randint(0, 2**250-1)) for _ in range(image_width)]
    As = s.copy()

    prover_inputs['delta'] = delta
    prover_inputs['transformed_delta'] = transformed_delta
    prover_inputs['r'] = r
    prover_inputs['s'] = s
    prover_inputs['rTA'] = rTA
    prover_inputs['As'] = As

    with config_path.open("wb") as f:
        f.write(tomli_w.dumps(prover_inputs).encode("utf-8"))

if __name__ == "__main__":
    main()