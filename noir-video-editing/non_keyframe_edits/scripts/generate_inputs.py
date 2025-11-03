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
    max_delta_len = len(prover_inputs['delta_batches'])
    delta_batch_size = len(prover_inputs['delta_batches'][0])
    # Reflects the empirical distribution of deltas we found.
    delta_batches = [[str(random.randint(0, 7)) for _ in range(delta_batch_size)] for __ in range(max_delta_len)]
    delta_is = [str(random.randint(0, image_height - 1)) for _ in range(max_delta_len)]
    delta_js = [[str(random.randint(0, image_width - 1)) for _ in range(delta_batch_size)] for __ in range(max_delta_len)]

    transformed_delta_batches = delta_batches.copy()
    transformed_delta_is = delta_is.copy()
    transformed_delta_js = delta_js.copy()
    
    r = [str(random.randint(0, 2**250-1)) for _ in range(image_height)]
    rTA = r.copy()
    s = [str(random.randint(0, 2**250-1)) for _ in range(image_width)]
    As = s.copy()

    prover_inputs['delta_batches'] = delta_batches
    prover_inputs['delta_is'] = delta_is
    prover_inputs['delta_js'] = delta_js
    prover_inputs['transformed_delta_batches'] = transformed_delta_batches
    prover_inputs['transformed_delta_is'] = transformed_delta_is
    prover_inputs['transformed_delta_js'] = transformed_delta_js
    prover_inputs['r'] = r
    prover_inputs['s'] = s
    prover_inputs['rTA'] = rTA
    prover_inputs['As'] = As

    with config_path.open("wb") as f:
        f.write(tomli_w.dumps(prover_inputs).encode("utf-8"))

if __name__ == "__main__":
    main()