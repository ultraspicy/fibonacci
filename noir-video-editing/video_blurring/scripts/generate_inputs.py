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

    image_height = len(prover_inputs['original_image'])
    image_width = len(prover_inputs['original_image'][0])
    random_image = [[str(random.randint(0, 255)) for _ in range(image_width)] for _ in range(image_height)]
    edited_image = random_image.copy()
    r = [str(random.randint(0, 2**250-1)) for _ in range(image_height)]
    rTA = r.copy()
    s = [str(random.randint(0, 2**250-1)) for _ in range(image_width)]
    As = s.copy()

    prover_inputs['original_image'] = random_image
    prover_inputs['edited_image'] = edited_image
    prover_inputs['r'] = r
    prover_inputs['s'] = s
    prover_inputs['rTA'] = rTA
    prover_inputs['As'] = As

    with config_path.open("wb") as f:
        f.write(tomli_w.dumps(prover_inputs).encode("utf-8"))

if __name__ == "__main__":
    main()