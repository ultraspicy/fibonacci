import json
import toml
import os
import glob
from typing import Dict, List, Any

# --- Core Function (Retained from previous step) ---

def generate_prover_toml_2d(json_filepath: str, toml_filepath: str):
    """
    Loads JSON data from a file and generates a Prover.toml file,
    keeping the image data as a 2D list of strings, including all placeholders.
    """
    print(f"Processing: {json_filepath} -> {toml_filepath}")
    
    # 1. Load the JSON data directly from the file
    try:
        with open(json_filepath, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"❌ Error: JSON file not found at {json_filepath}")
        return
    except json.JSONDecodeError as e:
        print(f"❌ Error: Could not decode JSON. Details: {e}")
        return

    # 2. Extract the 'data' field (2D list of strings)
    image_data_2d: List[List[str]] = data.get("data", [])
            
    # 3. Construct the complete TOML structure with required empty placeholders
    toml_data: Dict[str, Any] = {
        "original_image": image_data_2d,
        "target_middle_image": [],
        "edited_image": [],
        "r": [],
        "s": [],
        "rTA": [],
        "As": []
    }

    # 4. Write the TOML data to the output file
    try:
        with open(toml_filepath, 'w') as f:
            toml.dump(toml_data, f)
            f.write('\n')
            
    except Exception as e:
        print(f"❌ Error writing TOML file: {e}")
        return

# --- Batch Processing Logic ---

def process_all_images(input_dir: str = "outputs/channel_R_json_files", 
                       output_base_dir: str = "outputs/prover_input"):
    
    os.makedirs(output_base_dir, exist_ok=True)
    
  
    search_pattern = os.path.join(input_dir, "image_*.json")
    json_files = sorted(glob.glob(search_pattern))
    
    if not json_files:
        print(f"⚠️ No JSON files found matching pattern: {search_pattern}")
        return

    print(f"✅ Found {len(json_files)} image files to process.")
    print("-" * 40)

    for json_filepath in json_files:
        # Get the base filename (e.g., 'image_0001.json')
        base_filename = os.path.basename(json_filepath)
        
        # Create a new, unique output filename (e.g., 'Prover_0001.toml')
        # Replaces 'image_' with 'Prover_' and changes the extension to '.toml'
        output_filename = base_filename.replace("image_", "Prover_").replace(".json", ".toml")
        
        # Construct the full output path
        output_filepath = os.path.join(output_base_dir, output_filename)
        
        # Run the generation function
        generate_prover_toml_2d(json_filepath, output_filepath)
        
    print("-" * 40)
    print("✨ Batch processing complete!")

process_all_images()