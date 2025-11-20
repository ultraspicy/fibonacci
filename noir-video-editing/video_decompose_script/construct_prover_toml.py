import json
import toml
import os
import glob
from typing import Dict, List, Any

# --- Core Functions ---

def generate_prover_toml_2d(json_filepath: str, toml_filepath: str):
    """
    Loads JSON data from a file and generates a Prover.toml file,
    keeping the image data as a 2D list of strings, including all placeholders.
    """
    print(f"Processing TOML: {json_filepath} -> {toml_filepath}")
    
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


def generate_rust_readable_matrix(json_filepath: str, output_filepath: str):
    """
    Loads JSON data and generates a whitespace-separated text file 
    that can be read by the Rust read_file_as_vec function.
    
    Format: Each row on a new line, values separated by spaces.
    """
    print(f"Processing Matrix: {json_filepath} -> {output_filepath}")
    
    # 1. Load the JSON data
    try:
        with open(json_filepath, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"❌ Error: JSON file not found at {json_filepath}")
        return
    except json.JSONDecodeError as e:
        print(f"❌ Error: Could not decode JSON. Details: {e}")
        return

    # 2. Extract the 'data' field (2D list)
    image_data_2d = data.get("data", [])
    
    # 3. Write as whitespace-separated text
    try:
        with open(output_filepath, 'w') as f:
            for row in image_data_2d:
                # Join each row's values with spaces
                row_str = ' '.join(str(pixel) for pixel in row)
                f.write(row_str + '\n')
                
        print(f"✅ Matrix file written: {output_filepath}")
        
    except Exception as e:
        print(f"❌ Error writing matrix file: {e}")
        return


# --- Batch Processing Logic ---

def process_all_images(input_dir: str, 
                       output_toml_dir: str,
                       output_matrix_dir: str,
                       channel: str):
    """
    Process all JSON files in input directory.
    
    Args:
        input_dir: Directory containing image_*.json files
        output_toml_dir: Directory for TOML output files
        output_matrix_dir: Directory for matrix text files
        channel: Channel identifier (R, G, or B)
    """
    
    os.makedirs(output_toml_dir, exist_ok=True)
    os.makedirs(output_matrix_dir, exist_ok=True)
    
    # Find all JSON files
    search_pattern = os.path.join(input_dir, "image_*.json")
    json_files = sorted(glob.glob(search_pattern))
    
    if not json_files:
        print(f"⚠️ No JSON files found matching pattern: {search_pattern}")
        return

    print(f"✅ Found {len(json_files)} image files to process.")
    print(f"📝 Channel: {channel}")
    print("-" * 60)

    for json_filepath in json_files:
        # Get the base filename (e.g., 'image_0001.json')
        base_filename = os.path.basename(json_filepath)
        
        # Extract frame number (e.g., '0001' from 'image_0001.json')
        frame_number = base_filename.replace("image_", "").replace(".json", "")
        
        # --- Output 1: TOML file ---
        toml_filename = f"Prover_{frame_number}_{channel}.toml"
        toml_filepath = os.path.join(output_toml_dir, toml_filename)
        generate_prover_toml_2d(json_filepath, toml_filepath)
        
        # --- Output 2: Rust-readable matrix file ---
        matrix_filename = f"output_{frame_number}_{channel}.txt"
        matrix_filepath = os.path.join(output_matrix_dir, matrix_filename)
        generate_rust_readable_matrix(json_filepath, matrix_filepath)
        
        print()  # Blank line between files
        
    print("-" * 60)
    print("✨ Batch processing complete!")
    print(f"📁 TOML output directory: {output_toml_dir}")
    print(f"📁 Matrix output directory: {output_matrix_dir}")


# --- Main Execution ---
if __name__ == "__main__":
    # Process R channel
    process_all_images(
        input_dir="outputs/channel_R_json_files",
        output_toml_dir="outputs/prover_input",
        output_matrix_dir="outputs/matrix_files",
        channel="R"
    )
    
    # Process G channel
    process_all_images(
        input_dir="outputs/channel_G_json_files",
        output_toml_dir="outputs/prover_input",
        output_matrix_dir="outputs/matrix_files",
        channel="G"
    )
    
    # Process B channel
    process_all_images(
        input_dir="outputs/channel_B_json_files",
        output_toml_dir="outputs/prover_input",
        output_matrix_dir="outputs/matrix_files",
        channel="B"
    )
