import cv2
import numpy as np
import json
from pathlib import Path

def read_png(image_path):
    """Read a single grayscale PNG and return as matrix."""
    matrix = cv2.imread(str(image_path), cv2.IMREAD_GRAYSCALE)
    if matrix is None:
        raise ValueError(f"Could not read image: {image_path}")
    print(f"Loaded: {Path(image_path).name} - Shape: {matrix.shape}")
    return matrix

def read_directory(directory_path):
    """Read all PNGs from directory and return as list of matrices."""
    files = sorted(Path(directory_path).glob('*.png'))
    matrices = []
    
    print(f"Reading {len(files)} files from {directory_path}...")
    
    for file_path in files:
        matrix = read_png(file_path)
        matrices.append(matrix)
    
    print(f"Total loaded: {len(matrices)} images")
    return matrices

def read_as_array(directory_path):
    """Read all PNGs and stack into 3D array (n_images, height, width)."""
    matrices = read_directory(directory_path)
    array_3d = np.stack(matrices, axis=0)
    print(f"3D array shape: {array_3d.shape} (n_images, height, width)")
    return array_3d

def serialize_to_separate_files(array_3d, output_dir, as_strings=True):
    """
    Serialize each image in 3D array to separate JSON files.
    
    Args:
        array_3d: numpy array of shape (n_images, height, width)
        output_dir: directory to save JSON files
        as_strings: if True, convert pixel values to strings (for ZKP)
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    total_size = 0
    num_images = array_3d.shape[0]
    
    print(f"\nSerializing {num_images} images to separate JSON files...")
    
    for i, image in enumerate(array_3d):
        # Convert to list and optionally stringify
        if as_strings:
            data = [[str(pixel) for pixel in row] for row in image]
        else:
            data = image.tolist()
        
        # Create metadata for this image
        json_data = {
            "index": i,
            "shape": list(image.shape),
            "dtype": str(array_3d.dtype),
            "data": data
        }
        
        # Save to individual JSON file
        file_path = output_path / f"image_{i:04d}.json"
        with open(file_path, 'w') as f:
            json.dump(json_data, f, indent=2)
        
        file_size = file_path.stat().st_size
        total_size += file_size
        
        if (i + 1) % 10 == 0 or i == num_images - 1:
            print(f"Progress: {i + 1}/{num_images} files written")
    
    total_size_mb = total_size / (1024 * 1024)
    avg_size_kb = (total_size / num_images) / 1024
    
    print(f"\nSerialization complete!")
    print(f"Output directory: {output_path}")
    print(f"Total files: {num_images}")
    print(f"Total size: {total_size_mb:.2f} MB")
    print(f"Average file size: {avg_size_kb:.2f} KB")
    print(f"Format: {'String values' if as_strings else 'Numeric values'}")

def deserialize_from_separate_files(input_dir, as_array=True):
    """
    Load images from separate JSON files and optionally stack into 3D array.
    
    Args:
        input_dir: directory containing JSON files
        as_array: if True, return as stacked numpy array; if False, return as list
    """
    input_path = Path(input_dir)
    json_files = sorted(input_path.glob('image_*.json'))
    
    if not json_files:
        raise ValueError(f"No JSON files found in {input_dir}")
    
    print(f"Loading {len(json_files)} JSON files...")
    
    images = []
    for i, file_path in enumerate(json_files):
        with open(file_path, 'r') as f:
            json_data = json.load(f)
        
        data = json_data["data"]
        
        # Convert strings back to integers if needed
        if isinstance(data[0][0], str):
            data = [[int(pixel) for pixel in row] for row in data]
        
        images.append(data)
        
        if (i + 1) % 10 == 0 or i == len(json_files) - 1:
            print(f"Progress: {i + 1}/{len(json_files)} files loaded")
    
    if as_array:
        array_3d = np.array(images, dtype='uint8')
        print(f"\nLoaded array shape: {array_3d.shape}")
        print(f"Array memory size: {array_3d.nbytes / (1024 * 1024):.2f} MB")
        print(f"Array dtype: {array_3d.dtype}")
        return array_3d
    else:
        print(f"\nLoaded {len(images)} images as lists")
        return images


if __name__ == '__main__':
    
    channel_dir = './outputs/video_decomposition/rgb_channels/channel_R'
    output_dir = './outputs/channel_R_json_files'
    
    if Path(channel_dir).exists():
        # Read and serialize
        array_3d = read_as_array(channel_dir)
        print(f"Array dimensions: {array_3d.shape[0]} images of {array_3d.shape[1]}x{array_3d.shape[2]} pixels")
        
        # Serialize to separate JSON files
        serialize_to_separate_files(array_3d, output_dir, as_strings=True)
        
        print("\n--- Loading back from JSON files ---")
        # Load it back and print size
        loaded_array = deserialize_from_separate_files(output_dir)
        
        # Additional size information
        print(f"Total elements: {loaded_array.size:,}")
        print(f"Shape breakdown: {loaded_array.shape[0]} frames × {loaded_array.shape[1]} height × {loaded_array.shape[2]} width")
        
    else:
        print(f"Directory not found: {channel_dir}")
        print("Please run the video decomposer first to generate images.")
