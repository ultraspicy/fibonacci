import cv2
import numpy as np
import json
from pathlib import Path

def read_png(image_path):
    """Read a single grayscale PNG and return as matrix."""
    matrix = cv2.imread(str(image_path), cv2.IMREAD_GRAYSCALE)
    if matrix is None:
        raise ValueError(f"Could not read image: {image_path}")
    return matrix

def serialize_image_to_file(image_path, output_path, index, as_strings=True):
    """
    Read a single image and serialize it to a JSON file.
    
    Args:
        image_path: Path to input PNG file
        output_path: Path to output JSON file
        index: Image index number
        as_strings: if True, convert pixel values to strings (for ZKP)
    
    Returns:
        Size of the created JSON file in bytes
    """
    # Read the image
    image = read_png(image_path)
    
    # Convert to list and optionally stringify
    if as_strings:
        data = [[str(pixel) for pixel in row] for row in image]
    else:
        data = image.tolist()
    
    # Create metadata for this image
    json_data = {
        "index": index,
        "shape": list(image.shape),
        "dtype": str(image.dtype),
        "data": data
    }
    
    # Save to JSON file
    with open(output_path, 'w') as f:
        json.dump(json_data, f, indent=2)
    
    return output_path.stat().st_size

def serialize_directory_streaming(input_dir, output_dir, as_strings=True):
    """
    Serialize all PNGs in directory to separate JSON files.
    Processes one image at a time to minimize memory usage.
    
    Args:
        input_dir: directory containing PNG files
        output_dir: directory to save JSON files
        as_strings: if True, convert pixel values to strings (for ZKP)
    """
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Get all PNG files, sorted
    png_files = sorted(input_path.glob('*.png'))
    
    if not png_files:
        raise ValueError(f"No PNG files found in {input_dir}")
    
    num_images = len(png_files)
    total_size = 0
    
    print(f"Found {num_images} PNG files in {input_dir}")
    print(f"Processing one at a time to minimize memory usage...\n")
    
    for i, png_file in enumerate(png_files):
        # Process this single image
        output_file = output_path / f"image_{i:04d}.json"
        
        try:
            file_size = serialize_image_to_file(
                image_path=png_file,
                output_path=output_file,
                index=i,
                as_strings=as_strings
            )
            
            total_size += file_size
            
            # Progress update
            if (i + 1) % 10 == 0 or i == num_images - 1:
                print(f"Progress: {i + 1}/{num_images} files processed "
                      f"({((i + 1) / num_images * 100):.1f}%)")
                
        except Exception as e:
            print(f"Error processing {png_file}: {e}")
            continue
    
    # Final statistics
    total_size_mb = total_size / (1024 * 1024)
    avg_size_kb = (total_size / num_images) / 1024
    
    print(f"\n{'='*60}")
    print(f"Serialization complete!")
    print(f"{'='*60}")
    print(f"Input directory: {input_path}")
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


def process_channel(channel):
    """
    Process a single channel (R, G, or B).
    
    Args:
        channel: Channel identifier ('R', 'G', or 'B')
    """
    channel_dir = f'./outputs/video_decomposition/rgb_channels/channel_{channel}'
    output_dir = f'./outputs/channel_{channel}_json_files'
    
    print(f"\n{'='*60}")
    print(f"Processing Channel: {channel}")
    print(f"{'='*60}\n")
    
    if Path(channel_dir).exists():
        # Serialize using streaming approach (one image at a time)
        serialize_directory_streaming(channel_dir, output_dir, as_strings=True)
        
        print(f"\n--- Verifying Channel {channel}: Loading back from JSON files ---")
        # Load it back and print size
        loaded_array = deserialize_from_separate_files(output_dir)
        
        # Additional size information
        print(f"Total elements: {loaded_array.size:,}")
        print(f"Shape breakdown: {loaded_array.shape[0]} frames × "
              f"{loaded_array.shape[1]} height × {loaded_array.shape[2]} width")
        
    else:
        print(f"Directory not found: {channel_dir}")
        print("Please run the video decomposer first to generate images.")


if __name__ == '__main__':
    # Process all three channels
    channels = ['R', 'G', 'B']
    
    for channel in channels:
        process_channel(channel)
    
    print(f"\n{'='*60}")
    print("✨ All channels processed!")
    print(f"{'='*60}")
