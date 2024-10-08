import numpy as np
import matplotlib.pyplot as plt

def dft2d(image):
    M, N = image.shape
    F = np.zeros((M, N), dtype=np.complex128)
    for u in range(M):
        for v in range(N):
            sum_val = 0
            for x in range(M):
                for y in range(N):
                    e_power = -2j * np.pi * ((u*x/M) + (v*y/N))
                    sum_val += image[x, y] * np.exp(e_power)
            F[u, v] = sum_val
    
    return F

def load_data_from_file(filename):
    data = []
    with open(filename, 'r') as file:
        for line in file:
            # Split the line into individual numbers and convert to integers
            numbers = [int(num) for num in line.strip().split()]
            data.extend(numbers)
    return np.array(data)

def visualize_dft(image, dft_result):
    fig, axs = plt.subplots(2, 2, figsize=(12, 12))
    
    # Original image
    axs[0, 0].imshow(image, cmap='gray')
    axs[0, 0].set_title('Original Image')
    axs[0, 0].axis('off')
    
    # Magnitude spectrum
    magnitude_spectrum = np.abs(dft_result)
    magnitude_spectrum = np.fft.fftshift(magnitude_spectrum)
    magnitude_spectrum = np.log1p(magnitude_spectrum)
    
    axs[0, 1].imshow(magnitude_spectrum, cmap='viridis')
    axs[0, 1].set_title('Magnitude Spectrum')
    axs[0, 1].axis('off')
    
    # Phase spectrum
    phase_spectrum = np.angle(dft_result)
    phase_spectrum = np.fft.fftshift(phase_spectrum)
    
    axs[1, 0].imshow(phase_spectrum, cmap='hsv')
    axs[1, 0].set_title('Phase Spectrum')
    axs[1, 0].axis('off')
    
    # Reconstructed image
    reconstructed = np.real(np.fft.ifft2(dft_result))
    
    axs[1, 1].imshow(reconstructed, cmap='gray')
    axs[1, 1].set_title('Reconstructed Image')
    axs[1, 1].axis('off')
    
    plt.tight_layout()
    plt.show()


filename = './../resources/ffmpeg_original_frames_192_108/output_001_R.txt'
loaded_data = load_data_from_file(filename)
print(loaded_data.size)

# Compute 2D DFT
#dft_result = dft2d(image)

# Visualize results
#visualize_dft(image, dft_result)