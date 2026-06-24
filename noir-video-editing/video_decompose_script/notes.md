The key purpose is to prove that our own Rust implementation of Gblur, grayscale and resize is 
very close to what ffmpeg outputs.

The video is H.264 / yuv420p / 1280×720. 
 - H.264 is a video encoding scheme, it compress the video by throwing away some necessary info humans don't easily notice. 
 - yuv420p is the pixel format. We need to convert yuv420p to RGB. RGB is how we present pixels and feed data into circuit
 - 1280×720 is the video resolution

So the process from camera -> video -> oringal_frame0.png itself is not lossless. But it doesn't matter since what we try to
prove is that, using frame0_original.png as the starting point, our circuit's implmentation and ffmpeg has close outputs. The term
"lossless" means that we use PNG format to exactly preserve all info in output (either ffmpeg or our own impl).

We use the following command to extract the first frame. This frame is the source file.
```
ffmpeg -y -i short_video.mp4 -frames:v 1 -pix_fmt rgb24 frame0_original.png
```

We have two options to compare the diffs, assume the oringal picture X
 - option1: use python to reimplement the logic we rust code, concretly noir-video-editing/freivalds_vector_generator/src/main.rs for gblur and BT601 https://github.com/sashafrolov/Spartan2/blob/34edd8707e1d88b01f42588c4b783a8c439182e9/examples/implement_video_edit.rs#L22 grayscale. (in circuit we use field element so we cannot export the intermediaries directly)
 - option2: we run the ffmpeg to get the output Y = ffmpeg(X) first, then reserve engineering the filter F = reverse_ffmpeg(X, Y), then compare F(X) and Y

Correction: I mentioned we can almost perfectly match the gblur, this is wrong. I figured out I changed the source code of ffmpeg gblur locally then built it from source to exactly match our rust implementation while ago. That result was way too good to be true. Following option1 result are using the normal ffmpeg distribution:

If we go with option1
 - gblur has 51.2% exact pixel match (but we really need to tune the ffmpeg command) with max diff = 16. source code noir-video-editing/video_decompose_script/rust_reimplement_gblur.py
 - grayscale has 100% exact pixel match. source code noir-video-editing/video_decompose_script/rust_reimplement_grayscale.py
 - [attention] resize implemented in rust is very different from commmon numeric average approach. We use the right corner pixel while common ffmpeg use average of a rectangle. So comparison is meaningless. Result is 22% match with max diff = 51, due to the different resizing appraoch.  

If we go with option2, 
 -  Gaussian blur can exactly match 96.4% of pixels, with max pixel diff = 14. source file noir-video-editing/video_decompose_script/reverse_ffmpeg_filter.py
 - │Grayscale match 100% pixels without any drift. source file noir-video-editing/video_decompose_script/reverse_ffmpeg_grayscale_filter.py
 -  Resize can exactly match 80% but with max diff = 1. source file noir-video-editing/video_decompose_script/reverse_ffmpeg_resize_filter.py

From my experiment, grayscale and resize are easy to get very good experiment result, given the simplicity of filters. But if we can approach some non-linear filter with linear one, that could be another selling story.

