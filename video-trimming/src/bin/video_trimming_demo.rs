use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;

fn parse_filename(file_name: &str) -> Option<(u32, char)> {
    let parts: Vec<&str> = file_name.trim_end_matches(".txt").split('_').collect();
    if parts.len() == 3 {
        if let Ok(frame_number) = parts[1].parse::<u32>() {
            if let Some(channel) = parts[2].chars().next() {
                return Some((frame_number, channel));
            }
        }
    }
    None
}

fn read_file_as_vec<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut values = Vec::new();

    for line in reader.lines() {
        let line = line?;
        values.extend(
            line.split_whitespace()
                .filter_map(|num| num.parse::<u8>().ok()),
        );
    }

    Ok(values)
}

fn main() -> io::Result<()> {
    let dir_path = "../demo/decomposed_frames";
    let mut frames: BTreeMap<u32, Vec<Vec<u8>>> = BTreeMap::new();

    let entries = fs::read_dir(dir_path)?;

    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name().into_string().unwrap();

        if let Some((frame_number, channel)) = parse_filename(&file_name) {
            let file_path = entry.path();
            let content = read_file_as_vec(&file_path)?;

            let frame = frames
                .entry(frame_number)
                .or_insert_with(|| vec![vec![], vec![], vec![]]);
            match channel {
                'B' => frame[0] = content,
                'G' => frame[1] = content,
                'R' => frame[2] = content,
                _ => (),
            }
        }
    }

    // Note: BTreeMap is already sorterd by frame count.
    let sorted_frames: Vec<Vec<u8>> = frames.into_values().flatten().collect();
    println!(
        "Successfully processed {} frame-channel pairs.",
        sorted_frames.len()
    );

    // TODO: Write some code processing the BTreeMap.
    Ok(())
}
