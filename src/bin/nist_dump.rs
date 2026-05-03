use indicatif::{ProgressBar, ProgressStyle};
use spektr::SpektrCore;
use std::env;
use std::fs::File;
use std::io::Write;

fn main() {
    println!("========================================");
    println!("         CRYPTO AUDIT TOOL (NIST)       ");
    println!("========================================\n");
    let args: Vec<String> = env::args().collect();
    let megabytes: usize = if args.len() > 1 {
        args[1].parse().unwrap_or(100)
    } else {
        100
    };

    let output_file = "spektr_entropy.bin";

    let pb = ProgressBar::new(megabytes as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} MB ({msg})")
            .unwrap()
            .progress_chars("=>-"),
    );
    pb.set_message("gamma generation...");

    let mut file = File::create(output_file).expect("Error creating output file");
    let test_key = [0x42; 32];
    let core = SpektrCore::new(&test_key);
    let nonce = [0xAA; 16];

    let mut buffer = vec![0u8; 1024 * 1024];

for m in 0..megabytes {
        buffer.fill(0);
        
        let mut current_nonce = nonce;
        let m_bytes = (m as u64).to_le_bytes();
        for i in 0..8 {
            current_nonce[i + 8] ^= m_bytes[i];
        }

        core.process(&mut buffer, &current_nonce);
        file.write_all(&buffer).unwrap();
        pb.inc(1);
    }

    pb.finish_with_message("Ended");
    println!("\n Ready! data saved to {}", output_file);
}