use spektr::SpektrCore;
use std::time::Instant;

fn main() {
    println!("==================================================");
    println!("             STRICT AVALANCHE CRITERION TEST      ");
    println!("==================================================\n");

    let iterations = 100_000;
    let mut total_flipped_bits = 0;
    let total_bits_per_block = 128;
    
    let start_time = Instant::now();

    for i in 0..iterations {
        let mut key_a = [0x42; 32];
        key_a[0] ^= (i % 256) as u8; 
        
        let core_a = SpektrCore::new(&key_a);
        let mut out_a = [0u8; 16];
        core_a.process(&mut out_a, &[0xAA; 16]);

        let mut key_b = key_a.clone();
        key_b[15] ^= 0b0000_0001;
        
        let core_b = SpektrCore::new(&key_b);
        let mut out_b = [0u8; 16];
        core_b.process(&mut out_b, &[0xAA; 16]);

        // Hamming distance
        let mut bit_diff = 0;
        for (byte_a, byte_b) in out_a.iter().zip(out_b.iter()) {
            bit_diff += (byte_a ^ byte_b).count_ones();
        }
        
        total_flipped_bits += bit_diff as u64;
    }

    let duration = start_time.elapsed();
    
    let max_possible_flips = (iterations * total_bits_per_block) as f64;
    let actual_flips = total_flipped_bits as f64;
    let avalanche_percent = (actual_flips / max_possible_flips) * 100.0;

    println!("Interations: {}", iterations);
    println!("Duration time: {:?}", duration);
    println!("--------------------------------------------------");
    println!("Ideal avalanche effect:   50.0000 %");
    println!("Spektr-26 avalanche effect:   {:.4} %", avalanche_percent);
    println!("Deviation from ideal:       {:.4} %", (50.0 - avalanche_percent).abs());
    println!("--------------------------------------------------");
    
    if (50.0 - avalanche_percent).abs() < 1.0 {
        println!("Chipher meets the strict avalanche criterion.");
    } else {
        println!("FAILURE - Cipher does NOT meet the strict avalanche criterion.");
    }
}