use spektr::SpektrVolume;
use std::fs;
use std::path::Path;

#[test]
fn test_full_flow() {
    let path = "integration_test.wav";
    let real_data = b"Top Secret Data 2026";
    let decoy_data = b"Mundane grocery list";

    SpektrVolume::create(path, "real_pass", real_data, "decoy_pass", decoy_data).unwrap();

    let out_real = SpektrVolume::open(path, "real_pass", false).unwrap();
    assert_eq!(out_real, real_data);

    let out_decoy = SpektrVolume::open(path, "decoy_pass", false).unwrap();
    assert_eq!(out_decoy, decoy_data);

    fs::remove_file(path).unwrap();
}

#[test]
fn test_panic_shred() {
    let path = "panic_test.wav";
    SpektrVolume::create(path, "r", b"data", "p", b"fake").unwrap();
    
    // Взламываем через панику
    let _ = SpektrVolume::open(path, "p", true);
    
    assert!(!Path::new(path).exists(), "File should be deleted after panic");
}