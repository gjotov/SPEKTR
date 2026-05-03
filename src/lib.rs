use argon2::{Argon2, Params};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom, BufReader};
use std::time::Instant;
use std::thread;
use sysinfo::{System, Disks};
use zeroize::{Zeroize, ZeroizeOnDrop};
use pqc_kyber::*;

pub const SLOT_SIZE: usize = 1024 * 1024;
pub const FULL_SLOT_SIZE: usize = 16 + 32 + SLOT_SIZE;
const WAV_HEADER_SIZE: usize = 44;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub enum SpektrError {
    IoError,
    AuthenticationFailed,
    QuantumKeyError,
    ContainerCorrupted,
    EnvironmentUnsafe,
}

impl From<std::io::Error> for SpektrError {
    fn from(_: std::io::Error) -> Self {
        SpektrError::IoError
    }
}


#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct SpektrChaos { state: u64 }

impl SpektrChaos {
    fn new(seed: u64) -> Self { Self { state: if seed == 0 { 0x7FFFFFFF } else { seed } } }
    fn next_u32(&mut self) -> u32 {
        for _ in 0..3 {
            let x = self.state;
            let one_minus_x = 0xFFFFFFFFu64.wrapping_sub(x);
            self.state = (4u64.wrapping_mul(x).wrapping_mul(one_minus_x)) >> 32;
        }
        self.state as u32
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct SpektrSBox { sbox: [u8; 256] }

impl SpektrSBox {
    fn new(chaos: &mut SpektrChaos) -> Self {
        let mut sbox = [0u8; 256];
        for i in 0..=255 { sbox[i] = i as u8; }
        for i in (1..=255).rev() { sbox.swap(i, (chaos.next_u32() as usize) % (i + 1)); }
        Self { sbox }
    }
    fn substitute(&self, x: u8) -> u8 {
        let mut res = 0u8;
        for i in 0..=255 {
            let mask = (((i as u8 ^ x) as i16).wrapping_sub(1) >> 8) & 1;
            res |= self.sbox[i] & (mask as u8).wrapping_neg();
        }
        res
    }
}

pub struct SpektrCore { sbox: SpektrSBox, keys: [u8; 32] }

impl SpektrCore {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut seed: u64 = 0x9E3779B97F4A7C15; 
        for chunk in key.chunks_exact(8) {
            let val = u64::from_le_bytes(chunk.try_into().unwrap());
            seed ^= val;
            seed = seed.wrapping_add(val.rotate_left(13)); 
        }
        let mut chaos = SpektrChaos::new(seed);
        let sbox = SpektrSBox::new(&mut chaos);
        let mut keys = [0u8; 32];
        for k in &mut keys { *k = (chaos.next_u32() & 0xFF) as u8; }
        Self { sbox, keys }
    }
    pub fn process(&self, data: &mut [u8], nonce: &[u8; 16]) {
        data.par_chunks_mut(16).enumerate().for_each(|(idx, chunk)| {
            let mut ks = *nonce;
            let ctr = (idx as u64).to_le_bytes();
            for i in 0..8 { ks[i] ^= ctr[i]; }
            for r in 0..4 {
                for b in &mut ks { *b = self.sbox.substitute(*b); }
                let mut n = u128::from_le_bytes(ks);
                n = n.rotate_left(17) ^ (n >> 11) ^ n.rotate_right(31);
                ks = n.to_le_bytes();
                for i in 0..16 { ks[i] ^= self.keys[(r * 4 + i) % 32]; }
            }
            for (b, k) in chunk.iter_mut().zip(ks.iter()) { *b ^= *k; }
        });
    }
}

pub fn anti_forensics_check() -> bool {
    let mut score = 0;
    let cores = thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    if cores <= 2 { score += 1; }

    let start = Instant::now();
    thread::sleep(std::time::Duration::from_millis(10));
    if start.elapsed().as_millis() > 25 { score += 1; }

    let math_start = Instant::now();
    let mut _x = 0u64;
    for i in 0..1_000_000 { _x = _x.wrapping_add(i); }
    if math_start.elapsed().as_millis() > 50 { score += 1; }

    score >= 2
}

pub fn get_hardware_dna() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(machine_uid::get().unwrap_or_else(|_| "ID".into()).as_bytes());

    let mut s = System::new_all();
    s.refresh_all(); 
    for cpu in s.cpus() {
        hasher.update(cpu.brand().as_bytes());
        hasher.update(cpu.frequency().to_le_bytes()); 
    }
    hasher.update(s.total_memory().to_le_bytes());

    let disks = Disks::new_with_refreshed_list();
    for disk in &disks {
        hasher.update(disk.name().as_encoded_bytes());
        hasher.update(disk.file_system().as_encoded_bytes());
    }

    if let Ok(val) = std::env::var("COMPUTERNAME") { hasher.update(val.as_bytes()); }
    if let Ok(val) = std::env::var("USERNAME") { hasher.update(val.as_bytes()); }

    // Тихое отравление (Poisoning)
    if anti_forensics_check() {
        hasher.update(b"ENV_COMPROMISED");
    }

    let mut dna = [0u8; 32];
    dna.copy_from_slice(&hasher.finalize());
    dna
}

// --- ГЕНЕРАЦИЯ КЛЮЧЕЙ ---

fn derive_keys(p: &str, s: &[u8; 16], kf: Option<&String>) -> ([u8; 32], [u8; 32]) {
    let mut hw = get_hardware_dna();
    let mut kf_entropy = vec![0u8; 32];

    if let Some(path) = kf {
        if let Ok(file) = File::open(path) {
            let mut reader = BufReader::new(file);
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 8192];
            while let Ok(n) = reader.read(&mut buffer) {
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }
            kf_entropy = hasher.finalize().to_vec();
        }
    }

    let mut inp = p.as_bytes().to_vec();
    inp.extend_from_slice(&hw);
    inp.extend_from_slice(&kf_entropy);

    let mut out = [0u8; 64];
    let params = Params::new(65536, 3, 1, Some(64)).unwrap();
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(&inp, s, &mut out).unwrap();
    
    let mut c = [0u8; 32]; let mut m = [0u8; 32];
    c.copy_from_slice(&out[0..32]); m.copy_from_slice(&out[32..64]);
    hw.zeroize(); kf_entropy.zeroize();
    (c, m)
}

pub struct SpektrVolume;

impl SpektrVolume {
    pub fn create(path: &str, rp: &str, rd: &[u8], dp: &str, dd: &[u8], kf: Option<&String>) -> Result<(), SpektrError> {
        let mut salt = [0u8; 16]; OsRng.fill_bytes(&mut salt);
        let mut vol = vec![0u8; 16 + (FULL_SLOT_SIZE * 2)];
        OsRng.fill_bytes(&mut vol);
        vol[0..16].copy_from_slice(&salt);

        vol[16..16+FULL_SLOT_SIZE].copy_from_slice(&Self::pack(dp, &salt, dd, None)); 
        vol[16+FULL_SLOT_SIZE..].copy_from_slice(&Self::pack(rp, &salt, rd, kf));

        let mut f = File::create(path)?;
        f.write_all(&Self::header(vol.len() as u32))?;
        f.write_all(&vol)?;
        Ok(())
    }

    pub fn open(path: &str, pass: &str, panic: bool, kf: Option<&String>) -> Result<Vec<u8>, SpektrError> {
        let mut f = File::open(path)?;
        let mut buf = Vec::new(); f.read_to_end(&mut buf).unwrap();
        let raw = &buf[WAV_HEADER_SIZE..];
        let mut salt = [0u8; 16]; salt.copy_from_slice(&raw[0..16]);
        
        let keys = derive_keys(pass, &salt, kf);
        
        for &off in &[16, 16 + FULL_SLOT_SIZE] {
            let slot = &raw[off..off + FULL_SLOT_SIZE];
            let (nonce, tag, ct) = (&slot[0..16], &slot[16..48], &slot[48..]);
            let mut hmac = HmacSha256::new_from_slice(&keys.1).unwrap();
            hmac.update(nonce); hmac.update(ct);
            if hmac.verify_slice(tag).is_ok() {
                let mut pt = ct.to_vec();
                SpektrCore::new(&keys.0).process(&mut pt, nonce.try_into().unwrap());
                if panic { Self::shred(path, buf.len()); }
                let len = u32::from_le_bytes(pt[0..4].try_into().unwrap()) as usize;
                if len > SLOT_SIZE - 4 { return Err(SpektrError::ContainerCorrupted); }
                return Ok(pt[4..4+len].to_vec());
            }
        }
        Err(SpektrError::AuthenticationFailed)
    }

    fn pack(p: &str, s: &[u8; 16], d: &[u8], kf: Option<&String>) -> Vec<u8> {
        let k = derive_keys(p, s, kf);
        let mut n = [0u8; 16]; OsRng.fill_bytes(&mut n);
        let mut pt = vec![0u8; SLOT_SIZE]; OsRng.fill_bytes(&mut pt);
        pt[0..4].copy_from_slice(&(d.len() as u32).to_le_bytes());
        pt[4..4+d.len()].copy_from_slice(d);
        SpektrCore::new(&k.0).process(&mut pt, &n);
        let mut hmac = HmacSha256::new_from_slice(&k.1).unwrap();
        hmac.update(&n); hmac.update(&pt);
        let mut res = Vec::with_capacity(FULL_SLOT_SIZE);
        res.extend_from_slice(&n); res.extend_from_slice(&hmac.finalize().into_bytes());
        res.extend_from_slice(&pt);
        res
    }

    pub fn shred(path: &str, size: usize) {
        if let Ok(mut f) = OpenOptions::new().write(true).open(path) {
            let mut buf = vec![0u8; size];
            for cycle in 1..=35 {
                if cycle <= 4 || cycle > 31 { OsRng.fill_bytes(&mut buf); }
                else { buf.fill(if cycle % 2 == 0 { 0x55 } else { 0xAA }); }
                let _ = f.seek(SeekFrom::Start(0));
                let _ = f.write_all(&buf);
                let _ = f.sync_all();
            }
        }
        let _ = std::fs::remove_file(path);
    }

    fn header(sz: u32) -> [u8; 44] {
        let mut h = [0u8; 44];
        h[0..4].copy_from_slice(b"RIFF"); h[4..8].copy_from_slice(&(sz + 36).to_le_bytes());
        h[8..16].copy_from_slice(b"WAVEfmt "); h[16..20].copy_from_slice(&16u32.to_le_bytes());
        h[20..24].copy_from_slice(&[1, 0, 1, 0]); h[24..28].copy_from_slice(&44100u32.to_le_bytes());
        h[28..32].copy_from_slice(&44100u32.to_le_bytes()); h[32..36].copy_from_slice(&[1, 0, 8, 0]);
        h[36..40].copy_from_slice(b"data"); h[40..44].copy_from_slice(&sz.to_le_bytes());
        h
    }
}

// --- ПОСТКВАНТОВЫЙ ОБМЕН ---

pub struct PqcIdentity { pub public_key: PublicKey, pub secret_key: SecretKey }
impl PqcIdentity {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let keys = keypair(&mut rng).expect("PQC Gen Failed");
        Self { public_key: keys.public, secret_key: keys.secret }
    }
}

pub struct PqcTransmission;
impl PqcTransmission {
    pub fn encapsulate(recipient_pub: &PublicKey) -> (Vec<u8>, [u8; 32]) {
        let mut rng = OsRng;
        let (ct, ss) = encapsulate(recipient_pub, &mut rng).expect("PQC Encapsulation Error");
        let mut key = [0u8; 32]; key.copy_from_slice(&ss);
        (ct.to_vec(), key)
    }

    pub fn decapsulate(ct: &[u8], my_secret: &SecretKey) -> Result<[u8; 32], SpektrError> {
        if ct.len() != KYBER_CIPHERTEXTBYTES { return Err(SpektrError::QuantumKeyError); }
        let mut ct_arr = [0u8; KYBER_CIPHERTEXTBYTES]; ct_arr.copy_from_slice(ct);
        let ss = decapsulate(&ct_arr, my_secret).map_err(|_| SpektrError::QuantumKeyError)?;
        let mut key = [0u8; 32]; key.copy_from_slice(&ss);
        Ok(key)
    }
}