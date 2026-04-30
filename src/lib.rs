use argon2::{Argon2, Params};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SLOT_SIZE: usize = 1024 * 1024;
pub const FULL_SLOT_SIZE: usize = 16 + 32 + SLOT_SIZE;
const WAV_HEADER_SIZE: usize = 44;

type HmacSha256 = Hmac<Sha256>;

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
        let mut chaos = SpektrChaos::new(u64::from_le_bytes(key[0..8].try_into().unwrap()));
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

pub struct SpektrVolume;

impl SpektrVolume {
    pub fn create(path: &str, r_pass: &str, r_data: &[u8], d_pass: &str, d_data: &[u8]) -> std::io::Result<()> {
        let mut salt = [0u8; 16]; OsRng.fill_bytes(&mut salt);
        let mut vol = vec![0u8; 16 + (FULL_SLOT_SIZE * 2)];
        OsRng.fill_bytes(&mut vol);
        vol[0..16].copy_from_slice(&salt);

        vol[16..16+FULL_SLOT_SIZE].copy_from_slice(&Self::pack(d_pass, &salt, d_data));
        vol[16+FULL_SLOT_SIZE..].copy_from_slice(&Self::pack(r_pass, &salt, r_data));

        let mut f = File::create(path)?;
        f.write_all(&Self::header(vol.len() as u32))?;
        f.write_all(&vol)?;
        Ok(())
    }

    pub fn open(path: &str, pass: &str, panic: bool) -> Result<Vec<u8>, &'static str> {
        let mut f = File::open(path).map_err(|_| "Not found")?;
        let mut buf = Vec::new(); f.read_to_end(&mut buf).unwrap();
        let raw = &buf[WAV_HEADER_SIZE..];
        let mut salt = [0u8; 16]; salt.copy_from_slice(&raw[0..16]);
        
        let keys = derive_keys(pass, &salt);
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
                return Ok(pt[4..4+len].to_vec());
            }
        }
        Err("Auth failed")
    }

    fn pack(p: &str, s: &[u8; 16], d: &[u8]) -> Vec<u8> {
        let k = derive_keys(p, s);
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

    fn shred(p: &str, s: usize) {
        if let Ok(mut f) = OpenOptions::new().write(true).open(p) {
            let mut n = vec![0u8; s]; OsRng.fill_bytes(&mut n);
            let _ = f.write_all(&n); let _ = f.sync_all();
        }
        let _ = std::fs::remove_file(p);
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

fn derive_keys(p: &str, s: &[u8; 16]) -> ([u8; 32], [u8; 32]) {
    let mut hw = get_hw();
    let mut inp = p.as_bytes().to_vec(); inp.extend_from_slice(&hw);
    let mut out = [0u8; 64];
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, Params::new(65536, 3, 1, Some(64)).unwrap())
        .hash_password_into(&inp, s, &mut out).unwrap();
    let mut c = [0u8; 32]; let mut m = [0u8; 32];
    c.copy_from_slice(&out[0..32]); m.copy_from_slice(&out[32..64]);
    hw.zeroize();
    (c, m)
}

fn get_hw() -> [u8; 32] {
    #[cfg(miri)] return [0x42; 32];
    #[cfg(not(miri))] {
        Sha256::digest(machine_uid::get().unwrap_or_else(|_| "ID".into()).as_bytes()).into()
    }
}