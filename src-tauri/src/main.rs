#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use spektr::{SpektrVolume, PqcIdentity, PqcTransmission}; 
use std::fs;
use pqc_kyber::{KYBER_PUBLICKEYBYTES, KYBER_CIPHERTEXTBYTES};

// 1. Короткий ID железа
#[tauri::command]
async fn get_dna() -> String {
    hex::encode(&spektr::get_hardware_dna()[0..4]).to_uppercase()
}

// 2. Создание контейнера
#[tauri::command]
async fn gui_create(output: String, pass: String, data: String, keyfile: Option<String>) -> Result<String, String> {
    SpektrVolume::create(&output, &pass, data.as_bytes(), "decoy", b" ", keyfile.as_ref())
        .map(|_| "INITIALIZED".into())
        .map_err(|_| "IO_ERROR".into())
}

// 3. Открытие контейнера
#[tauri::command]
async fn gui_open(input: String, pass: String, keyfile: Option<String>) -> Result<String, String> {
    SpektrVolume::open(&input, &pass, false, keyfile.as_ref())
        .map(|d| String::from_utf8_lossy(&d).to_string())
        .map_err(|_| "AUTH_FAILED".into())
}

// 4. Генерация PQ-ключей
#[tauri::command]
async fn gui_pqc_gen(name: String) -> Result<String, String> {
    let id = PqcIdentity::generate();
    fs::write(format!("{}.pub", name), id.public_key.as_slice()).map_err(|_| "FS_ERR")?;
    fs::write(format!("{}.sec", name), id.secret_key.as_slice()).map_err(|_| "FS_ERR")?;
    Ok("KEYS_GENERATED".into())
}

// 5. Запечатывание PQ-контейнера
#[tauri::command]
async fn gui_pqc_seal(output: String, pubkey_path: String, data: String) -> Result<String, String> {
    let pub_bytes = fs::read(pubkey_path).map_err(|_| "READ_ERR")?;
    let mut pk_arr = [0u8; KYBER_PUBLICKEYBYTES];
    pk_arr.copy_from_slice(&pub_bytes);
    
    let (ct, shared_secret) = PqcTransmission::encapsulate(&pqc_kyber::PublicKey::from(pk_arr));
    let password = hex::encode(shared_secret);

    SpektrVolume::create(&output, &password, data.as_bytes(), "decoy", b" ", None).map_err(|_| "INIT_ERR")?;
    fs::write(format!("{}.seal", output), ct).map_err(|_| "WRITE_ERR")?;
    Ok("ENVELOPE_READY".into())
}

// 6. P2P Ожидание (Listen)
#[tauri::command]
async fn gui_p2p_listen(port: String) -> Result<String, String> {
    match SpektrVolume::p2p_listen(&port) {
        Ok((enc_data, ss)) => {
            let mut data = enc_data;
            spektr::SpektrCore::new(&ss).process(&mut data, &[0xCC; 16]);
            Ok(String::from_utf8_lossy(&data).to_string())
        },
        Err(_) => Err("NET_LINK_CLOSED".into())
    }
}

// 7. P2P Передача (Send)
#[tauri::command]
async fn gui_p2p_send(addr: String, data: String) -> Result<String, String> {
    match SpektrVolume::p2p_send(&addr, data.as_bytes()) {
        Ok(_) => Ok("DATA_SENT_SUCCESSFULLY".into()),
        Err(_) => Err("TARGET_REFUSED".into())
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            get_dna, 
            gui_create, 
            gui_open, 
            gui_pqc_gen, 
            gui_pqc_seal,
            gui_p2p_listen,
            gui_p2p_send
        ])
        .run(tauri::generate_context!())
        .expect("error");
}