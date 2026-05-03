use clap::{Parser, Subcommand};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use spektr::{SpektrVolume, SpektrError, PqcIdentity, PqcTransmission};
use obfstr::obfstr as s;
use pqc_kyber::{KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES, KYBER_CIPHERTEXTBYTES};
use std::{fs, process, time::Duration};

#[derive(Parser)]
#[command(name = "spektr", version = "2.0-PRO")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// [C]reate
    #[command(name = "c")]
    Create {
        #[arg(short, long)] output: String,
        #[arg(short, long)] p: String, // Password
        #[arg(short, long)] d: String, // Data
        #[arg(long)] dp: String,       // Decoy Password
        #[arg(long)] dd: String,       // Decoy Data
        #[arg(short, long)] k: Option<String>, // Keyfile
    },
    /// [O]pen
    #[command(name = "o")]
    Open {
        #[arg(short, long)] input: String,
        #[arg(short, long)] p: String,
        #[arg(long, default_value_t = false)] panic: bool,
        #[arg(short, long)] k: Option<String>,
    },
    /// [G]en
    #[command(name = "g")]
    Gen { #[arg(short, long)] n: String },

    /// [S]eal)
    #[command(name = "s")]
    Seal {
        #[arg(short, long)] output: String, // WAV файл
        #[arg(short, long)] pubkey: String, // .pub файл
        #[arg(short, long)] data: String,   // Секрет
    },
    /// [PO] PqcOpen
    #[command(name = "po")]
    PqcOpen {
        #[arg(short, long)] input: String,   // WAV файл
        #[arg(short, long)] sealkey: String, // .seal файл
        #[arg(short, long)] privkey: String, // .sec файл
    }
}

fn main() {

    println!("{}", *BANNER);
    println!("{}", " — CRYPTOGRAPHIC STEGANOGRAPHY SYSTEM — ".on_black().white());
    println!();

    if spektr::anti_forensics_check() { process::exit(0); }

    let cli = Cli::parse();

    match &cli.command {
        // --- CREATE ---
        Commands::Create { output, p, d, dp, dd, k } => {
            let pb = create_spinner(s!("INITIALIZING_CORE..."));
            let result = SpektrVolume::create(output, p, d.as_bytes(), dp, dd.as_bytes(), k.as_ref());
            pb.finish_and_clear();
            if result.is_ok() { println!("{}", s!("STATUS: OK")); } else { process::exit(1); }
        }

        // --- OPEN ---
        Commands::Open { input, p, panic, k } => {
            let pb = create_spinner(s!("AUTHENTICATING..."));
            let result = SpektrVolume::open(input, p, *panic, k.as_ref());
            pb.finish_and_clear();
            match result {
                Ok(data) => println!("{}", String::from_utf8_lossy(&data).bright_white()),
                Err(e) => handle_error(e),
            }
        }

        // --- GENERATE KEYS ---
        Commands::Gen { n } => {
            let id = PqcIdentity::generate();
            fs::write(format!("{}.pub", n), id.public_key.as_slice()).unwrap();
            fs::write(format!("{}.sec", n), id.secret_key.as_slice()).unwrap();
            println!("{}", s!("PQC_KEYS_STORED"));
        }

        // --- PQC SEAL  ---
        Commands::Seal { output, pubkey, data } => {
            let pb = create_spinner(s!("QUANTUM_SEALING..."));
            
            let pub_bytes = fs::read(pubkey).expect("E_PK");
            let mut pk_arr = [0u8; KYBER_PUBLICKEYBYTES];
            pk_arr.copy_from_slice(&pub_bytes);
            let pk = pqc_kyber::PublicKey::from(pk_arr);

            let (ct, shared_secret) = PqcTransmission::encapsulate(&pk);
            let password = hex::encode(shared_secret);

            // Создаем контейнер (Decoy в PQC режиме по умолчанию пустой)
            SpektrVolume::create(output, &password, data.as_bytes(), s!("decoy"), b" ", None).unwrap();
            fs::write(format!("{}.seal", output), ct).unwrap();

            pb.finish_and_clear();
            println!("{}", s!("ENVELOPE_CREATED"));
        }

        // --- PQC OPEN (НОВЫЙ) ---
        Commands::PqcOpen { input, sealkey, privkey } => {
            let pb = create_spinner(s!("DECAPSULATING..."));
            
            let sec_bytes = fs::read(privkey).expect("E_SK");
            let mut sk_arr = [0u8; KYBER_SECRETKEYBYTES];
            sk_arr.copy_from_slice(&sec_bytes);
            let sk = pqc_kyber::SecretKey::from(sk_arr);

            let ct = fs::read(sealkey).expect("E_SEAL");
            if ct.len() != KYBER_CIPHERTEXTBYTES { process::exit(1); }

            match PqcTransmission::decapsulate(&ct, &sk) {
                Ok(ss) => {
                    let password = hex::encode(ss);
                    pb.finish_and_clear();
                    match SpektrVolume::open(input, &password, false, None) {
                        Ok(data) => println!("{}", String::from_utf8_lossy(&data).bright_white()),
                        Err(e) => handle_error(e),
                    }
                }
                Err(_) => process::exit(1),
            }
        }
    }
}

fn handle_error(err: SpektrError) {
    match err {
        SpektrError::AuthenticationFailed => eprintln!("{}", s!("AUTH_ERR_01")),
        SpektrError::EnvironmentUnsafe => eprintln!("{}", s!("AUTH_ERR_02")),
        _ => eprintln!("{}", s!("AUTH_ERR_03")),
    }
    process::exit(1);
}

fn create_spinner(msg: &'static str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_message(msg);
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_style(ProgressStyle::with_template("{spinner:.cyan} {msg}").unwrap());
    pb
}