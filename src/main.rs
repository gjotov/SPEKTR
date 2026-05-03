use clap::{Parser, Subcommand};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use spektr::{SpektrVolume, PqcIdentity, PqcTransmission, SpektrError};
use std::{fs, process, time::Duration};
use pqc_kyber::{KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES, KYBER_CIPHERTEXTBYTES};
use obfstr::obfstr as s;

lazy_static::lazy_static! {
    static ref BANNER: String = s!(
"
 ███████╗██████╗ ███████╗██╗  ██╗████████╗██████╗      ██████╗  ██████╗ 
 ██╔════╝██╔══██╗██╔════╝██║ ██╔╝╚══██╔══╝██╔══██╗    ██╔═══██╗██╔════╝ 
 ███████╗██████╔╝█████╗  █████╔╝    ██║   ██████╔╝    ╚██████╔╝███████╗ 
 ╚════██║██╔═══╝ ██╔══╝  ██╔═██╗    ██║   ██╔══██╗     ██╔═══╝ ██╔═══██╗
 ███████║██║     ███████╗██║  ██╗   ██║   ██║  ██║     ███████╗╚██████╔╝
 ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝     ╚══════╝ ╚═════╝ 
").to_string();
}

#[derive(Parser)]
#[command(author = "Aleksander Gjotov", version = "1.0", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Create {
        #[arg(short, long)] output: String,
        #[arg(short = 'p', long)] real_pass: String,
        #[arg(short = 'd', long)] real_data: String,
        #[arg(long)] decoy_pass: String,
        #[arg(long)] decoy_data: String,
        #[arg(short = 'k', long)] keyfile: Option<String>,
    },
    Open {
        #[arg(short, long)] input: String,
        #[arg(short, long)] password: String,
        #[arg(long, default_value_t = false)] panic: bool,
        #[arg(short = 'k', long)] keyfile: Option<String>,
    },
    PqcGen {
        #[arg(short, long)] name: String,
    },
    PqcSeal {
        #[arg(short, long)] output: String,
        #[arg(short, long)] pubkey: String,
        #[arg(short, long)] data: String,
    },
    PqcOpen {
        #[arg(short, long)] input: String,
        #[arg(short, long)] sealkey: String,
        #[arg(short, long)] privkey: String,
    }
}

fn main() {
    println!("{}", *BANNER);
    println!("{}", " — CRYPTOGRAPHIC STEGANOGRAPHY SYSTEM — ".on_black().white());
    println!();

    if spektr::anti_forensics_check() {
        println!("{} {}", s!("[!] ALERT:").red().bold(), s!("VM artifacts or forensic tools detected."));
        println!("{} {}", s!("[!] STATUS:").red().bold(), s!("System blocked."));
        std::process::exit(1);
    }

    let cli = Cli::parse();

    match &cli.command {
        // --- CREATE ---
        Commands::Create { output, real_pass, real_data, decoy_pass, decoy_data, keyfile } => {
            let pb = create_spinner("Computing Argon2id + MFA entropy...");
            let result = SpektrVolume::create(
                output, real_pass, real_data.as_bytes(), 
                decoy_pass, decoy_data.as_bytes(), keyfile.as_ref()
            );
            pb.finish_and_clear();

            match result {
                Ok(_) => print_success(&format!("Container '{}' created successfully.", output)),
                Err(e) => handle_spektr_error(e), // Вызываем наш обработчик ошибок
            }
        }

        // --- OPEN ---
        Commands::Open { input, password, panic, keyfile } => {
            let pb = if *panic {
                create_spinner(&"Activating Gutmann method...".red().bold().to_string())
            } else {
                create_spinner("Auth Hardware DNA...")
            };

            let result = SpektrVolume::open(input, password, *panic, keyfile.as_ref());
            pb.finish_and_clear();

            match result {
                Ok(data) => {
                    if *panic {
                        println!("{}", "!!! DATA PHYSICALLY DESTROYED !!!".on_red().white().bold());
                    } else {
                        println!("{}", "— ACCESS GRANTED —".green().bold());
                    }
                    println!("\n{}\n", String::from_utf8_lossy(&data).bright_white());
                }
                Err(e) => handle_spektr_error(e),
            }
        }

        // --- PQC-GEN ---
        Commands::PqcGen { name } => {
            let pb = create_spinner("ML-KEM-1024 key generation in progress...");
            let id = PqcIdentity::generate();
            
            fs::write(format!("{}.pub", name), id.public_key.as_slice()).unwrap();
            fs::write(format!("{}.sec", name), id.secret_key.as_slice()).unwrap();
            
            pb.finish_and_clear();
            print_success(&format!("Keys {}.pub and {}.sec created.", name, name));
        }

        // --- PQC-SEAL ---
        Commands::PqcSeal { output, pubkey, data } => {
            let pb = create_spinner("Quantum key encapsulation in progress...");
            let pub_bytes = fs::read(pubkey).expect("Failed to read .pub key");

            let mut pk = [0u8; KYBER_PUBLICKEYBYTES];
            pk.copy_from_slice(&pub_bytes);
            let recipient_pk = pqc_kyber::PublicKey::from(pk);

            let (ct, shared_secret) = PqcTransmission::encapsulate(&recipient_pk);
            let password = hex::encode(shared_secret);

            SpektrVolume::create(
                output, &password, data.as_bytes(), 
                "decoy", b"Decoy data", None
            ).unwrap();

            fs::write(format!("{}.seal", output), ct).unwrap();

            pb.finish_and_clear();
            print_success(&format!("Container '{}' sealed. Send .wav and .seal files.", output));
        }

        // --- PQC-OPEN ---
        Commands::PqcOpen { input, sealkey, privkey } => {
            let pb = create_spinner("Decapsulating quantum key...");
            let sec_bytes = fs::read(privkey).expect("Failed to read .sec key");

            let mut sk = [0u8; KYBER_SECRETKEYBYTES];
            sk.copy_from_slice(&sec_bytes);
            let my_sk = pqc_kyber::SecretKey::from(sk);

            let ct = fs::read(sealkey).expect("Failed to read .seal file");

            if ct.len() != KYBER_CIPHERTEXTBYTES {
                pb.finish_and_clear();
                print_error(s!("ERROR: Invalid .seal file size."));
                return;
            }

            match PqcTransmission::decapsulate(&ct, &my_sk) {
                Ok(shared_secret) => {
                    let password = hex::encode(shared_secret);
                    pb.finish_and_clear();

                    match SpektrVolume::open(input, &password, false, None) {
                        Ok(data) => {
                            println!("{}", "— QUANTUM ACCESS GRANTED —".green().bold());
                            println!("\n{}\n", String::from_utf8_lossy(&data).bright_white());
                        }
                        Err(e) => handle_spektr_error(e),
                    }
                }
                Err(e) => {
                    pb.finish_and_clear();
                    handle_spektr_error(e);
                }
            }
        }
    }
}

// --- UI ---

fn handle_spektr_error(err: SpektrError) {
    let msg = match err {
        SpektrError::AuthenticationFailed => s!("AUTH_FAILED: INVALID_KEY_OR_DNA").to_string(),
        SpektrError::IoError => s!("I/O_FAILURE: FILE_ACCESS_DENIED").to_string(),
        SpektrError::QuantumKeyError => s!("PQC_ERROR: KEY_DECAPSULATION_FAILED").to_string(),
        SpektrError::ContainerCorrupted => s!("INTEGRITY_ERROR: DATA_TAMPERED").to_string(),
        SpektrError::EnvironmentUnsafe => s!("SECURITY_ALERT: UNTRUSTED_ENVIRONMENT").to_string(),
    };
    print_error(&msg);
}

fn create_spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_style(ProgressStyle::with_template("{spinner:.bright.white} {msg}").unwrap()
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]));
    pb
}

fn print_success(msg: &str) {
    println!("{} {}", "SUCCESS:".green().bold(), msg);
}

fn print_error(msg: &str) {
    println!("{} {}", "ERROR:".red().bold(), msg);
    process::exit(1);
}