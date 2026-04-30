use clap::{Parser, Subcommand};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use spektr::SpektrVolume;
use std::{process, time::Duration};

const BANNER: &str = r#"
 ███████╗██████╗ ███████╗██╗  ██╗████████╗██████╗      ██████╗  ██████╗ 
 ██╔════╝██╔══██╗██╔════╝██║ ██╔╝╚══██╔══╝██╔══██╗    ██╔═══██╗██╔════╝ 
 ███████╗██████╔╝█████╗  █████╔╝    ██║   ██████╔╝    ╚██████╔╝███████╗ 
 ╚════██║██╔═══╝ ██╔══╝  ██╔═██╗    ██║   ██╔══██╗     ██╔═══╝ ██╔═══██╗
 ███████║██║     ███████╗██║  ██╗   ██║   ██║  ██║     ███████╗╚██████╔╝
 ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝     ╚══════╝ ╚═════╝ 
"#;

#[derive(Parser)]
#[command(author = "Aleksandr Gjotov", version = "1.0", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Create {
        #[arg(short, long)]
        output: String,
        #[arg(short = 'p', long)]
        real_pass: String,
        #[arg(short = 'd', long)]
        real_data: String,
        #[arg(long)]
        decoy_pass: String,
        #[arg(long)]
        decoy_data: String,

        #[arg(short = 'k', long)]
        keyfile: Option<String>, 
    },
    Open {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        password: String,
        #[arg(long, default_value_t = false)]
        panic: bool,
        #[arg(short = 'k', long)]
        keyfile: Option<String>,
    },
}

fn main() {
    println!("{}", BANNER.bright_white().bold());
    println!("{}", " — СИСТЕМА КРИПТОГРАФИЧЕСКОЙ СТЕГАНОГРАФИИ — ".on_black().white());
    println!();

let cli = Cli::parse();

    match &cli.command {
        Commands::Create { output, real_pass, real_data, decoy_pass, decoy_data, keyfile } => {
            let pb = create_spinner("Генерация мастер-ключа (Argon2id + MFA)...");
            
            let result = SpektrVolume::create(
    output,
    real_pass,
    real_data.as_bytes(),
    decoy_pass,
    decoy_data.as_bytes(),
    keyfile.as_ref(),
);

pb.finish_and_clear(); 

match result { 
    Ok(_) => {
        println!("{} {}", "[+] SUCCESS:".green().bold(), "Контейнер успешно инициализирован.");
    }
    Err(e) => {
        println!("{} {}", "[-] ERROR:".red().bold(), e);
        process::exit(1);
    }
}
            
            pb.finish_and_clear();
        }
        Commands::Open { input, password, panic, keyfile } => {
  
            let pb = create_spinner("Аутентификация (Hardware DNA + Keyfile)...");
            
            let result = SpektrVolume::open(input, password, *panic, keyfile.as_ref());
            
            pb.finish_and_clear();

            match result {
                Ok(data) => {
                    if *panic {
                        println!("{}", "!!! ВНИМАНИЕ: ФАЙЛ БЫЛ ФИЗИЧЕСКИ УНИЧТОЖЕН !!!".on_red().white().bold());
                        println!("{} {}", "[+] EXTRACTED DECOY:".yellow().bold(), String::from_utf8_lossy(&data));
                    } else {
                        println!("{}", "— ДОСТУП РАЗРЕШЕН —".green().bold());
                        println!("\n{}\n", String::from_utf8_lossy(&data).bright_white());
                    }
                }
                Err(e) => {
                    println!("{} {}", "ACCESS DENIED:".red().bold(), e);
                    process::exit(1);
                }
            }
        }
    }
}

fn create_spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(120));
    pb.set_style(
        ProgressStyle::with_template("{spinner:.white} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb
}