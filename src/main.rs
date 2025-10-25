use clap::Parser;
use cortex::{
    commands::config::ConfigCmd,
    commands::create::Create,
    commands::delete::Delete,
    commands::edit::Edit,
    commands::export::Export,
    commands::find::Find,
    commands::get::Get,
    commands::import::Import,
    commands::init::Init,
    commands::list::List,
    commands::lock::Lock,
    commands::pass::Pass,
    commands::purge::Purge,
    commands::reset::Reset,
    ui::cli::{Cli, Commands, ConfigAction},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => Init::new(),
        Commands::Create { name } => Create::new(name),
        Commands::Get { name, clip } => Get::new(name, clip),
        Commands::List => List::new(),
        Commands::Delete { name } => Delete::new(name),
        Commands::Edit { name } => Edit::new(name),
        Commands::Find {
            pattern,
            ignore_case,
            names_only,
        } => Find::new(pattern, ignore_case, names_only),
        Commands::Export { template } => Export::new(template),
        Commands::Import { file, overwrite } => Import::new(file, overwrite),
        Commands::Reset => Reset::new(),
        Commands::Purge => Purge::new(),
        Commands::Lock => Lock::new(),
        Commands::Config { action } => match action {
            Some(ConfigAction::Show) => ConfigCmd::show(),
            Some(ConfigAction::SetTimeout { seconds }) => ConfigCmd::set_timeout(seconds),
            None => ConfigCmd::show(),
        },
        Commands::Pass {
            length,
            count,
            uppercase,
            lowercase,
            digits,
            special,
        } => Pass::new(length, count, uppercase, lowercase, digits, special),
    }
}
