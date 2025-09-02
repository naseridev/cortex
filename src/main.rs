use clap::Parser;
use cortex::{
    commands::create::Create,
    commands::delete::Delete,
    commands::edit::Edit,
    commands::export::Export,
    commands::find::Find,
    commands::get::Get,
    commands::init::Init,
    commands::list::List,
    commands::pass::Pass,
    commands::purge::Purge,
    commands::reset::Reset,
    ui::cli::{Cli, Commands},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => Init::new(),
        Commands::Create { name } => Create::new(name),
        Commands::Get { name } => Get::new(name),
        Commands::List => List::new(),
        Commands::Delete { name } => Delete::new(name),
        Commands::Edit { name } => Edit::new(name),
        Commands::Find {
            pattern,
            ignore_case,
            names_only,
        } => Find::new(pattern, ignore_case, names_only),
        Commands::Export => Export::new(),
        Commands::Reset => Reset::new(),
        Commands::Purge => Purge::new(),
        Commands::Pass {
            length,
            count,
            uppercase,
            lowercase,
            digits,
            special,
            no_ambiguous,
        } => Pass::new(
            length,
            count,
            uppercase,
            lowercase,
            digits,
            special,
            no_ambiguous,
        ),
    }
}
