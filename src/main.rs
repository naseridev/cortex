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
    commands::tag::Tag,
    ui::cli::{Cli, Commands, ConfigAction, TagAction},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => Init::new(),
        Commands::Create { name, tags } => Create::new(name, tags),
        Commands::Get { name, clip } => Get::new(name, clip),
        Commands::List { show_tags } => List::new(show_tags),
        Commands::Delete { name } => Delete::new(name),
        Commands::Edit { name, tags } => Edit::new(name, tags),
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
            Some(ConfigAction::SetHardwareBinding { enabled }) => {
                let enabled_bool = match enabled.to_lowercase().as_str() {
                    "true" | "1" | "yes" | "on" => true,
                    "false" | "0" | "no" | "off" => false,
                    _ => {
                        eprintln!("Invalid value. Use: true, false, yes, no, on, off, 1, or 0");
                        std::process::exit(1);
                    }
                };
                ConfigCmd::set_hardware_binding(enabled_bool)
            }
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
        Commands::Tag { action } => match action {
            TagAction::List => Tag::list(),
            TagAction::Add { name, tags } => {
                use cortex::modules::tags::TagValidator;
                let tag_list = TagValidator::parse_input(&tags);
                Tag::add(name, tag_list)
            }
            TagAction::Remove { name, tags } => {
                use cortex::modules::tags::TagValidator;
                let tag_list = TagValidator::parse_input(&tags);
                Tag::remove(name, tag_list)
            }
        },
    }
}
