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
        Commands::Init => Init::execute(),
        Commands::Create { name, tags } => Create::execute(name, tags),
        Commands::Get { name, clip } => Get::execute(name, clip),
        Commands::List { show_tags } => List::execute(show_tags),
        Commands::Delete { name } => Delete::execute(name),
        Commands::Edit { name, tags } => Edit::execute(name, tags),
        Commands::Find {
            pattern,
            ignore_case,
            names_only,
        } => Find::execute(pattern, ignore_case, names_only),
        Commands::Export { template } => Export::execute(template),
        Commands::Import { file, overwrite } => Import::execute(file, overwrite),
        Commands::Reset => Reset::execute(),
        Commands::Purge => Purge::execute(),
        Commands::Lock => Lock::execute(),
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
        } => Pass::execute(length, count, uppercase, lowercase, digits, special),
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
