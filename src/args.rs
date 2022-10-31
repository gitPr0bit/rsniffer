use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Name of the capture device
    #[arg(short, long)]
    pub name: Option<String>,

    /// Period for report writing (in seconds)
    #[arg(short, long)]
    pub period: Option<u64>,

    /// ID of the capture device
    /// (ignored if a name is specified with -n)
    #[arg(short, long)]
    pub id: Option<usize>,

    /// List the available capture interfaces
    #[clap(short, long)]
    pub devices: bool,

    /// Sort traffic accorting to specified criteria
    #[arg(short, long)]
    pub sort: Option<String>
}