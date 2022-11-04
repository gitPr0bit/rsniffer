use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Name of the capture device
    #[arg(short, long)]
    pub name: Option<String>,

    /// Output file
    #[arg(short, long, default_value="rsniffer_report.txt")]
    pub output: Option<String>,

    /// Capture filter
    #[arg(short, long, default_value=None)]
    pub filter: Option<String>,

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