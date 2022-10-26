pub mod args {
    use clap::Parser;

    /// Simple program to greet a person
    #[derive(Parser, Debug)]
    #[command(author, version, about, long_about = None)]
    pub struct Args {
        /// Name of the capture device
        #[arg(short, long)]
        pub name: Option<String>,

        /// ID of the capture device
        #[arg(short, long)]
        pub id: Option<u8>,
    }
}