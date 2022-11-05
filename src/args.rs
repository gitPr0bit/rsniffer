use clap::Parser;

/// 
#[derive(Parser, Debug)]
#[clap(name = "rsniffer",
       version,
       about = "\nWelcome to rsniffer!
        \rThis tool sets the network adapter in promiscuous mode, captures TCP/UDP traffic and generates a textual report.\n
        \r                            ###   ####   ###                                
        \r                       #### ###############(#( (((((                         
        \r                 (((( ((((((((((((((((((((((((((((((  (((                    
        \r                 ((((((((((((((((((((((((((((((((((((((((                    
        \r            ((((((((((((((((((((((((((((((((((((((((((((((((((               
        \r            ((((((((((((((((((((((((((((((((((((((((((((((((((               
        \r       ((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((          
        \r        ((((((((((((((((((((((((((((((((((((((((((((((((((((((((((           
        \r      ((((((((((((((((((      @(((((((((((((((@@     ((((((((((((((((        
        \r     (((((((((((((((((((      @@@   (((((   @@@     (((//////////////        
        \r      ((((((((((((((((((((        ////////        //////////////////         
        \r    ///////////////////////////////////////////////////////////////////      
        \r  ////////////////////////////// /////////////////////////////////////////   
        \r//////  ,,,,,////////////////////.        ///  ////////////////, ,,, /////   
        \r  /////   ,,   ////,,,,////////// /////// //////////,,,,,/////  ,,.  ////    
        \r     ////   ,    ////.////////////// ,.////////////////////    ,,   ///      
        \r       ///    .    /////////                   ///****/       ,    //        
        \r          //           *********            ********              /          
        \r            /             *********     *********                /         
    ")]
pub struct Args {
    /// Sets the capture device by name.
    #[arg(short, long)]
    pub device: Option<String>,

    /// Sets the filter on the capture using the given BPF program string.
    /// 
    /// Examples:
    ///     rsniffer -f "tcp src port 443"          captures TCP traffic with source port 443
    ///     rsniffer -f "dst portrange 300-500"     captures TCP/UDP traffic with destination port in given range
    /// 
    /// See http://biot.com/capstats/bpf.html for more information about this syntax.
    #[arg(short, long, default_value=None, verbatim_doc_comment)]
    pub filter: Option<String>,

    /// Sets the capture device by ID.
    /// You can get it by listing all the available devices with -l option.
    /// 
    /// Please note: the ID is ignored if a name is specified with -d
    #[arg(short, long, verbatim_doc_comment)]
    pub id: Option<usize>,

    /// Lists all the available capture devices
    #[clap(short, long)]
    pub list_devices: bool,

    /// Sets output file
    #[arg(short, long, default_value="rsniffer_report.txt")]
    pub output: Option<String>,

    /// Sorts captured traffic accorting to specified criteria.
    /// The criteria must be specified as XY, where:
    ///  - X is a number identifying the field (from 0 to 9)
    ///  - Y is 'G' (Greater to Lower) or 'L' (Lower to Greater)
    /// 
    /// Examples:
    ///     rsniffer -s 6G      sorting by number of packets, greater to lower
    ///     rsniffer -s 9G      sorting by last timestamp, greater to lower
    ///     rsniffer -s 0L      sorting by source ip, lower to greater
    #[arg(short, long, verbatim_doc_comment)]
    pub sort: Option<String>,

    /// Sets the time interval (in seconds) after which an updated version of the report will be generated.
    /// 
    /// [default: 3]
    #[arg(short, long)]
    pub time_interval: Option<u64>
}