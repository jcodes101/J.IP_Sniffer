// J.IP SNIFFER CLI TOOL

// NAMESPACES USED:
// standard environmental space library (used to pull args from the CLI)
use std::env;

// used for input/output operations, specifically flushing stdout after printing.
use std::io::{self, Write};

// handles IP address parsing and TCP connections for port scanning.
use std::net::{IpAddr, TcpStream};

// allows the conversion of strings to IPAddress type
// because arguments are being passed in as strings
use std::str::FromStr;

// manages the way program shuts down
use std::process;

// multi-producer, single-consumer channel for thread communication.
use std::sync::mpsc::{Sender, channel};

// allows for spawning threads for concurrent port scanning.
use std::thread;

// max port that can be sniffed
const MAX: u16 = 65535;

// struct (Args) that holds CLI arguments
struct Args {
    // stores flags like '-h' or '-t'
    flag: String,

    // enum that can take either v4 or v6 (target IP address)
    ipaddr: IpAddr,

    // number of threads to use for scanning
    threads: u16,
}

// implementation block for Args struct
impl Args {
    /* new method
        - takes in reference to the Vector of Strings
        - returns a result that shows either in the OK or ERROR
            - 'static slice of str is to send back any errors to the main fn
        - parses CLI arguments and constructs Args struct
    */
    fn new(args: &[String]) -> Result<Args, &'static str> {
        // checkers to make sure correct amount of arguments have been passed in
        // must have at least 2 and no more than 4 arguments
        if args.len() < 2 {
            return Err("not enough arguments.");
        } else if args.len() > 4 {
            return Err("too many arguments.");
        }

        // variable that inspects the first index of the String Vector
        let f = args[1].clone();

        // if let binding to construct the IP from the String
        // if user enters an IP directly, use default threads (4)
        if let Ok(ipaddr) = IpAddr::from_str(&f) {
            // returns the argument struct, with empty flag, entered ip, and default amnt of threads
            return Ok(Args {
                flag: String::from(""),
                ipaddr,
                threads: 4,
            });

        // either a flag has been used or incorrect IP value (gobble-dee-gook) has been passed through
        } else {
            // the flag is assigned to and inspected at the first index
            // stores the flag for later checks
            let flag = args[1].clone();

            // case check for: if user entered -h flag (help)
            if flag.contains("-h") || flag.contains("-help") && args.len() == 2 {
                println!(
                    "++Welcome to the J.IP Sniffer++
                \n Flag -h : use '-h' or '-help' to show this help message.
                \n Flag -t : use '-t' to select how many threads you want."
                );

                return Err("help");
            }
            // case check for: if user enters anything after either -h or -help
            else if flag.contains("-h") || flag.contains("-help") {
                return Err("you have entered too many arguements.");
            }
            // case check for: if user uses -t flag (thread count)
            else if flag.contains("-t") {
                // if so turns args in the 3rd index to an IP
                let ipaddr = match IpAddr::from_str(&args[3]) {
                    // unwrap Ok value
                    Ok(s) => s,
                    // otherwise print error message
                    Err(_) => return Err("this is not a valid IP_ADDRESS - must be IPv4 or IPv6."),
                };

                // changes strings into a u16 value (thread count)
                let threads = match args[2].parse::<u16>() {
                    // unwrap Ok value
                    Ok(s) => s,
                    // otherwise print error message
                    Err(_) => return Err("failed to parse thread number, please try again."),
                };
                // return Ok with Args struct
                return Ok(Args {
                    threads,
                    flag,
                    ipaddr,
                });

            // case check for: if user enters invalid syntax
            } else {
                return Err("invalid syntax");
            }
        }
    }
}

/* scan fn :
    - takes in Sender (channel transmitter)
    - start_port that scales from 0 to number of ports specified
    - addr: IP address to scan
    - num_threads: number of threads being used
    - scans ports in increments of num_threads, starting from start_port + 1
*/
fn scan(tx: Sender<u16>, start_port: u16, addr: IpAddr, num_threads: u16) {
    // used so port 0 is not being looked at
    let mut port: u16 = start_port + 1;

    loop {
        match TcpStream::connect((addr, port)) {
            Ok(_) => {
                // sends back a "." for every port that is open
                print!(".");
                io::stdout().flush().unwrap();

                // send open port to main thread
                tx.send(port).unwrap();
            }
            // if there is an error, return back an empty expression
            Err(_) => {}
        }

        // check so that if there are 0 threads, the loop is broken
        if (MAX - port) < num_threads {
            break;
        }

        // allows for iteration, so the fn and number of ports can scale
        port += num_threads;
    }
}

/* main fn :
    - entry point for the CLI tool
    - parses CLI arguments
    - sets up multithreading and channel communication
    - collects and prints open ports
    - prints debug information
*/
fn main() {
    // takes all args that were passed in and puts them inside a Vector of Strings
    let args: Vec<String> = env::args().collect();

    // program name
    let program = args[0].clone();

    // arguments variable that takes in the args Vector above
    // .unwrap_or_else() that takes in a closure for error handling
    let arguments = Args::new(&args).unwrap_or_else(|err| {
        if err.contains("help") {
            process::exit(0);
        } else {
            eprintln!("{} problem parsing arguments: {}", program, err);
            process::exit(0);
        }
    });

    // bind threads to num_threads variable
    let num_threads = arguments.threads;

    // addr variable that corresponds to 'arguments.ipaddr' variable
    let addr = arguments.ipaddr;

    // instantiate a channel -- destructure the tuple that is returned (transmitter, receiver)
    let (tx, rx) = channel();

    // spawn threads for concurrent port scanning
    for i in 0..num_threads {
        // bind a clone of tx so each thread has its own transmitter
        let tx = tx.clone();

        thread::spawn(move || {
            scan(tx, i, addr, num_threads);
        });
    }

    let mut out = vec![];
    // drop tx so it is not in the main thread
    drop(tx);

    // iterate through receiver and push into 'out' Vector
    for p in rx {
        out.push(p);
    }

    println!("");
    out.sort();
    for v in out {
        println!("port {} is open", v);
    }

    // DEBUG USE: to print out -- comment this out if needed
    // * used to output the path args
    println!("\nDEBUG USAGE BELOW:");
    for i in &args {
        println!("{}", i)
    }
    // * print with debug flag
    println!("{:?}", args)
}

/* EXAMPLES

    -   j_ip_sniffer.exe -h (-h flag for help screen)
    -   j_ip_sniffer.exe -t (-t flag for how many threads -- ex.100 111.111.1.1)
    -   j_ip_sniffer.exe 111.111.1.1 (actual executable to call on an IP address with default set number of threads)

    *   when you do 'cargo run --' the '--' tells the program to put the commands towards the excutable instead of cargo itself
*/
