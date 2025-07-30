# 🔍 J.IP Sniffer - CLI Port Scanning Tool in Rust

J.IP Sniffer is a lightweight, multi-threaded command-line port scanning tool written in **Rust**. It allows you to quickly and concurrently check for open TCP ports on a target IPv4 or IPv6 address.

---

## 📦 Features

- 🧠 Intelligent parsing of command-line arguments
- 🧵 Multi-threaded port scanning (up to 65535)
- ✅ Supports both IPv4 and IPv6
- ⚙️ Customizable thread count
- 🆘 Built-in help menu
- 📤 Channel-based thread communication

---

## 🛠️ Installation

### 1. Clone the repository:

```
git clone https://github.com/yourusername/j_ip_sniffer.git
cd j_ip_sniffer
```

### 2. Build the project with Cargo:
cargo build --release

### 3. Run it:
cargo run -- [OPTIONS]

(The -- tells Cargo to treat the following arguments as inputs to your program, not to Cargo itself.)

## 🚀 Usage:
j_ip_sniffer [FLAGS] [THREAD_COUNT] [TARGET_IP]

## ✅ Examples

```
# Help menu
cargo run -- -h

# Scan a target with default 4 threads
cargo run -- 192.168.0.1

# Scan a target with 100 threads
cargo run -- -t 100 192.168.0.1
```

## 🧠 Argument Breakdown
### Flag | Description | Example

+ -h	Shows the help menu ->	cargo run -- -h

+ -t	Sets the number of scanning threads ->	cargo run -- -t 50 10.0.0.5

+ IP Address	The target IP to scan (v4 or v6) ->	cargo run -- 127.0.0.1

📋 Output
When scanning, the program will print: "." for every open port found

A summary list of open ports

Debug information (CLI arguments passed)

```
...
port 21 is open
port 80 is open
port 443 is open

DEBUG USAGE BELOW:
cargo
run
--
192.168.0.1
["cargo", "run", "--", "192.168.0.1"]
```

## 🔐 Limitations & Notes
Only scans TCP ports.

Default port range is 1–65535.

Custom port ranges are not supported yet but can be added (see Issues for future features).

May require elevated privileges depending on your OS and network.

📃 License
MIT License — see LICENSE for details.

🤝 Acknowledgements
Rust Standard Library for std::net, std::thread, std::sync::mpsc

Community inspiration for CLI tools and scanners
