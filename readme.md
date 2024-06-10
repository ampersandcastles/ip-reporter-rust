# IP Reporter

IP Reporter is a desktop application built with Rust and GTK that listens for specific UDP packets on the network and displays the IP and MAC addresses of the sources. It allows users to export the collected data to a file and provides functionality to open the IP address in the default web browser.

## Features

- **Listen for UDP Packets**: Captures and displays the source IP and MAC addresses of UDP packets sent to a specific destination.
- **Export Data**: Export the collected IP and MAC addresses to a text file.
- **Open IP in Browser**: Double-click an IP address to open it in the default web browser.

## Dependencies

This project uses the following dependencies:

- `gtk`: For creating the graphical user interface.
- `glib`: For GLib integration with GTK.
- `pcap`: For capturing network packets.
- `reqwest`: For making HTTP requests.
- `threadpool`: For managing a pool of threads.
- `webbrowser`: For opening URLs in the default web browser.

## Installation

To build and run this project, you need to have Rust installed. If you don't have Rust installed, you can get it from [rustup.rs](https://rustup.rs/).

1. **Clone the repository**:

   ```sh
   git clone https://github.com/yourusername/ip-reporter.git
   cd ip-reporter
   ```

2. **Update dependencies**:
   Make sure your `Cargo.toml` file includes the required dependencies:

   ```toml
   [dependencies]
   gtk = "0.18.1"
   glib = "0.19.7"
   pcap = "2.0.0"
   reqwest = { version = "0.12.4", features = ["blocking"] }
   threadpool = "1.8"
   webbrowser = "0.6"
   ```

3. **Build the project**:

   ```sh
   cargo build
   ```

4. **Run the project**:
   ```sh
   cargo run
   ```

## Usage

1. **Start the Application**:
   Run the application using `cargo run`. The main window will display a list of IP and MAC addresses.

2. **Listen for UDP Packets**:
   Click the `Start` button to begin listening for UDP packets. The application will display the source IP and MAC addresses of packets that match the specified criteria.

3. **Export Data**:
   Click the `Export` button to save the collected IP and MAC addresses to a text file.

4. **Open IP in Browser**:
   Double-click an IP address in the list to open it in your default web browser.

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.

## Contributions

Contributions are welcome! Please open an issue or submit a pull request if you have any improvements or bug fixes.

## Acknowledgments

This project was developed with the help of several open-source libraries. Special thanks to the developers of `gtk`, `glib`, `pcap`, `reqwest`, `threadpool`, and `webbrowser` crates.
