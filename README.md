# Network Traffic Analyzer

Network Traffic Analyzer is a Python script that captures and analyzes network traffic on a specified network interface. It provides detailed insights into the captured traffic, including source and destination IP addresses, protocols, packet sizes, and more. The script utilizes the Scapy, Psutil, and Colorama libraries for packet manipulation, system information retrieval, and colorful terminal output, respectively.

## Features

- Capture and analyze network traffic on a specific network interface.
- Display detailed information about each captured packet, including IP addresses, protocols, and packet sizes.
- Provide a summary of traffic analysis, including packet counts, unique IP addresses, and protocols.
- Save captured packets to a PCAP file for further analysis.

## Prerequisites

Before running the script, make sure you have the following prerequisites:

- Python 3.6 or higher installed on your system.
- Scapy library: Install it using the command `pip install scapy`.
- Psutil library: Install it using the command `pip install psutil`.
- Colorama library: Install it using the command `pip install colorama`.

## Usage

Follow the steps below to use the Network Traffic Analyzer script:

1. Clone the repository:

   ```shell
   git clone https://github.com/ajithchandranr/network_traffic_analyzer.git
   ```

2. Navigate to the project directory:

   ```shell
   cd network_traffic_analyzer
   ```

3. Run the script:

   ```shell
   python traffic_analyzer.py
   ```

4. The script will display the available network interfaces. Enter the name of the network interface you want to capture traffic on.

5. Enter the number of packets you want to capture.

6. The script will start capturing the packets on the specified network interface.

7. As the packets are captured, the script will display detailed information about each packet, including IP addresses, protocols, and packet sizes.

8. Once the capturing is complete, the script will provide a summary of the traffic analysis, including packet counts, unique IP addresses, and protocols.

9. You can choose to save the captured packets to a `PCAP` file for further analysis by entering 'yes' when prompted. The PCAP file will be saved in the current directory.

## Contributing

Contributions, bug reports, and feature requests are welcome! If you find any issues or have suggestions for improvements, feel free to open an issue or submit a pull request.

## Acknowledgments

The Network Traffic Analyzer script is built using the following libraries:

- [Scapy](https://scapy.net/) - a powerful Python library for packet manipulation and network scanning.
- [Psutil](https://psutil.readthedocs.io/) - a cross-platform library for retrieving information about running processes and system utilization.
- [Colorama](https://pypi.org/project/colorama/) - a Python library for cross-platform colored terminal text.

## License

This project is licensed under the [MIT License](LICENSE).

## Contact

e-mail     : ajithchandranr@protonmail.com 

linkedin  : https://www.linkedin.com/in/ajithchandranr/
