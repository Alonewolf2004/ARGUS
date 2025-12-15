Python Multithreaded Port Scanner

A fast TCP port scanner written in Python using only the standard library.
The tool performs parallel port scanning with banner grabbing and basic service and OS fingerprinting.

This project is actively evolving and focused on learning real world network reconnaissance concepts.

What This Tool Does

Resolves hostnames and IP addresses

Scans multiple ports in parallel using threads

Supports single ports multiple ports and port ranges

Removes duplicate ports automatically

Detects open ports using TCP connect scanning

Grabs banners from common services

Performs lightweight service and OS identification

Displays a clean scan summary with timing

Why This Project Exists

This tool was built to understand how scanners like nmap work internally rather than just using them.
Every feature was added incrementally through debugging and testing against real hosts.

The goal is learning by building not copying.

Features in Detail

DNS resolution using socket functions

Robust input validation for ports and ranges

Queue based multithreaded scanning

Thread safe result handling

Protocol aware banner grabbing for SSH HTTP FTP SMTP

Basic fingerprinting using banner patterns

Accurate scan timing and reporting

Requirements

Python 3

No external libraries

Works on Windows Linux and macOS

How To Run

Run the scanner directly with Python

python scanningtool.py


You will be prompted for
Target hostname or IP address
Ports to scan using space separated values or ranges

Example inputs
22
22 80 443
25 to 35
22 25 to 35 443

Sample Output

The tool reports
Open and closed ports
Detected service versions
Likely operating system
Scan duration and summary

Output is similar in spirit to a TCP connect scan in nmap.

Limitations

This is a TCP connect scanner not a SYN scanner

OS detection is banner based and not guaranteed

HTTPS services are not decrypted

Very large port ranges may stress the local system

These are expected tradeoffs for a learning focused tool.

Future Improvements

Command line arguments instead of prompts

Adaptive thread count and timeouts

TLS aware banner grabbing

Extended service fingerprint database
