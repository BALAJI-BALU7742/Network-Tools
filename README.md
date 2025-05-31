# Network Tools Desktop Application

A PyQt6-based desktop application providing a suite of network utilities including:

- Public IP lookup  
- IP Geolocation  
- Internet Speed Test  
- DNS Lookup  
- Whois Lookup  
- Traceroute  

## Features

- Intuitive GUI with buttons and tooltips  
- Responsive UI using worker threads for network calls  
- Animated loading spinner and progress bar for feedback  
- Comprehensive logging and export logs to a text file  
- Supports multiple DNS record types and error handling  
- Cross-platform traceroute command detection  

## Requirements

- Python 3.8+  
- PyQt6  
- requests  
- whois  
- dnspython  
- speedtest-cli  

Install dependencies with:

```bash
pip install PyQt6 requests whois dnspython speedtest-cli
