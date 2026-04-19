# netrecon-nmap-wireshark-analysis
A local network scanner that uses ARP packets to detect all devices connected to your WiFi, showing their IP, MAC address, and hardware vendor.
netrecon is a WiFi device tracker built with Python and Flask. 
It broadcasts ARP packets across your local subnet to discover every 
connected device in real time — displaying IP addresses, MAC addresses, 
manufacturer/vendor names, and hostnames through a professional web dashboard.

Built using Scapy for raw packet analysis, Flask as the backend server, 
and vanilla HTML/CSS/JS for the frontend. Requires Administrator or root 
privileges for active ARP scanning.
