import re
import tkinter as tk
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Default IPs
default_ips = [
    "198.244.167.81",
    "135.125.123.127",
    "217.182.137.42",
    "51.195.180.17",
    "51.91.68.41",
    "", "", ""
]

# Function to query Minecraft server for version
def get_minecraft_version(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((ip, port))
            sock.send(b'\xFE\x01')  # Send the server list ping packet
            data = sock.recv(4096)  # Receive up to 4KB of data
            if data and data[0] == 0xFF:  # Check if it's a kick packet
                # Remove null characters from the received data
                cleaned_data = data.replace(b'\x00', b'')
                # Extract the version from the cleaned data
                version_info = cleaned_data.decode('utf-8', errors='ignore')[3:]
                version, description = extract_version_and_description(version_info)
                return version, description
            else:
                return "Unknown", "Unknown"
    except Exception as e:
        print(f"Error getting Minecraft version: {e}")
        return "Unknown", "Unknown"

# Function to extract version and description
def extract_version_and_description(version_info):
    # Search for sequences of digits separated by dots
    version_match = re.search(r'\d+\.\d+\.\d+', version_info)

    if version_match:
        version = version_match.group()
        version = version.replace("27", "")
        description = version_info.replace(version, '').strip()
        description = re.sub(r"\b27\b|\d+$", "", description)
        description = re.sub(r"27", "", description)
    else:
        version = "Unknown"
        description = version_info

    return version, description


# Function to scan ports for an IP
def scan_ports(ip, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        except Exception as e:
            print(f"Error scanning port {port} on {ip}: {e}")
    return ip, open_ports

# Function to scan IPs
def scan_ips():
    start_port = int(start_port_entry.get())
    end_port = int(end_port_entry.get())
    output_file = output_file_entry.get()

    with open(output_file, 'w') as f:
        f.write("")  # Clear the file

    for entry, ip in zip(ip_entries, default_ips):
        ip = entry.get() if entry.get() else ip
        if ip:
            with ThreadPoolExecutor(max_workers=5) as executor:
                future = executor.submit(scan_ports, ip, start_port, end_port)
                ip, open_ports = future.result()
                if open_ports:
                    with open(output_file, 'a') as f:
                        for port in open_ports:
                            version, description = get_minecraft_version(ip, port)
                            f.write(f"{ip}:{port} (Minecraft version: {version}, Description: {description})\n")

    print("Scanning completed. Results written to", output_file)

# Main window
root = tk.Tk()
root.title("Minecraft Server Scanner")

# Port Range Entries
start_port_label = tk.Label(root, text="Start Port:")
start_port_label.grid(row=0, column=0, padx=5, pady=5)
start_port_entry = tk.Entry(root)
start_port_entry.insert(0, "25565")
start_port_entry.grid(row=0, column=1, padx=5, pady=5)

end_port_label = tk.Label(root, text="End Port:")
end_port_label.grid(row=1, column=0, padx=5, pady=5)
end_port_entry = tk.Entry(root)
end_port_entry.insert(0, "25575")
end_port_entry.grid(row=1, column=1, padx=5, pady=5)

output_file_label = tk.Label(root, text="Output File:")
output_file_label.grid(row=2, column=0, padx=5, pady=5)
output_file_entry = tk.Entry(root)
output_file_entry.insert(0, "minecraft_server_scan_results.txt")
output_file_entry.grid(row=2, column=1, padx=5, pady=5)

# IP Entries
ip_entries = []
for i, ip in enumerate(default_ips):
    ip_label = tk.Label(root, text=f"IP {i+1}:")
    ip_label.grid(row=i+3, column=0, padx=5, pady=5)
    ip_entry = tk.Entry(root)
    ip_entry.insert(0, ip)
    ip_entry.grid(row=i+3, column=1, padx=5, pady=5)
    ip_entries.append(ip_entry)

# Scan Button
scan_button = tk.Button(root, text="Scan and Save", command=scan_ips)
scan_button.grid(row=11, column=0, columnspan=2, padx=5, pady=5)

root.mainloop()
