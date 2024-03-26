import tkinter as tk
import socket
from concurrent.futures import ThreadPoolExecutor

# Default IPs
default_ips = [
    "198.244.167.81",
    "135.125.123.127",
    "217.182.137.42",
    "51.195.180.17",
    "51.91.68.41",
    "", "", ""
]

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
            pass
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
                            f.write(f"{ip}:{port}\n")

    print("Scanning completed. Results written to", output_file)

# Main window
root = tk.Tk()
root.title("IP Port Scanner")

# Port Range Entries
start_port_label = tk.Label(root, text="Start Port:")
start_port_label.grid(row=0, column=0, padx=5, pady=5)
start_port_entry = tk.Entry(root)
start_port_entry.insert(0, "25500")
start_port_entry.grid(row=0, column=1, padx=5, pady=5)

end_port_label = tk.Label(root, text="End Port:")
end_port_label.grid(row=1, column=0, padx=5, pady=5)
end_port_entry = tk.Entry(root)
end_port_entry.insert(0, "25699")
end_port_entry.grid(row=1, column=1, padx=5, pady=5)

output_file_label = tk.Label(root, text="Output File:")
output_file_label.grid(row=2, column=0, padx=5, pady=5)
output_file_entry = tk.Entry(root)
output_file_entry.insert(0, "scan_results.txt")
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
