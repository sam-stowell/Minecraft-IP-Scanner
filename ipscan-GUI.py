import tkinter as tk
from tkinter import ttk
import socket
from concurrent.futures import ThreadPoolExecutor
import re

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
                return f"{ip}:{port}", version, description  # Merge IP and port into one string
            else:
                return f"{ip}:{port}", "Unknown", "Unknown"  # Merge IP and port into one string
    except Exception as e:
        print(f"Error getting Minecraft version for {ip}:{port}: {e}")
        return f"{ip}:{port}", "Unknown", "Unknown"  # Merge IP and port into one string



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

    # Clear previous results
    for row in results_tree.get_children():
        results_tree.delete(row)

    for entry, ip in zip(ip_entries, default_ips):
        ip = entry.get() if entry.get() else ip
        if ip:
            with ThreadPoolExecutor(max_workers=5) as executor:
                future = executor.submit(scan_ports, ip, start_port, end_port)
                ip, open_ports = future.result()
                if open_ports:
                    for port in open_ports:
                        result = get_minecraft_version(ip, port)
                        results_tree.insert("", tk.END, values=result)  # Insert the result tuple

def sort_column(tree, col, reverse):
    data = [(tree.set(child, col), child) for child in tree.get_children('')]
    data.sort(reverse=reverse)

    for index, (val, child) in enumerate(data):
        tree.move(child, '', index)

    tree.heading(col, command=lambda: sort_column(tree, col, not reverse))

def copy_text():
    selected_item = results_tree.focus()
    if selected_item:
        ip, port = results_tree.item(selected_item, 'values')[:2]
        text_to_copy = f"{ip}"
        root.clipboard_clear()
        root.clipboard_append(text_to_copy)



# Main window
root = tk.Tk()
root.title("Minecraft Server Scanner")

# Create a frame for the input fields
input_frame = ttk.Frame(root)
input_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

# Port Range Entries
start_port_label = tk.Label(input_frame, text="Start Port:")
start_port_label.grid(row=0, column=0, padx=5, pady=5)
start_port_entry = tk.Entry(input_frame)
start_port_entry.insert(0, "25565")
start_port_entry.grid(row=0, column=1, padx=5, pady=5)

end_port_label = tk.Label(input_frame, text="End Port:")
end_port_label.grid(row=1, column=0, padx=5, pady=5)
end_port_entry = tk.Entry(input_frame)
end_port_entry.insert(0, "25575")
end_port_entry.grid(row=1, column=1, padx=5, pady=5)

# IP Entries
ip_entries = []
for i, ip in enumerate(default_ips):
    ip_label = tk.Label(input_frame, text=f"IP {i+1}:")
    ip_label.grid(row=i+2, column=0, padx=5, pady=5)
    ip_entry = tk.Entry(input_frame)
    ip_entry.insert(0, ip)
    ip_entry.grid(row=i+2, column=1, padx=5, pady=5)
    ip_entries.append(ip_entry)

# Scan Button
scan_button = tk.Button(root, text="Scan and Show Results", command=scan_ips)
scan_button.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

# Results Tree
results_tree_frame = ttk.Frame(root)
results_tree_frame.grid(row=2, column=0, sticky="nsew", padx=5, pady=5)

results_tree = ttk.Treeview(results_tree_frame, columns=("IP", "Version", "Description"), show="headings")
results_tree.heading("IP", text="IP", command=lambda: sort_column(results_tree, "IP", False))
results_tree.heading("Version", text="Version", command=lambda: sort_column(results_tree, "Version", False))
results_tree.heading("Description", text="Description", command=lambda: sort_column(results_tree, "Description", False))
results_tree.pack(side="left", fill="both", expand=True)

# Add scrollbar
tree_scroll = ttk.Scrollbar(results_tree_frame, orient="vertical", command=results_tree.yview)
tree_scroll.pack(side="right", fill="y")
results_tree.config(yscrollcommand=tree_scroll.set)

# Configure column weights
root.grid_columnconfigure(0, weight=1)

# Configure row weights
root.grid_rowconfigure(2, weight=1)

# Context Menu
context_menu = tk.Menu(root, tearoff=0)
context_menu.add_command(label="Copy", command=copy_text)

def popup(event):
    context_menu.post(event.x_root, event.y_root)

results_tree.bind("<Button-3>", popup)  # Right-click to open context menu

root.mainloop()