import os
import argparse
import re

def extract_services(directory):
    host_ports = []
    for filename in os.listdir(directory):
        if filename.endswith(".gnmap"):
            with open(os.path.join(directory, filename), 'r', errors='ignore') as file:
                for line in file:
                    if "open" in line and ("http" in line or "https" in line):
                        # Buscar el hostname y la dirección IP en la línea
                        match = re.search(r'Host: (\d+\.\d+\.\d+\.\d+) \(([^)]+)\)', line)
                        if match:
                            hostname = match.group(2)
                            ports = re.findall(r'(\d+)/open/tcp//https?/', line)
                            for port in ports:
                                host_port = f"{hostname}:{port}"
                                host_ports.append(host_port)
    return host_ports

def main():
    parser = argparse.ArgumentParser(description="Extract web service hostnames and ports from .gnmap files.")
    parser.add_argument("-d", "--directory", required=True, help="Directory containing .gnmap files")
    parser.add_argument("-o", "--output", help="Output file to save host:port pairs")
    args = parser.parse_args()

    host_ports = extract_services(args.directory)
    if args.output:
        with open(args.output, "w") as f:
            for entry in host_ports:
                f.write(entry + "\n")
    else:
        for entry in host_ports:
            print(entry)

if __name__ == "__main__":
    main()
