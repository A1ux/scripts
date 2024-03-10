import csv
import argparse
import re

def parse_csv(file_path):
    with open(file_path, 'r') as file:
        reader = csv.reader(file)
        data = {}
        for row in reader:
            ip, port, _, _, _, version = row
            # Regex modificada para identificar una gama más amplia de versiones
            if re.search(r'\d+(\.\d+)*(\w+)?', version):
                key = version.split(' ')[0] + ' ' + re.search(r'\d+(\.\d+)*(\w+)?', version).group()
                if key not in data:
                    data[key] = []
                data[key].append(f"{ip}:{port}/TCP")
        return data

def print_or_save(data, output_file=None):
    for version, hosts in data.items():
        print(f"{version}:")
        for host in hosts:
            print(f"  {host}")
        print()

    if output_file:
        with open(output_file, 'w') as file:
            for version, hosts in data.items():
                file.write(f"{version}:\n")
                for host in hosts:
                    file.write(f"  {host}\n")
                file.write("\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse and group CSV data by product version.")
    parser.add_argument('-f', '--file', required=True, help="Path to the CSV file")
    parser.add_argument('-o', '--output', help="Output file to save the results")
    args = parser.parse_args()

    parsed_data = parse_csv(args.file)
    print_or_save(parsed_data, args.output)