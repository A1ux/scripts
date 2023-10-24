import os
import json
import argparse
import re

def process_gnmap_file(gnmap_file, result_dict):
    with open(gnmap_file, 'r') as file:
        for line in file:
            # Busca las líneas que indican puertos abiertos
            if "Ports: " in line:
                # Busca los números de puerto que están abiertos
                open_ports = re.findall(r'(\d+)/open', line)
                if open_ports:
                    parts = line.split()
                    ip = parts[1]
                    if ip in result_dict:
                        result_dict[ip].extend(open_ports)
                    else:
                        result_dict[ip] = open_ports

def save_to_json(data, json_filename):
    with open(json_filename, 'w') as json_file:
        json.dump(data, json_file, indent=4)

def main():
    parser = argparse.ArgumentParser(description="Procesa archivos .gnmap de Nmap y genera un archivo JSON con la información de puertos abiertos.")
    parser.add_argument("-d", "--directory", required=True, help="Directorio que contiene los archivos .gnmap")
    parser.add_argument("-j", "--json", default="puertos_abiertos.json", help="Nombre del archivo JSON de salida")
    args = parser.parse_args()

    directory = args.directory
    gnmap_files = [f for f in os.listdir(directory) if f.endswith(".gnmap")]

    result_dict = {}
    
    for gnmap_file in gnmap_files:
        gnmap_file_path = os.path.join(directory, gnmap_file)
        process_gnmap_file(gnmap_file_path, result_dict)

    json_filename = args.json
    save_to_json(result_dict, json_filename)

    print(f"Información de puertos abiertos guardada en {json_filename}")

if __name__ == "__main__":
    main()