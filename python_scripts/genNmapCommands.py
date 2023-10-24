import json
import argparse

# Configura los argumentos
parser = argparse.ArgumentParser(description='Generar comandos Nmap desde un archivo JSON.')
parser.add_argument('-f', '--file', required=True, help='Archivo JSON de entrada')
parser.add_argument('-o', '--output', default='comandos_nmap.txt', help='Nombre del archivo de salida')
args = parser.parse_args()

# Cargar el archivo JSON especificado
with open(args.file, 'r') as file:
    data = json.load(file)

# Crear y abrir el archivo de salida
with open(args.output, 'w') as output:
    for ip, ports in data.items():
        # Crear el comando Nmap
        port_list = ",".join(map(str, ports))
        nmap_command = f'nmap -vvv -Pn -p {port_list} -sV -sC {ip} -oA {ip}\n'

        # Escribir el comando en el archivo de salida
        output.write(nmap_command)

print(f'Se han generado los comandos en {args.output}')