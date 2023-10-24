import json
import argparse

# Configura los argumentos
parser = argparse.ArgumentParser(description='Generar comandos Nmap desde un archivo JSON.')
parser.add_argument('-f', '--file', required=True, help='Archivo JSON de entrada')
parser.add_argument('-o', '--output', default='comandos_nmap.txt', help='Nombre del archivo de salida')
parser.add_argument('-c', '--command', required=True, help='Comando Nmap con marcadores de posición IP y PORTS')
args = parser.parse_args()

# Cargar el archivo JSON especificado
with open(args.file, 'r') as file:
    data = json.load(file)

# Crear y abrir el archivo de salida
with open(args.output, 'w') as output:
    for ip, ports in data.items():
        # Reemplazar los marcadores de posición IP y PORTS en el comando Nmap
        nmap_command = args.command.replace('IP', ip).replace('PORTS', ','.join(map(str, ports))) + '\n'

        # Escribir el comando en el archivo de salida
        output.write(nmap_command)

print(f'Se han generado los comandos en {args.output}')
