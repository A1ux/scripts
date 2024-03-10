import json
import argparse

# Configura los argumentos
parser = argparse.ArgumentParser(description='Generar comandos Nmap desde un archivo JSON.')
parser.add_argument('-f', '--file', required=True, help='Archivo JSON de entrada')
parser.add_argument('-o', '--output', help='Nombre del archivo de salida (opcional)')
parser.add_argument('-c', '--command', required=True, help='Comando Nmap con marcadores de posición IP y PORTS')
args = parser.parse_args()

# Cargar el archivo JSON especificado
with open(args.file, 'r') as file:
    data = json.load(file)

# Comprobar si se ha especificado un archivo de salida
if args.output:
    # Crear y abrir el archivo de salida si se especifica
    with open(args.output, 'w') as output:
        for ip, ports in data.items():
            nmap_command = args.command.replace('IP', ip).replace('PORTS', ','.join(map(str, ports))) + '\n'
            output.write(nmap_command)
    print(f'Se han generado los comandos en {args.output}')
else:
    # Imprimir en pantalla si no se especifica archivo de salida
    for ip, ports in data.items():
        nmap_command = args.command.replace('IP', ip).replace('PORTS', ','.join(map(str, ports)))
        print(nmap_command)
