import argparse

# Configurar los argumentos
parser = argparse.ArgumentParser(description='Generar comandos personalizados a partir de un archivo con IPs o CIDRs.')
parser.add_argument('-f', '--file', required=True, help='Archivo de entrada que contiene IPs o CIDRs')
parser.add_argument('-o', '--output', help='Nombre del archivo de salida (opcional)')
parser.add_argument('-c', '--command', required=True, help='Comando personalizado con marcadores de posición IP')
args = parser.parse_args()

# Leer el archivo con IPs o CIDRs y generar los comandos
with open(args.file, 'r') as input_file:
    ips = input_file.read().splitlines()

# Comprobar si se ha especificado un archivo de salida
if args.output:
    # Escribir los comandos en el archivo de salida si se especifica
    with open(args.output, 'w') as output_file:
        for ip in ips:
            nmap_command = args.command.replace('IP', ip) + '\n'
            output_file.write(nmap_command)
    print(f'Se han generado los comandos en {args.output}')
else:
    # Imprimir los comandos en pantalla si no se especifica archivo de salida
    for ip in ips:
        nmap_command = args.command.replace('IP', ip)
        print(nmap_command)
