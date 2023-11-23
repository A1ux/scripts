# main.py

import argparse
from modules.nmap import generate_nmap_commands

def main():
    parser = argparse.ArgumentParser(description="Herramienta principal para ejecutar comandos Nmap personalizados.")
    subparsers = parser.add_subparsers(help='sub-command help')

    # Crear el analizador para el subcomando "nmap"
    parser_nmap = subparsers.add_parser('nmap', help='nmap command help')
    parser_nmap.add_argument('-f', '--file', required=True, help='Archivo de entrada que contiene IPs o CIDRs')
    parser_nmap.add_argument('-o', '--output', help='Nombre del archivo de salida (opcional)')
    parser_nmap.add_argument('-c', '--command', required=True, help='Comando personalizado con marcadores de posición IP')
    parser_nmap.set_defaults(func=nmap_command)

    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

def nmap_command(args):
    with open(args.file, 'r') as input_file:
        ips = input_file.read().splitlines()
    generate_nmap_commands(ips, args.command, args.output)

if __name__ == "__main__":
    main()
