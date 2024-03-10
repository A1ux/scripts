#!/usr/bin/python3

import argparse
import csv
import re
import json

def filter_and_extract_credentials(input_file):
    credentials = []

    with open(input_file, 'r') as file:
        reader = csv.reader(file)
        header = next(reader)  # Leer la primera fila (encabezado)

        for row in reader:
            # Comprobar si la palabra "password" está en alguna parte de la fila
            if any("password" in str(cell).lower() for cell in row):
                email = row[1]  # Correo electrónico en la columna 2
                # Extraer el contenido de la contraseña en la columna 5
                password_match = re.search(r'"password"\s*:\s*\["(.*?)"\]', row[4])
                if password_match:
                    password = password_match.group(1)
                    # Reemplazar secuencias como \u0026 o \uXXXX por sus valores correspondientes
                    password = json.loads(f'"{password}"')
                    credentials.append((email, password))

    return credentials

def print_or_save_results(credentials, output_file):
    if output_file:
        with open(output_file, 'w', newline='') as output:
            writer = csv.writer(output)
            writer.writerow(["Email", "Password"])
            for email, password in credentials:
                writer.writerow([email, password])
        print(f"Los resultados se guardaron en '{output_file}'.")
    else:
        for email, password in credentials:
            print(f"{email},{password}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Parser de CSV para filtrar líneas que contienen la palabra "password" y extraer credenciales.')
    parser.add_argument('-f', '--file', required=True, help='Archivo CSV de entrada')
    parser.add_argument('-o', '--output', help='Archivo CSV de salida (opcional)')

    args = parser.parse_args()

    credentials = filter_and_extract_credentials(args.file)

    if not credentials:
        print("No se encontraron credenciales.")
    else:
        print_or_save_results(credentials, args.output)
