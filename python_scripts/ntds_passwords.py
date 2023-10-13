import argparse
import csv
# Configurar argumentos de línea de comando
parser = argparse.ArgumentParser(description='Parsear archivo y guardar valores 1 y 4 en CSV.')
parser.add_argument('-n', '--ntds', type=str, help='Nombre del archivo NTDS')
parser.add_argument('-p', '--passwords', type=str, help='Nombre del archivo de contraseñas')
parser.add_argument('-o', '--output', type=str, default='salida.csv', help='Nombre del archivo de salida CSV')
args = parser.parse_args()
# Verificar si se proporcionó un nombre de archivo NTDS
if args.ntds is None:
    print('Debe proporcionar el nombre del archivo NTDS con el parámetro -n o --ntds.')
    exit()
# Verificar si se proporcionó un nombre de archivo de contraseñas
if args.passwords is None:
    print('Debe proporcionar el nombre del archivo de contraseñas con el parámetro -p o --passwords.')
    exit()
# Abrir archivo de texto con contraseñas
with open(args.passwords, 'r') as archivo_contrasenas:
    contrasenas = {}
    for line in archivo_contrasenas:
        parts = line.strip().split(':')
        hash_valor = parts[0]
        contrasena_valor = parts[1]
        contrasenas[hash_valor] = contrasena_valor
# Abrir archivo de texto NTDS
with open(args.ntds, 'r') as archivo_ntds:
    valores = []
    for line in archivo_ntds:
        parts = line.strip().split(':')
        valor1 = parts[0]
        valor4 = parts[3]
        
        if valor4 in contrasenas:
            valor_password = contrasenas[valor4]
        else:
            valor_password = ''
        
        valores.append([valor1, valor4, valor_password])
# Guardar valores en archivo CSV
with open(args.output, 'w', newline='') as archivo_csv:
    writer = csv.writer(archivo_csv)
    writer.writerows(valores)
