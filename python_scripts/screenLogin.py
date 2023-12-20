#!/usr/bin/python3

# Author: A1ux
# pip3 insall selenium
# Tambien modificar el sleep si anda algo lento 

import argparse
import csv
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium import webdriver
from selenium.webdriver.common.by import By
import time
import datetime

def login(mail, password):
    driver = webdriver.Firefox()

    driver.get("https://login.microsoftonline.com/")
    valcon = True
    time.sleep(5)
    usu = driver.find_element(By.ID, 'i0116')
    usu.clear()
    usu.send_keys(mail)
    ing = driver.find_element(By.ID, 'idSIButton9')
    ing.click()

    time.sleep(5)
    pw = driver.find_element(By.ID, 'passwordInput')  #Input de password siguiente
    pw.clear()
    pw.send_keys(password)
    ingPersonal = driver.find_element(By.ID, 'submitButton')  ## Boton de password siguiente
    ingPersonal.click()

    nombre_usuario = mail.split("@")[0]
    fecha_hora_actual = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    nombre_archivo = f"{nombre_usuario}_{fecha_hora_actual}.png"
    time.sleep(5)
    driver.save_screenshot(nombre_archivo)
    driver.quit()

def login_from_csv(csv_file):
    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            if len(row) == 2:
                username, password = row
                login(username, password)
            else:
                print("Formato incorrecto en el archivo CSV. Cada línea debe tener un usuario y una contraseña.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Script de inicio de sesión con argumentos de línea de comandos.')
    parser.add_argument('-u', '--user', help='Nombre de usuario')
    parser.add_argument('-p', '--password', help='Contraseña')
    parser.add_argument('--userpassfile', '--upf', help='Archivo CSV con pares de usuario y contraseña')

    args = parser.parse_args()

    if args.userpassfile:
        login_from_csv(args.userpassfile)
    elif args.user and args.password:
        login(args.user, args.password)
    else:
        print("Se requieren credenciales. Usa -u y -p o --userpassfile para proporcionarlas.")
