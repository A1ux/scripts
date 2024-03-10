from neo4j import GraphDatabase
import argparse

# Clase para gestionar la conexión con la base de datos
class Database:
    def __init__(self, uri, user, password):
        self._driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self._driver.close()

    # Ejecuta una consulta
    def run_query(self, query):
        with self._driver.session() as session:
            result = session.run(query)
            return result

# Función para marcar usuarios como 'owned'
def mark_as_owned(username):
    query = f"MATCH (u:User {{samaccountname: '{username}'}}) SET u.owned = true RETURN u"
    return query

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="Archivo de usuarios", required=True)
    args = parser.parse_args()

    # Parámetros de conexión a tu base de datos Neo4j
    uri = "bolt://localhost:7687"  # Reemplaza con tu URI
    user = "neo4j"  # Reemplaza con tu usuario
    password = "changeme"  # Reemplaza con tu contraseña

    # Crea una instancia de la base de datos
    db = Database(uri, user, password)

    # Lee la lista de usuarios desde el archivo
    with open(args.file, "r") as file:
        users = [line.strip().upper() for line in file]  # Convertir a mayúsculas

    for username in users:
        query = mark_as_owned(username)
        result = db.run_query(query)
        print(f"Marcando como 'owned' a {username}")

    # Cierra la conexión
    db.close()