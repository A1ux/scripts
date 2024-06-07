import argparse
from neo4j import GraphDatabase

def query_users(tx):
    query = """
    MATCH (u:User)
    RETURN u.samaccountname AS samaccountname, u.displayname AS displayname
    """
    result = tx.run(query)
    return [{"samaccountname": record["samaccountname"], "displayname": record["displayname"]} for record in result]

def filter_and_process_users(users):
    seen_samaccountnames = set()
    processed_users = []

    for user in users:
        samaccountname = user['samaccountname']
        displayname = user['displayname']
        
        if samaccountname:
            samaccountname = samaccountname.replace('$', '')
            if samaccountname not in seen_samaccountnames:
                seen_samaccountnames.add(samaccountname)
                processed_users.append({"samaccountname": samaccountname, "displayname": displayname})
    
    return processed_users

def write_to_csv(output_file, data):
    with open(output_file, mode='w', newline='', encoding='utf-8') as file:
        for row in data:
            displayname_parts = row['displayname'].split() if row['displayname'] else []
            file.write(f"{row['samaccountname']}\n")
            for part in displayname_parts:
                file.write(f"{part}\n")

def main():
    parser = argparse.ArgumentParser(description="Query Neo4j database for users and output results.")
    parser.add_argument("-u", "--username", required=True, help="Neo4j username")
    parser.add_argument("-p", "--password", required=True, help="Neo4j password")
    parser.add_argument("-o", "--output", help="Output file (CSV format)")
    
    args = parser.parse_args()

    uri = "bolt://localhost:7687"  # Assuming default URI; adjust if necessary
    driver = GraphDatabase.driver(uri, auth=(args.username, args.password))

    with driver.session() as session:
        users = session.read_transaction(query_users)
    
    processed_users = filter_and_process_users(users)
    
    if args.output:
        write_to_csv(args.output, processed_users)
    else:
        for user in processed_users:
            print(user["samaccountname"])
            if user["displayname"]:
                displayname_parts = user["displayname"].split()
                for part in displayname_parts:
                    print(part)

    driver.close()

if __name__ == "__main__":
    main()
