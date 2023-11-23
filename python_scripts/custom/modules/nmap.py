# modnmap.py

def generate_nmap_commands(ips, nmap_command, output_file=None):
    commands = [nmap_command.replace('IP', ip) for ip in ips]

    if output_file:
        with open(output_file, 'w') as file:
            for command in commands:
                file.write(command + '\n')
        print(f'Se han generado los comandos en {output_file}')
    else:
        for command in commands:
            print(command)