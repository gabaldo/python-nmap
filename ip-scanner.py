import os
from tabulate import tabulate
import nmap

    
os.system('clear')

# Dstino da Rede
destino = '10.7.0.0/22'
#destino = '10.7.2.1-100'

# Porta a ser verificada
port = '22'

nm = nmap.PortScanner()
nm.scan(hosts=destino, ports=port)

# Cria uma lista vazia
host_list = []

# Se encontrar algum host, percorre todos
if nm.all_hosts():
    for host in nm.all_hosts():
        host_ip = host
        host_name = nm[host_ip].hostname()
        host_state = nm[host_ip].state()
        port_state = nm[host_ip]['tcp'][int(port)]['state']
        # Criando uma lista de todos os hosts
        host_list.append([host_ip, host_state, port_state, host_name])
else:
    print('Nenhum Host encontrado')
    
# Imprimindo a lista tabulada        
print(tabulate(host_list, headers=['IP do HOST', 'Estado do HOST', 'Estado da Porta 22', 'Nome do HOST']))

