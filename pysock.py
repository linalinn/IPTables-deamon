#only python2
import socket
import sys
import os
import json
from thread import *

MAX_Clients =  100
server_address = './uds_socket'

def error(connection,msg):
    connection.sendall(msg)

def addnat4rule(connection):
    connection.sendall("ADDNAT4RULE_STATE_OK")
    data = connection.recv(1042)
    IPTable = "iptables -t nat"
    ruledata = json.loads(data.decode("utf-8").lower())
    if ruledata["traffic"] in ["OUTPUT","INPUT"] : IPTable += " -A " + ruledata["traffic"]
    if ruledata["protocol"] in ["tcp","udp"] : IPTable += " -p " + ruledata["protocol"]
    if ruledata["interface"] in ["ALL"] : IPTable += " -i " + ruledata["interface"]
    if ruledata["dIP"]  != "NO" : IPTable += " -d " + ruledata["dIP"]
    if ruledata["dPort"] in ["NO"] : IPTable += " -dport " + ruledata["dPort"]
    IPTable += " -j DNAT " + "--to-destination " + ruledata["todest"]
    connection.sendall(IPTable)

def adddrop4rule(connection):
    connection.sendall("ADDDROP4RULE_STATE_FAIL")
    data = connection.recv(1042)
    IPTable = "iptables "
    ruledata = json.loads(data.decode("utf-8").lower())
    if ruledata["traffic"] in ["OUTPUT","INPUT"] : IPTable += " -A " + ruledata["traffic"]
    if ruledata["protocol"] in ["tcp","udp"] : IPTable += " -p " + ruledata["protocol"]
    if ruledata["interface"] in ["ALL"] : IPTable += " -i " + ruledata["interface"]
    if ruledata["dPort"] in ["NO"] : IPTable += " -dport " + ruledata["dPort"]
    if ruledata["sIP"]  != "NO" : IPTable += " -s " + ruledata["dIP"]
    IPTable += " -j DROP"
    connection.sendall(IPTable)

def adddreject4rule(connection):
    connection.sendall("ADDDROP4RULE_STATE_FAIL")
    data = connection.recv(1042)
    IPTable = "iptables "
    ruledata = json.loads(data.decode("utf-8").lower())
    if ruledata["traffic"] in ["OUTPUT","INPUT"] : IPTable += " -A " + ruledata["traffic"]
    if ruledata["protocol"] in ["tcp","udp"] : IPTable += " -p " + ruledata["protocol"]
    if ruledata["interface"] in ["ALL"] : IPTable += " -i " + ruledata["interface"]
    if ruledata["dPort"] in ["NO"] : IPTable += " -dport " + ruledata["dPort"]
    if ruledata["sIP"]  != "NO" : IPTable += " -s " + ruledata["dIP"]
    IPTable += " -j DROP"
    connection.sendall(IPTable)

def client(connection):
    connection.send("ready")
    while True:
        data = connection.recv(1042)
        if not data:
            break
        decoded = data.decode("utf-8")
        if "addnat4rule" in decoded:
            addnat4rule(connection)
        if "adddrop4rule" in decoded:
            addnat4rule(connection)
    connection.close()

try:
    os.unlink(server_address)
except OSError:
    if os.path.exists(server_address):
        raise

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

try:
    print "try bind"
    server.bind(server_address)
    server.listen(MAX_Clients)
except socket.error as errormsg:
    print errormsg
    sys.exit()

while True:
    connection, addr = server.accept()
    start_new_thread(client,(connection,))
server.close()
