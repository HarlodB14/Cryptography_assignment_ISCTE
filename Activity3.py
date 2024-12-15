from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import CertificateBuilder, Name, NameAttribute
from cryptography.x509.oid import NameOID
import datetime
import threading
import socket
import os

# General configuration
HOST = '127.0.0.1'  # Localhost address
PORT = 12345         # Port used by the Gateway

# Gateway class
class Gateway:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.clients = {}
        self.running = True
        self.shared_keys = {}
        self.private_key = None
        self.public_key = None
        self.generate_key_pair()
        self.generate_certificate()
        
        
    def generate_key_pair(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private.key.public()
        print("[GATEWAY] RSA key pair generated.")

    def generate_certificate(self):
        subject= issuer = Name([
            NameAttribute(NameOID.COUNTRY_NAME('PORTUGAL')),
            NameAttribute(NameOID.LOCALITY_NAME('Lisbon')),
            NameAttribute(NameOID.ORGANIZATION_NAME('ISCTE'))
        ])
        self.certificate =(
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.public_key)
            .not_valid_before(datetime.datetime)
            .not_valid_after(datetime.datetime + datetime.timedelta(365))
        )
        print("[GATEWAY] Self-signed certificate generated.")

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            print(f"[GATEWAY] Listening on {self.host}:{self.port}")

            while self.running:
                try:
                    server_socket.settimeout(1.0)  # Allow periodic check for shutdown
                    client_socket, client_address = server_socket.accept()
                    print(f"[GATEWAY] New agent connected: {client_address}")
                    threading.Thread(target=self.handle_client, args=(client_socket,)).start()
                except socket.timeout:
                    continue

    def handle_client(self, client_socket):
        with client_socket:
            agent_name = client_socket.recv(1024).decode("utf-8")
            self.clients[agent_name] = client_socket
            while True:
                try:
                    message = client_socket.recv(1024)
                    if not message:
                        break
                    parts = message.decode("utf-8").split()
                    command, *args = parts

                    if command == "COMMON_KEY_REQUEST":
                        agent1, agent2 = args

                        if agent1 in self.clients and agent2 in self.clients:
                            # Generate a shared key
                            shared_key = os.urandom(32)
                            self.shared_keys[(agent1, agent2)] = shared_key
                            self.shared_keys[(agent2, agent1)] = shared_key

                            # Send the shared key information to both agents
                            client1_socket = self.clients[agent1]
                            client2_socket = self.clients[agent2]

                            client1_socket.sendall(f"SHARED_KEY {agent2}".encode())
                            client2_socket.sendall(f"SHARED_KEY {agent1}".encode())

                            print(f"[GATEWAY] Shared key established between {agent1} and {agent2}")
                        else:
                            print(f"[GATEWAY] One or both agents are not connected")

                    elif command == "MESSAGE":
                        target_agent = args[0]
                        message = " ".join(args[1:])
                        if target_agent in self.clients:
                            self.clients[target_agent].sendall(f"MESSAGE {agent_name} {message}".encode())
                            print(f"[GATEWAY] Message sent to {target_agent}")
                        else:
                            print(f"[GATEWAY] Target agent {target_agent} not found.")
                    
                    elif command == "SHUTDOWN":
                        print("[GATEWAY] Shutdown command received.")
                        self.running = False
                        break
                except ConnectionResetError:
                    break

        self.clients.pop(agent_name, None)
        print(f"[GATEWAY] An agent {agent_name} has disconnected.")

# Agent class
class Agent:
    def __init__(self, host, port, name):
        self.name = name
        self.host = host
        self.port = port
        self.client_socket = None
        self.shared_keys = {}
        self.private_key = None
        self.public_key = None
        self.generate_key_pair()

    def generate_key_pair(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        print(f"[AGENT-{self.name}] RSA key pair generated.")

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((self.host, self.port))
            print(f"[AGENT-{self.name}] Connected to the Gateway")

            client_socket.sendall(self.name.encode('utf-8'))

            threading.Thread(target=self.receive_messages, args=(client_socket,)).start()

            while True:
                command = input(f"[AGENT-{self.name}] Enter command (SEND_MESSAGE/EXIT/COMMON_KEY_REQUEST): ").strip()

                if command == "SEND_MESSAGE":
                    target_agent = input("Enter target agent name: ").strip()
                    if (self.name, target_agent) not in self.shared_keys:
                        print(f"[AGENT-{self.name}] No shared key with {target_agent}. Please create a key first.")
                    else:
                        message = input("Enter the message to send: ").strip()
                        client_socket.sendall(f"MESSAGE {target_agent} {message}".encode('utf-8'))
                        print(f"[AGENT-{self.name}] Message sent to {target_agent}")

                elif command == "COMMON_KEY_REQUEST":
                    target_agent = input("Enter target agent name to create a shared key: ").strip()
                    client_socket.sendall(f"COMMON_KEY_REQUEST {self.name} {target_agent}".encode('utf-8'))
                    print(f"[AGENT-{self.name}] Requested shared key with {target_agent}")

                elif command == "EXIT":
                    print(f"[AGENT-{self.name}] Disconnecting from Gateway.")
                    client_socket.close()
                    break

    def receive_messages(self, client_socket):
        while True:
            try:
                message = client_socket.recv(1024)
                if message.startswith(b"SHARED_KEY"):
                    _, other_agent = message.split(maxsplit=1)
                    self.shared_keys[(self.name, other_agent.decode())] = "shared_key_info"
                    print(f"[AGENT-{self.name}] Shared key established with {other_agent.decode()}")
                elif message.startswith(b"MESSAGE"):
                    parts = message.decode("utf-8").split(maxsplit=2)
                    _, sender, msg = parts
                    print(f"[AGENT-{self.name}] Message from {sender}: {msg}")
                else:
                    print(f"[AGENT-{self.name}] Message received: {message.decode('utf-8')}")
            except ConnectionResetError:
                print(f"[AGENT-{self.name}] Disconnected from the Gateway.")
                break

# Main execution
if __name__ == "__main__":
    role = input("Start as Gateway or Agent? (gateway/agent): ").strip().lower()

    if role == "gateway":
        gateway = Gateway(HOST, PORT)
        threading.Thread(target=gateway.start).start()
        input("Press Enter to shut down the gateway...\n")
        gateway.running = False
    elif role == "agent":
        name = input("Enter the agent's name: ").strip()
        agent = Agent(HOST, PORT, name)
        agent.start()
    else:
        print("Invalid role. Please choose 'gateway' or 'agent'.")
