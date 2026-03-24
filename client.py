import socket
import json

HOST = '127.0.0.1'
PORT = 5000
BUFFER_SIZE = 2048

def main():
    
    client_config = {
        'modo_operacao': 'cliente',
        'tamanho_maximo': BUFFER_SIZE
    }

    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        print(f"[CLIENTE] Conectando ao servidor {HOST}:{PORT}...")
        client_socket.connect((HOST, PORT))
        print("[CLIENTE] Conectado!")

        
        handshake_data = json.dumps(client_config).encode('utf-8')
        client_socket.sendall(handshake_data)

        print(f"[CLIENTE] Handshake enviado:")
        print(f"  - Modo de operação: {client_config['modo_operacao']}")
        print(f"  - Tamanho máximo: {client_config['tamanho_maximo']} bytes")

        
        data = client_socket.recv(BUFFER_SIZE)
        server_config = json.loads(data.decode('utf-8'))

        print(f"[CLIENTE] Handshake recebido do servidor:")
        print(f"  - Modo de operação: {server_config['modo_operacao']}")
        print(f"  - Tamanho máximo: {server_config['tamanho_maximo']} bytes")

        print("[CLIENTE] Handshake completo!")

if __name__ == '__main__':
    main()
