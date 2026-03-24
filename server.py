import socket
import json

HOST = '127.0.0.1'
PORT = 5000
BUFFER_SIZE = 4096

def main():
    
    server_config = {
        'modo_operacao': 'servidor',
        'tamanho_maximo': BUFFER_SIZE
    }

    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen()

        print(f"[SERVIDOR] Aguardando conexões em {HOST}:{PORT}...")

        conn, addr = server_socket.accept()
        with conn:
            print(f"[SERVIDOR] Conectado por {addr}")

            
            data = conn.recv(BUFFER_SIZE)
            client_config = json.loads(data.decode('utf-8'))

            print(f"[SERVIDOR] Handshake recebido do cliente:")
            print(f"  - Modo de operação: {client_config['modo_operacao']}")
            print(f"  - Tamanho máximo: {client_config['tamanho_maximo']} bytes")

           
            handshake_response = json.dumps(server_config).encode('utf-8')
            conn.sendall(handshake_response)

            print(f"[SERVIDOR] Handshake enviado:")
            print(f"  - Modo de operação: {server_config['modo_operacao']}")
            print(f"  - Tamanho máximo: {server_config['tamanho_maximo']} bytes")

            print("[SERVIDOR] Handshake completo!")

if __name__ == '__main__':
    main()
