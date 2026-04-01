import socket
import json

HOST = '127.0.0.1'
PORT = 5000
BUFFER_SIZE = 2048
MIN_TAMANHO = 30


def solicitar_tamanho_maximo():
    while True:
        entrada = input(f"[CLIENTE] Defina o limite maximo de caracteres por vez (tamanho >= {MIN_TAMANHO}): ").strip()
        try:
            tamanho = int(entrada)
        except ValueError:
            print("[CLIENTE] Valor invalido. Digite um numero inteiro.")
            continue

        if tamanho < MIN_TAMANHO:
            print(f"[CLIENTE] Valor invalido. O tamanho deve ser >= {MIN_TAMANHO}.")
            continue

        return tamanho


def solicitar_tipo_operacao():
    while True:
        print("[CLIENTE] Selecione o tipo de operacao:")
        print("  1 - individual")
        print("  2 - lotes")
        entrada = input("[CLIENTE] Opcao (1/2): ").strip().lower()

        if entrada in ('1', 'individual'):
            return 'individual'
        if entrada in ('2', 'lotes', 'lote'):
            return 'lotes'

        print("[CLIENTE] Opcao invalida. Escolha 1 (individual) ou 2 (lotes).")

def main():
    tamanho_maximo = solicitar_tamanho_maximo()
    tipo_operacao = solicitar_tipo_operacao()

    client_config = {
        'modo_operacao': 'cliente',
        'tamanho_maximo': tamanho_maximo,
        'tipo_operacao': tipo_operacao
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
        print(f"  - Tipo de operacao: {client_config['tipo_operacao']}")

        
        data = client_socket.recv(BUFFER_SIZE)
        server_config = json.loads(data.decode('utf-8'))

        print(f"[CLIENTE] Handshake recebido do servidor:")
        print(f"  - Modo de operação: {server_config['modo_operacao']}")
        print(f"  - Tamanho máximo: {server_config['tamanho_maximo']} bytes")

        print("[CLIENTE] Handshake completo!")

if __name__ == '__main__':
    main()
