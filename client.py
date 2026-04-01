import socket
import json

HOST = '127.0.0.1'
PORT = 5000
MIN_TAMANHO = 30
MIN_JANELA = 1
MAX_JANELA = 5
JANELA_PADRAO = 5
PAYLOAD_CHUNK_SIZE = 4


def enviar_json(arquivo_socket, mensagem):
    arquivo_socket.write((json.dumps(mensagem) + '\n').encode('utf-8'))
    arquivo_socket.flush()


def receber_json(arquivo_socket):
    linha = arquivo_socket.readline()
    if not linha:
        raise ConnectionError('Conexao encerrada pelo servidor.')
    return json.loads(linha.decode('utf-8'))


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


def solicitar_janela_atual():
    while True:
        entrada = input(
            f"[CLIENTE] Defina a janela atual ({MIN_JANELA}-{MAX_JANELA}, Enter para {JANELA_PADRAO}): "
        ).strip()

        if entrada == '':
            return JANELA_PADRAO

        try:
            janela = int(entrada)
        except ValueError:
            print('[CLIENTE] Valor invalido. Digite um numero inteiro.')
            continue

        if janela < MIN_JANELA or janela > MAX_JANELA:
            print(f'[CLIENTE] Valor invalido. A janela deve estar entre {MIN_JANELA} e {MAX_JANELA}.')
            continue

        return janela


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


def fragmentar_payload(texto, tamanho_fragmento):
    return [texto[i:i + tamanho_fragmento] for i in range(0, len(texto), tamanho_fragmento)]


def enviar_payload_com_janela(arquivo_socket, mensagem, tamanho_maximo_sessao, janela_sessao):
    if len(mensagem) > tamanho_maximo_sessao:
        raise ValueError(
            f'Mensagem com {len(mensagem)} caracteres excede o limite negociado de {tamanho_maximo_sessao}.'
        )

    fragmentos = fragmentar_payload(mensagem, PAYLOAD_CHUNK_SIZE)
    if not fragmentos:
        fragmentos = ['']

    seq = 0
    indice = 0
    total = len(fragmentos)

    while indice < total:
        janela_em_uso = fragmentos[indice:indice + janela_sessao]

        for deslocamento, fragmento in enumerate(janela_em_uso):
            seq_atual = seq + deslocamento
            fim = (indice + deslocamento) == (total - 1)
            pacote = {
                'tipo': 'dados',
                'seq': seq_atual,
                'payload': fragmento,
                'fim': fim
            }
            enviar_json(arquivo_socket, pacote)
            print(f"[CLIENTE] Pacote enviado seq={seq_atual}, payload='{fragmento}'")

        for deslocamento in range(len(janela_em_uso)):
            esperado = seq + deslocamento
            ack = receber_json(arquivo_socket)

            if ack.get('tipo') != 'ack':
                raise ValueError('Resposta inesperada do servidor durante ACK.')
            if ack.get('seq') != esperado:
                raise ValueError(f"ACK fora de ordem. Esperado seq={esperado}, recebido seq={ack.get('seq')}")
            if ack.get('status') != 'ok':
                raise ValueError(f"Servidor rejeitou pacote seq={esperado}: {ack.get('mensagem', 'erro desconhecido')}")

            print(f'[CLIENTE] ACK recebido seq={esperado}')

        seq += len(janela_em_uso)
        indice += len(janela_em_uso)


def main():
    tamanho_maximo = solicitar_tamanho_maximo()
    janela_atual = solicitar_janela_atual()
    tipo_operacao = solicitar_tipo_operacao()

    handshake_requisicao = {
        'tipo': 'handshake',
        'modo_operacao': 'cliente',
        'tamanho_maximo_desejado': tamanho_maximo,
        'janela_desejada': janela_atual,
        'tipo_operacao': tipo_operacao
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        print(f"[CLIENTE] Conectando ao servidor {HOST}:{PORT}...")
        client_socket.connect((HOST, PORT))
        print("[CLIENTE] Conectado!")

        with client_socket.makefile('rwb') as arquivo_socket:
            enviar_json(arquivo_socket, handshake_requisicao)

            print(f'[CLIENTE] Handshake enviado:')
            print(f"  - Modo de operacao: {handshake_requisicao['modo_operacao']}")
            print(f"  - Tamanho maximo desejado: {handshake_requisicao['tamanho_maximo_desejado']} caracteres")
            print(f"  - Janela desejada: {handshake_requisicao['janela_desejada']}")
            print(f"  - Tipo de operacao: {handshake_requisicao['tipo_operacao']}")

            handshake_resposta = receber_json(arquivo_socket)
            if handshake_resposta.get('tipo') != 'handshake_ack':
                print('[CLIENTE] Resposta invalida no handshake.')
                return
            if handshake_resposta.get('status') != 'ok':
                print(f"[CLIENTE] Handshake rejeitado: {handshake_resposta.get('mensagem', 'erro desconhecido')}")
                return

            tamanho_maximo_sessao = handshake_resposta['tamanho_maximo_sessao']
            janela_sessao = handshake_resposta['janela_sessao']

            print(f'[CLIENTE] Handshake recebido do servidor:')
            print(f"  - Modo de operacao: {handshake_resposta['modo_operacao']}")
            print(f'  - Tamanho maximo da sessao: {tamanho_maximo_sessao} caracteres')
            print(f'  - Janela da sessao: {janela_sessao}')
            print('[CLIENTE] Handshake completo!')

            while True:
                mensagem = input("[CLIENTE] Digite a mensagem para envio (ou 'sair' para encerrar): ")
                if mensagem.strip().lower() == 'sair':
                    print('[CLIENTE] Encerrando cliente por solicitacao do usuario.')
                    break

                enviar_payload_com_janela(arquivo_socket, mensagem, tamanho_maximo_sessao, janela_sessao)
                print('[CLIENTE] Envio da carga util concluido.')

if __name__ == '__main__':
    main()
