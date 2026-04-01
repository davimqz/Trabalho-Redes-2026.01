import socket
import json

HOST = '127.0.0.1'
PORT = 5000
SERVER_BUFFER_SIZE = 4096
MIN_TAMANHO = 30
MIN_JANELA = 1
MAX_JANELA = 5
JANELA_INICIAL = 5
PAYLOAD_CHUNK_SIZE = 4


def enviar_json(arquivo_socket, mensagem):
    arquivo_socket.write((json.dumps(mensagem) + '\n').encode('utf-8'))
    arquivo_socket.flush()


def receber_json(arquivo_socket):
    linha = arquivo_socket.readline()
    if not linha:
        raise ConnectionError('Conexao encerrada pelo cliente.')
    return json.loads(linha.decode('utf-8'))


def validar_handshake(cliente_handshake):
    if cliente_handshake.get('tipo') != 'handshake':
        return False, 'Mensagem inicial nao e um handshake valido.'

    tamanho_desejado = cliente_handshake.get('tamanho_maximo_desejado')
    janela_desejada = cliente_handshake.get('janela_desejada', JANELA_INICIAL)

    if not isinstance(tamanho_desejado, int):
        return False, 'Campo tamanho_maximo_desejado deve ser inteiro.'
    if tamanho_desejado < MIN_TAMANHO:
        return False, f'Campo tamanho_maximo_desejado deve ser >= {MIN_TAMANHO}.'
    if not isinstance(janela_desejada, int):
        return False, 'Campo janela_desejada deve ser inteiro.'
    if janela_desejada < MIN_JANELA or janela_desejada > MAX_JANELA:
        return False, f'Campo janela_desejada deve estar entre {MIN_JANELA} e {MAX_JANELA}.'

    return True, ''


def receber_payload_com_ack(arquivo_socket, tamanho_maximo_sessao):
    mensagem_reconstruida = ''
    seq_esperado = 0

    while True:
        pacote = receber_json(arquivo_socket)

        if pacote.get('tipo') != 'dados':
            enviar_json(arquivo_socket, {
                'tipo': 'ack',
                'seq': pacote.get('seq', -1),
                'status': 'erro',
                'mensagem': 'Mensagem fora do protocolo de dados.'
            })
            break

        seq = pacote.get('seq')
        payload = pacote.get('payload', '')
        fim = pacote.get('fim', False)

        if seq != seq_esperado:
            enviar_json(arquivo_socket, {
                'tipo': 'ack',
                'seq': seq,
                'status': 'erro',
                'mensagem': f'Sequencia inesperada. Esperado {seq_esperado}, recebido {seq}.'
            })
            break

        if not isinstance(payload, str):
            enviar_json(arquivo_socket, {
                'tipo': 'ack',
                'seq': seq,
                'status': 'erro',
                'mensagem': 'Payload deve ser texto.'
            })
            break

        if len(payload) > PAYLOAD_CHUNK_SIZE:
            enviar_json(arquivo_socket, {
                'tipo': 'ack',
                'seq': seq,
                'status': 'erro',
                'mensagem': f'Payload excede {PAYLOAD_CHUNK_SIZE} caracteres por pacote.'
            })
            break

        nova_mensagem = mensagem_reconstruida + payload
        if len(nova_mensagem) > tamanho_maximo_sessao:
            enviar_json(arquivo_socket, {
                'tipo': 'ack',
                'seq': seq,
                'status': 'erro',
                'mensagem': f'Mensagem total excede o limite da sessao ({tamanho_maximo_sessao}).'
            })
            break

        mensagem_reconstruida = nova_mensagem
        enviar_json(arquivo_socket, {
            'tipo': 'ack',
            'seq': seq,
            'status': 'ok'
        })

        print(f"[SERVIDOR] Pacote recebido seq={seq}, payload='{payload}'")

        seq_esperado += 1
        if fim:
            print('[SERVIDOR] Recebimento da carga util concluido.')
            print(f"[SERVIDOR] Mensagem reconstruida: '{mensagem_reconstruida}'")
            break

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen()

        print(f"[SERVIDOR] Aguardando conexões em {HOST}:{PORT}...")
        try:
            while True:
                conn, addr = server_socket.accept()
                with conn:
                    print(f"[SERVIDOR] Conectado por {addr}")
                    with conn.makefile('rwb') as arquivo_socket:
                        try:
                            client_config = receber_json(arquivo_socket)
                        except (json.JSONDecodeError, ConnectionError) as erro:
                            print(f'[SERVIDOR] Erro ao receber handshake: {erro}')
                            continue

                        tipo_operacao = client_config.get('tipo_operacao', 'nao informado')

                        print(f"[SERVIDOR] Handshake recebido do cliente:")
                        print(f"  - Modo de operacao: {client_config.get('modo_operacao', 'nao informado')}")
                        print(f"  - Tamanho maximo desejado: {client_config.get('tamanho_maximo_desejado', 'nao informado')} caracteres")
                        print(f"  - Janela desejada: {client_config.get('janela_desejada', 'nao informado')}")
                        print(f"  - Tipo de operacao: {tipo_operacao}")

                        valido, mensagem_validacao = validar_handshake(client_config)
                        if not valido:
                            resposta_erro = {
                                'tipo': 'handshake_ack',
                                'status': 'erro',
                                'mensagem': mensagem_validacao
                            }
                            enviar_json(arquivo_socket, resposta_erro)
                            print(f"[SERVIDOR] Handshake rejeitado: {mensagem_validacao}")
                            continue

                        tamanho_maximo_sessao = min(client_config['tamanho_maximo_desejado'], SERVER_BUFFER_SIZE)
                        janela_sessao = min(max(client_config['janela_desejada'], MIN_JANELA), MAX_JANELA)

                        server_config = {
                            'tipo': 'handshake_ack',
                            'status': 'ok',
                            'modo_operacao': 'servidor',
                            'tamanho_maximo_sessao': tamanho_maximo_sessao,
                            'janela_sessao': janela_sessao
                        }
                        enviar_json(arquivo_socket, server_config)

                        print(f"[SERVIDOR] Handshake enviado:")
                        print(f"  - Modo de operacao: {server_config['modo_operacao']}")
                        print(f"  - Tamanho maximo da sessao: {server_config['tamanho_maximo_sessao']} caracteres")
                        print(f"  - Janela da sessao: {server_config['janela_sessao']}")
                        print('[SERVIDOR] Handshake completo!')

                        while True:
                            try:
                                receber_payload_com_ack(arquivo_socket, tamanho_maximo_sessao)
                            except ConnectionError:
                                print('[SERVIDOR] Cliente encerrou a conexao.')
                                break
                            except json.JSONDecodeError as erro:
                                print(f'[SERVIDOR] Erro de decodificacao JSON: {erro}')
                                break
        except KeyboardInterrupt:
            print('\n[SERVIDOR] Encerrado por Ctrl + C.')

if __name__ == '__main__':
    main()
