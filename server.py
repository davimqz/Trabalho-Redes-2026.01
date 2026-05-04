import argparse
import base64
import hashlib
import hmac
import json
import os
import socket
import threading
import sys
from typing import Dict, Optional, Set
import zlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 5000
SERVER_BUFFER_SIZE = 4096
MIN_TAMANHO = 30
MIN_JANELA = 1
MAX_JANELA = 5
JANELA_INICIAL = 5
PAYLOAD_CHUNK_SIZE = 4
HANDSHAKE_TIMEOUT = 10
DEFAULT_MODO_CONFIRMACAO = 'go_back_n'
DEFAULT_TIMEOUT_ACK_MS = 5000
DEFAULT_MAX_RETRANSMISSOES = 3
ACCEPTED_MODO_OPERACAO = 'cliente'
PSK = os.environ.get('PSK', 'dev_psk_for_testing_only_please_change').encode()


def enviar_json(arquivo_socket, mensagem):
    arquivo_socket.write((json.dumps(mensagem) + '\n').encode('utf-8'))
    arquivo_socket.flush()


def receber_json(arquivo_socket):
    linha = arquivo_socket.readline()
    if not linha:
        raise ConnectionError('Conexao encerrada pelo cliente.')
    return json.loads(linha.decode('utf-8'))


def parse_args():
    parser = argparse.ArgumentParser(description='Servidor TCP com confiabilidade na camada de aplicacao.')
    parser.add_argument('--host', type=str, help='Host/IP para bind do servidor.')
    parser.add_argument('--port', type=int, help='Porta para bind do servidor.')
    parser.add_argument(
        '--modo-confirmacao-padrao',
        choices=['go_back_n', 'seletivo'],
        default=DEFAULT_MODO_CONFIRMACAO,
        help='Modo aplicado quando o cliente nao informar modo_confirmacao.',
    )
    return parser.parse_args()


def obter_host_port(args):
    host = args.host
    port = args.port

    if host is None and sys.stdin.isatty():
        entrada_host = input(f'[SERVIDOR] Host para bind (Enter para {DEFAULT_HOST}): ').strip()
        host = entrada_host or DEFAULT_HOST
    elif host is None:
        host = DEFAULT_HOST

    if port is None and sys.stdin.isatty():
        while True:
            entrada_port = input(f'[SERVIDOR] Porta para bind (Enter para {DEFAULT_PORT}): ').strip()
            if entrada_port == '':
                port = DEFAULT_PORT
                break
            try:
                port = int(entrada_port)
            except ValueError:
                print('[SERVIDOR] Porta invalida. Digite um inteiro.')
                continue
            break
    elif port is None:
        port = DEFAULT_PORT

    if port <= 0 or port > 65535:
        raise ValueError('Porta deve estar entre 1 e 65535.')

    return host, port


def validar_handshake(cliente_handshake, modo_confirmacao_padrao):
    if cliente_handshake.get('tipo') != 'handshake':
        return False, 'Mensagem inicial nao e um handshake valido.'

    modo_operacao = cliente_handshake.get('modo_operacao')
    if modo_operacao != ACCEPTED_MODO_OPERACAO:
        return False, f"Campo modo_operacao invalido. Esperado '{ACCEPTED_MODO_OPERACAO}'."

    tamanho_desejado = cliente_handshake.get('tamanho_maximo_desejado')
    janela_desejada = cliente_handshake.get('janela_desejada', JANELA_INICIAL)
    tipo_operacao = cliente_handshake.get('tipo_operacao', 'lotes')
    modo_confirmacao = cliente_handshake.get('modo_confirmacao', modo_confirmacao_padrao)
    timeout_ack_ms = cliente_handshake.get('timeout_ack_ms', DEFAULT_TIMEOUT_ACK_MS)
    max_retransmissoes = cliente_handshake.get('max_retransmissoes', DEFAULT_MAX_RETRANSMISSOES)

    if not isinstance(tamanho_desejado, int):
        return False, 'Campo tamanho_maximo_desejado deve ser inteiro.'
    if tamanho_desejado < MIN_TAMANHO:
        return False, f'Campo tamanho_maximo_desejado deve ser >= {MIN_TAMANHO}.'

    if not isinstance(janela_desejada, int):
        return False, 'Campo janela_desejada deve ser inteiro.'
    if janela_desejada < MIN_JANELA or janela_desejada > MAX_JANELA:
        return False, f'Campo janela_desejada deve estar entre {MIN_JANELA} e {MAX_JANELA}.'

    if tipo_operacao not in ('individual', 'lotes'):
        return False, "Campo tipo_operacao deve ser 'individual' ou 'lotes'."

    if modo_confirmacao not in ('go_back_n', 'seletivo'):
        return False, "Campo modo_confirmacao deve ser 'go_back_n' ou 'seletivo'."

    if not isinstance(timeout_ack_ms, int) or timeout_ack_ms <= 0:
        return False, 'Campo timeout_ack_ms deve ser inteiro > 0.'

    if not isinstance(max_retransmissoes, int) or max_retransmissoes < 0:
        return False, 'Campo max_retransmissoes deve ser inteiro >= 0.'

    return True, ''


def derive_session_keys(session_salt: bytes):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=session_salt,
        info=b'handshake data',
    )
    key_material = hkdf.derive(PSK)
    aes_key = key_material[:32]
    hmac_key = key_material[32:]
    return AESGCM(aes_key), hmac_key


def validar_pacote_payload(pacote, aesgcm, hmac_key):
    seq_raw = pacote.get('seq')
    if not isinstance(seq_raw, int):
        return None, None, 'Campo seq deve ser inteiro.'

    if pacote.get('tipo') != 'dados':
        return seq_raw, None, 'Mensagem fora do protocolo de dados.'

    if 'ciphertext' in pacote:
        if aesgcm is None or hmac_key is None:
            return seq_raw, None, 'Servidor nao suporta criptografia nesta sessao.'
        try:
            nonce = base64.b64decode(pacote.get('nonce', ''))
            ciphertext = base64.b64decode(pacote.get('ciphertext', ''))
        except Exception:
            return seq_raw, None, 'Formato de ciphertext/nonce invalido.'

        recv_hmac = pacote.get('hmac', '')
        mac = hmac.new(hmac_key, nonce + ciphertext + int(seq_raw).to_bytes(4, 'big'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, recv_hmac):
            return seq_raw, None, 'Falha na verificacao de integridade (HMAC).'

        try:
            payload = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
        except Exception:
            return seq_raw, None, 'Falha na autenticacao do ciphertext.'
    else:
        payload = pacote.get('payload', '')
        # checksum is required for non-encrypted packets
        recv_checksum = pacote.get('checksum')
        if recv_checksum is None:
            return seq_raw, None, 'Falta checksum no pacote sem criptografia.'
        try:
            calc = '{:08x}'.format(zlib.crc32(payload.encode('utf-8')) & 0xFFFFFFFF)
        except Exception:
            return seq_raw, None, 'Erro ao calcular checksum.'
        if calc != recv_checksum:
            return seq_raw, None, 'Falha na verificacao de integridade (checksum).'

    if not isinstance(payload, str):
        return seq_raw, None, 'Payload deve ser texto.'
    if len(payload) > PAYLOAD_CHUNK_SIZE:
        return seq_raw, None, f'Payload excede {PAYLOAD_CHUNK_SIZE} caracteres por pacote.'

    return seq_raw, payload, ''


def enviar_nack(arquivo_socket, seq, mensagem):
    enviar_json(
        arquivo_socket,
        {
            'tipo': 'nack',
            'seq': seq,
            'status': 'reenviar',
            'mensagem': mensagem,
        },
    )


def receber_payload_com_ack(
    arquivo_socket,
    tamanho_maximo_sessao,
    janela_sessao,
    tipo_operacao,
    modo_confirmacao,
    aesgcm=None,
    hmac_key=None,
):
    janela_em_uso = 1 if tipo_operacao == 'individual' else janela_sessao
    mensagem_partes: Dict[int, str] = {}
    fim_seq: Optional[int] = None
    seq_esperado = 0
    nacks_emitidos: Set[int] = set()

    while True:
        pacote = receber_json(arquivo_socket)

        seq, payload, erro = validar_pacote_payload(pacote, aesgcm, hmac_key)
        if erro:
            enviar_nack(arquivo_socket, seq if seq is not None else -1, erro)
            if modo_confirmacao == 'go_back_n':
                continue
            continue

        fim = bool(pacote.get('fim', False))

        if modo_confirmacao == 'go_back_n':
            if seq != seq_esperado:
                enviar_nack(
                    arquivo_socket,
                    seq_esperado,
                    f'Sequencia inesperada. Esperado {seq_esperado}, recebido {seq}.',
                )
                continue

            tamanho_novo = sum(len(v) for v in mensagem_partes.values()) + len(payload)
            if tamanho_novo > tamanho_maximo_sessao:
                enviar_nack(arquivo_socket, seq, f'Mensagem total excede o limite da sessao ({tamanho_maximo_sessao}).')
                continue

            mensagem_partes[seq] = payload
            if fim:
                fim_seq = seq

            enviar_json(arquivo_socket, {'tipo': 'ack', 'seq': seq, 'status': 'ok'})
            # Print metadata: checksum for plaintext, or nonce/hmac for ciphertext
            meta = ''
            if 'ciphertext' in pacote:
                nonce_b64 = pacote.get('nonce', '')
                hmac_val = pacote.get('hmac', '')
                meta = f", nonce={nonce_b64[:6]}..., hmac={hmac_val[:6]}..."
            else:
                checksum = pacote.get('checksum')
                meta = f", checksum={checksum}"
            print(f"[SERVIDOR] Pacote recebido seq={seq}, payload='{payload}'{meta}")
            seq_esperado += 1

            if fim_seq is not None and seq_esperado > fim_seq:
                mensagem_final = ''.join(mensagem_partes[i] for i in range(fim_seq + 1))
                print('[SERVIDOR] Recebimento da carga util concluido.')
                print(f"[SERVIDOR] Mensagem reconstruida: '{mensagem_final}'")
                return

            continue

        if seq < seq_esperado:
            enviar_json(arquivo_socket, {'tipo': 'ack', 'seq': seq, 'status': 'ok'})
            continue

        if seq > seq_esperado + janela_em_uso - 1:
            enviar_nack(arquivo_socket, seq_esperado, f'Seq fora da janela atual. Esperado entre {seq_esperado} e {seq_esperado + janela_em_uso - 1}.')
            continue

        # Proactive NACK in Selective Repeat: if we receive a later seq but missing the expected one,
        # immediately request retransmission for seq_esperado (once).
        if seq > seq_esperado and seq_esperado not in nacks_emitidos:
            enviar_nack(arquivo_socket, seq_esperado, f'Sequencia faltante {seq_esperado}.')
            nacks_emitidos.add(seq_esperado)

        if seq not in mensagem_partes:
            tamanho_novo = sum(len(v) for v in mensagem_partes.values()) + len(payload)
            if tamanho_novo > tamanho_maximo_sessao:
                enviar_nack(arquivo_socket, seq, f'Mensagem total excede o limite da sessao ({tamanho_maximo_sessao}).')
                continue
            mensagem_partes[seq] = payload
            meta = ''
            if 'ciphertext' in pacote:
                nonce_b64 = pacote.get('nonce', '')
                hmac_val = pacote.get('hmac', '')
                meta = f", nonce={nonce_b64[:6]}..., hmac={hmac_val[:6]}..."
            else:
                checksum = pacote.get('checksum')
                meta = f", checksum={checksum}"
            print(f"[SERVIDOR] Pacote recebido seq={seq}, payload='{payload}'{meta}")

        if fim:
            fim_seq = seq

        enviar_json(arquivo_socket, {'tipo': 'ack', 'seq': seq, 'status': 'ok'})

        seq_esperado_anterior = seq_esperado
        while seq_esperado in mensagem_partes:
            seq_esperado += 1

        if seq_esperado > seq_esperado_anterior:
            nacks_emitidos = {s for s in nacks_emitidos if s >= seq_esperado}

        if fim_seq is not None and seq_esperado > fim_seq:
            mensagem_final = ''.join(mensagem_partes[i] for i in range(fim_seq + 1))
            print('[SERVIDOR] Recebimento da carga util concluido.')
            print(f"[SERVIDOR] Mensagem reconstruida: '{mensagem_final}'")
            return

        if seq_esperado not in mensagem_partes and seq_esperado not in nacks_emitidos:
            enviar_nack(arquivo_socket, seq_esperado, f'Sequencia faltante {seq_esperado}.')
            nacks_emitidos.add(seq_esperado)


def main():
    args = parse_args()
    host, port = obter_host_port(args)

    def handle_client(conn, addr):
        try:
            with conn:
                print(f'[SERVIDOR] Conectado por {addr}')
                conn.settimeout(HANDSHAKE_TIMEOUT)

                with conn.makefile('rwb') as arquivo_socket:
                    try:
                        client_config = receber_json(arquivo_socket)
                    except socket.timeout:
                        print(f'[SERVIDOR] Timeout ({HANDSHAKE_TIMEOUT}s) aguardando handshake de {addr}. Encerrando conexao.')
                        try:
                            enviar_json(
                                arquivo_socket,
                                {
                                    'tipo': 'handshake_ack',
                                    'status': 'erro',
                                    'mensagem': 'Timeout aguardando handshake.',
                                },
                            )
                        except Exception:
                            pass
                        return
                    except (json.JSONDecodeError, ConnectionError) as erro:
                        print(f'[SERVIDOR] Erro ao receber handshake: {erro}')
                        try:
                            enviar_json(
                                arquivo_socket,
                                {
                                    'tipo': 'handshake_ack',
                                    'status': 'erro',
                                    'mensagem': 'Handshake invalido ou conexao fechada.',
                                },
                            )
                        except Exception:
                            pass
                        return

                    tipo_operacao = client_config.get('tipo_operacao', 'nao informado')
                    modo_confirmacao_cliente = client_config.get('modo_confirmacao', args.modo_confirmacao_padrao)

                    print('[SERVIDOR] Handshake recebido do cliente:')
                    print(f"  - Modo de operacao: {client_config.get('modo_operacao', 'nao informado')}")
                    print(
                        f"  - Tamanho maximo desejado: {client_config.get('tamanho_maximo_desejado', 'nao informado')} caracteres"
                    )
                    print(f"  - Janela desejada: {client_config.get('janela_desejada', 'nao informado')}")
                    print(f'  - Tipo de operacao: {tipo_operacao}')
                    print(f'  - Modo de confirmacao: {modo_confirmacao_cliente}')

                    valido, mensagem_validacao = validar_handshake(client_config, args.modo_confirmacao_padrao)
                    if not valido:
                        resposta_erro = {
                            'tipo': 'handshake_ack',
                            'status': 'erro',
                            'mensagem': mensagem_validacao,
                        }
                        enviar_json(arquivo_socket, resposta_erro)
                        print(f'[SERVIDOR] Handshake rejeitado: {mensagem_validacao}')
                        return

                    session_salt = os.urandom(16)
                    aesgcm, hmac_key = derive_session_keys(session_salt)

                    modo_confirmacao = client_config.get('modo_confirmacao', args.modo_confirmacao_padrao)
                    timeout_ack_ms = int(client_config.get('timeout_ack_ms', DEFAULT_TIMEOUT_ACK_MS))
                    max_retransmissoes = int(client_config.get('max_retransmissoes', DEFAULT_MAX_RETRANSMISSOES))

                    try:
                        conn.settimeout(max(2.0, (timeout_ack_ms / 1000.0) * (max_retransmissoes + 2)))
                    except Exception:
                        pass

                    tamanho_maximo_sessao = min(client_config['tamanho_maximo_desejado'], SERVER_BUFFER_SIZE)
                    janela_sessao = min(max(client_config['janela_desejada'], MIN_JANELA), MAX_JANELA)

                    server_config = {
                        'tipo': 'handshake_ack',
                        'status': 'ok',
                        'modo_operacao': 'servidor',
                        'tamanho_maximo_sessao': tamanho_maximo_sessao,
                        'janela_sessao': janela_sessao,
                        'session_salt': base64.b64encode(session_salt).decode('ascii'),
                        'modo_confirmacao_acordado': modo_confirmacao,
                        'timeout_ack_ms_acordado': timeout_ack_ms,
                        'max_retransmissoes_acordado': max_retransmissoes,
                    }
                    enviar_json(arquivo_socket, server_config)

                    print('[SERVIDOR] Handshake enviado:')
                    print(f"  - Modo de operacao: {server_config['modo_operacao']}")
                    print(f"  - Tamanho maximo da sessao: {server_config['tamanho_maximo_sessao']} caracteres")
                    print(f"  - Janela da sessao: {server_config['janela_sessao']}")
                    print(f"  - Modo de confirmacao acordado: {server_config['modo_confirmacao_acordado']}")
                    print('[SERVIDOR] Handshake completo!')

                    while True:
                        try:
                            receber_payload_com_ack(
                                arquivo_socket,
                                tamanho_maximo_sessao,
                                janela_sessao,
                                client_config.get('tipo_operacao', 'lotes'),
                                modo_confirmacao,
                                aesgcm=aesgcm,
                                hmac_key=hmac_key,
                            )
                        except socket.timeout:
                            print('[SERVIDOR] Timeout de inatividade no fluxo de dados. Encerrando conexao.')
                            break
                        except ConnectionError:
                            print('[SERVIDOR] Cliente encerrou a conexao.')
                            break
                        except json.JSONDecodeError as erro:
                            print(f'[SERVIDOR] Erro de decodificacao JSON: {erro}')
                            break
        except OSError as erro:
            print(f'[SERVIDOR] Conexao com {addr} encerrada com erro de socket: {erro}')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen()

        print(f'[SERVIDOR] Aguardando conexoes em {host}:{port}...')
        try:
            while True:
                conn, addr = server_socket.accept()
                t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                t.start()
        except KeyboardInterrupt:
            print('\n[SERVIDOR] Encerrado por Ctrl + C.')


if __name__ == '__main__':
    main()
