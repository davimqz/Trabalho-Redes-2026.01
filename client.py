import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import sys
from typing import Dict, List, Set

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 5000
MIN_TAMANHO = 30
MIN_JANELA = 1
MAX_JANELA = 5
JANELA_PADRAO = 5
PAYLOAD_CHUNK_SIZE = 4
DEFAULT_MODO_CONFIRMACAO = 'go_back_n'
DEFAULT_TIMEOUT_ACK_MS = 5000
DEFAULT_MAX_RETRANSMISSOES = 3


def enviar_json(arquivo_socket, mensagem):
    arquivo_socket.write((json.dumps(mensagem) + '\n').encode('utf-8'))
    arquivo_socket.flush()


def receber_json(arquivo_socket):
    linha = arquivo_socket.readline()
    if not linha:
        raise ConnectionError('Conexao encerrada pelo servidor.')
    return json.loads(linha.decode('utf-8'))


def parse_seq_list(raw: str) -> Set[int]:
    if not raw:
        return set()

    resultado = set()
    for item in raw.split(','):
        item = item.strip()
        if not item:
            continue
        try:
            seq = int(item)
        except ValueError as exc:
            raise ValueError(f"Sequencia invalida em lista: '{item}'. Use inteiros separados por virgula.") from exc
        if seq < 0:
            raise ValueError('Sequencias para simulacao devem ser >= 0.')
        resultado.add(seq)
    return resultado


def solicitar_tamanho_maximo():
    while True:
        entrada = input(f"[CLIENTE] Defina o limite maximo de caracteres por vez (tamanho >= {MIN_TAMANHO}): ").strip()
        try:
            tamanho = int(entrada)
        except ValueError:
            print('[CLIENTE] Valor invalido. Digite um numero inteiro.')
            continue

        if tamanho < MIN_TAMANHO:
            print(f'[CLIENTE] Valor invalido. O tamanho deve ser >= {MIN_TAMANHO}.')
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
        print('[CLIENTE] Selecione o tipo de operacao:')
        print('  1 - individual')
        print('  2 - lotes')
        entrada = input('[CLIENTE] Opcao (1/2): ').strip().lower()

        if entrada in ('1', 'individual'):
            return 'individual'
        if entrada in ('2', 'lotes', 'lote'):
            return 'lotes'

        print('[CLIENTE] Opcao invalida. Escolha 1 (individual) ou 2 (lotes).')


def parse_args():
    parser = argparse.ArgumentParser(description='Cliente TCP com confiabilidade na camada de aplicacao.')
    parser.add_argument('--host', type=str, help='Host/IP do servidor.')
    parser.add_argument('--port', type=int, help='Porta do servidor.')
    parser.add_argument(
        '--modo-confirmacao',
        type=str,
        choices=['go_back_n', 'seletivo'],
        default=DEFAULT_MODO_CONFIRMACAO,
        help='Modo de confirmacao da janela.',
    )
    parser.add_argument(
        '--timeout-ack-ms',
        type=int,
        default=DEFAULT_TIMEOUT_ACK_MS,
        help='Timeout (ms) para aguardar ACK/NACK.',
    )
    parser.add_argument(
        '--max-retransmissoes',
        type=int,
        default=DEFAULT_MAX_RETRANSMISSOES,
        help='Numero maximo de retransmissoes antes de falhar.',
    )
    parser.add_argument(
        '--drop-seqs',
        type=str,
        default='',
        help='Lista de seq para simular perda uma vez (ex.: 1,4,7).',
    )
    parser.add_argument(
        '--corrupt-seqs',
        type=str,
        default='',
        help='Lista de seq para simular corrupcao uma vez (ex.: 2,5).',
    )
    return parser.parse_args()


def obter_host_port(args):
    host = args.host
    port = args.port

    if host is None and sys.stdin.isatty():
        entrada_host = input(f'[CLIENTE] Host do servidor (Enter para {DEFAULT_HOST}): ').strip()
        host = entrada_host or DEFAULT_HOST
    elif host is None:
        host = DEFAULT_HOST

    if port is None and sys.stdin.isatty():
        while True:
            entrada_port = input(f'[CLIENTE] Porta do servidor (Enter para {DEFAULT_PORT}): ').strip()
            if entrada_port == '':
                port = DEFAULT_PORT
                break
            try:
                port = int(entrada_port)
            except ValueError:
                print('[CLIENTE] Porta invalida. Digite um inteiro.')
                continue
            break
    elif port is None:
        port = DEFAULT_PORT

    if port <= 0 or port > 65535:
        raise ValueError('Porta deve estar entre 1 e 65535.')

    return host, port


def fragmentar_payload(texto, tamanho_fragmento):
    return [texto[i:i + tamanho_fragmento] for i in range(0, len(texto), tamanho_fragmento)]


def construir_pacote(seq_atual, fragmento, fim, aesgcm=None, hmac_key=None):
    pacote = {
        'tipo': 'dados',
        'seq': seq_atual,
        'fim': fim,
    }

    if aesgcm is not None and hmac_key is not None:
        nonce = secrets.token_bytes(12)
        ct = aesgcm.encrypt(nonce, fragmento.encode('utf-8'), None)
        pacote['ciphertext'] = base64.b64encode(ct).decode('ascii')
        pacote['nonce'] = base64.b64encode(nonce).decode('ascii')
        mac = hmac.new(hmac_key, nonce + ct + int(seq_atual).to_bytes(4, 'big'), hashlib.sha256).hexdigest()
        pacote['hmac'] = mac
    else:
        pacote['payload'] = fragmento

    return pacote


def enviar_pacote_controlado(
    arquivo_socket,
    pacote,
    drop_once_seqs,
    corrupt_once_seqs,
    drop_aplicado,
    corrupt_aplicado,
):
    seq = pacote['seq']

    if seq in drop_once_seqs and seq not in drop_aplicado:
        drop_aplicado.add(seq)
        print(f'[CLIENTE] Simulacao: perda do pacote seq={seq} (nao enviado nesta tentativa).')
        return

    pacote_envio = dict(pacote)

    if seq in corrupt_once_seqs and seq not in corrupt_aplicado:
        corrupt_aplicado.add(seq)
        if 'hmac' in pacote_envio:
            h = pacote_envio['hmac']
            pacote_envio['hmac'] = ('0' if h[-1] != '0' else '1') + h[1:]
        elif 'payload' in pacote_envio:
            payload = pacote_envio['payload']
            if payload:
                novo_primeiro = '#' if payload[0] != '#' else '@'
                pacote_envio['payload'] = novo_primeiro + payload[1:]
            else:
                pacote_envio['payload'] = '#'
        print(f'[CLIENTE] Simulacao: corrupcao do pacote seq={seq} (apenas na primeira tentativa).')

    enviar_json(arquivo_socket, pacote_envio)

    if 'ciphertext' in pacote_envio:
        print(f"[CLIENTE] Pacote enviado seq={seq}, ciphertext(len)={len(base64.b64decode(pacote_envio['ciphertext']))}")
    else:
        print(f"[CLIENTE] Pacote enviado seq={seq}, payload='{pacote_envio.get('payload', '')}'")


def normalizar_resposta_controle(resp):
    if not isinstance(resp, dict):
        raise ValueError('Resposta invalida do servidor (nao e JSON objeto).')

    tipo = resp.get('tipo')
    seq = resp.get('seq')
    status = resp.get('status')

    if tipo == 'ack' and status == 'ok':
        return 'ack', seq, resp.get('mensagem', '')

    if tipo == 'nack':
        return 'nack', seq, resp.get('mensagem', 'Solicitacao de retransmissao recebida.')

    if tipo == 'ack' and status != 'ok':
        return 'nack', seq, resp.get('mensagem', 'ACK de erro recebido.')

    raise ValueError(f"Resposta inesperada do servidor: tipo={tipo}, status={status}")


def receber_controle_com_timeout(arquivo_socket):
    try:
        return receber_json(arquivo_socket)
    except socket.timeout as exc:
        raise TimeoutError('Timeout aguardando ACK/NACK do servidor.') from exc


def reenviar_faixa(
    arquivo_socket,
    pacotes,
    inicio,
    fim,
    drop_once_seqs,
    corrupt_once_seqs,
    drop_aplicado,
    corrupt_aplicado,
):
    for seq in range(inicio, fim + 1):
        enviar_pacote_controlado(
            arquivo_socket,
            pacotes[seq],
            drop_once_seqs,
            corrupt_once_seqs,
            drop_aplicado,
            corrupt_aplicado,
        )


def enviar_individual(
    arquivo_socket,
    pacotes,
    drop_once_seqs,
    corrupt_once_seqs,
    drop_aplicado,
    corrupt_aplicado,
    max_retransmissoes,
):
    for seq in sorted(pacotes.keys()):
        tentativas = 0
        while True:
            enviar_pacote_controlado(
                arquivo_socket,
                pacotes[seq],
                drop_once_seqs,
                corrupt_once_seqs,
                drop_aplicado,
                corrupt_aplicado,
            )

            try:
                resp = receber_controle_com_timeout(arquivo_socket)
                tipo_resp, seq_resp, msg = normalizar_resposta_controle(resp)
            except TimeoutError:
                tentativas += 1
                if tentativas > max_retransmissoes:
                    raise TimeoutError(f'Timeout no pacote seq={seq} apos {max_retransmissoes} retransmissoes.')
                print(f'[CLIENTE] Timeout no seq={seq}. Retransmitindo (tentativa {tentativas}/{max_retransmissoes})...')
                continue

            if seq_resp != seq:
                print(f'[CLIENTE] Controle para seq inesperado: recebido {seq_resp}, esperado {seq}. Ignorando.')
                continue

            if tipo_resp == 'ack':
                print(f'[CLIENTE] ACK recebido seq={seq}')
                break

            tentativas += 1
            if tentativas > max_retransmissoes:
                raise ValueError(f'Servidor rejeitou seq={seq} e limite de retransmissoes foi excedido: {msg}')
            print(f'[CLIENTE] NACK recebido seq={seq}: {msg}. Retransmitindo ({tentativas}/{max_retransmissoes})...')


def enviar_lotes_go_back_n(
    arquivo_socket,
    pacotes,
    janela_sessao,
    drop_once_seqs,
    corrupt_once_seqs,
    drop_aplicado,
    corrupt_aplicado,
    max_retransmissoes,
):
    total = len(pacotes)
    base = 0

    while base < total:
        fim_janela = min(base + janela_sessao - 1, total - 1)
        reenviar_faixa(
            arquivo_socket,
            pacotes,
            base,
            fim_janela,
            drop_once_seqs,
            corrupt_once_seqs,
            drop_aplicado,
            corrupt_aplicado,
        )

        esperado = base
        tentativas_janela = 0

        while esperado <= fim_janela:
            try:
                resp = receber_controle_com_timeout(arquivo_socket)
                tipo_resp, seq_resp, msg = normalizar_resposta_controle(resp)
            except TimeoutError:
                tentativas_janela += 1
                if tentativas_janela > max_retransmissoes:
                    raise TimeoutError(
                        f'Timeout na janela {base}-{fim_janela} apos {max_retransmissoes} retransmissoes.'
                    )
                print(
                    f'[CLIENTE] Timeout na janela {base}-{fim_janela}. '
                    f'Retransmitindo (tentativa {tentativas_janela}/{max_retransmissoes})...'
                )
                reenviar_faixa(
                    arquivo_socket,
                    pacotes,
                    esperado,
                    fim_janela,
                    drop_once_seqs,
                    corrupt_once_seqs,
                    drop_aplicado,
                    corrupt_aplicado,
                )
                continue

            if seq_resp is None:
                continue

            if tipo_resp == 'ack' and seq_resp == esperado:
                print(f'[CLIENTE] ACK recebido seq={seq_resp}')
                esperado += 1
                continue

            if tipo_resp == 'ack' and seq_resp < esperado:
                continue

            tentativas_janela += 1
            if tentativas_janela > max_retransmissoes:
                raise ValueError(
                    f'Janela {base}-{fim_janela} rejeitada apos {max_retransmissoes} retransmissoes: {msg}'
                )

            alvo = esperado
            if isinstance(seq_resp, int) and esperado <= seq_resp <= fim_janela:
                alvo = seq_resp

            print(
                f'[CLIENTE] NACK na janela {base}-{fim_janela}, seq alvo={alvo}: {msg}. '
                f'Retransmitindo ({tentativas_janela}/{max_retransmissoes})...'
            )
            esperado = alvo
            reenviar_faixa(
                arquivo_socket,
                pacotes,
                alvo,
                fim_janela,
                drop_once_seqs,
                corrupt_once_seqs,
                drop_aplicado,
                corrupt_aplicado,
            )

        base = fim_janela + 1


def enviar_lotes_seletivo(
    arquivo_socket,
    pacotes,
    janela_sessao,
    drop_once_seqs,
    corrupt_once_seqs,
    drop_aplicado,
    corrupt_aplicado,
    max_retransmissoes,
):
    total = len(pacotes)
    base = 0

    while base < total:
        fim_janela = min(base + janela_sessao - 1, total - 1)
        pendentes = set(range(base, fim_janela + 1))
        tentativas_por_seq = {seq: 0 for seq in pendentes}

        reenviar_faixa(
            arquivo_socket,
            pacotes,
            base,
            fim_janela,
            drop_once_seqs,
            corrupt_once_seqs,
            drop_aplicado,
            corrupt_aplicado,
        )

        while pendentes:
            try:
                resp = receber_controle_com_timeout(arquivo_socket)
                tipo_resp, seq_resp, msg = normalizar_resposta_controle(resp)
            except TimeoutError:
                for seq in sorted(pendentes):
                    tentativas_por_seq[seq] += 1
                    if tentativas_por_seq[seq] > max_retransmissoes:
                        raise TimeoutError(f'Timeout persistente no pacote seq={seq} (modo seletivo).')
                    print(
                        f'[CLIENTE] Timeout seletivo no seq={seq}. '
                        f'Retransmitindo ({tentativas_por_seq[seq]}/{max_retransmissoes})...'
                    )
                    enviar_pacote_controlado(
                        arquivo_socket,
                        pacotes[seq],
                        drop_once_seqs,
                        corrupt_once_seqs,
                        drop_aplicado,
                        corrupt_aplicado,
                    )
                continue

            if not isinstance(seq_resp, int):
                continue

            if tipo_resp == 'ack':
                if seq_resp in pendentes:
                    pendentes.remove(seq_resp)
                    print(f'[CLIENTE] ACK recebido seq={seq_resp}')
                continue

            if seq_resp not in pendentes:
                # NACK atrasado/obsoleto de um seq ja confirmado.
                continue

            alvo = seq_resp
            tentativas_por_seq[alvo] += 1
            if tentativas_por_seq[alvo] > max_retransmissoes:
                raise ValueError(f'Retransmissoes excedidas no seq={alvo} (seletivo): {msg}')

            print(
                f'[CLIENTE] NACK recebido seq={alvo}: {msg}. '
                f'Retransmitindo ({tentativas_por_seq[alvo]}/{max_retransmissoes})...'
            )
            enviar_pacote_controlado(
                arquivo_socket,
                pacotes[alvo],
                drop_once_seqs,
                corrupt_once_seqs,
                drop_aplicado,
                corrupt_aplicado,
            )

        base = fim_janela + 1


def enviar_payload_com_janela(
    client_socket,
    arquivo_socket,
    mensagem,
    tamanho_maximo_sessao,
    janela_sessao,
    tipo_operacao,
    modo_confirmacao,
    timeout_ack_ms,
    max_retransmissoes,
    drop_once_seqs,
    corrupt_once_seqs,
    aesgcm=None,
    hmac_key=None,
):
    if len(mensagem) > tamanho_maximo_sessao:
        raise ValueError(
            f'Mensagem com {len(mensagem)} caracteres excede o limite negociado de {tamanho_maximo_sessao}.'
        )

    fragmentos = fragmentar_payload(mensagem, PAYLOAD_CHUNK_SIZE)
    if not fragmentos:
        fragmentos = ['']

    pacotes: Dict[int, Dict] = {}
    for seq, fragmento in enumerate(fragmentos):
        pacotes[seq] = construir_pacote(
            seq,
            fragmento,
            seq == len(fragmentos) - 1,
            aesgcm=aesgcm,
            hmac_key=hmac_key,
        )

    drop_aplicado = set()
    corrupt_aplicado = set()

    old_timeout = client_socket.gettimeout()
    client_socket.settimeout(timeout_ack_ms / 1000.0)
    try:
        if tipo_operacao == 'individual':
            enviar_individual(
                arquivo_socket,
                pacotes,
                drop_once_seqs,
                corrupt_once_seqs,
                drop_aplicado,
                corrupt_aplicado,
                max_retransmissoes,
            )
            return

        if modo_confirmacao == 'seletivo':
            enviar_lotes_seletivo(
                arquivo_socket,
                pacotes,
                janela_sessao,
                drop_once_seqs,
                corrupt_once_seqs,
                drop_aplicado,
                corrupt_aplicado,
                max_retransmissoes,
            )
            return

        enviar_lotes_go_back_n(
            arquivo_socket,
            pacotes,
            janela_sessao,
            drop_once_seqs,
            corrupt_once_seqs,
            drop_aplicado,
            corrupt_aplicado,
            max_retransmissoes,
        )
    finally:
        client_socket.settimeout(old_timeout)


def main():
    args = parse_args()

    if args.timeout_ack_ms <= 0:
        raise ValueError('--timeout-ack-ms deve ser > 0.')
    if args.max_retransmissoes < 0:
        raise ValueError('--max-retransmissoes deve ser >= 0.')

    drop_once_seqs = parse_seq_list(args.drop_seqs)
    corrupt_once_seqs = parse_seq_list(args.corrupt_seqs)

    host, port = obter_host_port(args)
    tamanho_maximo = solicitar_tamanho_maximo()
    janela_atual = solicitar_janela_atual()
    tipo_operacao = solicitar_tipo_operacao()

    handshake_requisicao = {
        'tipo': 'handshake',
        'versao_protocolo': 2,
        'modo_operacao': 'cliente',
        'tamanho_maximo_desejado': tamanho_maximo,
        'janela_desejada': janela_atual,
        'tipo_operacao': tipo_operacao,
        'modo_confirmacao': args.modo_confirmacao,
        'timeout_ack_ms': args.timeout_ack_ms,
        'max_retransmissoes': args.max_retransmissoes,
        'simulacao_perda_seq': sorted(drop_once_seqs),
        'simulacao_corrupcao_seq': sorted(corrupt_once_seqs),
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        print(f'[CLIENTE] Conectando ao servidor {host}:{port}...')
        client_socket.connect((host, port))
        print('[CLIENTE] Conectado!')

        with client_socket.makefile('rwb') as arquivo_socket:
            enviar_json(arquivo_socket, handshake_requisicao)

            print('[CLIENTE] Handshake enviado:')
            print(f"  - Modo de operacao: {handshake_requisicao['modo_operacao']}")
            print(f"  - Tamanho maximo desejado: {handshake_requisicao['tamanho_maximo_desejado']} caracteres")
            print(f"  - Janela desejada: {handshake_requisicao['janela_desejada']}")
            print(f"  - Tipo de operacao: {handshake_requisicao['tipo_operacao']}")
            print(f"  - Modo de confirmacao: {handshake_requisicao['modo_confirmacao']}")

            handshake_resposta = receber_json(arquivo_socket)
            if not isinstance(handshake_resposta, dict) or handshake_resposta.get('tipo') != 'handshake_ack':
                print('[CLIENTE] Resposta invalida no handshake (tipo inesperado). Encerrando.')
                return

            status = handshake_resposta.get('status')
            if status == 'erro':
                print(f"[CLIENTE] Handshake rejeitado: {handshake_resposta.get('mensagem', 'erro desconhecido')}")
                return
            if status != 'ok':
                print('[CLIENTE] Handshake com status desconhecido. Encerrando.')
                return

            modo_operacao_srv = handshake_resposta.get('modo_operacao')
            tamanho_maximo_sessao = handshake_resposta.get('tamanho_maximo_sessao')
            janela_sessao = handshake_resposta.get('janela_sessao')

            session_salt_b64 = handshake_resposta.get('session_salt')
            aesgcm_obj = None
            hmac_key = None
            if session_salt_b64:
                try:
                    session_salt = base64.b64decode(session_salt_b64)
                    psk = os.environ.get('PSK', 'dev_psk_for_testing_only_please_change').encode()
                    hkdf = HKDF(
                        algorithm=hashes.SHA256(),
                        length=64,
                        salt=session_salt,
                        info=b'handshake data',
                    )
                    km = hkdf.derive(psk)
                    aes_key = km[:32]
                    hmac_key = km[32:]
                    aesgcm_obj = AESGCM(aes_key)
                except Exception:
                    print('[CLIENTE] Falha ao processar session_salt do servidor. Encerrando.')
                    return

            if modo_operacao_srv != 'servidor':
                print('[CLIENTE] Modo de operacao inesperado no servidor. Encerrando.')
                return
            if not isinstance(tamanho_maximo_sessao, int) or not isinstance(janela_sessao, int):
                print('[CLIENTE] Campos do handshake invalidos (tamanho/janela). Encerrando.')
                return

            modo_confirmacao = handshake_resposta.get('modo_confirmacao_acordado', args.modo_confirmacao)
            timeout_ack_ms = handshake_resposta.get('timeout_ack_ms_acordado', args.timeout_ack_ms)
            max_retransmissoes = handshake_resposta.get('max_retransmissoes_acordado', args.max_retransmissoes)

            print('[CLIENTE] Handshake recebido do servidor:')
            print(f"  - Modo de operacao: {handshake_resposta['modo_operacao']}")
            print(f'  - Tamanho maximo da sessao: {tamanho_maximo_sessao} caracteres')
            print(f'  - Janela da sessao: {janela_sessao}')
            print(f'  - Modo de confirmacao acordado: {modo_confirmacao}')
            print(f'  - Timeout ACK acordado: {timeout_ack_ms} ms')
            print(f'  - Max retransmissoes acordado: {max_retransmissoes}')
            print('[CLIENTE] Handshake completo!')

            while True:
                mensagem = input("[CLIENTE] Digite a mensagem para envio (ou 'sair' para encerrar): ")
                if mensagem.strip().lower() == 'sair':
                    print('[CLIENTE] Encerrando cliente por solicitacao do usuario.')
                    break

                enviar_payload_com_janela(
                    client_socket,
                    arquivo_socket,
                    mensagem,
                    tamanho_maximo_sessao,
                    janela_sessao,
                    tipo_operacao,
                    modo_confirmacao,
                    timeout_ack_ms,
                    max_retransmissoes,
                    drop_once_seqs,
                    corrupt_once_seqs,
                    aesgcm=aesgcm_obj,
                    hmac_key=hmac_key,
                )
                print('[CLIENTE] Envio da carga util concluido.')


if __name__ == '__main__':
    main()
