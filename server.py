#!/usr/bin/env python3
"""
Servidor TCP com transporte confiavel na camada de aplicacao.

Implementa:
- sockets TCP;
- protocolo JSON por linha;
- handshake de sessao;
- limite de tamanho de mensagem definido no inicio;
- payload maximo de 4 caracteres por pacote;
- checksum CRC32;
- temporizador por socket;
- numeros de sequencia;
- ACK positivo;
- NACK negativo;
- janela definida pelo servidor, de 1 a 5, padrao 5;
- envio individual como Stop-and-Wait;
- envio em lotes com Go-Back-N ou repeticao seletiva;
- criptografia simetrica opcional com AES-GCM;
- HMAC-SHA256 para autenticacao dos metadados criptografados principais;
- tratamento de encerramento gracioso.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import socket
import sys
import threading
import warnings
import zlib
from typing import Dict, Optional, Tuple

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover - depende do ambiente do avaliador
    AESGCM = None  # type: ignore
    HKDF = None  # type: ignore
    hashes = None  # type: ignore
    CRYPTO_AVAILABLE = False


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000
SERVER_BUFFER_SIZE = 4096
MIN_TAMANHO = 30
MIN_JANELA = 1
MAX_JANELA = 5
JANELA_INICIAL_SERVIDOR = 5
PAYLOAD_CHUNK_SIZE = 4
HANDSHAKE_TIMEOUT = 10
DEFAULT_MODO_CONFIRMACAO = "go_back_n"
DEFAULT_TIMEOUT_ACK_MS = 5000
DEFAULT_MAX_RETRANSMISSOES = 3
ACCEPTED_MODO_OPERACAO = "cliente"
VERSAO_PROTOCOLO_SUPORTADA = 2
RECV_CHUNK_SIZE = 4096

_PSK_ENV = os.environ.get("PSK", "")
if not _PSK_ENV:
    warnings.warn(
        "[SEGURANCA] Variavel de ambiente PSK nao definida. "
        "Usando chave de desenvolvimento insegura. "
        "Defina PSK antes da apresentacao: export PSK='sua_chave'.",
        stacklevel=1,
    )
    _PSK_ENV = "dev_psk_for_testing_only_please_change"
PSK = _PSK_ENV.encode("utf-8")


class JsonLineSocket:
    """JSON por linha sobre socket usando recv/sendall, sem makefile().

    O uso direto de recv() evita o problema em que socket.makefile().readline()
    pode ficar inutilizavel depois de socket.timeout.
    """

    def __init__(self, sock: socket.socket, peer_label: str = "peer") -> None:
        self.sock = sock
        self.peer_label = peer_label
        self._recv_buffer = b""

    def write(self, data: bytes) -> int:
        self.sock.sendall(data)
        return len(data)

    def flush(self) -> None:
        return None

    def readline(self) -> bytes:
        while b"\n" not in self._recv_buffer:
            chunk = self.sock.recv(RECV_CHUNK_SIZE)
            if not chunk:
                if self._recv_buffer:
                    line = self._recv_buffer
                    self._recv_buffer = b""
                    return line
                return b""
            self._recv_buffer += chunk

        line, self._recv_buffer = self._recv_buffer.split(b"\n", 1)
        return line + b"\n"


def enviar_json(canal: JsonLineSocket, mensagem: dict) -> None:
    canal.write((json.dumps(mensagem, ensure_ascii=False) + "\n").encode("utf-8"))
    canal.flush()


def receber_json(canal: JsonLineSocket) -> dict:
    linha = canal.readline()
    if not linha:
        raise ConnectionError("Conexao encerrada pelo cliente.")
    obj = json.loads(linha.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("Mensagem JSON recebida nao e um objeto.")
    return obj


def calcular_checksum(payload: str) -> str:
    return f"{zlib.crc32(payload.encode('utf-8')) & 0xFFFFFFFF:08x}"


def montar_hmac_data(seq: int, fim: bool, nonce: bytes, ciphertext: bytes) -> bytes:
    return (
        b"trabalho-i-v2|dados|"
        + int(seq).to_bytes(8, "big", signed=False)
        + (b"\x01" if fim else b"\x00")
        + nonce
        + ciphertext
    )


def derive_session_keys(session_salt: bytes) -> Tuple[object, bytes]:
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("Biblioteca cryptography nao esta instalada.")

    hkdf = HKDF(  # type: ignore[misc]
        algorithm=hashes.SHA256(),  # type: ignore[union-attr]
        length=64,
        salt=session_salt,
        info=b"trabalho-i-handshake-v2",
    )
    key_material = hkdf.derive(PSK)
    aes_key = key_material[:32]
    hmac_key = key_material[32:]
    return AESGCM(aes_key), hmac_key  # type: ignore[operator]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Servidor TCP com confiabilidade na camada de aplicacao."
    )
    parser.add_argument("--host", type=str, help="Host/IP para bind do servidor.")
    parser.add_argument("--port", type=int, help="Porta para bind do servidor.")
    parser.add_argument(
        "--modo-confirmacao-padrao",
        choices=["go_back_n", "seletivo"],
        default=DEFAULT_MODO_CONFIRMACAO,
        help="Modo aplicado quando o cliente nao informar modo_confirmacao.",
    )
    parser.add_argument(
        "--janela-inicial",
        type=int,
        default=JANELA_INICIAL_SERVIDOR,
        help=f"Janela definida pelo servidor ({MIN_JANELA}-{MAX_JANELA}, padrao {JANELA_INICIAL_SERVIDOR}).",
    )
    return parser.parse_args()


def obter_host_port(args: argparse.Namespace) -> Tuple[str, int]:
    host = args.host
    port = args.port

    if host is None and sys.stdin.isatty():
        entrada_host = input(f"[SERVIDOR] Host para bind (Enter para {DEFAULT_HOST}): ").strip()
        host = entrada_host or DEFAULT_HOST
    elif host is None:
        host = DEFAULT_HOST

    if port is None and sys.stdin.isatty():
        while True:
            entrada_port = input(f"[SERVIDOR] Porta para bind (Enter para {DEFAULT_PORT}): ").strip()
            if entrada_port == "":
                port = DEFAULT_PORT
                break
            try:
                port = int(entrada_port)
            except ValueError:
                print("[SERVIDOR] Porta invalida. Digite um inteiro.")
                continue
            break
    elif port is None:
        port = DEFAULT_PORT

    if port <= 0 or port > 65535:
        raise ValueError("Porta deve estar entre 1 e 65535.")

    return host, port


def validar_handshake(cliente_handshake: dict, modo_confirmacao_padrao: str) -> Tuple[bool, str]:
    if cliente_handshake.get("tipo") != "handshake":
        return False, "Mensagem inicial nao e um handshake valido."

    versao = cliente_handshake.get("versao_protocolo")
    if versao != VERSAO_PROTOCOLO_SUPORTADA:
        return False, (
            f"Versao de protocolo incompativel: recebido {versao!r}, "
            f"esperado {VERSAO_PROTOCOLO_SUPORTADA}."
        )

    modo_operacao = cliente_handshake.get("modo_operacao")
    if modo_operacao != ACCEPTED_MODO_OPERACAO:
        return False, f"Campo modo_operacao invalido. Esperado '{ACCEPTED_MODO_OPERACAO}'."

    tamanho_desejado = cliente_handshake.get("tamanho_maximo_desejado")
    janela_desejada = cliente_handshake.get("janela_desejada", JANELA_INICIAL_SERVIDOR)
    tipo_operacao = cliente_handshake.get("tipo_operacao", "lotes")
    modo_confirmacao = cliente_handshake.get("modo_confirmacao", modo_confirmacao_padrao)
    timeout_ack_ms = cliente_handshake.get("timeout_ack_ms", DEFAULT_TIMEOUT_ACK_MS)
    max_retransmissoes = cliente_handshake.get("max_retransmissoes", DEFAULT_MAX_RETRANSMISSOES)
    criptografia_desejada = cliente_handshake.get("criptografia_desejada", True)

    if not isinstance(tamanho_desejado, int):
        return False, "Campo tamanho_maximo_desejado deve ser inteiro."
    if tamanho_desejado < MIN_TAMANHO:
        return False, f"Campo tamanho_maximo_desejado deve ser >= {MIN_TAMANHO}."

    if not isinstance(janela_desejada, int):
        return False, "Campo janela_desejada deve ser inteiro."
    if janela_desejada < MIN_JANELA or janela_desejada > MAX_JANELA:
        return False, f"Campo janela_desejada deve estar entre {MIN_JANELA} e {MAX_JANELA}."

    if tipo_operacao not in ("individual", "lotes"):
        return False, "Campo tipo_operacao deve ser 'individual' ou 'lotes'."

    if modo_confirmacao not in ("go_back_n", "seletivo"):
        return False, "Campo modo_confirmacao deve ser 'go_back_n' ou 'seletivo'."

    if not isinstance(timeout_ack_ms, int) or timeout_ack_ms <= 0:
        return False, "Campo timeout_ack_ms deve ser inteiro > 0."

    if not isinstance(max_retransmissoes, int) or max_retransmissoes < 0:
        return False, "Campo max_retransmissoes deve ser inteiro >= 0."

    if not isinstance(criptografia_desejada, bool):
        return False, "Campo criptografia_desejada deve ser booleano."

    if criptografia_desejada and not CRYPTO_AVAILABLE:
        return False, "Criptografia solicitada, mas a biblioteca cryptography nao esta instalada."

    return True, ""


def enviar_ack(arquivo_socket: JsonLineSocket, seq: int, cumulativo: bool) -> None:
    enviar_json(
        arquivo_socket,
        {
            "tipo": "ack",
            "seq": seq,
            "status": "ok",
            "cumulativo": cumulativo,
            "mensagem": "Recebido com sucesso.",
        },
    )


def enviar_ack_cumulativo(arquivo_socket: JsonLineSocket, seq: int) -> None:
    enviar_ack(arquivo_socket, seq, True)


def enviar_ack_individual(arquivo_socket: JsonLineSocket, seq: int) -> None:
    enviar_ack(arquivo_socket, seq, False)


def enviar_nack(arquivo_socket: JsonLineSocket, seq: int, mensagem: str) -> None:
    enviar_json(
        arquivo_socket,
        {
            "tipo": "nack",
            "seq": seq,
            "status": "reenviar",
            "mensagem": mensagem,
        },
    )
    print(f"[SERVIDOR] NACK enviado seq={seq} motivo='{mensagem}'")


def enviar_mensagem_encerramento_servidor(arquivo_socket: JsonLineSocket, addr: object) -> None:
    try:
        enviar_json(
            arquivo_socket,
            {
                "tipo": "encerramento",
                "status": "timeout",
                "mensagem": "Servidor encerrando conexao por inatividade.",
            },
        )
        print(f"[SERVIDOR] Notificacao de encerramento enviada a {addr}.")
    except Exception as erro:  # pragma: no cover - so loga falha de rede
        print(f"[SERVIDOR] Nao foi possivel notificar {addr}: {erro}")


def validar_pacote_payload(pacote: dict, aesgcm: Optional[object], hmac_key: Optional[bytes]) -> Tuple[Optional[int], Optional[str], str]:
    if pacote.get("tipo") != "dados":
        return None, None, "Mensagem fora do protocolo de dados."

    seq_raw = pacote.get("seq")
    if not isinstance(seq_raw, int) or seq_raw < 0:
        return None, None, "Campo seq deve ser inteiro >= 0."

    fim_raw = pacote.get("fim")
    if not isinstance(fim_raw, bool):
        return seq_raw, None, "Campo fim deve ser booleano."

    recv_checksum = pacote.get("checksum")
    if not isinstance(recv_checksum, str) or len(recv_checksum) != 8:
        return seq_raw, None, "Falta checksum valido no pacote."

    if "ciphertext" in pacote:
        if aesgcm is None or hmac_key is None:
            return seq_raw, None, "Pacote criptografado recebido em sessao sem criptografia."
        try:
            nonce = base64.b64decode(pacote.get("nonce", ""), validate=True)
            ciphertext = base64.b64decode(pacote.get("ciphertext", ""), validate=True)
        except Exception:
            return seq_raw, None, "Formato de ciphertext/nonce invalido."

        if len(nonce) != 12:
            return seq_raw, None, "Nonce AES-GCM deve ter 12 bytes."

        recv_hmac = pacote.get("hmac", "")
        if not isinstance(recv_hmac, str):
            return seq_raw, None, "HMAC ausente ou invalido."

        mac = hmac.new(
            hmac_key,
            montar_hmac_data(seq_raw, fim_raw, nonce, ciphertext),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(mac, recv_hmac):
            return seq_raw, None, "Falha na verificacao de integridade (HMAC)."

        try:
            payload = aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")  # type: ignore[attr-defined]
        except Exception:
            return seq_raw, None, "Falha na autenticacao/descriptografia do ciphertext."

        calc_checksum = calcular_checksum(payload)
        if calc_checksum != recv_checksum:
            return seq_raw, None, "Falha na verificacao de integridade (checksum)."
    else:
        payload = pacote.get("payload")
        if not isinstance(payload, str):
            return seq_raw, None, "Payload deve ser texto."

        calc_checksum = calcular_checksum(payload)
        if calc_checksum != recv_checksum:
            return seq_raw, None, "Falha na verificacao de integridade (checksum)."

    if not isinstance(payload, str):
        return seq_raw, None, "Payload deve ser texto."
    if len(payload) == 0:
        return seq_raw, None, "Payload vazio nao e aceito."
    if len(payload) > PAYLOAD_CHUNK_SIZE:
        return seq_raw, None, f"Payload excede {PAYLOAD_CHUNK_SIZE} caracteres por pacote."

    return seq_raw, payload, ""


def _log_pacote_recebido(seq: int, payload: str, pacote: dict) -> None:
    fim = bool(pacote.get("fim", False))
    checksum = pacote.get("checksum")
    criptografado = "ciphertext" in pacote
    if criptografado:
        nonce = str(pacote.get("nonce", ""))
        hmac_val = str(pacote.get("hmac", ""))
        print(
            f"[SERVIDOR] DADOS seq={seq} fim={fim} len_payload={len(payload)} "
            f"checksum={checksum} criptografado=True nonce={nonce[:8]}... hmac={hmac_val[:8]}..."
        )
    else:
        print(
            f"[SERVIDOR] DADOS seq={seq} fim={fim} len_payload={len(payload)} "
            f"payload='{payload}' checksum={checksum} criptografado=False"
        )


def _validar_limite_mensagem(mensagem_partes: Dict[int, str], payload: str, tamanho_maximo_sessao: int) -> bool:
    return (sum(len(v) for v in mensagem_partes.values()) + len(payload)) <= tamanho_maximo_sessao


def receber_gbn(
    arquivo_socket: JsonLineSocket,
    tamanho_maximo_sessao: int,
    janela_sessao: int,
    aesgcm: Optional[object] = None,
    hmac_key: Optional[bytes] = None,
) -> None:
    """Go-Back-N com ACK cumulativo.

    O receptor aceita apenas o proximo seq esperado. Pacotes futuros sao
    descartados com NACK do seq esperado. Pacotes duplicados antigos geram
    reenvio do ultimo ACK cumulativo, evitando NACK obsoleto.
    """

    mensagem_partes: Dict[int, str] = {}
    fim_seq: Optional[int] = None
    seq_esperado = 0

    while True:
        pacote = receber_json(arquivo_socket)

        if pacote.get("tipo") == "fim_sessao":
            print(f"[SERVIDOR] Encerramento gracioso recebido: {pacote.get('mensagem', '')}")
            raise ConnectionError("Cliente encerrou a sessao normalmente.")

        seq_raw = pacote.get("seq")
        if isinstance(seq_raw, int) and seq_raw < seq_esperado:
            ultimo_confirmado = seq_esperado - 1
            enviar_ack_cumulativo(arquivo_socket, ultimo_confirmado)
            print(
                f"[SERVIDOR] Duplicado GBN seq={seq_raw}. "
                f"Reenviando ACK cumulativo seq={ultimo_confirmado}."
            )
            continue

        seq, payload, erro = validar_pacote_payload(pacote, aesgcm, hmac_key)
        if erro:
            enviar_nack(arquivo_socket, seq_esperado, erro)
            continue

        assert seq is not None
        assert payload is not None

        if seq > seq_esperado:
            enviar_nack(
                arquivo_socket,
                seq_esperado,
                f"Sequencia inesperada. Esperado {seq_esperado}, recebido {seq}.",
            )
            continue

        if not _validar_limite_mensagem(mensagem_partes, payload, tamanho_maximo_sessao):
            enviar_nack(arquivo_socket, seq, f"Mensagem total excede o limite da sessao ({tamanho_maximo_sessao}).")
            continue

        mensagem_partes[seq] = payload
        _log_pacote_recebido(seq, payload, pacote)

        if bool(pacote.get("fim", False)):
            fim_seq = seq

        enviar_ack_cumulativo(arquivo_socket, seq)
        print(f"[SERVIDOR] ACK cumulativo enviado seq={seq} confirma=0..{seq}")
        seq_esperado += 1

        if fim_seq is not None and seq_esperado > fim_seq:
            mensagem_final = "".join(mensagem_partes[i] for i in range(fim_seq + 1))
            print("[SERVIDOR] Recebimento da carga util concluido.")
            print(f"[SERVIDOR] Mensagem reconstruida: '{mensagem_final}'")
            return


def receber_seletivo(
    arquivo_socket: JsonLineSocket,
    tamanho_maximo_sessao: int,
    janela_sessao: int,
    aesgcm: Optional[object] = None,
    hmac_key: Optional[bytes] = None,
) -> None:
    """Repeticao seletiva com ACK individual e buffer fora de ordem."""

    mensagem_partes: Dict[int, str] = {}
    fim_seq: Optional[int] = None
    seq_esperado = 0
    nacks_emitidos = set()

    while True:
        pacote = receber_json(arquivo_socket)

        if pacote.get("tipo") == "fim_sessao":
            print(f"[SERVIDOR] Encerramento gracioso recebido: {pacote.get('mensagem', '')}")
            raise ConnectionError("Cliente encerrou a sessao normalmente.")

        seq, payload, erro = validar_pacote_payload(pacote, aesgcm, hmac_key)
        if erro:
            nack_seq = seq if isinstance(seq, int) else seq_esperado
            enviar_nack(arquivo_socket, nack_seq, erro)
            continue

        assert seq is not None
        assert payload is not None

        if seq < seq_esperado:
            enviar_ack_individual(arquivo_socket, seq)
            print(f"[SERVIDOR] Duplicado seletivo seq={seq}. ACK individual reenviado.")
            continue

        if seq > seq_esperado + janela_sessao - 1:
            enviar_nack(
                arquivo_socket,
                seq_esperado,
                f"Seq fora da janela atual. Esperado entre {seq_esperado} e {seq_esperado + janela_sessao - 1}.",
            )
            continue

        if seq > seq_esperado:
            for faltante in range(seq_esperado, seq):
                if faltante not in mensagem_partes and faltante not in nacks_emitidos:
                    enviar_nack(arquivo_socket, faltante, f"Sequencia faltante {faltante}.")
                    nacks_emitidos.add(faltante)

        if seq not in mensagem_partes:
            if not _validar_limite_mensagem(mensagem_partes, payload, tamanho_maximo_sessao):
                enviar_nack(arquivo_socket, seq, f"Mensagem total excede o limite da sessao ({tamanho_maximo_sessao}).")
                continue

            mensagem_partes[seq] = payload
            _log_pacote_recebido(seq, payload, pacote)
            if bool(pacote.get("fim", False)) and fim_seq is None:
                fim_seq = seq

        enviar_ack_individual(arquivo_socket, seq)
        print(f"[SERVIDOR] ACK individual enviado seq={seq}")

        seq_esperado_anterior = seq_esperado
        while seq_esperado in mensagem_partes:
            seq_esperado += 1

        if seq_esperado > seq_esperado_anterior:
            nacks_emitidos = {s for s in nacks_emitidos if s >= seq_esperado}

        if fim_seq is not None and seq_esperado > fim_seq:
            mensagem_final = "".join(mensagem_partes[i] for i in range(fim_seq + 1))
            print("[SERVIDOR] Recebimento da carga util concluido.")
            print(f"[SERVIDOR] Mensagem reconstruida: '{mensagem_final}'")
            return


def receber_payload_com_ack(
    arquivo_socket: JsonLineSocket,
    tamanho_maximo_sessao: int,
    janela_sessao: int,
    tipo_operacao: str,
    modo_confirmacao: str,
    aesgcm: Optional[object] = None,
    hmac_key: Optional[bytes] = None,
) -> None:
    if tipo_operacao == "individual" or modo_confirmacao == "go_back_n":
        receber_gbn(
            arquivo_socket,
            tamanho_maximo_sessao,
            1 if tipo_operacao == "individual" else janela_sessao,
            aesgcm=aesgcm,
            hmac_key=hmac_key,
        )
    else:
        receber_seletivo(
            arquivo_socket,
            tamanho_maximo_sessao,
            janela_sessao,
            aesgcm=aesgcm,
            hmac_key=hmac_key,
        )


def handle_client(conn: socket.socket, addr: object, args: argparse.Namespace, janela_inicial: int) -> None:
    try:
        with conn:
            print(f"[SERVIDOR] Conectado por {addr}")
            conn.settimeout(HANDSHAKE_TIMEOUT)
            arquivo_socket = JsonLineSocket(conn, str(addr))

            try:
                client_config = receber_json(arquivo_socket)
            except socket.timeout:
                print(f"[SERVIDOR] Timeout ({HANDSHAKE_TIMEOUT}s) aguardando handshake de {addr}.")
                try:
                    enviar_json(
                        arquivo_socket,
                        {
                            "tipo": "handshake_ack",
                            "status": "erro",
                            "mensagem": "Timeout aguardando handshake.",
                        },
                    )
                except Exception:
                    pass
                return
            except (json.JSONDecodeError, ValueError, ConnectionError) as erro:
                print(f"[SERVIDOR] Erro ao receber handshake: {erro}")
                try:
                    enviar_json(
                        arquivo_socket,
                        {
                            "tipo": "handshake_ack",
                            "status": "erro",
                            "mensagem": "Handshake invalido ou conexao fechada.",
                        },
                    )
                except Exception:
                    pass
                return

            print("[SERVIDOR] Handshake recebido do cliente:")
            print(f"  - Modo de operacao: {client_config.get('modo_operacao', 'nao informado')}")
            print(f"  - Tamanho maximo desejado: {client_config.get('tamanho_maximo_desejado', 'nao informado')} caracteres")
            print(f"  - Janela desejada pelo cliente: {client_config.get('janela_desejada', 'nao informado')}")
            print(f"  - Tipo de operacao: {client_config.get('tipo_operacao', 'nao informado')}")
            print(f"  - Modo de confirmacao: {client_config.get('modo_confirmacao', args.modo_confirmacao_padrao)}")
            print(f"  - Criptografia desejada: {client_config.get('criptografia_desejada', True)}")

            valido, mensagem_validacao = validar_handshake(client_config, args.modo_confirmacao_padrao)
            if not valido:
                enviar_json(
                    arquivo_socket,
                    {"tipo": "handshake_ack", "status": "erro", "mensagem": mensagem_validacao},
                )
                print(f"[SERVIDOR] Handshake rejeitado: {mensagem_validacao}")
                return

            timeout_ack_ms = int(client_config.get("timeout_ack_ms", DEFAULT_TIMEOUT_ACK_MS))
            max_retransmissoes = int(client_config.get("max_retransmissoes", DEFAULT_MAX_RETRANSMISSOES))
            timeout_dados = max(2.0, (timeout_ack_ms / 1000.0) * (max_retransmissoes + 2))
            conn.settimeout(timeout_dados)

            tamanho_maximo_sessao = min(int(client_config["tamanho_maximo_desejado"]), SERVER_BUFFER_SIZE)
            janela_sessao = janela_inicial
            if not (MIN_JANELA <= janela_sessao <= MAX_JANELA):
                enviar_json(
                    arquivo_socket,
                    {
                        "tipo": "handshake_ack",
                        "status": "erro",
                        "mensagem": "Janela do servidor fora do intervalo permitido.",
                    },
                )
                return

            criptografia_ativa = bool(client_config.get("criptografia_desejada", True))
            aesgcm: Optional[object] = None
            hmac_key: Optional[bytes] = None
            session_salt: Optional[bytes] = None

            if criptografia_ativa:
                session_salt = os.urandom(16)
                aesgcm, hmac_key = derive_session_keys(session_salt)

            modo_confirmacao = client_config.get("modo_confirmacao", args.modo_confirmacao_padrao)
            tipo_operacao = client_config.get("tipo_operacao", "lotes")

            server_config = {
                "tipo": "handshake_ack",
                "status": "ok",
                "modo_operacao": "servidor",
                "tamanho_maximo_sessao": tamanho_maximo_sessao,
                "janela_sessao": janela_sessao,
                "criptografia_ativa": criptografia_ativa,
                "modo_confirmacao_acordado": modo_confirmacao,
                "timeout_ack_ms_acordado": timeout_ack_ms,
                "max_retransmissoes_acordado": max_retransmissoes,
            }
            if session_salt is not None:
                server_config["session_salt"] = base64.b64encode(session_salt).decode("ascii")

            enviar_json(arquivo_socket, server_config)

            print("[SERVIDOR] Handshake enviado:")
            print(f"  - Modo de operacao: {server_config['modo_operacao']}")
            print(f"  - Tamanho maximo da sessao: {tamanho_maximo_sessao} caracteres")
            print(f"  - Janela da sessao definida pelo servidor: {janela_sessao}")
            print(f"  - Cliente sugeriu janela: {client_config.get('janela_desejada')}")
            print(f"  - Modo de confirmacao acordado: {modo_confirmacao}")
            print(f"  - Tipo de operacao: {tipo_operacao}")
            print(f"  - Timeout de dados: {timeout_dados:.2f}s")
            print(f"  - Criptografia ativa: {criptografia_ativa}")
            print("[SERVIDOR] Handshake completo!")

            while True:
                try:
                    receber_payload_com_ack(
                        arquivo_socket,
                        tamanho_maximo_sessao,
                        janela_sessao,
                        tipo_operacao,
                        modo_confirmacao,
                        aesgcm=aesgcm,
                        hmac_key=hmac_key,
                    )
                except socket.timeout:
                    print("[SERVIDOR] Timeout de inatividade no fluxo de dados. Notificando cliente...")
                    enviar_mensagem_encerramento_servidor(arquivo_socket, addr)
                    print("[SERVIDOR] Encerrando conexao.")
                    break
                except ConnectionError as erro:
                    print(f"[SERVIDOR] Conexao encerrada: {erro}")
                    break
                except json.JSONDecodeError as erro:
                    print(f"[SERVIDOR] Erro de decodificacao JSON: {erro}")
                    break
                except ValueError as erro:
                    print(f"[SERVIDOR] Erro de protocolo: {erro}")
                    break

    except OSError as erro:
        print(f"[SERVIDOR] Conexao com {addr} encerrada com erro de socket: {erro}")
    except Exception as erro:  # pragma: no cover - protege thread do servidor
        print(f"[SERVIDOR] Erro inesperado com {addr}: {erro}")


def main() -> None:
    args = parse_args()
    host, port = obter_host_port(args)
    janela_inicial = max(MIN_JANELA, min(MAX_JANELA, int(args.janela_inicial)))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen()

        print(f"[SERVIDOR] Aguardando conexoes em {host}:{port}...")
        print(f"[SERVIDOR] Janela inicial configurada pelo servidor: {janela_inicial}")
        print("[SERVIDOR] Pressione Ctrl+C para encerrar.")

        try:
            while True:
                conn, addr = server_socket.accept()
                thread = threading.Thread(
                    target=handle_client,
                    args=(conn, addr, args, janela_inicial),
                    daemon=True,
                )
                thread.start()
        except KeyboardInterrupt:
            print("\n[SERVIDOR] Encerrado por Ctrl+C.")


if __name__ == "__main__":
    main()
