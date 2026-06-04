"""TCP server for the Redes de Computadores assignment.

The server negotiates a session by JSON handshake, receives text payloads
fragmented into four-character packets, validates integrity/authenticity,
and acknowledges packets using Stop-and-Wait, Go-Back-N, or Selective Repeat.
"""

from __future__ import annotations

import argparse
import base64
import os
import socket
import sys
import threading
from typing import Dict, Optional, Set, Tuple

from protocol import (
    DEFAULT_HOST,
    DEFAULT_MAX_RETRANSMISSOES,
    DEFAULT_MODO_CONFIRMACAO,
    DEFAULT_PORT,
    DEFAULT_TIMEOUT_ACK_MS,
    DuplexFile,
    HANDSHAKE_TIMEOUT,
    JANELA_PADRAO,
    MAX_JANELA,
    MIN_JANELA,
    SERVER_BUFFER_SIZE,
    SessionKeys,
    derive_session_keys,
    get_psk,
    make_ack,
    make_nack,
    recv_json,
    send_json,
    validate_data_packet,
    validate_handshake,
)


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
        default=JANELA_PADRAO,
        help=f"Janela inicial definida pelo servidor ({MIN_JANELA}-{MAX_JANELA}).",
    )
    parser.add_argument(
        "--allow-insecure-dev-psk",
        action="store_true",
        help="Permite PSK padrao insegura apenas para testes locais.",
    )
    return parser.parse_args()


def obter_host_port(args: argparse.Namespace) -> Tuple[str, int]:
    host = args.host
    port = args.port

    if host is None and sys.stdin.isatty():
        raw = input(f"[SERVIDOR] Host para bind (Enter para {DEFAULT_HOST}): ").strip()
        host = raw or DEFAULT_HOST
    elif host is None:
        host = DEFAULT_HOST

    if port is None and sys.stdin.isatty():
        while True:
            raw = input(f"[SERVIDOR] Porta para bind (Enter para {DEFAULT_PORT}): ").strip()
            if raw == "":
                port = DEFAULT_PORT
                break
            try:
                port = int(raw)
            except ValueError:
                print("[SERVIDOR] Porta invalida. Digite um inteiro.")
                continue
            break
    elif port is None:
        port = DEFAULT_PORT

    if port <= 0 or port > 65535:
        raise ValueError("Porta deve estar entre 1 e 65535.")
    return host, port


def send_nack(file_obj, message_id: int, seq: int, message: str) -> None:
    send_json(file_obj, make_nack(message_id, seq, message))


def send_server_shutdown(file_obj, addr) -> None:
    try:
        send_json(
            file_obj,
            {
                "tipo": "encerramento",
                "status": "timeout",
                "mensagem": "Servidor encerrando conexao por inatividade.",
            },
        )
        print(f"[SERVIDOR] Notificacao de encerramento enviada a {addr}.")
    except Exception as exc:
        print(f"[SERVIDOR] Nao foi possivel notificar {addr}: {exc}")


def log_packet(message_id: int, seq: int, payload: str, packet: Dict) -> None:
    if "ciphertext" in packet:
        hmac_value = str(packet.get("hmac", ""))
        meta = f"hmac={hmac_value[:8]}..."
    else:
        meta = f"checksum={packet.get('checksum')}"
    print(
        f"[SERVIDOR] Pacote recebido message_id={message_id}, "
        f"seq={seq}, payload='{payload}', {meta}"
    )


def handle_old_or_future_message(
    file_obj,
    received_message_id: int,
    expected_message_id: int,
    seq: int,
) -> bool:
    """Return True when packet was handled and current receiver must continue."""
    if received_message_id < expected_message_id:
        # Duplicate packet from a previous completed message. It must not be
        # interpreted as the first packet of the next message.
        send_json(file_obj, make_ack(received_message_id, max(seq, 0), cumulativo=False))
        print(
            f"[SERVIDOR] Pacote duplicado antigo ignorado: "
            f"message_id={received_message_id}, seq={seq}."
        )
        return True
    if received_message_id > expected_message_id:
        send_nack(
            file_obj,
            expected_message_id,
            0,
            f"message_id inesperado. Esperado {expected_message_id}, recebido {received_message_id}.",
        )
        return True
    return False


def receber_gbn(
    file_obj,
    tamanho_maximo_sessao: int,
    expected_message_id: int,
    keys: Optional[SessionKeys],
) -> str:
    """Receive one complete message using Go-Back-N semantics."""
    parts: Dict[int, str] = {}
    fim_seq: Optional[int] = None
    seq_esperado = 0

    while True:
        packet = recv_json(file_obj, peer_name="cliente")

        if packet.get("tipo") == "fim_sessao":
            print(f"[SERVIDOR] Encerramento gracioso: {packet.get('mensagem', '')}")
            raise ConnectionError("Cliente encerrou a sessao normalmente.")

        message_id, seq, payload, error = validate_data_packet(packet, keys)
        if error:
            send_nack(file_obj, max(message_id, expected_message_id), max(seq, seq_esperado), error)
            continue

        if handle_old_or_future_message(file_obj, message_id, expected_message_id, seq):
            continue

        if seq != seq_esperado:
            send_nack(
                file_obj,
                expected_message_id,
                seq_esperado,
                f"Sequencia inesperada. Esperado {seq_esperado}, recebido {seq}.",
            )
            continue

        new_size = sum(len(value) for value in parts.values()) + len(payload)
        if new_size > tamanho_maximo_sessao:
            send_nack(
                file_obj,
                expected_message_id,
                seq,
                f"Mensagem total excede o limite da sessao ({tamanho_maximo_sessao}).",
            )
            continue

        parts[seq] = payload
        log_packet(message_id, seq, payload, packet)
        if bool(packet.get("fim", False)):
            fim_seq = seq

        send_json(file_obj, make_ack(expected_message_id, seq, cumulativo=True))
        print(f"[SERVIDOR] ACK cumulativo enviado message_id={expected_message_id}, seq={seq}")
        seq_esperado += 1

        if fim_seq is not None and seq_esperado > fim_seq:
            message = "".join(parts[i] for i in range(fim_seq + 1))
            print(f"[SERVIDOR] Mensagem reconstruida message_id={expected_message_id}: '{message}'")
            return message


def receber_seletivo(
    file_obj,
    tamanho_maximo_sessao: int,
    janela_sessao: int,
    expected_message_id: int,
    keys: Optional[SessionKeys],
) -> str:
    """Receive one complete message using Selective Repeat semantics."""
    parts: Dict[int, str] = {}
    fim_seq: Optional[int] = None
    seq_esperado = 0
    nacks_emitidos: Set[int] = set()

    while True:
        packet = recv_json(file_obj, peer_name="cliente")

        if packet.get("tipo") == "fim_sessao":
            print(f"[SERVIDOR] Encerramento gracioso: {packet.get('mensagem', '')}")
            raise ConnectionError("Cliente encerrou a sessao normalmente.")

        message_id, seq, payload, error = validate_data_packet(packet, keys)
        if error:
            send_nack(file_obj, max(message_id, expected_message_id), max(seq, 0), error)
            continue

        if handle_old_or_future_message(file_obj, message_id, expected_message_id, seq):
            continue

        if seq < seq_esperado:
            send_json(file_obj, make_ack(expected_message_id, seq, cumulativo=False))
            continue

        if seq > seq_esperado + janela_sessao - 1:
            send_nack(
                file_obj,
                expected_message_id,
                seq_esperado,
                "Seq fora da janela atual. "
                f"Esperado entre {seq_esperado} e {seq_esperado + janela_sessao - 1}.",
            )
            continue

        if seq > seq_esperado:
            for missing in range(seq_esperado, seq):
                if missing not in parts and missing not in nacks_emitidos:
                    send_nack(file_obj, expected_message_id, missing, f"Sequencia faltante {missing}.")
                    nacks_emitidos.add(missing)

        if seq not in parts:
            new_size = sum(len(value) for value in parts.values()) + len(payload)
            if new_size > tamanho_maximo_sessao:
                send_nack(
                    file_obj,
                    expected_message_id,
                    seq,
                    f"Mensagem total excede o limite da sessao ({tamanho_maximo_sessao}).",
                )
                continue
            parts[seq] = payload
            log_packet(message_id, seq, payload, packet)
            if bool(packet.get("fim", False)) and fim_seq is None:
                fim_seq = seq

        send_json(file_obj, make_ack(expected_message_id, seq, cumulativo=False))
        print(f"[SERVIDOR] ACK individual enviado message_id={expected_message_id}, seq={seq}")

        previous = seq_esperado
        while seq_esperado in parts:
            seq_esperado += 1
        if seq_esperado > previous:
            nacks_emitidos = {item for item in nacks_emitidos if item >= seq_esperado}

        if fim_seq is not None and seq_esperado > fim_seq:
            message = "".join(parts[i] for i in range(fim_seq + 1))
            print(f"[SERVIDOR] Mensagem reconstruida message_id={expected_message_id}: '{message}'")
            return message


def receive_payload(
    file_obj,
    tamanho_maximo_sessao: int,
    janela_sessao: int,
    tipo_operacao: str,
    modo_confirmacao: str,
    expected_message_id: int,
    keys: Optional[SessionKeys],
) -> str:
    if tipo_operacao == "individual" or modo_confirmacao == "go_back_n":
        return receber_gbn(file_obj, tamanho_maximo_sessao, expected_message_id, keys)
    return receber_seletivo(file_obj, tamanho_maximo_sessao, janela_sessao, expected_message_id, keys)


def handle_client(conn: socket.socket, addr, args: argparse.Namespace, psk: bytes, janela_inicial: int) -> None:
    try:
        with conn:
            print(f"[SERVIDOR] Conectado por {addr}")
            conn.settimeout(HANDSHAKE_TIMEOUT)

            with conn.makefile("rb") as reader, conn.makefile("wb") as writer:
                file_obj = DuplexFile(reader, writer)

                try:
                    request = recv_json(file_obj, peer_name="cliente")
                except socket.timeout:
                    print(f"[SERVIDOR] Timeout de handshake ({HANDSHAKE_TIMEOUT}s) para {addr}.")
                    try:
                        send_json(
                            file_obj,
                            {
                                "tipo": "handshake_ack",
                                "status": "erro",
                                "mensagem": "Timeout aguardando handshake.",
                            },
                        )
                    except Exception:
                        pass
                    return
                except Exception as exc:
                    print(f"[SERVIDOR] Handshake invalido de {addr}: {exc}")
                    try:
                        send_json(
                            file_obj,
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
                print(f"  - Modo de operacao: {request.get('modo_operacao', 'nao informado')}")
                print(f"  - Tamanho desejado: {request.get('tamanho_maximo_desejado', 'nao informado')}")
                print(f"  - Janela desejada: {request.get('janela_desejada', 'nao informado')}")
                print(f"  - Tipo de operacao: {request.get('tipo_operacao', 'nao informado')}")
                print(f"  - Modo confirmacao: {request.get('modo_confirmacao', 'nao informado')}")

                valid, validation_message = validate_handshake(
                    request,
                    args.modo_confirmacao_padrao,
                )
                if not valid:
                    send_json(
                        file_obj,
                        {
                            "tipo": "handshake_ack",
                            "status": "erro",
                            "mensagem": validation_message,
                        },
                    )
                    print(f"[SERVIDOR] Handshake rejeitado: {validation_message}")
                    return

                session_salt = os.urandom(16)
                keys = derive_session_keys(psk, session_salt)
                tipo_operacao = request.get("tipo_operacao", "lotes")
                modo_confirmacao = request.get("modo_confirmacao", args.modo_confirmacao_padrao)
                timeout_ack_ms = int(request.get("timeout_ack_ms", DEFAULT_TIMEOUT_ACK_MS))
                max_retransmissoes = int(request.get("max_retransmissoes", DEFAULT_MAX_RETRANSMISSOES))
                timeout_dados = max(2.0, (timeout_ack_ms / 1000.0) * (max_retransmissoes + 2))
                conn.settimeout(timeout_dados)

                tamanho_maximo_sessao = min(
                    int(request["tamanho_maximo_desejado"]),
                    SERVER_BUFFER_SIZE,
                )
                janela_sessao = janela_inicial

                response = {
                    "tipo": "handshake_ack",
                    "status": "ok",
                    "modo_operacao": "servidor",
                    "tamanho_maximo_sessao": tamanho_maximo_sessao,
                    "janela_sessao": janela_sessao,
                    "session_salt": base64.b64encode(session_salt).decode("ascii"),
                    "modo_confirmacao_acordado": modo_confirmacao,
                    "timeout_ack_ms_acordado": timeout_ack_ms,
                    "max_retransmissoes_acordado": max_retransmissoes,
                }
                send_json(file_obj, response)

                print("[SERVIDOR] Handshake enviado:")
                print(f"  - Tamanho maximo da sessao: {tamanho_maximo_sessao}")
                print(f"  - Janela da sessao definida pelo servidor: {janela_sessao}")
                print(f"  - Modo confirmacao acordado: {modo_confirmacao}")
                print("[SERVIDOR] Handshake completo!")

                expected_message_id = 0
                while True:
                    try:
                        receive_payload(
                            file_obj,
                            tamanho_maximo_sessao,
                            janela_sessao,
                            tipo_operacao,
                            modo_confirmacao,
                            expected_message_id,
                            keys,
                        )
                        expected_message_id += 1
                    except socket.timeout:
                        print("[SERVIDOR] Timeout de inatividade no fluxo de dados.")
                        send_server_shutdown(file_obj, addr)
                        break
                    except ConnectionError as exc:
                        print(f"[SERVIDOR] Conexao encerrada: {exc}")
                        break
                    except Exception as exc:
                        print(f"[SERVIDOR] Erro no fluxo de dados: {exc}")
                        break
    except OSError as exc:
        print(f"[SERVIDOR] Conexao com {addr} encerrada com erro de socket: {exc}")


def main() -> None:
    args = parse_args()
    host, port = obter_host_port(args)
    janela_inicial = max(MIN_JANELA, min(MAX_JANELA, args.janela_inicial))
    psk = get_psk(args.allow_insecure_dev_psk)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen()

        print(f"[SERVIDOR] Aguardando conexoes em {host}:{port}...")
        print(f"[SERVIDOR] Janela inicial configurada: {janela_inicial}")
        try:
            while True:
                conn, addr = server_socket.accept()
                thread = threading.Thread(
                    target=handle_client,
                    args=(conn, addr, args, psk, janela_inicial),
                    daemon=True,
                )
                thread.start()
        except KeyboardInterrupt:
            print("\n[SERVIDOR] Encerrado por Ctrl+C.")


if __name__ == "__main__":
    main()
