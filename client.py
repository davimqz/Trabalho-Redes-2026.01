"""TCP client for the Redes de Computadores assignment."""

from __future__ import annotations

import argparse
import base64
import socket
import sys
from typing import Dict, Optional, Set, Tuple

from protocol import (
    DEFAULT_HOST,
    DEFAULT_MAX_RETRANSMISSOES,
    DEFAULT_MODO_CONFIRMACAO,
    DEFAULT_PORT,
    DEFAULT_TIMEOUT_ACK_MS,
    DuplexFile,
    JANELA_PADRAO,
    MAX_JANELA,
    MIN_JANELA,
    MIN_TAMANHO,
    PAYLOAD_CHUNK_SIZE,
    VERSAO_PROTOCOLO_SUPORTADA,
    ServerClosedError,
    SessionKeys,
    build_data_packet,
    corrupt_packet_once,
    derive_session_keys,
    format_seq_list,
    fragment_payload,
    get_psk,
    parse_seq_list,
    recv_json,
    send_json,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Cliente TCP com confiabilidade na camada de aplicacao."
    )
    parser.add_argument("--host", type=str, help="Host/IP do servidor.")
    parser.add_argument("--port", type=int, help="Porta do servidor.")
    parser.add_argument(
        "--modo-confirmacao",
        choices=["go_back_n", "seletivo"],
        default=DEFAULT_MODO_CONFIRMACAO,
        help="Modo de confirmacao usado em operacao por lotes.",
    )
    parser.add_argument(
        "--timeout-ack-ms",
        type=int,
        default=DEFAULT_TIMEOUT_ACK_MS,
        help="Timeout em milissegundos para aguardar ACK/NACK.",
    )
    parser.add_argument(
        "--max-retransmissoes",
        type=int,
        default=DEFAULT_MAX_RETRANSMISSOES,
        help="Numero maximo de retransmissoes antes de falhar.",
    )
    parser.add_argument(
        "--drop-seqs",
        type=str,
        default="",
        help="Lista de seq para simular perda uma vez. Exemplo: 1,4,7.",
    )
    parser.add_argument(
        "--corrupt-seqs",
        type=str,
        default="",
        help="Lista de seq para simular corrupcao uma vez. Exemplo: 2,5.",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=10.0,
        help="Timeout em segundos para conectar ao servidor.",
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
        raw = input(f"[CLIENTE] Host do servidor (Enter para {DEFAULT_HOST}): ").strip()
        host = raw or DEFAULT_HOST
    elif host is None:
        host = DEFAULT_HOST

    if port is None and sys.stdin.isatty():
        while True:
            raw = input(f"[CLIENTE] Porta do servidor (Enter para {DEFAULT_PORT}): ").strip()
            if raw == "":
                port = DEFAULT_PORT
                break
            try:
                port = int(raw)
            except ValueError:
                print("[CLIENTE] Porta invalida. Digite um inteiro.")
                continue
            break
    elif port is None:
        port = DEFAULT_PORT

    if port <= 0 or port > 65535:
        raise ValueError("Porta deve estar entre 1 e 65535.")
    return host, port


def solicitar_tamanho_maximo() -> int:
    while True:
        raw = input(
            f"[CLIENTE] Defina o limite maximo de caracteres por vez "
            f"(tamanho >= {MIN_TAMANHO}): "
        ).strip()
        try:
            tamanho = int(raw)
        except ValueError:
            print("[CLIENTE] Valor invalido. Digite um inteiro.")
            continue
        if tamanho < MIN_TAMANHO:
            print(f"[CLIENTE] Valor invalido. O tamanho deve ser >= {MIN_TAMANHO}.")
            continue
        return tamanho


def solicitar_janela_sugerida() -> int:
    while True:
        raw = input(
            f"[CLIENTE] Sugira um tamanho de janela "
            f"({MIN_JANELA}-{MAX_JANELA}, Enter para {JANELA_PADRAO}): "
        ).strip()
        if raw == "":
            return JANELA_PADRAO
        try:
            janela = int(raw)
        except ValueError:
            print("[CLIENTE] Valor invalido. Digite um inteiro.")
            continue
        if not MIN_JANELA <= janela <= MAX_JANELA:
            print(f"[CLIENTE] Valor invalido. A janela deve estar entre {MIN_JANELA} e {MAX_JANELA}.")
            continue
        return janela


def solicitar_tipo_operacao() -> str:
    while True:
        print("[CLIENTE] Selecione o tipo de operacao:")
        print("  1 - individual")
        print("  2 - lotes")
        raw = input("[CLIENTE] Opcao (1/2): ").strip().lower()
        if raw in ("1", "individual"):
            return "individual"
        if raw in ("2", "lotes", "lote"):
            return "lotes"
        print("[CLIENTE] Opcao invalida. Escolha 1 ou 2.")


def enviar_pacote_controlado(
    file_obj,
    packet: Dict,
    drop_once_seqs: Set[int],
    corrupt_once_seqs: Set[int],
    drop_aplicado: Set[int],
    corrupt_aplicado: Set[int],
) -> None:
    seq = int(packet["seq"])

    if seq in drop_once_seqs and seq not in drop_aplicado:
        drop_aplicado.add(seq)
        print(f"[CLIENTE] Simulacao: perda do pacote seq={seq} nesta tentativa.")
        return

    packet_to_send = dict(packet)
    if seq in corrupt_once_seqs and seq not in corrupt_aplicado:
        corrupt_aplicado.add(seq)
        packet_to_send = corrupt_packet_once(packet_to_send)
        print(f"[CLIENTE] Simulacao: corrupcao do pacote seq={seq} nesta tentativa.")

    send_json(file_obj, packet_to_send)
    msg_id = packet_to_send.get("message_id")
    if "ciphertext" in packet_to_send:
        print(f"[CLIENTE] Pacote enviado message_id={msg_id}, seq={seq}, ciphertext=sim")
    else:
        payload = packet_to_send.get("payload", "")
        print(f"[CLIENTE] Pacote enviado message_id={msg_id}, seq={seq}, payload='{payload}'")


def normalizar_resposta_controle(response: Dict) -> Tuple[str, Optional[int], Optional[int], str, bool]:
    if not isinstance(response, dict):
        raise ValueError("Resposta invalida do servidor.")

    tipo = response.get("tipo")
    if tipo == "encerramento":
        message = response.get("mensagem", "Servidor encerrou a conexao.")
        raise ServerClosedError(str(message))

    message_id = response.get("message_id")
    seq = response.get("seq")
    status = response.get("status")
    cumulativo = bool(response.get("cumulativo", False))

    if tipo == "ack" and status == "ok":
        return "ack", message_id, seq, str(response.get("mensagem", "")), cumulativo
    if tipo == "nack":
        return "nack", message_id, seq, str(response.get("mensagem", "Solicitacao de retransmissao.")), False
    if tipo == "ack" and status != "ok":
        return "nack", message_id, seq, str(response.get("mensagem", "ACK de erro recebido.")), False
    raise ValueError(f"Resposta inesperada do servidor: tipo={tipo}, status={status}")


def receber_controle(file_obj) -> Dict:
    try:
        return recv_json(file_obj, peer_name="servidor")
    except socket.timeout as exc:
        raise TimeoutError("Timeout aguardando ACK/NACK do servidor.") from exc


def reenviar_faixa(
    file_obj,
    packets: Dict[int, Dict],
    start: int,
    end: int,
    drop_once_seqs: Set[int],
    corrupt_once_seqs: Set[int],
    drop_aplicado: Set[int],
    corrupt_aplicado: Set[int],
) -> None:
    for seq in range(start, end + 1):
        enviar_pacote_controlado(
            file_obj,
            packets[seq],
            drop_once_seqs,
            corrupt_once_seqs,
            drop_aplicado,
            corrupt_aplicado,
        )


def enviar_individual(
    file_obj,
    packets: Dict[int, Dict],
    message_id: int,
    drop_once_seqs: Set[int],
    corrupt_once_seqs: Set[int],
    drop_aplicado: Set[int],
    corrupt_aplicado: Set[int],
    max_retransmissoes: int,
) -> None:
    for seq in sorted(packets):
        tentativas = 0
        while True:
            enviar_pacote_controlado(
                file_obj,
                packets[seq],
                drop_once_seqs,
                corrupt_once_seqs,
                drop_aplicado,
                corrupt_aplicado,
            )
            try:
                response = receber_controle(file_obj)
                tipo, resp_msg_id, resp_seq, message, _ = normalizar_resposta_controle(response)
            except TimeoutError:
                tentativas += 1
                if tentativas > max_retransmissoes:
                    raise TimeoutError(
                        f"Timeout no pacote seq={seq} apos {max_retransmissoes} retransmissoes."
                    )
                print(f"[CLIENTE] Timeout no seq={seq}. Retransmitindo ({tentativas}/{max_retransmissoes}).")
                continue

            if resp_msg_id != message_id or resp_seq != seq:
                print(
                    f"[CLIENTE] Controle inesperado ignorado: "
                    f"message_id={resp_msg_id}, seq={resp_seq}."
                )
                continue
            if tipo == "ack":
                print(f"[CLIENTE] ACK recebido message_id={message_id}, seq={seq}")
                break

            tentativas += 1
            if tentativas > max_retransmissoes:
                raise ValueError(f"Servidor rejeitou seq={seq}: {message}")
            print(f"[CLIENTE] NACK recebido seq={seq}: {message}. Retransmitindo.")


def enviar_lotes_go_back_n(
    file_obj,
    packets: Dict[int, Dict],
    janela_sessao: int,
    message_id: int,
    drop_once_seqs: Set[int],
    corrupt_once_seqs: Set[int],
    drop_aplicado: Set[int],
    corrupt_aplicado: Set[int],
    max_retransmissoes: int,
) -> None:
    total = len(packets)
    base = 0

    while base < total:
        fim_janela = min(base + janela_sessao - 1, total - 1)
        reenviar_faixa(
            file_obj,
            packets,
            base,
            fim_janela,
            drop_once_seqs,
            corrupt_once_seqs,
            drop_aplicado,
            corrupt_aplicado,
        )
        tentativas_janela = 0
        last_retransmit_target = None

        while base <= fim_janela:
            try:
                response = receber_controle(file_obj)
                tipo, resp_msg_id, resp_seq, message, _ = normalizar_resposta_controle(response)
            except TimeoutError:
                tentativas_janela += 1
                if tentativas_janela > max_retransmissoes:
                    raise TimeoutError(
                        f"Timeout na janela {base}-{fim_janela} apos {max_retransmissoes} retransmissoes."
                    )
                print(
                    f"[CLIENTE] Timeout na janela {base}-{fim_janela}. "
                    f"Retransmitindo desde {base}."
                )
                reenviar_faixa(
                    file_obj,
                    packets,
                    base,
                    fim_janela,
                    drop_once_seqs,
                    corrupt_once_seqs,
                    drop_aplicado,
                    corrupt_aplicado,
                )
                last_retransmit_target = base
                continue

            if resp_msg_id != message_id or not isinstance(resp_seq, int):
                print("[CLIENTE] Controle de outra mensagem ignorado.")
                continue

            if tipo == "ack":
                if resp_seq >= base:
                    print(
                        f"[CLIENTE] ACK cumulativo recebido message_id={message_id}, "
                        f"seq={resp_seq}."
                    )
                    base = min(resp_seq + 1, total)
                    last_retransmit_target = None
                continue

            tentativas_janela += 1
            if tentativas_janela > max_retransmissoes:
                raise ValueError(f"Janela {base}-{fim_janela} rejeitada: {message}")
            alvo = resp_seq if base <= resp_seq <= fim_janela else base
            if alvo == last_retransmit_target:
                print(
                    f"[CLIENTE] NACK duplicado para seq={resp_seq}: {message}. "
                    "Retransmissao ja enviada; aguardando ACK."
                )
                continue

            print(f"[CLIENTE] NACK recebido seq={resp_seq}: {message}. GBN retransmite {alvo}-{fim_janela}.")
            reenviar_faixa(
                file_obj,
                packets,
                alvo,
                fim_janela,
                drop_once_seqs,
                corrupt_once_seqs,
                drop_aplicado,
                corrupt_aplicado,
            )
            last_retransmit_target = alvo


def enviar_lotes_seletivo(
    file_obj,
    packets: Dict[int, Dict],
    janela_sessao: int,
    message_id: int,
    drop_once_seqs: Set[int],
    corrupt_once_seqs: Set[int],
    drop_aplicado: Set[int],
    corrupt_aplicado: Set[int],
    max_retransmissoes: int,
) -> None:
    total = len(packets)
    base = 0

    while base < total:
        fim_janela = min(base + janela_sessao - 1, total - 1)
        pendentes = set(range(base, fim_janela + 1))
        tentativas = {seq: 0 for seq in pendentes}

        reenviar_faixa(
            file_obj,
            packets,
            base,
            fim_janela,
            drop_once_seqs,
            corrupt_once_seqs,
            drop_aplicado,
            corrupt_aplicado,
        )

        while pendentes:
            try:
                response = receber_controle(file_obj)
                tipo, resp_msg_id, resp_seq, message, _ = normalizar_resposta_controle(response)
            except TimeoutError:
                for seq in sorted(pendentes):
                    tentativas[seq] += 1
                    if tentativas[seq] > max_retransmissoes:
                        raise TimeoutError(
                            f"Timeout no seq={seq} apos {max_retransmissoes} retransmissoes."
                        )
                    print(f"[CLIENTE] Timeout seletivo no seq={seq}. Retransmitindo.")
                    enviar_pacote_controlado(
                        file_obj,
                        packets[seq],
                        drop_once_seqs,
                        corrupt_once_seqs,
                        drop_aplicado,
                        corrupt_aplicado,
                    )
                continue

            if resp_msg_id != message_id or not isinstance(resp_seq, int):
                print("[CLIENTE] Controle de outra mensagem ignorado.")
                continue

            if tipo == "ack":
                if resp_seq in pendentes:
                    pendentes.remove(resp_seq)
                    print(f"[CLIENTE] ACK individual recebido message_id={message_id}, seq={resp_seq}")
                continue

            if resp_seq not in pendentes:
                print(f"[CLIENTE] NACK ignorado para seq={resp_seq}: nao esta pendente.")
                continue

            tentativas[resp_seq] += 1
            if tentativas[resp_seq] > max_retransmissoes:
                raise ValueError(f"Retransmissoes excedidas no seq={resp_seq}: {message}")
            print(f"[CLIENTE] NACK recebido seq={resp_seq}: {message}. SR retransmite somente esse seq.")
            enviar_pacote_controlado(
                file_obj,
                packets[resp_seq],
                drop_once_seqs,
                corrupt_once_seqs,
                drop_aplicado,
                corrupt_aplicado,
            )

        base = fim_janela + 1


def enviar_fim_sessao(file_obj) -> None:
    try:
        send_json(file_obj, {"tipo": "fim_sessao", "mensagem": "Cliente encerrando sessao normalmente."})
        print("[CLIENTE] Mensagem de encerramento enviada ao servidor.")
    except Exception as exc:
        print(f"[CLIENTE] Aviso: nao foi possivel enviar encerramento: {exc}")


def enviar_payload_com_janela(
    client_socket: socket.socket,
    file_obj,
    message: str,
    message_id: int,
    tamanho_maximo_sessao: int,
    janela_sessao: int,
    tipo_operacao: str,
    modo_confirmacao: str,
    timeout_ack_ms: int,
    max_retransmissoes: int,
    drop_once_seqs: Set[int],
    corrupt_once_seqs: Set[int],
    keys: Optional[SessionKeys],
) -> None:
    if not message or not message.strip():
        print("[CLIENTE] Mensagem vazia ignorada.")
        return
    if len(message) > tamanho_maximo_sessao:
        raise ValueError(
            f"Mensagem com {len(message)} caracteres excede o limite negociado de {tamanho_maximo_sessao}."
        )

    fragments = fragment_payload(message, PAYLOAD_CHUNK_SIZE)
    packets: Dict[int, Dict] = {}
    for seq, fragment in enumerate(fragments):
        packets[seq] = build_data_packet(
            message_id=message_id,
            seq=seq,
            fragment=fragment,
            fim=seq == len(fragments) - 1,
            keys=keys,
        )

    drop_aplicado: Set[int] = set()
    corrupt_aplicado: Set[int] = set()
    previous_timeout = client_socket.gettimeout()
    client_socket.settimeout(timeout_ack_ms / 1000.0)
    try:
        if tipo_operacao == "individual":
            enviar_individual(
                file_obj,
                packets,
                message_id,
                drop_once_seqs,
                corrupt_once_seqs,
                drop_aplicado,
                corrupt_aplicado,
                max_retransmissoes,
            )
        elif modo_confirmacao == "seletivo":
            enviar_lotes_seletivo(
                file_obj,
                packets,
                janela_sessao,
                message_id,
                drop_once_seqs,
                corrupt_once_seqs,
                drop_aplicado,
                corrupt_aplicado,
                max_retransmissoes,
            )
        else:
            enviar_lotes_go_back_n(
                file_obj,
                packets,
                janela_sessao,
                message_id,
                drop_once_seqs,
                corrupt_once_seqs,
                drop_aplicado,
                corrupt_aplicado,
                max_retransmissoes,
            )
    finally:
        client_socket.settimeout(previous_timeout)


def validar_handshake_servidor(response: Dict) -> Tuple[int, int, str, int, int]:
    if not isinstance(response, dict) or response.get("tipo") != "handshake_ack":
        raise ValueError("Resposta invalida no handshake: tipo inesperado.")
    status = response.get("status")
    if status == "erro":
        raise ValueError(f"Handshake rejeitado: {response.get('mensagem', 'erro desconhecido')}")
    if status != "ok":
        raise ValueError("Handshake com status desconhecido.")
    if response.get("modo_operacao") != "servidor":
        raise ValueError("Modo de operacao inesperado no servidor.")

    tamanho = response.get("tamanho_maximo_sessao")
    janela = response.get("janela_sessao")
    modo = response.get("modo_confirmacao_acordado", DEFAULT_MODO_CONFIRMACAO)
    timeout_ack = response.get("timeout_ack_ms_acordado", DEFAULT_TIMEOUT_ACK_MS)
    max_retx = response.get("max_retransmissoes_acordado", DEFAULT_MAX_RETRANSMISSOES)

    if isinstance(tamanho, bool) or not isinstance(tamanho, int) or tamanho < MIN_TAMANHO:
        raise ValueError("tamanho_maximo_sessao invalido.")
    if isinstance(janela, bool) or not isinstance(janela, int) or not MIN_JANELA <= janela <= MAX_JANELA:
        raise ValueError("janela_sessao invalida.")
    if modo not in ("go_back_n", "seletivo"):
        raise ValueError("modo_confirmacao_acordado invalido.")
    if isinstance(timeout_ack, bool) or not isinstance(timeout_ack, int) or timeout_ack <= 0:
        raise ValueError("timeout_ack_ms_acordado invalido.")
    if isinstance(max_retx, bool) or not isinstance(max_retx, int) or max_retx < 0:
        raise ValueError("max_retransmissoes_acordado invalido.")
    return tamanho, janela, modo, timeout_ack, max_retx


def main() -> None:
    args = parse_args()
    if args.timeout_ack_ms <= 0:
        raise ValueError("--timeout-ack-ms deve ser > 0.")
    if args.max_retransmissoes < 0:
        raise ValueError("--max-retransmissoes deve ser >= 0.")
    if args.connect_timeout <= 0:
        raise ValueError("--connect-timeout deve ser > 0.")

    drop_once_seqs = parse_seq_list(args.drop_seqs)
    corrupt_once_seqs = parse_seq_list(args.corrupt_seqs)
    host, port = obter_host_port(args)
    psk = get_psk(args.allow_insecure_dev_psk)

    tamanho_maximo = solicitar_tamanho_maximo()
    janela_sugerida = solicitar_janela_sugerida()
    tipo_operacao = solicitar_tipo_operacao()

    request = {
        "tipo": "handshake",
        "versao_protocolo": VERSAO_PROTOCOLO_SUPORTADA,
        "modo_operacao": "cliente",
        "tamanho_maximo_desejado": tamanho_maximo,
        "janela_desejada": janela_sugerida,
        "tipo_operacao": tipo_operacao,
        "modo_confirmacao": args.modo_confirmacao,
        "timeout_ack_ms": args.timeout_ack_ms,
        "max_retransmissoes": args.max_retransmissoes,
        "simulacao_perda_seq": format_seq_list(drop_once_seqs),
        "simulacao_corrupcao_seq": format_seq_list(corrupt_once_seqs),
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.settimeout(args.connect_timeout)
        print(f"[CLIENTE] Conectando ao servidor {host}:{port}...")
        client_socket.connect((host, port))
        print("[CLIENTE] Conectado!")

        with client_socket.makefile("rb") as reader, client_socket.makefile("wb") as writer:
            file_obj = DuplexFile(reader, writer)
            send_json(file_obj, request)

            print("[CLIENTE] Handshake enviado:")
            print(f"  - Tamanho maximo desejado: {tamanho_maximo}")
            print(f"  - Janela sugerida: {janela_sugerida}")
            print(f"  - Tipo de operacao: {tipo_operacao}")
            print(f"  - Modo de confirmacao: {args.modo_confirmacao}")

            response = recv_json(file_obj, peer_name="servidor")
            tamanho_sessao, janela_sessao, modo_confirmacao, timeout_ack_ms, max_retx = validar_handshake_servidor(
                response
            )
            salt_b64 = response.get("session_salt")
            if not isinstance(salt_b64, str):
                raise ValueError("session_salt ausente ou invalido.")
            keys = derive_session_keys(psk, base64.b64decode(salt_b64, validate=True))

            print("[CLIENTE] Handshake recebido do servidor:")
            print(f"  - Tamanho maximo da sessao: {tamanho_sessao}")
            print(f"  - Janela da sessao: {janela_sessao}")
            print(f"  - Modo de confirmacao acordado: {modo_confirmacao}")
            print(f"  - Timeout ACK acordado: {timeout_ack_ms} ms")
            print(f"  - Max retransmissoes acordado: {max_retx}")
            print("[CLIENTE] Handshake completo!")

            message_id = 0
            try:
                while True:
                    message = input("[CLIENTE] Digite a mensagem para envio (ou 'sair' para encerrar): ")
                    if message.strip().lower() == "sair":
                        enviar_fim_sessao(file_obj)
                        print("[CLIENTE] Encerrando cliente por solicitacao do usuario.")
                        break
                    if not message.strip():
                        print("[CLIENTE] Mensagem vazia ignorada. Digite ao menos um caractere.")
                        continue

                    try:
                        enviar_payload_com_janela(
                            client_socket,
                            file_obj,
                            message,
                            message_id,
                            tamanho_sessao,
                            janela_sessao,
                            tipo_operacao,
                            modo_confirmacao,
                            timeout_ack_ms,
                            max_retx,
                            drop_once_seqs,
                            corrupt_once_seqs,
                            keys,
                        )
                    except ServerClosedError as exc:
                        print(f"[CLIENTE] Conexao encerrada pelo servidor: {exc}")
                        break
                    except TimeoutError as exc:
                        print(f"[CLIENTE] Falha de timeout/retransmissao: {exc}")
                        continue
                    except ValueError as exc:
                        print(f"[CLIENTE] Mensagem rejeitada: {exc}")
                        continue
                    except OSError as exc:
                        print(f"[CLIENTE] Erro de rede durante envio: {exc}")
                        break
                    else:
                        print(f"[CLIENTE] Envio concluido para message_id={message_id}.")
                        message_id += 1
            except KeyboardInterrupt:
                print("\n[CLIENTE] Interrupcao pelo usuario.")
                enviar_fim_sessao(file_obj)


if __name__ == "__main__":
    main()
