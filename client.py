#!/usr/bin/env python3
"""
Cliente TCP com transporte confiavel na camada de aplicacao.

Implementa:
- conexao por localhost ou IP;
- protocolo JSON por linha;
- handshake de sessao;
- limite maximo de caracteres definido no inicio;
- fragmentacao em pacotes com payload maximo de 4 caracteres;
- checksum CRC32 em todos os pacotes;
- temporizador e retransmissao;
- numeros de sequencia;
- ACK positivo;
- NACK negativo;
- janela de 1 a 5 determinada pelo servidor;
- envio individual como Stop-and-Wait;
- envio em lotes por Go-Back-N ou repeticao seletiva;
- simulacao deterministica de perda;
- simulacao deterministica de corrupcao de HMAC/payload;
- simulacao deterministica de corrupcao de checksum;
- criptografia simetrica opcional com AES-GCM.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import sys
import warnings
import zlib
from typing import Dict, Optional, Set, Tuple

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
MIN_TAMANHO = 30
MIN_JANELA = 1
MAX_JANELA = 5
JANELA_PADRAO = 5
PAYLOAD_CHUNK_SIZE = 4
DEFAULT_MODO_CONFIRMACAO = "go_back_n"
DEFAULT_TIMEOUT_ACK_MS = 5000
DEFAULT_MAX_RETRANSMISSOES = 3
VERSAO_PROTOCOLO = 2
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

    O uso direto de recv() permite continuar lendo normalmente apos
    socket.timeout, o que e essencial para temporizador e retransmissao.
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
        raise ConnectionError("Conexao encerrada pelo servidor.")
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


def parse_seq_list(raw: str) -> Set[int]:
    if not raw:
        return set()

    resultado: Set[int] = set()
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            seq = int(item)
        except ValueError as exc:
            raise ValueError(f"Sequencia invalida em lista: '{item}'. Use inteiros separados por virgula.") from exc
        if seq < 0:
            raise ValueError("Sequencias para simulacao devem ser >= 0.")
        resultado.add(seq)
    return resultado


def corromper_string_deterministica(valor: str) -> str:
    """Altera obrigatoriamente o primeiro caractere de uma string."""
    if not valor:
        return "0"
    novo_primeiro = "0" if valor[0] != "0" else "1"
    return novo_primeiro + valor[1:]


def solicitar_tamanho_maximo() -> int:
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


def solicitar_janela_sugerida() -> int:
    while True:
        entrada = input(
            f"[CLIENTE] Sugira um tamanho de janela ({MIN_JANELA}-{MAX_JANELA}, Enter para {JANELA_PADRAO}): "
        ).strip()

        if entrada == "":
            return JANELA_PADRAO

        try:
            janela = int(entrada)
        except ValueError:
            print("[CLIENTE] Valor invalido. Digite um numero inteiro.")
            continue

        if janela < MIN_JANELA or janela > MAX_JANELA:
            print(f"[CLIENTE] Valor invalido. A janela deve estar entre {MIN_JANELA} e {MAX_JANELA}.")
            continue

        return janela


def solicitar_tipo_operacao() -> str:
    while True:
        print("[CLIENTE] Selecione o tipo de operacao:")
        print("  1 - individual (Stop-and-Wait)")
        print("  2 - lotes (janela)")
        entrada = input("[CLIENTE] Opcao (1/2): ").strip().lower()

        if entrada in ("1", "individual", "stop-and-wait", "stop_and_wait"):
            return "individual"
        if entrada in ("2", "lotes", "lote", "janela"):
            return "lotes"

        print("[CLIENTE] Opcao invalida. Escolha 1 (individual) ou 2 (lotes).")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Cliente TCP com confiabilidade na camada de aplicacao."
    )
    parser.add_argument("--host", type=str, help="Host/IP do servidor.")
    parser.add_argument("--port", type=int, help="Porta do servidor.")
    parser.add_argument(
        "--modo-confirmacao",
        type=str,
        choices=["go_back_n", "seletivo"],
        default=DEFAULT_MODO_CONFIRMACAO,
        help="Modo de confirmacao da janela quando a operacao for em lotes.",
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
        help="Numero maximo de retransmissoes por pacote/janela antes de falhar.",
    )
    parser.add_argument(
        "--drop-seqs",
        type=str,
        default="",
        help="Lista de seq para simular perda uma vez (ex.: 1,4,7).",
    )
    parser.add_argument(
        "--corrupt-seqs",
        type=str,
        default="",
        help="Lista de seq para corromper HMAC em sessao criptografada ou payload em claro (ex.: 2,5).",
    )
    parser.add_argument(
        "--corrupt-checksum-seqs",
        type=str,
        default="",
        help="Lista de seq para corromper checksum uma vez (ex.: 2,5).",
    )
    parser.add_argument(
        "--sem-criptografia",
        action="store_true",
        help="Desativa AES-GCM/HMAC para demonstrar payload e checksum em claro.",
    )
    return parser.parse_args()


def obter_host_port(args: argparse.Namespace) -> Tuple[str, int]:
    host = args.host
    port = args.port

    if host is None and sys.stdin.isatty():
        entrada_host = input(f"[CLIENTE] Host do servidor (Enter para {DEFAULT_HOST}): ").strip()
        host = entrada_host or DEFAULT_HOST
    elif host is None:
        host = DEFAULT_HOST

    if port is None and sys.stdin.isatty():
        while True:
            entrada_port = input(f"[CLIENTE] Porta do servidor (Enter para {DEFAULT_PORT}): ").strip()
            if entrada_port == "":
                port = DEFAULT_PORT
                break
            try:
                port = int(entrada_port)
            except ValueError:
                print("[CLIENTE] Porta invalida. Digite um inteiro.")
                continue
            break
    elif port is None:
        port = DEFAULT_PORT

    if port <= 0 or port > 65535:
        raise ValueError("Porta deve estar entre 1 e 65535.")

    return host, port


def fragmentar_payload(texto: str, tamanho_fragmento: int) -> list[str]:
    return [texto[i : i + tamanho_fragmento] for i in range(0, len(texto), tamanho_fragmento)]


def construir_pacote(seq_atual: int, fragmento: str, fim: bool, aesgcm: Optional[object] = None, hmac_key: Optional[bytes] = None) -> dict:
    pacote = {
        "tipo": "dados",
        "seq": seq_atual,
        "fim": fim,
        "checksum": calcular_checksum(fragmento),
    }

    if aesgcm is not None and hmac_key is not None:
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, fragmento.encode("utf-8"), None)  # type: ignore[attr-defined]
        pacote["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
        pacote["nonce"] = base64.b64encode(nonce).decode("ascii")
        pacote["hmac"] = hmac.new(
            hmac_key,
            montar_hmac_data(seq_atual, fim, nonce, ciphertext),
            hashlib.sha256,
        ).hexdigest()
    else:
        pacote["payload"] = fragmento

    return pacote


def enviar_pacote_controlado(
    arquivo_socket: JsonLineSocket,
    pacote: dict,
    drop_once_seqs: Set[int],
    corrupt_once_seqs: Set[int],
    corrupt_checksum_once_seqs: Set[int],
    drop_aplicado: Set[int],
    corrupt_aplicado: Set[int],
    corrupt_checksum_aplicado: Set[int],
) -> None:
    seq = pacote["seq"]

    if seq in drop_once_seqs and seq not in drop_aplicado:
        drop_aplicado.add(seq)
        print(f"[CLIENTE] Simulacao: perda do pacote seq={seq} (nao enviado nesta tentativa).")
        return

    pacote_envio = dict(pacote)

    if seq in corrupt_once_seqs and seq not in corrupt_aplicado:
        corrupt_aplicado.add(seq)
        if "hmac" in pacote_envio:
            pacote_envio["hmac"] = corromper_string_deterministica(str(pacote_envio["hmac"]))
            print(f"[CLIENTE] Simulacao: corrupcao de HMAC seq={seq} (apenas na primeira tentativa).")
        elif "payload" in pacote_envio:
            pacote_envio["payload"] = corromper_string_deterministica(str(pacote_envio["payload"]))
            print(f"[CLIENTE] Simulacao: corrupcao de payload seq={seq} (apenas na primeira tentativa).")
        else:
            print(f"[CLIENTE] Aviso: seq={seq} nao possui campo corrompivel por --corrupt-seqs.")

    if seq in corrupt_checksum_once_seqs and seq not in corrupt_checksum_aplicado:
        corrupt_checksum_aplicado.add(seq)
        pacote_envio["checksum"] = corromper_string_deterministica(str(pacote_envio.get("checksum", "")))
        print(f"[CLIENTE] Simulacao: corrupcao de checksum seq={seq} (apenas na primeira tentativa).")

    enviar_json(arquivo_socket, pacote_envio)

    if "ciphertext" in pacote_envio:
        ciphertext_len = len(base64.b64decode(str(pacote_envio["ciphertext"])))
        print(
            f"[CLIENTE] DADOS enviado seq={seq} fim={pacote_envio.get('fim')} "
            f"ciphertext_len={ciphertext_len} checksum={pacote_envio.get('checksum')} "
            f"hmac={str(pacote_envio.get('hmac', ''))[:8]}..."
        )
    else:
        print(
            f"[CLIENTE] DADOS enviado seq={seq} fim={pacote_envio.get('fim')} "
            f"payload='{pacote_envio.get('payload', '')}' checksum={pacote_envio.get('checksum')}"
        )


class ServidorEncerradoError(Exception):
    pass


def normalizar_resposta_controle(resp: dict) -> Tuple[str, Optional[int], str, bool]:
    if not isinstance(resp, dict):
        raise ValueError("Resposta invalida do servidor: nao e objeto JSON.")

    tipo = resp.get("tipo")
    seq = resp.get("seq")
    status = resp.get("status")
    cumulativo = bool(resp.get("cumulativo", False))

    if tipo == "encerramento":
        motivo = str(resp.get("mensagem", "Servidor encerrou a conexao."))
        print(f"[CLIENTE] Servidor encerrou a conexao: {motivo}")
        raise ServidorEncerradoError(motivo)

    if tipo == "ack" and status == "ok":
        return "ack", seq if isinstance(seq, int) else None, str(resp.get("mensagem", "")), cumulativo

    if tipo == "nack":
        return "nack", seq if isinstance(seq, int) else None, str(resp.get("mensagem", "Solicitacao de retransmissao.")), False

    if tipo == "ack" and status != "ok":
        return "nack", seq if isinstance(seq, int) else None, str(resp.get("mensagem", "ACK de erro recebido.")), False

    raise ValueError(f"Resposta inesperada do servidor: tipo={tipo}, status={status}")


def receber_controle_com_timeout(arquivo_socket: JsonLineSocket) -> dict:
    try:
        return receber_json(arquivo_socket)
    except socket.timeout as exc:
        raise TimeoutError("Timeout aguardando ACK/NACK do servidor.") from exc


def reenviar_faixa(
    arquivo_socket: JsonLineSocket,
    pacotes: Dict[int, dict],
    inicio: int,
    fim: int,
    drop_once_seqs: Set[int],
    corrupt_once_seqs: Set[int],
    corrupt_checksum_once_seqs: Set[int],
    drop_aplicado: Set[int],
    corrupt_aplicado: Set[int],
    corrupt_checksum_aplicado: Set[int],
) -> None:
    for seq in range(inicio, fim + 1):
        enviar_pacote_controlado(
            arquivo_socket,
            pacotes[seq],
            drop_once_seqs,
            corrupt_once_seqs,
            corrupt_checksum_once_seqs,
            drop_aplicado,
            corrupt_aplicado,
            corrupt_checksum_aplicado,
        )


def enviar_individual(
    arquivo_socket: JsonLineSocket,
    pacotes: Dict[int, dict],
    drop_once_seqs: Set[int],
    corrupt_once_seqs: Set[int],
    corrupt_checksum_once_seqs: Set[int],
    drop_aplicado: Set[int],
    corrupt_aplicado: Set[int],
    corrupt_checksum_aplicado: Set[int],
    max_retransmissoes: int,
) -> None:
    """Stop-and-Wait: envia um pacote e aguarda ACK/NACK."""

    for seq in sorted(pacotes.keys()):
        tentativas = 0
        while True:
            enviar_pacote_controlado(
                arquivo_socket,
                pacotes[seq],
                drop_once_seqs,
                corrupt_once_seqs,
                corrupt_checksum_once_seqs,
                drop_aplicado,
                corrupt_aplicado,
                corrupt_checksum_aplicado,
            )

            try:
                resp = receber_controle_com_timeout(arquivo_socket)
                tipo_resp, seq_resp, msg, cumulativo = normalizar_resposta_controle(resp)
            except TimeoutError:
                tentativas += 1
                if tentativas > max_retransmissoes:
                    raise TimeoutError(f"Timeout no pacote seq={seq} apos {max_retransmissoes} retransmissoes.")
                print(f"[CLIENTE] Timeout no seq={seq}. Retransmitindo ({tentativas}/{max_retransmissoes})...")
                continue

            print(
                f"[CLIENTE] CONTROLE tipo={tipo_resp} seq={seq_resp} "
                f"cumulativo={cumulativo} mensagem='{msg}'"
            )

            if seq_resp != seq:
                print(f"[CLIENTE] Controle para seq inesperado: recebido {seq_resp}, esperado {seq}. Ignorando.")
                continue

            if tipo_resp == "ack":
                print(f"[CLIENTE] ACK recebido seq={seq}")
                break

            tentativas += 1
            if tentativas > max_retransmissoes:
                raise ValueError(f"Servidor rejeitou seq={seq} e limite de retransmissoes foi excedido: {msg}")
            print(f"[CLIENTE] NACK recebido seq={seq}: {msg}. Retransmitindo ({tentativas}/{max_retransmissoes})...")


def enviar_lotes_go_back_n(
    arquivo_socket: JsonLineSocket,
    pacotes: Dict[int, dict],
    janela_sessao: int,
    drop_once_seqs: Set[int],
    corrupt_once_seqs: Set[int],
    corrupt_checksum_once_seqs: Set[int],
    drop_aplicado: Set[int],
    corrupt_aplicado: Set[int],
    corrupt_checksum_aplicado: Set[int],
    max_retransmissoes: int,
) -> None:
    """Go-Back-N com ACK cumulativo.

    ACK(N) confirma todos os pacotes ate N. NACK(K) dentro da janela atual
    retransmite K..fim_janela. ACK/NACK antigos sao ignorados.

    Observacao importante: quando o primeiro pacote faltante de uma janela
    sofre perda/corrupcao, o servidor Go-Back-N descarta todos os pacotes
    posteriores e pode emitir varios NACKs iguais enquanto esses pacotes
    fora de ordem chegam. Esses NACKs duplicados nao representam novas
    falhas depois da retransmissao; portanto, o cliente retransmite uma vez
    por NACK distinto enquanto a base nao avanca e ignora duplicatas ate
    receber um ACK cumulativo ou ocorrer timeout. Isso evita abortar uma
    janela valida apenas por controles antigos que ja estavam no socket.
    """

    total = len(pacotes)
    base = 0

    while base < total:
        fim_janela = min(base + janela_sessao - 1, total - 1)
        print(f"[CLIENTE] GBN: enviando janela {base}-{fim_janela}.")
        reenviar_faixa(
            arquivo_socket,
            pacotes,
            base,
            fim_janela,
            drop_once_seqs,
            corrupt_once_seqs,
            corrupt_checksum_once_seqs,
            drop_aplicado,
            corrupt_aplicado,
            corrupt_checksum_aplicado,
        )

        tentativas_janela = 0
        ultimo_nack_retransmitido: Optional[int] = None

        while base <= fim_janela:
            try:
                resp = receber_controle_com_timeout(arquivo_socket)
                tipo_resp, seq_resp, msg, cumulativo = normalizar_resposta_controle(resp)
            except TimeoutError:
                tentativas_janela += 1
                if tentativas_janela > max_retransmissoes:
                    raise TimeoutError(
                        f"Timeout na janela {base}-{fim_janela} apos {max_retransmissoes} retransmissoes."
                    )
                print(
                    f"[CLIENTE] Timeout na janela {base}-{fim_janela}. "
                    f"Retransmitindo {base}..{fim_janela} ({tentativas_janela}/{max_retransmissoes})..."
                )
                reenviar_faixa(
                    arquivo_socket,
                    pacotes,
                    base,
                    fim_janela,
                    drop_once_seqs,
                    corrupt_once_seqs,
                    corrupt_checksum_once_seqs,
                    drop_aplicado,
                    corrupt_aplicado,
                    corrupt_checksum_aplicado,
                )
                ultimo_nack_retransmitido = None
                continue

            print(
                f"[CLIENTE] CONTROLE tipo={tipo_resp} seq={seq_resp} "
                f"cumulativo={cumulativo} mensagem='{msg}'"
            )

            if seq_resp is None:
                print("[CLIENTE] Controle sem seq inteiro ignorado.")
                continue

            if tipo_resp == "ack":
                if seq_resp < base:
                    print(f"[CLIENTE] ACK antigo ignorado seq={seq_resp}; base atual={base}.")
                    continue
                if seq_resp > fim_janela:
                    print(f"[CLIENTE] ACK fora da janela ignorado seq={seq_resp}; janela={base}-{fim_janela}.")
                    continue

                pacotes_confirmados = seq_resp - base + 1
                print(
                    f"[CLIENTE] ACK cumulativo recebido seq={seq_resp} "
                    f"(confirma {pacotes_confirmados} pacote(s): {base}..{seq_resp})"
                )
                base = seq_resp + 1
                ultimo_nack_retransmitido = None
                continue

            if seq_resp < base:
                print(f"[CLIENTE] NACK antigo ignorado seq={seq_resp}; base atual={base}.")
                continue
            if seq_resp > fim_janela:
                print(f"[CLIENTE] NACK fora da janela ignorado seq={seq_resp}; janela={base}-{fim_janela}.")
                continue

            if seq_resp == ultimo_nack_retransmitido:
                print(
                    f"[CLIENTE] NACK duplicado seq={seq_resp} ignorado; "
                    "a faixa correspondente ja foi retransmitida e a base ainda nao avancou."
                )
                continue

            tentativas_janela += 1
            if tentativas_janela > max_retransmissoes:
                raise ValueError(
                    f"Janela {base}-{fim_janela} rejeitada apos {max_retransmissoes} retransmissoes: {msg}"
                )

            alvo = seq_resp
            print(
                f"[CLIENTE] NACK recebido seq={seq_resp}: {msg}. "
                f"GBN: retransmitindo {alvo}..{fim_janela} ({tentativas_janela}/{max_retransmissoes})..."
            )
            reenviar_faixa(
                arquivo_socket,
                pacotes,
                alvo,
                fim_janela,
                drop_once_seqs,
                corrupt_once_seqs,
                corrupt_checksum_once_seqs,
                drop_aplicado,
                corrupt_aplicado,
                corrupt_checksum_aplicado,
            )
            ultimo_nack_retransmitido = alvo


def enviar_lotes_seletivo(
    arquivo_socket: JsonLineSocket,
    pacotes: Dict[int, dict],
    janela_sessao: int,
    drop_once_seqs: Set[int],
    corrupt_once_seqs: Set[int],
    corrupt_checksum_once_seqs: Set[int],
    drop_aplicado: Set[int],
    corrupt_aplicado: Set[int],
    corrupt_checksum_aplicado: Set[int],
    max_retransmissoes: int,
) -> None:
    """Repeticao seletiva com ACK individual."""

    total = len(pacotes)
    base = 0

    while base < total:
        fim_janela = min(base + janela_sessao - 1, total - 1)
        pendentes = set(range(base, fim_janela + 1))
        tentativas_por_seq = {seq: 0 for seq in pendentes}

        print(f"[CLIENTE] SR: enviando janela {base}-{fim_janela}.")
        reenviar_faixa(
            arquivo_socket,
            pacotes,
            base,
            fim_janela,
            drop_once_seqs,
            corrupt_once_seqs,
            corrupt_checksum_once_seqs,
            drop_aplicado,
            corrupt_aplicado,
            corrupt_checksum_aplicado,
        )

        while pendentes:
            try:
                resp = receber_controle_com_timeout(arquivo_socket)
                tipo_resp, seq_resp, msg, cumulativo = normalizar_resposta_controle(resp)
            except TimeoutError:
                for seq in sorted(pendentes):
                    tentativas_por_seq[seq] += 1
                    if tentativas_por_seq[seq] > max_retransmissoes:
                        raise TimeoutError(
                            f"Timeout persistente no seq={seq} apos {max_retransmissoes} retransmissoes (seletivo)."
                        )
                    print(
                        f"[CLIENTE] Timeout seletivo no seq={seq}. "
                        f"Retransmitindo apenas este pacote ({tentativas_por_seq[seq]}/{max_retransmissoes})..."
                    )
                    enviar_pacote_controlado(
                        arquivo_socket,
                        pacotes[seq],
                        drop_once_seqs,
                        corrupt_once_seqs,
                        corrupt_checksum_once_seqs,
                        drop_aplicado,
                        corrupt_aplicado,
                        corrupt_checksum_aplicado,
                    )
                continue

            print(
                f"[CLIENTE] CONTROLE tipo={tipo_resp} seq={seq_resp} "
                f"cumulativo={cumulativo} mensagem='{msg}'"
            )

            if seq_resp is None:
                print("[CLIENTE] Controle sem seq inteiro ignorado.")
                continue

            if tipo_resp == "ack":
                if seq_resp in pendentes:
                    pendentes.remove(seq_resp)
                    print(f"[CLIENTE] ACK individual recebido seq={seq_resp}")
                else:
                    print(f"[CLIENTE] ACK ignorado seq={seq_resp} (nao esta pendente).")
                continue

            if seq_resp not in pendentes:
                print(f"[CLIENTE] NACK ignorado seq={seq_resp} (nao esta pendente).")
                continue

            tentativas_por_seq[seq_resp] += 1
            if tentativas_por_seq[seq_resp] > max_retransmissoes:
                raise ValueError(f"Retransmissoes excedidas no seq={seq_resp} (seletivo): {msg}")

            print(
                f"[CLIENTE] NACK recebido seq={seq_resp}: {msg}. "
                f"SR: retransmitindo apenas seq={seq_resp} ({tentativas_por_seq[seq_resp]}/{max_retransmissoes})..."
            )
            enviar_pacote_controlado(
                arquivo_socket,
                pacotes[seq_resp],
                drop_once_seqs,
                corrupt_once_seqs,
                corrupt_checksum_once_seqs,
                drop_aplicado,
                corrupt_aplicado,
                corrupt_checksum_aplicado,
            )

        base = fim_janela + 1


def enviar_mensagem_encerramento(arquivo_socket: JsonLineSocket) -> None:
    try:
        enviar_json(
            arquivo_socket,
            {"tipo": "fim_sessao", "mensagem": "Cliente encerrando sessao normalmente."},
        )
        print("[CLIENTE] Mensagem de encerramento de sessao enviada ao servidor.")
    except Exception as erro:
        print(f"[CLIENTE] Aviso: nao foi possivel enviar mensagem de encerramento: {erro}")


def enviar_payload_com_janela(
    client_socket: socket.socket,
    arquivo_socket: JsonLineSocket,
    mensagem: str,
    tamanho_maximo_sessao: int,
    janela_sessao: int,
    tipo_operacao: str,
    modo_confirmacao: str,
    timeout_ack_ms: int,
    max_retransmissoes: int,
    drop_once_seqs: Set[int],
    corrupt_once_seqs: Set[int],
    corrupt_checksum_once_seqs: Set[int],
    aesgcm: Optional[object] = None,
    hmac_key: Optional[bytes] = None,
) -> None:
    if not mensagem or not mensagem.strip():
        print("[CLIENTE] Mensagem vazia ou apenas espacos ignorada.")
        return

    if len(mensagem) > tamanho_maximo_sessao:
        raise ValueError(
            f"Mensagem com {len(mensagem)} caracteres excede o limite negociado de {tamanho_maximo_sessao}."
        )

    fragmentos = fragmentar_payload(mensagem, PAYLOAD_CHUNK_SIZE)
    if not fragmentos:
        print("[CLIENTE] Nenhum fragmento gerado.")
        return

    pacotes: Dict[int, dict] = {}
    for seq, fragmento in enumerate(fragmentos):
        pacotes[seq] = construir_pacote(
            seq,
            fragmento,
            seq == len(fragmentos) - 1,
            aesgcm=aesgcm,
            hmac_key=hmac_key,
        )

    drop_aplicado: Set[int] = set()
    corrupt_aplicado: Set[int] = set()
    corrupt_checksum_aplicado: Set[int] = set()

    old_timeout = client_socket.gettimeout()
    client_socket.settimeout(timeout_ack_ms / 1000.0)
    try:
        if tipo_operacao == "individual":
            enviar_individual(
                arquivo_socket,
                pacotes,
                drop_once_seqs,
                corrupt_once_seqs,
                corrupt_checksum_once_seqs,
                drop_aplicado,
                corrupt_aplicado,
                corrupt_checksum_aplicado,
                max_retransmissoes,
            )
            return

        if modo_confirmacao == "seletivo":
            enviar_lotes_seletivo(
                arquivo_socket,
                pacotes,
                janela_sessao,
                drop_once_seqs,
                corrupt_once_seqs,
                corrupt_checksum_once_seqs,
                drop_aplicado,
                corrupt_aplicado,
                corrupt_checksum_aplicado,
                max_retransmissoes,
            )
            return

        enviar_lotes_go_back_n(
            arquivo_socket,
            pacotes,
            janela_sessao,
            drop_once_seqs,
            corrupt_once_seqs,
            corrupt_checksum_once_seqs,
            drop_aplicado,
            corrupt_aplicado,
            corrupt_checksum_aplicado,
            max_retransmissoes,
        )
    finally:
        client_socket.settimeout(old_timeout)


def main() -> None:
    args = parse_args()

    if args.timeout_ack_ms <= 0:
        raise ValueError("--timeout-ack-ms deve ser > 0.")
    if args.max_retransmissoes < 0:
        raise ValueError("--max-retransmissoes deve ser >= 0.")
    if not args.sem_criptografia and not CRYPTO_AVAILABLE:
        raise RuntimeError(
            "A biblioteca cryptography nao esta instalada. Instale com 'pip install cryptography' "
            "ou execute com --sem-criptografia."
        )

    drop_once_seqs = parse_seq_list(args.drop_seqs)
    corrupt_once_seqs = parse_seq_list(args.corrupt_seqs)
    corrupt_checksum_once_seqs = parse_seq_list(args.corrupt_checksum_seqs)

    host, port = obter_host_port(args)
    tamanho_maximo = solicitar_tamanho_maximo()
    janela_sugerida = solicitar_janela_sugerida()
    tipo_operacao = solicitar_tipo_operacao()

    handshake_requisicao = {
        "tipo": "handshake",
        "versao_protocolo": VERSAO_PROTOCOLO,
        "modo_operacao": "cliente",
        "tamanho_maximo_desejado": tamanho_maximo,
        "janela_desejada": janela_sugerida,
        "tipo_operacao": tipo_operacao,
        "modo_confirmacao": args.modo_confirmacao,
        "timeout_ack_ms": args.timeout_ack_ms,
        "max_retransmissoes": args.max_retransmissoes,
        "criptografia_desejada": not args.sem_criptografia,
        "simulacao_perda_seq": sorted(drop_once_seqs),
        "simulacao_corrupcao_seq": sorted(corrupt_once_seqs),
        "simulacao_corrupcao_checksum_seq": sorted(corrupt_checksum_once_seqs),
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        print(f"[CLIENTE] Conectando ao servidor {host}:{port}...")
        client_socket.connect((host, port))
        print("[CLIENTE] Conectado!")

        arquivo_socket = JsonLineSocket(client_socket, "servidor")
        enviar_json(arquivo_socket, handshake_requisicao)

        print("[CLIENTE] Handshake enviado:")
        print(f"  - Modo de operacao: {handshake_requisicao['modo_operacao']}")
        print(f"  - Tamanho maximo desejado: {handshake_requisicao['tamanho_maximo_desejado']} caracteres")
        print(f"  - Janela sugerida ao servidor: {handshake_requisicao['janela_desejada']}")
        print(f"  - Tipo de operacao: {handshake_requisicao['tipo_operacao']}")
        print(f"  - Modo de confirmacao: {handshake_requisicao['modo_confirmacao']}")
        print(f"  - Criptografia desejada: {handshake_requisicao['criptografia_desejada']}")
        print(f"  - Simulacao perda seq: {handshake_requisicao['simulacao_perda_seq']}")
        print(f"  - Simulacao corrupcao seq: {handshake_requisicao['simulacao_corrupcao_seq']}")
        print(f"  - Simulacao checksum seq: {handshake_requisicao['simulacao_corrupcao_checksum_seq']}")

        handshake_resposta = receber_json(arquivo_socket)
        if handshake_resposta.get("tipo") != "handshake_ack":
            print("[CLIENTE] Resposta invalida no handshake. Encerrando.")
            return

        status = handshake_resposta.get("status")
        if status == "erro":
            print(f"[CLIENTE] Handshake rejeitado: {handshake_resposta.get('mensagem', 'erro desconhecido')}")
            return
        if status != "ok":
            print("[CLIENTE] Handshake com status desconhecido. Encerrando.")
            return

        modo_operacao_srv = handshake_resposta.get("modo_operacao")
        tamanho_maximo_sessao = handshake_resposta.get("tamanho_maximo_sessao")
        janela_sessao = handshake_resposta.get("janela_sessao")

        if modo_operacao_srv != "servidor":
            print("[CLIENTE] Modo de operacao inesperado no servidor. Encerrando.")
            return
        if not isinstance(tamanho_maximo_sessao, int) or not isinstance(janela_sessao, int):
            print("[CLIENTE] Campos do handshake invalidos (tamanho/janela). Encerrando.")
            return

        aesgcm_obj: Optional[object] = None
        hmac_key: Optional[bytes] = None
        criptografia_ativa = bool(handshake_resposta.get("criptografia_ativa", False))
        if criptografia_ativa:
            session_salt_b64 = handshake_resposta.get("session_salt")
            if not isinstance(session_salt_b64, str):
                print("[CLIENTE] Criptografia ativa, mas session_salt ausente. Encerrando.")
                return
            try:
                session_salt = base64.b64decode(session_salt_b64, validate=True)
                aesgcm_obj, hmac_key = derive_session_keys(session_salt)
            except Exception as erro:
                print(f"[CLIENTE] Falha ao processar session_salt do servidor: {erro}. Encerrando.")
                return

        modo_confirmacao = handshake_resposta.get("modo_confirmacao_acordado", args.modo_confirmacao)
        timeout_ack_ms = handshake_resposta.get("timeout_ack_ms_acordado", args.timeout_ack_ms)
        max_retransmissoes = handshake_resposta.get("max_retransmissoes_acordado", args.max_retransmissoes)

        if not isinstance(timeout_ack_ms, int) or not isinstance(max_retransmissoes, int):
            print("[CLIENTE] Parametros de timeout/retransmissao invalidos no handshake. Encerrando.")
            return

        print("[CLIENTE] Handshake recebido do servidor:")
        print(f"  - Modo de operacao: {handshake_resposta['modo_operacao']}")
        print(f"  - Tamanho maximo da sessao: {tamanho_maximo_sessao} caracteres")
        print(f"  - Janela da sessao definida pelo servidor: {janela_sessao}")
        print(f"  - Modo de confirmacao acordado: {modo_confirmacao}")
        print(f"  - Timeout ACK acordado: {timeout_ack_ms} ms")
        print(f"  - Max retransmissoes acordado: {max_retransmissoes}")
        print(f"  - Criptografia ativa: {criptografia_ativa}")
        print("[CLIENTE] Handshake completo!")

        try:
            while True:
                mensagem = input("[CLIENTE] Digite a mensagem para envio (ou 'sair' para encerrar): ")

                if mensagem.strip().lower() == "sair":
                    enviar_mensagem_encerramento(arquivo_socket)
                    print("[CLIENTE] Encerrando cliente por solicitacao do usuario.")
                    break

                if not mensagem.strip():
                    print("[CLIENTE] Mensagem vazia ignorada. Digite ao menos um caractere.")
                    continue

                try:
                    enviar_payload_com_janela(
                        client_socket,
                        arquivo_socket,
                        mensagem,
                        tamanho_maximo_sessao,
                        janela_sessao,
                        tipo_operacao,
                        str(modo_confirmacao),
                        timeout_ack_ms,
                        max_retransmissoes,
                        drop_once_seqs,
                        corrupt_once_seqs,
                        corrupt_checksum_once_seqs,
                        aesgcm=aesgcm_obj,
                        hmac_key=hmac_key,
                    )
                except ValueError as erro:
                    print(f"[CLIENTE] {erro}")
                    continue
                except ServidorEncerradoError:
                    print("[CLIENTE] Conexao encerrada pelo servidor durante o envio. Saindo.")
                    break
                print("[CLIENTE] Envio da carga util concluido.")

        except KeyboardInterrupt:
            print("\n[CLIENTE] Interrupcao pelo usuario (Ctrl+C). Encerrando...")
            enviar_mensagem_encerramento(arquivo_socket)


if __name__ == "__main__":
    main()
