import signal
import subprocess
import sys
import time
from pathlib import Path


def encerrar_processos(processos):
    for nome, processo in processos:
        if processo.poll() is None:
            print(f"[RUNNER] Encerrando {nome}...")
            processo.terminate()

    limite = time.time() + 5
    while time.time() < limite:
        if all(processo.poll() is not None for _, processo in processos):
            return
        time.sleep(0.1)

    for nome, processo in processos:
        if processo.poll() is None:
            print(f"[RUNNER] Forcando encerramento de {nome}...")
            processo.kill()


def main():
    base_dir = Path(__file__).resolve().parent
    python = sys.executable

    print("[RUNNER] Iniciando servidor...")
    server_proc = subprocess.Popen([python, str(base_dir / "server.py")], cwd=base_dir)

    # Pequeno atraso para reduzir chance do cliente conectar antes do bind/listen.
    time.sleep(0.5)

    print("[RUNNER] Iniciando cliente...")
    client_proc = subprocess.Popen([python, str(base_dir / "client.py")], cwd=base_dir)

    processos = [("server", server_proc), ("client", client_proc)]

    try:
        while True:
            for nome, processo in processos:
                codigo = processo.poll()
                if codigo is not None:
                    print(f"[RUNNER] Processo {nome} finalizou com codigo {codigo}.")
                    encerrar_processos(processos)
                    return
            time.sleep(0.2)
    except KeyboardInterrupt:
        print("\n[RUNNER] Ctrl + C recebido.")
        encerrar_processos(processos)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)
    main()
