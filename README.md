# Trabalho de Redes 2026.1

Projeto cliente-servidor em Python usando sockets TCP, handshake em JSON,
fragmentacao de mensagens, controle de janela, ACK/NACK, Go-Back-N,
Repeticao Seletiva, integridade por HMAC e criptografia AES-GCM.

## Objetivo

Implementar uma aplicacao cliente-servidor que permita o envio de texto do
cliente para o servidor com negociacao inicial de parametros, fragmentacao em
pacotes de ate 4 caracteres, confirmacao por ACK/NACK, retransmissao em caso de
falha e suporte a multiplos clientes simultaneos.

## Autoria

- Autor: Henrique Sergio
- Disciplina: Redes de Computadores
- Periodo: 2026.1

## Tecnologias utilizadas

- Python 3.8 ou superior
- Sockets TCP (`socket.AF_INET`, `socket.SOCK_STREAM`)
- JSON em UTF-8 com delimitacao por quebra de linha
- Threads para atendimento concorrente no servidor
- AES-256-GCM para confidencialidade/autenticidade do payload
- HMAC-SHA256 para integridade explicita dos pacotes
- HKDF-SHA256 para derivacao de chaves de sessao a partir de PSK

## Estrutura do projeto

```text
.
|-- client.py
|-- server.py
|-- protocol.py
|-- requirements.txt
|-- README.md
|-- docs/
|   |-- matriz_requisitos.md
|   |-- relatorio.md
|   `-- evidencias_testes.md
`-- tests/
    `-- test_protocol.py
```

## Dependencias

Instale as dependencias com:

```bash
python -m pip install -r requirements.txt
```

Conteudo esperado do `requirements.txt`:

```text
cryptography>=42.0.0
```

## Configuracao obrigatoria da PSK

Por padrao, cliente e servidor exigem a variavel de ambiente `PSK`. Ela deve ter
o mesmo valor nos dois processos.

Linux/macOS:

```bash
export PSK='chave_compartilhada_forte_para_o_trabalho'
```

PowerShell:

```powershell
$env:PSK = 'chave_compartilhada_forte_para_o_trabalho'
```

Para testes locais rapidos, e possivel usar explicitamente a PSK de
desenvolvimento insegura:

```bash
python server.py --allow-insecure-dev-psk
python client.py --allow-insecure-dev-psk
```

Essa opcao nao deve ser usada como configuracao principal de entrega.

## Como executar

### 1. Iniciar o servidor

```bash
python server.py --host 127.0.0.1 --port 5000
```

Opcionalmente, escolha o modo padrao de confirmacao e a janela do servidor:

```bash
python server.py --host 127.0.0.1 --port 5000 --modo-confirmacao-padrao go_back_n --janela-inicial 5
```

### 2. Iniciar o cliente

```bash
python client.py --host 127.0.0.1 --port 5000
```

O cliente solicitara:

1. tamanho maximo desejado da sessao, com valor minimo 30;
2. janela desejada, entre 1 e 5;
3. tipo de operacao: `individual` ou `lotes`;
4. mensagens a enviar;
5. comando `sair` para encerrar.

## Execucao automatizada

Exemplo com Go-Back-N:

```bash
printf '2048\n5\n2\nmensagem de teste\nsair\n' | python client.py --host 127.0.0.1 --port 5000 --modo-confirmacao go_back_n
```

Exemplo com Repeticao Seletiva:

```bash
printf '2048\n5\n2\nmensagem de teste\nsair\n' | python client.py --host 127.0.0.1 --port 5000 --modo-confirmacao seletivo
```

Exemplo com modo individual:

```bash
printf '2048\n1\n1\nmensagem de teste\nsair\n' | python client.py --host 127.0.0.1 --port 5000
```

## Simulacao de falhas

Perda controlada de pacotes:

```bash
printf '2048\n5\n2\nmensagem de teste\nsair\n' | python client.py --drop-seqs 1
```

Corrupcao controlada de pacotes:

```bash
printf '2048\n5\n2\nmensagem de teste\nsair\n' | python client.py --corrupt-seqs 2
```

A corrupcao altera um campo sensivel a integridade. Em pacotes criptografados,
o HMAC e modificado, forscando NACK do servidor.

## Protocolo

### Handshake do cliente

```json
{
  "tipo": "handshake",
  "versao_protocolo": 2,
  "modo_operacao": "cliente",
  "tamanho_maximo_desejado": 2048,
  "janela_desejada": 5,
  "tipo_operacao": "lotes",
  "modo_confirmacao": "go_back_n",
  "timeout_ack_ms": 5000,
  "max_retransmissoes": 3
}
```

### Handshake do servidor

```json
{
  "tipo": "handshake_ack",
  "status": "ok",
  "modo_operacao": "servidor",
  "tamanho_maximo_sessao": 2048,
  "janela_sessao": 5,
  "session_salt": "...",
  "modo_confirmacao_acordado": "go_back_n",
  "timeout_ack_ms_acordado": 5000,
  "max_retransmissoes_acordado": 3
}
```

### Pacote de dados

```json
{
  "tipo": "dados",
  "message_id": 0,
  "seq": 0,
  "fim": false,
  "nonce": "...",
  "ciphertext": "...",
  "hmac": "..."
}
```

O campo `message_id` evita que retransmissoes antigas sejam confundidas com uma
nova mensagem quando `seq` reinicia em zero.

### ACK

```json
{
  "tipo": "ack",
  "message_id": 0,
  "seq": 0,
  "status": "ok",
  "cumulativo": true
}
```

### NACK

```json
{
  "tipo": "nack",
  "message_id": 0,
  "seq": 1,
  "status": "reenviar",
  "mensagem": "Sequencia faltante 1."
}
```

## Regras implementadas

- Aplicacao cliente-servidor usando TCP.
- Handshake inicial em JSON.
- Validacao estrita de versao, modo, tamanho, janela, timeout e retransmissoes.
- Tamanho minimo de sessao: 30 caracteres.
- Limite local do servidor: 4096 caracteres.
- Janela de sessao entre 1 e 5, definida pelo servidor.
- Fragmentacao da carga util em pacotes de ate 4 caracteres.
- Campo `seq` validado como inteiro nao negativo de 32 bits.
- Campo `message_id` validado como inteiro nao negativo de 64 bits.
- Criptografia AES-GCM com salt por sessao.
- HMAC-SHA256 cobrindo `nonce`, `ciphertext`, `message_id` e `seq`.
- ACK cumulativo em Go-Back-N.
- ACK individual em Repeticao Seletiva.
- NACK para pacote invalido, fora de ordem ou ausente.
- Timeout de handshake no servidor.
- Timeout de ACK no cliente.
- Retransmissao com limite configuravel.
- Encerramento gracioso com `fim_sessao`.
- Multiplos clientes por threads.

## Testes automatizados

Execute:

```bash
python -m unittest discover -s tests
```

Os testes validam fragmentacao, checksum, validacao de handshake, rejeicao de
sequencias invalidas, HMAC, corrupcao controlada e construcao de pacotes.

## Testes manuais recomendados

1. fluxo valido com Go-Back-N;
2. fluxo valido com Repeticao Seletiva;
3. modo individual;
4. perda simulada com `--drop-seqs`;
5. corrupcao simulada com `--corrupt-seqs`;
6. dois clientes simultaneos;
7. handshake invalido com tamanho menor que 30;
8. encerramento com `sair`.

## Limitacoes conhecidas

- O protocolo e academico e nao substitui TLS em ambiente real.
- A autenticacao depende de PSK compartilhada manualmente.
- O servidor usa uma thread por cliente; para escala elevada, seria melhor usar
  pool de threads ou I/O assincrono.
- O servidor registra payloads no terminal para fins didaticos; em producao,
  isso deveria ser removido ou protegido.

## Uso de agentes de LLM no projeto

Agentes de LLM foram usados como apoio tecnico e organizacional para revisao de
requisitos, melhoria da documentacao, estruturacao de testes e identificacao de
lacunas de robustez. As decisoes finais de implementacao, execucao e validacao
permanecem sob responsabilidade humana.

## Problemas comuns

- `Connection refused`: inicie o servidor antes do cliente.
- `PSK nao definida`: configure `PSK` nos dois terminais.
- `Porta em uso`: altere `--port` ou encerre processo antigo.
- Cliente e servidor nao negociam: verifique se ambos usam a mesma versao do
  codigo e a mesma PSK.
