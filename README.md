# Trabalho I - Transporte Confiavel na Camada de Aplicacao

## 1. Visao geral

Este projeto implementa uma aplicacao cliente-servidor em Python capaz de fornecer, na camada de aplicacao, um transporte confiavel de dados sobre sockets TCP. Embora o TCP ja seja confiavel, o objetivo do trabalho e implementar e demonstrar explicitamente os mecanismos classicos de transporte confiavel no nivel da aplicacao.

A implementacao inclui:

- conexao cliente-servidor por socket, via `localhost` ou IP;
- protocolo de aplicacao proprio usando mensagens JSON delimitadas por quebra de linha;
- handshake inicial com negociacao de parametros da sessao;
- limite maximo de caracteres por mensagem, definido no inicio da comunicacao, com minimo de 30;
- fragmentacao da mensagem em pacotes de aplicacao com carga util maxima de 4 caracteres;
- numero de sequencia em todos os pacotes;
- checksum CRC32 em todos os pacotes;
- ACK positivo;
- NACK negativo;
- temporizador e retransmissao no cliente;
- janela/paralelismo, com tamanho entre 1 e 5, determinado pelo servidor e valor inicial padrao 5;
- envio individual, equivalente a Stop-and-Wait;
- envio em lotes com Go-Back-N ou repeticao seletiva;
- simulacao deterministica de perdas no lado cliente;
- simulacao deterministica de falhas de integridade no lado cliente;
- criptografia simetrica opcional com AES-GCM;
- derivacao de chaves por HKDF a partir de uma PSK;
- HMAC-SHA256 para autenticacao dos dados criptografados principais;
- logs dos metadados dos pacotes no servidor;
- logs dos metadados das confirmacoes no cliente;
- encerramento gracioso de sessao.

Arquivos entregues:

```text
server.py
client.py
readme.md
```

---

## 2. Dependencias

Versao recomendada:

```bash
python --version
```

Recomendado: Python 3.10 ou superior.

Instale a dependencia de criptografia:

```bash
pip install cryptography
```

A biblioteca `cryptography` e necessaria quando a sessao usa AES-GCM/HMAC, que e o modo padrao. Para executar sem criptografia, use a flag `--sem-criptografia` no cliente.

---

## 3. Configuracao da chave pre-compartilhada

O cliente e o servidor derivam as chaves de sessao a partir de uma PSK definida na variavel de ambiente `PSK`.

Linux/macOS:

```bash
export PSK='chave_secreta_do_grupo'
```

Windows PowerShell:

```powershell
$env:PSK='chave_secreta_do_grupo'
```

Se a variavel `PSK` nao for definida, o codigo usa uma chave de desenvolvimento insegura apenas para testes locais. Para apresentacao e entrega, recomenda-se definir `PSK` nos dois terminais antes de executar cliente e servidor.

---

## 4. Como executar

Abra dois terminais: um para o servidor e outro para o cliente.

### 4.1. Servidor

Execucao padrao em `127.0.0.1:5000`:

```bash
python server.py
```

Execucao especificando host e porta:

```bash
python server.py --host 127.0.0.1 --port 5000
```

Executar aceitando conexoes por IP da maquina na rede local:

```bash
python server.py --host 0.0.0.0 --port 5000
```

Definir a janela inicial do servidor:

```bash
python server.py --host 127.0.0.1 --port 5000 --janela-inicial 5
```

A janela sempre e definida pelo servidor, fica limitada ao intervalo `1..5` e tem valor padrao inicial `5`.

### 4.2. Cliente

Execucao padrao:

```bash
python client.py
```

Execucao especificando host e porta:

```bash
python client.py --host 127.0.0.1 --port 5000
```

Usar Go-Back-N:

```bash
python client.py --host 127.0.0.1 --port 5000 --modo-confirmacao go_back_n
```

Usar repeticao seletiva:

```bash
python client.py --host 127.0.0.1 --port 5000 --modo-confirmacao seletivo
```

Desativar criptografia para demonstrar payload/checksum em claro:

```bash
python client.py --host 127.0.0.1 --port 5000 --sem-criptografia
```

---

## 5. Entradas interativas do cliente

Ao iniciar, o cliente solicita:

1. `tamanho_maximo_desejado`: limite maximo de caracteres por mensagem. Deve ser maior ou igual a 30.
2. `janela_desejada`: sugestao de tamanho de janela entre 1 e 5. O servidor pode ignorar essa sugestao e determina a janela efetiva da sessao.
3. `tipo_operacao`:
   - `1`: individual, equivalente a Stop-and-Wait;
   - `2`: lotes, com janela.

Depois do handshake, o cliente solicita mensagens de texto. Para encerrar a sessao, digite:

```text
sair
```

---

## 6. Protocolo de aplicacao

A comunicacao usa JSON por linha. Cada mensagem JSON termina com `\n`.

O codigo nao usa `socket.makefile().readline()`; ele usa `socket.recv()` com buffer proprio. Isso evita falhas apos `socket.timeout` e permite retransmissao correta apos perdas simuladas.

### 6.1. Handshake do cliente

Exemplo conceitual:

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
  "max_retransmissoes": 3,
  "criptografia_desejada": true,
  "simulacao_perda_seq": [2],
  "simulacao_corrupcao_seq": [],
  "simulacao_corrupcao_checksum_seq": []
}
```

### 6.2. Resposta de handshake do servidor

Exemplo conceitual:

```json
{
  "tipo": "handshake_ack",
  "status": "ok",
  "modo_operacao": "servidor",
  "tamanho_maximo_sessao": 2048,
  "janela_sessao": 5,
  "criptografia_ativa": true,
  "session_salt": "...",
  "modo_confirmacao_acordado": "go_back_n",
  "timeout_ack_ms_acordado": 5000,
  "max_retransmissoes_acordado": 3
}
```

### 6.3. Pacote de dados sem criptografia

```json
{
  "tipo": "dados",
  "seq": 0,
  "fim": false,
  "checksum": "ed82cd11",
  "payload": "abcd"
}
```

### 6.4. Pacote de dados com criptografia

```json
{
  "tipo": "dados",
  "seq": 0,
  "fim": false,
  "checksum": "ed82cd11",
  "ciphertext": "...",
  "nonce": "...",
  "hmac": "..."
}
```

Observacao: o checksum e calculado sobre o texto original de cada fragmento. Em sessoes criptografadas, o servidor descriptografa o fragmento e valida o checksum. O HMAC autentica os metadados criptografados principais (`seq`, `fim`, `nonce` e `ciphertext`).

### 6.5. ACK

ACK cumulativo usado no Go-Back-N:

```json
{
  "tipo": "ack",
  "seq": 4,
  "status": "ok",
  "cumulativo": true,
  "mensagem": "Recebido com sucesso."
}
```

ACK individual usado na repeticao seletiva:

```json
{
  "tipo": "ack",
  "seq": 4,
  "status": "ok",
  "cumulativo": false,
  "mensagem": "Recebido com sucesso."
}
```

### 6.6. NACK

```json
{
  "tipo": "nack",
  "seq": 2,
  "status": "reenviar",
  "mensagem": "Sequencia faltante 2."
}
```

### 6.7. Encerramento gracioso

```json
{
  "tipo": "fim_sessao",
  "mensagem": "Cliente encerrando sessao normalmente."
}
```

---

## 7. Funcionamento dos modos

### 7.1. Envio individual

No modo individual, o cliente envia um pacote e aguarda ACK/NACK antes de enviar o proximo. Esse modo equivale a Stop-and-Wait.

Mesmo que o servidor tenha definido janela 5, o envio individual usa janela efetiva 1 para a troca de dados.

### 7.2. Go-Back-N

No modo Go-Back-N:

- o cliente envia uma janela de pacotes;
- o servidor aceita apenas o proximo numero de sequencia esperado;
- pacotes fora de ordem sao descartados;
- ACKs sao cumulativos;
- `ACK(N)` significa que todos os pacotes ate `N` foram recebidos;
- quando o cliente recebe `NACK(K)`, retransmite de `K` ate o final da janela atual;
- ACKs/NACKs antigos sao ignorados pelo cliente;
- NACKs duplicados para a mesma base, gerados por pacotes fora de ordem ja descartados, nao consomem novas tentativas de retransmissao;
- pacotes duplicados antigos fazem o servidor reenviar o ultimo ACK cumulativo, nao NACK.

### 7.3. Repeticao seletiva

No modo de repeticao seletiva:

- o cliente envia uma janela de pacotes;
- o servidor aceita pacotes fora de ordem dentro da janela atual;
- cada pacote correto recebe ACK individual;
- lacunas geram NACK para o pacote faltante;
- o cliente retransmite somente o pacote indicado pelo NACK;
- em caso de timeout, o cliente retransmite apenas pacotes ainda pendentes.

---

## 8. Simulacao de erros e perdas

As simulacoes sao definidas no lado cliente e sao deterministicas. Cada sequencia informada e afetada apenas uma vez. Na retransmissao seguinte, o pacote e enviado corretamente.

### 8.1. Simular perda

```bash
python client.py --host 127.0.0.1 --port 5000 --drop-seqs 2
```

Exemplo com mais de uma sequencia:

```bash
python client.py --host 127.0.0.1 --port 5000 --drop-seqs 1,4,7
```

### 8.2. Simular corrupcao de HMAC/payload

Em sessao criptografada, `--corrupt-seqs` altera o HMAC. Em sessao sem criptografia, altera o payload em claro.

```bash
python client.py --host 127.0.0.1 --port 5000 --corrupt-seqs 2
```

### 8.3. Simular corrupcao de checksum

```bash
python client.py --host 127.0.0.1 --port 5000 --corrupt-checksum-seqs 2
```

### 8.4. Configurar temporizador e retransmissoes

```bash
python client.py --host 127.0.0.1 --port 5000 --timeout-ack-ms 1500 --max-retransmissoes 5
```

---

## 9. Roteiro de demonstracao dos requisitos

Antes de cada teste, inicie o servidor:

```bash
python server.py --host 127.0.0.1 --port 5000
```

Em cada execucao do cliente, use as entradas interativas abaixo quando solicitado:

```text
2048
5
2
abcdefghijklmnopqrstuvwxyz
sair
```

A terceira linha (`2`) seleciona envio em lotes.

### 9.1. Handshake e envio sem erro - Go-Back-N

```bash
python client.py --host 127.0.0.1 --port 5000 --modo-confirmacao go_back_n
```

Deve aparecer:

- handshake completo nos dois lados;
- janela definida pelo servidor;
- pacotes com `seq`, `fim`, `checksum` e metadados de criptografia;
- ACK cumulativo no cliente;
- mensagem reconstruida corretamente no servidor.

### 9.2. Perda no meio da janela - Go-Back-N

```bash
python client.py --host 127.0.0.1 --port 5000 --modo-confirmacao go_back_n --drop-seqs 2 --timeout-ack-ms 1500 --max-retransmissoes 5
```

Deve aparecer:

- simulacao de perda do pacote `seq=2`;
- NACK do servidor;
- retransmissao de `2..fim_janela`;
- mensagem final reconstruida corretamente.

### 9.2.1. Perda no primeiro pacote da janela - Go-Back-N

```bash
python client.py --host 127.0.0.1 --port 5000 --modo-confirmacao go_back_n --drop-seqs 0 --timeout-ack-ms 1500 --max-retransmissoes 5
```

Deve aparecer:

- simulacao de perda do pacote `seq=0`;
- NACK do servidor para `seq=0`;
- retransmissao de `0..fim_janela`;
- NACKs duplicados obsoletos ignorados pelo cliente, sem consumo indevido de tentativas;
- mensagem final reconstruida corretamente.

### 9.3. Perda do ultimo pacote - Go-Back-N

```bash
python client.py --host 127.0.0.1 --port 5000 --modo-confirmacao go_back_n --drop-seqs 6 --timeout-ack-ms 1500 --max-retransmissoes 5
```

Esse teste demonstra o temporizador. Deve ocorrer timeout no cliente, retransmissao e reconstrucao correta da mensagem.

### 9.4. Corrupcao de HMAC - Go-Back-N

```bash
python client.py --host 127.0.0.1 --port 5000 --modo-confirmacao go_back_n --corrupt-seqs 2 --timeout-ack-ms 1500 --max-retransmissoes 5
```

O servidor deve detectar falha de HMAC, enviar NACK e receber corretamente a retransmissao.

### 9.5. Corrupcao de checksum - Go-Back-N

```bash
python client.py --host 127.0.0.1 --port 5000 --modo-confirmacao go_back_n --corrupt-checksum-seqs 2 --timeout-ack-ms 1500 --max-retransmissoes 5
```

O servidor deve detectar falha de checksum, enviar NACK e receber corretamente a retransmissao.

### 9.6. Repeticao seletiva sem erro

```bash
python client.py --host 127.0.0.1 --port 5000 --modo-confirmacao seletivo
```

Deve aparecer ACK individual para cada pacote.

### 9.7. Repeticao seletiva com perda no meio da janela

```bash
python client.py --host 127.0.0.1 --port 5000 --modo-confirmacao seletivo --drop-seqs 2 --timeout-ack-ms 1500 --max-retransmissoes 5
```

Deve aparecer:

- lacuna detectada pelo servidor;
- NACK apenas do pacote faltante;
- retransmissao apenas do pacote faltante;
- mensagem reconstruida corretamente.

### 9.8. Repeticao seletiva com perda do ultimo pacote

```bash
python client.py --host 127.0.0.1 --port 5000 --modo-confirmacao seletivo --drop-seqs 6 --timeout-ack-ms 1500 --max-retransmissoes 5
```

Esse teste demonstra timeout com retransmissao seletiva apenas dos pendentes.

### 9.9. Envio individual com perda

Use a terceira entrada interativa como `1` para selecionar individual:

```text
2048
5
1
mensagemindividualconfiavel
sair
```

Comando:

```bash
python client.py --host 127.0.0.1 --port 5000 --modo-confirmacao go_back_n --drop-seqs 1 --timeout-ack-ms 1500 --max-retransmissoes 5
```

Deve aparecer Stop-and-Wait com timeout/retransmissao e mensagem reconstruida corretamente.

### 9.10. Demonstracao sem criptografia

```bash
python client.py --host 127.0.0.1 --port 5000 --sem-criptografia --corrupt-checksum-seqs 2 --timeout-ack-ms 1500 --max-retransmissoes 5
```

Esse roteiro deixa o payload em claro nos logs e facilita visualizar a soma de verificacao.

---

## 10. Como cada requisito e atendido

| Requisito | Implementacao |
|---|---|
| Conexao via localhost ou IP | `--host` e `--port` no cliente e no servidor; uso de sockets TCP. |
| Protocolo de aplicacao | JSON por linha, com tipos `handshake`, `handshake_ack`, `dados`, `ack`, `nack`, `fim_sessao` e `encerramento`. |
| Limite minimo de 30 caracteres | Cliente exige entrada `>= 30`; servidor valida `tamanho_maximo_desejado >= 30`. |
| Payload maximo de 4 caracteres | Cliente fragmenta com `PAYLOAD_CHUNK_SIZE = 4`; servidor rejeita payload maior que 4. |
| Soma de verificacao | Campo `checksum` CRC32 em todos os pacotes, validado pelo servidor. |
| Temporizador | Cliente usa `socket.settimeout()` durante espera de ACK/NACK e retransmite em timeout. |
| Numero de sequencia | Campo `seq` em cada pacote. |
| ACK positivo | Servidor envia `tipo: ack`, `status: ok`. |
| NACK negativo | Servidor envia `tipo: nack`, `status: reenviar`. |
| Janela/paralelismo | Servidor define `janela_sessao` entre 1 e 5, padrao 5. |
| Envio individual | Tipo de operacao `individual`, equivalente a Stop-and-Wait. |
| Envio em lotes | Tipo de operacao `lotes`, usando janela. |
| Go-Back-N | `--modo-confirmacao go_back_n`, ACK cumulativo e retransmissao da faixa. |
| Repeticao seletiva | `--modo-confirmacao seletivo`, ACK individual, buffer fora de ordem e retransmissao seletiva. |
| Simulacao de perda | `--drop-seqs`. |
| Simulacao de erro de integridade | `--corrupt-seqs` e `--corrupt-checksum-seqs`. |
| Criptografia simetrica | AES-GCM com chave derivada por HKDF a partir de `PSK` e `session_salt`. |
| Logs de metadados no servidor | Servidor imprime `seq`, `fim`, tamanho do payload, checksum, criptografia, nonce/HMAC parcial ou payload em claro. |
| Logs de confirmacoes no cliente | Cliente imprime tipo de controle, `seq`, cumulatividade e mensagem. |
| Manual de utilizacao | Este README. |
| Declaracao de uso de IA | Secao 13 deste README. |

---

## 11. Observacoes sobre robustez

1. A implementacao evita `socket.makefile().readline()` para que o socket continue utilizavel apos um timeout.
2. Em Go-Back-N, pacotes duplicados antigos fazem o servidor reenviar o ultimo ACK cumulativo em vez de gerar NACK obsoleto.
3. Em Go-Back-N, NACKs duplicados para a mesma base sao tratados como controles obsoletos ate a base avancar ou ocorrer timeout; isso evita abortar a janela quando o primeiro pacote da janela sofre perda/corrupcao e os demais pacotes geram varios NACKs iguais.
4. O cliente ignora ACKs/NACKs antigos ou fora da janela atual.
5. A corrupcao simulada e deterministica: o primeiro caractere do campo afetado e sempre alterado.
6. O checksum existe em pacotes criptografados e nao criptografados.
7. O modo sem criptografia existe para demonstracao didatica do payload e do checksum.

---

## 12. Troubleshooting

### Porta em uso

Erro:

```text
OSError: [Errno 98] Address already in use
```

Solucao: escolha outra porta ou encerre o servidor antigo.

```bash
python server.py --host 127.0.0.1 --port 5001
python client.py --host 127.0.0.1 --port 5001
```

### Biblioteca cryptography ausente

Erro:

```text
Biblioteca cryptography nao esta instalada
```

Solucao:

```bash
pip install cryptography
```

Ou rode sem criptografia:

```bash
python client.py --sem-criptografia
```

### PSK diferente entre cliente e servidor

Se `PSK` for diferente nos dois terminais, o servidor rejeitara os pacotes criptografados por falha de HMAC ou descriptografia. Configure o mesmo valor nos dois lados.

### Mensagem maior que o limite negociado

Se a mensagem digitada tiver mais caracteres que o limite definido no inicio, o cliente rejeita o envio.

---

## 13. Declaracao de uso de IA

Foram utilizados agentes de LLM como apoio para:

- interpretar os requisitos do enunciado;
- revisar a aderencia entre especificacao e implementacao;
- identificar falhas em temporizador, Go-Back-N, simulacao de corrupcao e demonstracao de checksum;
- propor melhorias de arquitetura para leitura por `recv()` em vez de `makefile().readline()`;
- auxiliar na redacao do manual de utilizacao e do roteiro de testes.

A implementacao final deve ser compreendida, revisada e apresentada pelo grupo. Durante a avaliacao oral, todos os integrantes devem conseguir explicar o protocolo, os campos das mensagens, o funcionamento dos algoritmos de retransmissao e os testes de erro/perda.
