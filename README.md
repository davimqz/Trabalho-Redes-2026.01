# Trabalho de Redes 2026.1

Projeto cliente-servidor em Python usando sockets TCP, com handshake em JSON entre cliente e servidor.

## Primeira Entrega - Checkpoints (Confirmacao)

-  Uma aplicacao cliente-servidor.
-  Envio de comunicacao em texto entre cliente e servidor.
-  Limitacao minima de tamanho de caracteres (validacao para valor minimo de 30).
-  A comunicacao e realizada via sockets TCP.
-  Realizacao de handshake inicial com negociacao bilateral de tamanho maximo e janela da sessao (sugestao do cliente, decisao final do servidor).
-  Carga util fragmentada em pacotes de 4 caracteres com ACK por pacote.
-  Relatorio sobre como a IA foi usada no projeto (secao "Uso de agentes de LLM no projeto").
-  Manual de utilizacao documentado no README (secao "Manual de Utilizacao").
 -  Validação estrita do handshake (presença/tipo/valores exigidos).
 -  Timeout de handshake no servidor (10 segundos) para descartar conexões inativas.

## Estrutura do projeto

- `server.py`: inicia o servidor TCP, negocia parametros da sessao e recebe payload fragmentado.
- `client.py`: conecta ao servidor, coleta entradas, negocia sessao e envia payload com janela/ACK.
- `instrução/Trabalho I 2026.1.pdf`: enunciado do trabalho.

## Pre-requisitos

- Python 3.8 ou superior
- Sistema operacional com terminal (PowerShell, CMD, Bash etc.)
- Dependencias Python instaladas:

```powershell
py -m pip install -r requirements.txt
```

## Manual de Utilizacao

### Como executar

1. Abra um terminal na raiz do projeto.
2. Instale as dependencias, se ainda nao tiver feito:

```powershell
py -m pip install -r requirements.txt
```

3. Inicie o servidor (com host/porta configuraveis):

```powershell
py server.py --host 127.0.0.1 --port 5000
```

4. Em outro terminal, execute o cliente:

```powershell
py client.py --host 127.0.0.1 --port 5000
```

5. No cliente, informe:
- O limite maximo de caracteres por vez (deve ser maior ou igual a 30).
- A janela desejada (entre 1 e 5, Enter usa 5; o servidor decide o valor final).
- O tipo de operacao:
  - `1` ou `individual`
  - `2` ou `lotes`
- A mensagem a ser enviada (voce pode enviar varias mensagens na mesma execucao).

6. Verifique no terminal do servidor e do cliente:
- handshake concluido com `tamanho_maximo_sessao` e `janela_sessao` iguais em ambos os lados;
- envio/recebimento de pacotes com payload de ate 4 caracteres;
- ACK por pacote (`seq`) ate o fim da mensagem.

Para encerrar:
- no cliente, digite `sair`; ou
- use `Ctrl + C` no terminal.

### Execucao automatizada (opcional)

Exemplo para enviar entradas no cliente sem digitar manualmente:

```powershell
"2048`n5`n1`nteste protocolo`nsair" | py client.py
```

Esse exemplo envia:
- `2048` como tamanho maximo
- `5` como janela desejada
- `1` como tipo de operacao (`individual`)
- mensagem `teste protocolo`
- comando `sair` para encerrar o loop do cliente

Exemplo atualizado com todos os campos:

```powershell
"2048`n5`n1`nmensagem 1`nmensagem 2`nsair" | py client.py
```

Ordem das entradas:
1. tamanho maximo desejado
2. janela desejada
3. tipo de operacao
4. mensagem (pode repetir varias vezes)
5. `sair` para encerrar

### Argumentos de linha de comando

Servidor:

```powershell
py server.py --host 127.0.0.1 --port 5000 --modo-confirmacao-padrao go_back_n
```

Cliente:

```powershell
py client.py --host 127.0.0.1 --port 5000 --modo-confirmacao go_back_n --timeout-ack-ms 1500 --max-retransmissoes 3
```

Simulacao controlada de testes:

```powershell
py client.py --drop-seqs 1,4 --corrupt-seqs 2
```

## Detalhes tecnicos

- Host/Porta: configuraveis em runtime por `--host` e `--port` (padrao `127.0.0.1:5000`)
- Limite local do servidor para negociacao: `4096`
- Tamanho minimo aceito para sessao: `30`
- Janela da sessao: valor entre `1` e `5` (inicial/padrao `5`)
- Fragmentacao da carga util: `4` caracteres por pacote
- Comunicacao em JSON codificado em UTF-8
- Integridade: `HMAC-SHA256` por pacote
- Criptografia: `AES-256-GCM` com chave de sessao derivada via HKDF a partir de `PSK`
- Modo de confirmacao: `go_back_n` (padrao) ou `seletivo`
- Timeout de dados e retransmissao no cliente: `timeout_ack_ms` e `max_retransmissoes`
- Simulacao deterministica de teste no cliente: perda (`--drop-seqs`) e corrupcao (`--corrupt-seqs`)

### Protocolo resumido

1. Cliente envia `handshake` com:
- `modo_operacao`
- `tamanho_maximo_desejado` (>= 30)
- `janela_desejada` (1..5)
- `tipo_operacao` (`individual` ou `lotes`)
- `modo_confirmacao` (`go_back_n` ou `seletivo`)
- `timeout_ack_ms`
- `max_retransmissoes`
- `simulacao_perda_seq` (lista de `seq` para perda deterministica)
- `simulacao_corrupcao_seq` (lista de `seq` para corrupcao deterministica)

2. Servidor valida e responde `handshake_ack`:
- `status: ok` com `tamanho_maximo_sessao`, `janela_sessao`, `session_salt` e campos acordados (`modo_confirmacao_acordado`, `timeout_ack_ms_acordado`, `max_retransmissoes_acordado`), ou
- `status: erro` com mensagem de validacao.

3. Cliente fragmenta a mensagem em blocos de 4 caracteres e envia pacotes `dados`:
- `seq`
- `fim` (true no ultimo pacote)
- `ciphertext` + `nonce` + `hmac` (ou `payload` em fallback)

4. Servidor responde com:
- `ack` quando pacote valido
- `nack` quando pacote deve ser retransmitido

5. Regras operacionais:
- `individual`: cliente envia 1 pacote e aguarda confirmacao antes do proximo.
- `lotes`: cliente envia por janela.
- `go_back_n`: em falha, retransmite faixa da janela.
- `seletivo`: retransmite apenas `seq` com `nack`/timeout.

## Testes rapidos (entrega final)

1. Fluxo valido com Go-Back-N:

```powershell
"2048`n5`n2`nmensagem de teste`nsair" | py client.py --host 127.0.0.1 --port 5000 --modo-confirmacao go_back_n
```

Saida esperada resumida:

```text
[CLIENTE] Handshake completo!
[CLIENTE] Pacote enviado seq=0 ...
[CLIENTE] ACK recebido seq=0
[CLIENTE] Envio da carga util concluido.
```

2. Simulacao deterministica de perda (ex.: perder seq 1 na primeira tentativa):

```powershell
"2048`n5`n2`nmensagem de teste`nsair" | py client.py --drop-seqs 1
```

Saida esperada resumida:

```text
[CLIENTE] Simulacao: perda do pacote seq=1 (nao enviado nesta tentativa).
[CLIENTE] NACK recebido seq=1: Sequencia faltante 1.
[CLIENTE] Retransmitindo ...
```

3. Simulacao deterministica de corrupcao (ex.: corromper seq 2 na primeira tentativa):

```powershell
"2048`n5`n2`nmensagem de teste`nsair" | py client.py --corrupt-seqs 2
```

Saida esperada resumida:

```text
[CLIENTE] Simulacao: corrupcao do pacote seq=2 (apenas na primeira tentativa).
[CLIENTE] NACK recebido seq=2: Falha na verificacao de integridade (HMAC).
```

4. Modo seletivo:

```powershell
"2048`n5`n2`nmensagem de teste`nsair" | py client.py --modo-confirmacao seletivo
```

Saida esperada resumida:

```text
[CLIENTE] Modo de confirmacao acordado: seletivo
[CLIENTE] ACK recebido seq=0
[CLIENTE] ACK recebido seq=1
```

5. Dois clientes simultaneos:

```powershell
py client.py --host 127.0.0.1 --port 5000
```

Repita em outro terminal. O servidor deve exibir duas conexoes diferentes e manter os logs de cada uma separadamente.

## Hardening do Handshake

Melhorias implementadas para reduzir riscos e garantir comportamento determinístico na negociação inicial:

- Timeout de handshake: o servidor aplica `10s` de espera após o `accept()`; se nenhum handshake válido for recebido, a conexão é encerrada e um `handshake_ack` com `status: erro` pode ser enviado antes do fechamento.
- Validação estrita: o servidor valida `modo_operacao` (esperado `cliente`), `tamanho_maximo_desejado` (inteiro, >= 30) e `janela_desejada` (inteiro entre 1 e 5). Respostas inválidas retornam sempre um `handshake_ack` com `status: erro` e campo `mensagem` explicativo.
- Cliente defensivo: o cliente valida que a resposta é `handshake_ack`, checa `status` e exige campos obrigatórios (`modo_operacao`, `tamanho_maximo_sessao`, `janela_sessao`) quando `status: ok`. Em `status: erro` o cliente encerra sem enviar payload.

Exemplos mínimos de logs (avaliador):

- Handshake bem-sucedido (trecho do servidor):

```
[SERVIDOR] Handshake recebido do cliente:
  - Modo de operacao: cliente
  - Tamanho maximo desejado: 2048 caracteres
  - Janela desejada: 5
[SERVIDOR] Handshake enviado:
  - Modo de operacao: servidor
  - Tamanho maximo da sessao: 2048 caracteres
  - Janela da sessao: 5
[SERVIDOR] Handshake completo!
```

- Handshake rejeitado (modo_operacao incorreto):

```
[SERVIDOR] Handshake recebido do cliente:
  - Modo de operacao: atacante
  - Tamanho maximo desejado: 50 caracteres
[SERVIDOR] Handshake rejeitado: Campo modo_operacao invalido. Esperado 'cliente'.
```

Checklist de entrega atualizada:

- **Validação estrita**: presença, tipo e limites verificados no servidor e cliente.
- **Timeout de handshake**: 10s aplicado no servidor para descartar conexões sem handshake.

## Problemas comuns

- Erro de conexao recusada:
  - Garanta que `server.py` foi iniciado antes de `client.py`.
- Porta em uso:
  - Feche processos antigos que estejam usando a porta `5000`.
- Cliente nao conecta:
  - Confirme se cliente e servidor usam o mesmo `HOST` e `PORT`.

## Uso de agentes de LLM no projeto

Durante o desenvolvimento deste trabalho, o grupo utilizou agentes de LLM como ferramenta de apoio tecnico e organizacional, sem substituir a validacao humana do codigo e dos resultados. O uso foi concentrado em frentes bem delimitadas, sempre com revisao manual antes de qualquer entrega:

1. Criacao e melhoria da documentacao
- Estruturacao do `README.md` com instrucoes claras de instalacao e execucao.
- Revisao de texto para aumentar objetividade, padronizar termos tecnicos e reduzir ambiguidades.
- Organizacao da documentacao em secoes praticas (pre-requisitos, execucao, detalhes tecnicos e troubleshooting), facilitando reproducao do projeto por terceiros.
- Ajuste de exemplos de comando e logs esperados para tornar a demonstracao mais reproducivel.

2. Analise de requisitos por checkpoints
- Apoio na leitura do enunciado e separacao do problema em etapas de entrega (checkpoints).
- Verificacao sistematica de conformidade: o grupo comparou funcionalidades implementadas com os requisitos esperados em cada fase.
- Identificacao antecipada de lacunas (por exemplo, validacao de entradas, formato do handshake e fluxo cliente-servidor), permitindo correcoes antes da etapa final.
- Priorizacao das implementacoes para reduzir retrabalho em partes que impactam o protocolo.

3. Melhor entendimento de bibliotecas e metodos
- Consulta orientada sobre funcionamento de `socket`, serializacao em `json`, codificacao `UTF-8` e fluxo de envio/recebimento de dados em TCP.
- Esclarecimento de conceitos praticos, como diferenca entre `send`/`sendall`, limites de `buffer` e tratamento de erros de conexao.
- Apoio na interpretacao de mensagens de erro e sugestoes de diagnostico durante os testes locais.

4. Apoio em validacao e roteiro de teste
- Sugestao de cenarios de smoke test para handshake, envio valido, perda simulada, corrupcao simulada e concorrencia.
- Conferencia de mensagens esperadas em terminal para facilitar apresentacao aos monitores.
- Apoio na definicao de campos do handshake e argumentos de execucao para manter compatibilidade entre cliente e servidor.

### Forma de uso adotada pelo grupo

- Os agentes de LLM foram usados como suporte de estudo, revisao e documentacao.
- As decisoes finais de arquitetura, implementacao e testes permaneceram sob responsabilidade do grupo.
- Os resultados gerados pelos agentes foram sempre conferidos com execucao real do codigo e leitura do enunciado do trabalho.

### Beneficios observados

- Maior velocidade na organizacao da documentacao e do plano de implementacao.
- Melhor rastreabilidade do que foi entregue em cada checkpoint.
- Reducao de tempo na compreensao de bibliotecas e na resolucao de duvidas tecnicas recorrentes.
- Maior clareza nos exemplos de terminal usados na demonstracao da entrega.

## Saidas esperadas no terminal

Exemplos curtos para orientar a avaliacao:

- Servidor no ar:

```text
[SERVIDOR] Aguardando conexoes em 127.0.0.1:5000...
```

- Handshake concluido:

```text
[CLIENTE] Handshake completo!
[SERVIDOR] Handshake completo!
```

- Fluxo com erro simulado:

```text
[CLIENTE] Simulacao: perda do pacote seq=1 (nao enviado nesta tentativa).
[CLIENTE] NACK recebido seq=1: Sequencia faltante 1.
```

- Retransmissao por timeout:

```text
[CLIENTE] Timeout no seq=0. Retransmitindo ...
```

- Concorrencia:

```text
[SERVIDOR] Conectado por ('127.0.0.1', 12345)
[SERVIDOR] Conectado por ('127.0.0.1', 12346)
```
