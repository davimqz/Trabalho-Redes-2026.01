# Trabalho de Redes 2026.1

Projeto cliente-servidor em Python usando sockets TCP, com handshake em JSON entre cliente e servidor.

## Primeira Entrega - Checkpoints (Confirmacao)

-  Uma aplicacao cliente-servidor.
-  Envio de comunicacao em texto entre cliente e servidor.
-  Limitacao minima de tamanho de caracteres (validacao para valor minimo de 30).
-  A comunicacao e realizada via sockets TCP.
-  Realizacao de handshake inicial com negociacao bilateral de tamanho maximo e janela da sessao.
-  Carga util fragmentada em pacotes de 4 caracteres com ACK por pacote.
-  Relatorio sobre como a IA foi usada no projeto (secao "Uso de agentes de LLM no projeto").
-  Manual de utilizacao documentado no README (secao "Manual de Utilizacao").

## Estrutura do projeto

- `server.py`: inicia o servidor TCP, negocia parametros da sessao e recebe payload fragmentado.
- `client.py`: conecta ao servidor, coleta entradas, negocia sessao e envia payload com janela/ACK.
- `instrução/Trabalho I 2026.1.pdf`: enunciado do trabalho.

## Pre-requisitos

- Python 3.8 ou superior
- Sistema operacional com terminal (PowerShell, CMD, Bash etc.)

## Manual de Utilizacao

### Como executar

1. Abra um terminal na raiz do projeto.
2. Inicie o servidor:

```powershell
py server.py
```

3. Em outro terminal, execute o cliente:

```powershell
py client.py
```

4. No cliente, informe:
- O limite maximo de caracteres por vez (deve ser maior ou igual a 30).
- A janela desejada (entre 1 e 5, Enter usa 5).
- O tipo de operacao:
  - `1` ou `individual`
  - `2` ou `lotes`
- A mensagem a ser enviada (voce pode enviar varias mensagens na mesma execucao).

5. Verifique no terminal do servidor e do cliente:
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

## Detalhes tecnicos

- Host: `127.0.0.1`
- Porta: `5000`
- Limite local do servidor para negociacao: `4096`
- Tamanho minimo aceito para sessao: `30`
- Janela da sessao: valor entre `1` e `5` (inicial/padrao `5`)
- Fragmentacao da carga util: `4` caracteres por pacote
- Comunicacao em JSON codificado em UTF-8

### Protocolo resumido

1. Cliente envia `handshake` com:
- `modo_operacao`
- `tamanho_maximo_desejado` (>= 30)
- `janela_desejada` (1..5)
- `tipo_operacao`

2. Servidor valida e responde `handshake_ack`:
- `status: ok` com `tamanho_maximo_sessao` e `janela_sessao`, ou
- `status: erro` com mensagem de validacao.

3. Cliente fragmenta a mensagem em blocos de 4 caracteres e envia pacotes `dados`:
- `seq`
- `payload`
- `fim` (true no ultimo pacote)

4. Servidor confirma cada pacote com `ack`:
- `seq`
- `status: ok` ou `erro`

## Problemas comuns

- Erro de conexao recusada:
  - Garanta que `server.py` foi iniciado antes de `client.py`.
- Porta em uso:
  - Feche processos antigos que estejam usando a porta `5000`.
- Cliente nao conecta:
  - Confirme se cliente e servidor usam o mesmo `HOST` e `PORT`.

## Uso de agentes de LLM no projeto

Durante o desenvolvimento deste trabalho, o grupo utilizou agentes de LLM como ferramenta de apoio tecnico e organizacional, sem substituir a validacao humana do codigo e dos resultados. O uso foi concentrado em tres frentes principais:

1. Criacao e melhoria da documentacao
- Estruturacao do `README.md` com instrucoes claras de instalacao e execucao.
- Revisao de texto para aumentar objetividade, padronizar termos tecnicos e reduzir ambiguidades.
- Organizacao da documentacao em secoes praticas (pre-requisitos, execucao, detalhes tecnicos e troubleshooting), facilitando reproducao do projeto por terceiros.

2. Analise de requisitos por checkpoints
- Apoio na leitura do enunciado e separacao do problema em etapas de entrega (checkpoints).
- Verificacao sistematica de conformidade: o grupo comparou funcionalidades implementadas com os requisitos esperados em cada fase.
- Identificacao antecipada de lacunas (por exemplo, validacao de entradas, formato do handshake e fluxo cliente-servidor), permitindo correcoes antes da etapa final.

3. Melhor entendimento de bibliotecas e metodos
- Consulta orientada sobre funcionamento de `socket`, serializacao em `json`, codificacao `UTF-8` e fluxo de envio/recebimento de dados em TCP.
- Esclarecimento de conceitos praticos, como diferenca entre `send`/`sendall`, limites de `buffer` e tratamento de erros de conexao.
- Apoio na interpretacao de mensagens de erro e sugestoes de diagnostico durante os testes locais.

### Forma de uso adotada pelo grupo

- Os agentes de LLM foram usados como suporte de estudo, revisao e documentacao.
- As decisoes finais de arquitetura, implementacao e testes permaneceram sob responsabilidade do grupo.

### Beneficios observados

- Maior velocidade na organizacao da documentacao e do plano de implementacao.
- Melhor rastreabilidade do que foi entregue em cada checkpoint.
- Reducao de tempo na compreensao de bibliotecas e na resolucao de duvidas tecnicas recorrentes.
