# Documentação do Handshake

## Introdução

O handshake é o processo inicial de comunicação entre cliente e servidor, onde ambos trocam informações essenciais sobre suas configurações e capacidades antes de iniciar a troca de dados propriamente dita.

## Objetivo

Estabelecer parâmetros comuns de comunicação entre cliente e servidor, incluindo:
- Identificação do modo de operação de cada parte
- Acordar o tamanho máximo de dados a serem transmitidos
- Validar a conexão antes de operações mais complexas

## Protocolo Implementado

### Formato dos Dados

**Tipo:** JSON
**Codificação:** UTF-8
**Transporte:** TCP (SOCK_STREAM)

### Estrutura da Mensagem

```json
{
    "modo_operacao": "string",
    "tamanho_maximo": integer
}
```

**Campos:**

| Campo | Tipo | Descrição | Valores |
|-------|------|-----------|---------|
| `modo_operacao` | string | Identifica o tipo de aplicação | `"cliente"` ou `"servidor"` |
| `tamanho_maximo` | integer | Tamanho máximo do buffer em bytes | Valor positivo (ex: 2048, 4096) |

### Exemplo de Mensagem

**Cliente:**
```json
{
    "modo_operacao": "cliente",
    "tamanho_maximo": 2048
}
```

**Servidor:**
```json
{
    "modo_operacao": "servidor",
    "tamanho_maximo": 4096
}
```

## Fluxo de Comunicação

### Diagrama de Sequência

```
Cliente                                    Servidor
  |                                           |
  |  1. socket.connect(HOST, PORT)           |
  |------------------------------------------>|
  |                                           |
  |  2. Envia handshake (JSON)               |
  |  {"modo_operacao": "cliente", ...}       |
  |=========================================>|
  |                                           |
  |                                           | 3. Processa handshake
  |                                           |    do cliente
  |                                           |
  |  4. Recebe handshake (JSON)              |
  |  {"modo_operacao": "servidor", ...}      |
  |<=========================================|
  |                                           |
  5. Handshake completo                       5. Handshake completo
  |                                           |
```

### Passo a Passo

#### No Servidor (server.py)

1. **Inicialização**
   ```python
   server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   server_socket.bind((HOST, PORT))
   server_socket.listen()
   ```

2. **Aceitar Conexão**
   ```python
   conn, addr = server_socket.accept()
   ```

3. **Receber Handshake do Cliente**
   ```python
   data = conn.recv(BUFFER_SIZE)
   client_config = json.loads(data.decode('utf-8'))
   ```

4. **Enviar Handshake ao Cliente**
   ```python
   server_config = {
       'modo_operacao': 'servidor',
       'tamanho_maximo': BUFFER_SIZE
   }
   handshake_data = json.dumps(server_config).encode('utf-8')
   conn.sendall(handshake_data)
   ```

#### No Cliente (client.py)

1. **Conexão ao Servidor**
   ```python
   client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   client_socket.connect((HOST, PORT))
   ```

2. **Enviar Handshake**
   ```python
   client_config = {
       'modo_operacao': 'cliente',
       'tamanho_maximo': BUFFER_SIZE
   }
   handshake_data = json.dumps(client_config).encode('utf-8')
   client_socket.sendall(handshake_data)
   ```

3. **Receber Handshake do Servidor**
   ```python
   data = client_socket.recv(BUFFER_SIZE)
   server_config = json.loads(data.decode('utf-8'))
   ```

## Implementação Técnica

### Bibliotecas Utilizadas

- **socket**: Criação de sockets TCP/IP
- **json**: Serialização e deserialização de dados

### Escolhas de Design

#### Por que JSON?

- ✅ Formato legível e fácil de debugar
- ✅ Suporte nativo em Python
- ✅ Extensível para adicionar novos campos no futuro
- ✅ Leve e eficiente para mensagens pequenas

#### Por que TCP?

- ✅ Confiabilidade: garante entrega dos pacotes
- ✅ Ordem: pacotes chegam na ordem enviada
- ✅ Controle de fluxo e congestionamento
- ✅ Adequado para handshake crítico

### Tratamento de Erros

**Atualmente implementado:**
- Uso de `with` statement para gerenciamento automático de recursos
- Socket fecha automaticamente em caso de erro

**Melhorias futuras:**
- Timeout de conexão
- Validação de formato JSON
- Retry automático
- Logging de erros

## Configurações

### Servidor

```python
HOST = '127.0.0.1'        # Localhost (apenas local)
PORT = 5000               # Porta de escuta
BUFFER_SIZE = 4096        # Buffer de 4KB
```

### Cliente

```python
HOST = '127.0.0.1'        # IP do servidor
PORT = 5000               # Porta do servidor
BUFFER_SIZE = 2048        # Buffer de 2KB
```

## Testes

### Teste Básico

1. Execute o servidor:
   ```bash
   python server.py
   ```

2. Em outro terminal, execute o cliente:
   ```bash
   python client.py
   ```

3. **Resultado esperado:**
   - Servidor mostra handshake recebido do cliente
   - Cliente mostra handshake recebido do servidor
   - Ambos exibem "Handshake completo!"

### Verificando a Troca de Dados

No servidor, você verá:
```
[SERVIDOR] Cliente conectado: 127.0.0.1:XXXXX
[SERVIDOR] Handshake recebido do cliente:
  - Modo de operação: cliente
  - Tamanho máximo: 2048 bytes
[SERVIDOR] Handshake completo!
```

No cliente, você verá:
```
[CLIENTE] Conectando ao servidor 127.0.0.1:5000...
[CLIENTE] Conectado!
[CLIENTE] Handshake enviado:
  - Modo de operação: cliente
  - Tamanho máximo: 2048 bytes
[CLIENTE] Handshake recebido do servidor:
  - Modo de operação: servidor
  - Tamanho máximo: 4096 bytes
[CLIENTE] Handshake completo!
```

## Limitações Conhecidas

1. **Sem tratamento de timeout**: Se o servidor não responder, o cliente ficará travado
2. **Sem validação de dados**: Não verifica se o JSON é válido ou tem os campos corretos
3. **Buffer fixo**: Assume que o handshake cabe no buffer especificado
4. **Sem criptografia**: Dados trafegam em texto plano
5. **Conexão única**: Servidor processa apenas uma conexão por vez

## Extensões Futuras

### Campos Adicionais no Handshake

```json
{
    "modo_operacao": "cliente",
    "tamanho_maximo": 2048,
    "versao_protocolo": "1.0",
    "capacidades": ["compressao", "criptografia"],
    "id_sessao": "uuid-aqui"
}
```

### Validação de Compatibilidade

- Verificar se as versões do protocolo são compatíveis
- Negociar o menor tamanho_maximo entre cliente e servidor
- Aceitar conexão apenas se capacidades mínimas forem suportadas

## Referências

- [Python socket documentation](https://docs.python.org/3/library/socket.html)
- [Python json documentation](https://docs.python.org/3/library/json.html)
- [TCP/IP Protocol](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)
