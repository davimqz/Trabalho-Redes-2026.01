# Sistema Cliente-Servidor TCP com Handshake

Sistema de comunicação em rede baseado em sockets TCP para estabelecimento de handshake entre cliente e servidor.

## 📋 Índice

- [Guia de Início Rápido](#guia-de-início-rápido)
- [Arquitetura do Sistema](#arquitetura-do-sistema)
- [Referências](#referências-técnicas)

---

## Guia de Início Rápido

### Pré-requisitos

✅ Python 3.6 ou superior instalado
✅ Nenhuma biblioteca externa necessária

### Verificar Instalação do Python

```bash
python --version
```

ou

```bash
python3 --version
```

Você deve ver algo como: `Python 3.x.x`

### Executando pela Primeira Vez

#### Passo 1: Abrir Terminal no Diretório do Projeto

```bash
cd Trabalho-Redes-2026.01
```

#### Passo 2: Iniciar o Servidor

**Terminal 1:**

```bash
python server.py
```

**Saída esperada:**
```
[SERVIDOR] Iniciando servidor em 127.0.0.1:5000...
[SERVIDOR] Aguardando conexões...
```

#### Passo 3: Executar o Cliente

**Terminal 2** (novo terminal):

```bash
python client.py
```

**Saída esperada no cliente:**
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

**Saída esperada no servidor:**
```
[SERVIDOR] Cliente conectado: 127.0.0.1:XXXXX
[SERVIDOR] Handshake recebido do cliente:
  - Modo de operação: cliente
  - Tamanho máximo: 2048 bytes
[SERVIDOR] Handshake completo!
```

#### Passo 4: Encerrar

Pressione `Ctrl+C` em ambos os terminais para encerrar servidor e cliente.

### Customização Básica

#### Alterar a Porta

**Em server.py e client.py:**

```python
PORT = 8080  # Altere de 5000 para 8080
```

#### Alterar o Buffer Size

**Em server.py:**
```python
BUFFER_SIZE = 8192  # Aumenta para 8KB
```

**Em client.py:**
```python
BUFFER_SIZE = 4096  # Aumenta para 4KB
```

#### Conectar em Outra Máquina

**No server.py:**
```python
HOST = '0.0.0.0'  # Aceita conexões de qualquer IP
```

**No client.py:**
```python
HOST = '192.168.1.100'  # IP da máquina do servidor
```

### Troubleshooting

#### Problema: "Address already in use"

**Causa:** Porta 5000 já está em uso

**Solução 1:** Espere alguns segundos e tente novamente

**Solução 2:** Altere a porta:
```python
PORT = 5001  # Use outra porta
```

#### Problema: "Connection refused"

**Causa:** Servidor não está rodando

**Solução:** Certifique-se de iniciar o servidor primeiro antes do cliente

#### Problema: Cliente trava sem resposta

**Causa:** IP ou porta incorretos no cliente

**Solução:** Verifique que `HOST` e `PORT` no cliente coincidem com o servidor

#### Problema: "No module named 'json'"

**Causa:** Instalação incompleta do Python

**Solução:** Reinstale o Python ou use uma distribuição oficial

### Estrutura de Arquivos

```
Trabalho-Redes-2026.01/
├── client.py          ← Execute segundo
├── server.py          ← Execute primeiro
├── README.md          ← Você está aqui!
├── docs/              ← Documentação adicional
└── instrução/
```

### Comandos Úteis

#### Verificar se a Porta Está em Uso

**Linux/Mac:**
```bash
lsof -i :5000
```

**Windows (PowerShell):**
```powershell
netstat -ano | findstr :5000
```

#### Matar Processo na Porta

**Linux/Mac:**
```bash
kill -9 $(lsof -t -i:5000)
```

**Windows (PowerShell):**
```powershell
# Encontre o PID
netstat -ano | findstr :5000
# Mate o processo
taskkill /PID <PID> /F
```

### Testando a Conexão

#### Teste 1: Handshake Básico

✅ Execute servidor e cliente conforme instruções acima
✅ Verifique se ambos mostram "Handshake completo!"

#### Teste 2: Múltiplas Conexões

1. Inicie o servidor
2. Execute o cliente várias vezes seguidas
3. Cada execução deve completar o handshake

#### Teste 3: Dados do Handshake

Verifique se os dados recebidos correspondem aos enviados:

- Cliente envia: `modo_operacao: "cliente"`, `tamanho_maximo: 2048`
- Servidor envia: `modo_operacao: "servidor"`, `tamanho_maximo: 4096`

### Checklist de Verificação

Antes de considerar a primeira entrega completa:

- [ ] Servidor inicia sem erros
- [ ] Cliente conecta ao servidor
- [ ] Handshake é trocado (modo_operacao + tamanho_maximo)
- [ ] Ambos mostram "Handshake completo!"
- [ ] Conexão fecha corretamente
- [ ] Documentação está atualizada

### Dicas

💡 **Use dois terminais** lado a lado para visualizar servidor e cliente simultaneamente

💡 **Inicie sempre o servidor primeiro** antes de executar o cliente

💡 **Ctrl+C** encerra tanto servidor quanto cliente de forma segura

💡 **Logs detalhados** ajudam a entender o fluxo de comunicação

---

## Arquitetura do Sistema

### Visão Geral

Sistema cliente-servidor baseado em sockets TCP para comunicação em rede. A arquitetura segue o modelo clássico de requisição-resposta com handshake inicial para estabelecimento de parâmetros de comunicação.

### Componentes

#### 1. Servidor (server.py)

**Responsabilidades:**
- Inicializar socket TCP e aguardar conexões
- Aceitar conexões de clientes
- Receber e processar handshake do cliente
- Enviar handshake de resposta
- Gerenciar sessões de comunicação

**Características:**
- Modo de operação: `"servidor"`
- Buffer size: 4096 bytes
- Porta padrão: 5000
- Interface: localhost (127.0.0.1)

**Fluxo de Execução:**
```
Início
  ↓
Criar socket TCP
  ↓
Bind (HOST, PORT)
  ↓
Listen()
  ↓
┌─────────────────┐
│ Accept()        │ ← Loop (aguarda conexões)
└─────────────────┘
  ↓
Receber handshake do cliente
  ↓
Processar dados
  ↓
Enviar handshake ao cliente
  ↓
Handshake completo
  ↓
Fechar conexão
```

#### 2. Cliente (client.py)

**Responsabilidades:**
- Estabelecer conexão com o servidor
- Enviar handshake inicial
- Receber e processar resposta do servidor
- Validar conexão

**Características:**
- Modo de operação: `"cliente"`
- Buffer size: 2048 bytes
- Conecta ao servidor em 127.0.0.1:5000

**Fluxo de Execução:**
```
Início
  ↓
Criar socket TCP
  ↓
Connect(HOST, PORT)
  ↓
Enviar handshake ao servidor
  ↓
Aguardar resposta
  ↓
Receber handshake do servidor
  ↓
Processar dados
  ↓
Handshake completo
  ↓
Fechar conexão
```

### Camadas de Comunicação

#### Camada 4 - Transporte (TCP)

```
┌─────────────────────────────────────┐
│     Aplicação (Client/Server)       │
├─────────────────────────────────────┤
│     Serialização (JSON)             │
├─────────────────────────────────────┤
│     Socket API (Python socket)      │
├─────────────────────────────────────┤
│     TCP (Transmission Control)      │
├─────────────────────────────────────┤
│     IP (Internet Protocol)          │
├─────────────────────────────────────┤
│     Enlace/Física                   │
└─────────────────────────────────────┘
```

### Formato de Dados

#### Protocolo de Handshake

**Camada de Aplicação:**
```
Dados da Aplicação (dict Python)
         ↓
json.dumps() - Serialização
         ↓
String JSON
         ↓
encode('utf-8') - Codificação
         ↓
Bytes UTF-8
         ↓
socket.sendall() - Envio via TCP
```

**Exemplo:**
```python
# Aplicação
data = {'modo_operacao': 'cliente', 'tamanho_maximo': 2048}

# Serialização
json_str = '{"modo_operacao": "cliente", "tamanho_maximo": 2048}'

# Codificação
bytes_data = b'{"modo_operacao": "cliente", "tamanho_maximo": 2048}'

# Envio
socket.sendall(bytes_data)
```

### Diagrama de Componentes

```
┌─────────────────────────────────────────────────────┐
│                   SERVIDOR                          │
│  ┌────────────────────────────────────────────┐    │
│  │  server.py                                  │    │
│  │  ┌──────────────────────────────────────┐  │    │
│  │  │  Main Loop                           │  │    │
│  │  │  - socket.listen()                   │  │    │
│  │  │  - socket.accept()                   │  │    │
│  │  └──────────────────────────────────────┘  │    │
│  │  ┌──────────────────────────────────────┐  │    │
│  │  │  Handshake Handler                   │  │    │
│  │  │  - recv(BUFFER_SIZE)                 │  │    │
│  │  │  - json.loads()                      │  │    │
│  │  │  - json.dumps()                      │  │    │
│  │  │  - sendall()                         │  │    │
│  │  └──────────────────────────────────────┘  │    │
│  └────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
                       ↕ TCP/IP
┌─────────────────────────────────────────────────────┐
│                   CLIENTE                           │
│  ┌────────────────────────────────────────────┐    │
│  │  client.py                                  │    │
│  │  ┌──────────────────────────────────────┐  │    │
│  │  │  Connection Manager                  │  │    │
│  │  │  - socket.connect()                  │  │    │
│  │  └──────────────────────────────────────┘  │    │
│  │  ┌──────────────────────────────────────┐  │    │
│  │  │  Handshake Handler                   │  │    │
│  │  │  - json.dumps()                      │  │    │
│  │  │  - sendall()                         │  │    │
│  │  │  - recv(BUFFER_SIZE)                 │  │    │
│  │  │  - json.loads()                      │  │    │
│  │  └──────────────────────────────────────┘  │    │
│  └────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

### Padrões de Projeto

#### 1. Context Manager (with statement)

Usado para gerenciamento automático de recursos:

```python
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    # Usa o socket
    pass
# Socket é fechado automaticamente
```

**Benefícios:**
- Garante fechamento do socket mesmo em caso de erro
- Código mais limpo e legível
- Previne vazamento de recursos

#### 2. Request-Response Pattern

Padrão de comunicação onde:
- Cliente inicia a comunicação (request)
- Servidor responde (response)

```
Cliente  →  [Request]   →  Servidor
Cliente  ←  [Response]  ←  Servidor
```

#### 3. Protocol Buffers (JSON)

Uso de formato estruturado para troca de dados:
- Serialização: `json.dumps()`
- Deserialização: `json.loads()`

### Modelo de Estados

#### Estado do Servidor

```
[INICIADO] → [ESCUTANDO] → [CONECTADO] → [HANDSHAKE_RECEBIDO] → [HANDSHAKE_ENVIADO] → [COMPLETO]
    ↓            ↓             ↓                ↓                        ↓
[ERRO]      [ERRO]        [ERRO]          [ERRO]                   [ERRO]
```

#### Estado do Cliente

```
[INICIADO] → [CONECTANDO] → [CONECTADO] → [HANDSHAKE_ENVIADO] → [HANDSHAKE_RECEBIDO] → [COMPLETO]
    ↓            ↓              ↓                 ↓                      ↓
[ERRO]      [ERRO]         [ERRO]           [ERRO]                 [ERRO]
```

### Decisões de Design

#### Por que TCP em vez de UDP?

| Aspecto | TCP | UDP |
|---------|-----|-----|
| Confiabilidade | ✅ Garante entrega | ❌ Sem garantia |
| Ordem | ✅ Pacotes ordenados | ❌ Pode chegar fora de ordem |
| Handshake | ✅ Essencial | ❌ Complicado |
| Overhead | Maior | Menor |

**Decisão:** TCP é ideal para handshake onde confiabilidade é crítica.

#### Por que JSON em vez de Binary?

| Aspecto | JSON | Binary |
|---------|------|--------|
| Legibilidade | ✅ Fácil debug | ❌ Difícil debug |
| Tamanho | Maior | ✅ Menor |
| Extensibilidade | ✅ Fácil adicionar campos | ❌ Precisa versionar |
| Parsing | ✅ Nativo em Python | Requer biblioteca |

**Decisão:** JSON é adequado para mensagens pequenas de handshake, priorizando simplicidade.

#### Configurações de Buffer

- **Servidor: 4096 bytes** - Maior buffer para aceitar diferentes tamanhos de cliente
- **Cliente: 2048 bytes** - Buffer menor, suficiente para handshake simples

### Segurança

#### Vulnerabilidades Conhecidas

1. **Sem autenticação** - Qualquer cliente pode conectar
2. **Sem criptografia** - Dados em texto plano
3. **Sem validação** - JSON pode ser malformado
4. **DDoS susceptível** - Servidor single-threaded

#### Melhorias Futuras

- [ ] TLS/SSL para criptografia
- [ ] Autenticação via token/senha
- [ ] Validação de schema JSON
- [ ] Rate limiting
- [ ] Timeout de conexão

### Performance

#### Métricas Atuais

- **Latência de handshake**: ~1-5ms (localhost)
- **Throughput**: Limitado pelo single-threading
- **Conexões simultâneas**: 1 (blocking)

#### Otimizações Planejadas

- [ ] Multi-threading para múltiplos clientes
- [ ] Async I/O (asyncio)
- [ ] Connection pooling
- [ ] Binary protocol (protobuf)

### Escalabilidade

#### Limitações Atuais

```
┌─────────┐
│ Server  │ ← Processa 1 cliente por vez
└─────────┘
```

#### Arquitetura Futura (Multi-client)

```
             ┌─────────┐
          ┌─→│ Thread1 │
          │  └─────────┘
┌────────┐│  ┌─────────┐
│ Server │├─→│ Thread2 │
└────────┘│  └─────────┘
          │  ┌─────────┐
          └─→│ Thread3 │
             └─────────┘
```

### Dependências

#### Bibliotecas Python Standard

- `socket` - Comunicação de rede
- `json` - Serialização de dados

#### Requisitos do Sistema

- Python 3.6+
- Sistema operacional: Windows/Linux/macOS
- Porta 5000 disponível

### Referências Técnicas

- RFC 793 - TCP Protocol
- RFC 7159 - JSON Data Interchange Format
- Python PEP 3151 - Reworking the OS and IO exception hierarchy

---

**Pronto para usar!** 🚀

Se todos os passos acima funcionaram, sua implementação do handshake está correta e completa.
