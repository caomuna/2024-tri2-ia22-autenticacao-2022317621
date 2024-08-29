# 1. Autenticação de Usuários (Single Server)
## Objetivo: Implementar um sistema básico de autenticação de usuários em um único servidor.

### Preparar o Ambiente:

Escolha uma linguagem e framework para implementar o servidor. Para este exemplo, usaremos Node.js com Express.
Instale as dependências necessárias: Express, bcrypt (para hash de senhas), e body-parser.

```bash
npm init -y
npm install express bcryptjs body-parser
```
### Configurar o Servidor:

Crie um arquivo server.js e configure o Express.

```javascript
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');

const app = express();
app.use(bodyParser.json());

// Simular um banco de dados em memória
let users = {};

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (users[username]) {
    return res.status(400).send('Usuário já existe.');
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  users[username] = hashedPassword;
  res.status(201).send('Usuário registrado.');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = users[username];
  if (!hashedPassword || !(await bcrypt.compare(password, hashedPassword))) {
    return res.status(400).send('Credenciais inválidas.');
  }
  res.status(200).send('Autenticado com sucesso.');
});

app.listen(3000, () => {
  console.log('Servidor rodando na porta 3000');
});
```
## Testar:

Utilize ferramentas como Postman para testar os endpoints /register e /login.
2. Autenticação VS Autorização
Autenticação é o processo de verificar a identidade de um usuário. Autorização é o processo de determinar se um usuário tem permissão para acessar um recurso específico. Aqui está um resumo das diferenças:

### Autenticação:

O objetivo é confirmar a identidade do usuário.
Métodos comuns incluem login com nome de usuário e senha, biometria, ou tokens.
Autorização:

O objetivo é garantir que o usuário tenha permissão para realizar ações específicas.
Normalmente envolve a verificação de permissões ou papéis (roles).
Exemplo Prático:

### Autenticação:

Um usuário faz login no sistema. O sistema valida o login e cria uma sessão ou gera um token.
Autorização:

Após o login, o usuário tenta acessar uma página restrita. O sistema verifica o papel do usuário (ex: admin, usuário padrão) para determinar se ele tem acesso.
3. Autenticação com Token (JWT)
Objetivo: Implementar a autenticação de usuários usando JSON Web Tokens (JWT).

### Passos:

### Preparar o Ambiente:

Instale as dependências necessárias: jsonwebtoken e dotenv para gerenciamento de variáveis de ambiente.

```bash
npm install jsonwebtoken dotenv
Configurar o Servidor com JWT:
```

Atualize o arquivo server.js para usar JWT.

```javascript
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

let users = {};

// Registro de usuário
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (users[username]) {
    return res.status(400).send('Usuário já existe.');
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  users[username] = hashedPassword;
  res.status(201).send('Usuário registrado.');
});

// Login e emissão do token
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = users[username];
  if (!hashedPassword || !(await bcrypt.compare(password, hashedPassword))) {
    return res.status(400).send('Credenciais inválidas.');
  }
  const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.status(200).json({ token });
});

// Middleware para verificar o token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Recurso protegido
app.get('/protected', authenticateToken, (req, res) => {
  res.status(200).send(`Olá, ${req.user.username}`);
});

app.listen(3000, () => {
  console.log('Servidor rodando na porta 3000');
});
```
## Testar:

Primeiro, registre um usuário e faça login para obter um token.
Use o token obtido para acessar o recurso protegido (/protected).
Notas Adicionais:

``JWT_SECRET`` deve ser uma chave secreta segura armazenada em um arquivo ``.env``.
