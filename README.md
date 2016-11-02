# Desafio Python Concrete Solutions

Crie uma aplicação que exponha uma API RESTful de criação de usuários e login.

Todos os endpoints devem aceitar e responder somente JSON, inclusive ao responder mensagens de erro.

Todas as mensagens de erro devem ter o formato:

```json
    {"mensagem": "mensagem de erro"}
```

## Cadastro

* Esse endpoint deverá receber um usuário com os campos "nome", "email", "senha", mais uma lista de objetos "telefone", seguindo o formato abaixo:

```json
    {
        "name": "João da Silva",
        "email": "joao@silva.org",
        "password": "hunter2",
        "phones": [
            {
                "number": "987654321",
                "ddd": "21"
            }
        ]
    }
```

* Responder o código de status HTTP apropriado
* Em caso de sucesso, retorne o usuário, mais os campos:
    * `id`: id do usuário (pode ser o próprio gerado pelo banco, porém seria interessante se fosse um GUID)
    * `created`: data da criação do usuário
    * `modified`: data da última atualização do usuário
    * `last_login`: data do último login (no caso da criação, será a mesma que a criação)
    * `token`: token de acesso da API (pode ser um GUID ou um JWT)

* Caso o e-mail já exista, deverá retornar erro com a mensagem "E-mail já existente".
* O token deverá ser persistido junto com o usuário

## Login

* Este endpoint irá receber um objeto com e-mail e senha.
* Caso o e-mail e a senha correspondam a um usuário existente, retornar igual ao endpoint de Criação.
* Caso o e-mail não exista, retornar erro com status apropriado mais a mensagem "Usuário e/ou senha inválidos"
* Caso o e-mail exista mas a senha não bata, retornar o status apropriado 401 mais a mensagem "Usuário e/ou senha inválidos"

## Perfil do Usuário
* Caso o token não exista, retornar erro com status apropriado com a mensagem "Não autorizado".
* Caso o token exista, buscar o usuário pelo `id` passado no path e comparar se o token no modelo é igual ao token passado no header.
* Caso não seja o mesmo token, retornar erro com status apropriado e mensagem "Não autorizado"
* Caso seja o mesmo token, verificar se o último login foi a MENOS que 30 minutos atrás. Caso não seja a MENOS que 30 minutos atrás, retornar erro com status apropriado com mensagem "Sessão inválida".
* Caso tudo esteja ok, retornar o usuário no mesmo formato do retorno do Login.

## Requisitos
* Banco de dados em memória, de preferência SQLite.
* Gestão de dependências via gerenciador de pacotes.
* Persistência com ferramenta de ORM adequada.
* Escolha livre de framework.
* Prazo de 4 dias corridos.
* Entregar um repo público (github ou bitbucket) com o código fonte.
* Entregar a API rodando em algum host (Heroku, AWS, etc).


## Requisitos desejáveis
* JWT como token
* Testes unitários
* Criptografia não reversível (hash) na senha e no token

------

##Install

### OS dependencies

```bash
  make setup-os
```

### Project's dependencies (Using virtualenv)

```bash
  make setup
```

Make sure to change *.env* with your database credentials and custom configuration

```bash
  touch user_api.db #create sqlite database file
  python manage.py recreate_database #recreate database tables
```

##Run

```bash
  make debug #run server at localhost:5000 in debug mode
  make run #run server at localhost:5000
```

##Test

```bash
  make test #run unit tests
  make flake8 #run pep8 verifications
```

-----

##Endpoints

## Healthcheck

**GET** */api/healthcheck*

Exemplo:

```bash
  curl https://user-api-app.herokuapp.com/api/healthcheck
```

### Perfil do usuário

**GET** */api/users/id*

Exemplo:

```bash
  curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Nzc5ODMzMTMsImlkZW50aXR5IjoxLCJpYXQiOjE0Nzc5ODE1MTMsIm5iZiI6MTQ3Nzk4MTUxM30.Ob7KTc_jcel2yc2oc4AavGAj-YY3yAG8AEtMxhf9O0M" https://user-api-app.herokuapp.com/api/users/1
```

### Criação de usuário

**POST** */api/users*

Exemplo:

```bash
  curl -H "Content-Type: application/json" -X POST -d '{"password":"raissa", "email": "rai200890@gmail.com", "name": "Raissa"}' https://user-api-app.herokuapp.com/api/users
```

### Login

**POST** */api/auth*

Exemplo:

```bash
  curl -H "Content-Type: application/json" -X POST -d '{"password":"raissa", "email": "rai200890@gmail.com"}' https://user-api-app.herokuapp.com/api/auth
```
