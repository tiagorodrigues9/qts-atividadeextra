# Laboratório de Segurança OWASP (SQL Injection e XSS)

Atividade prática comparando endpoints vulneráveis e seguros contra falhas do **OWASP Top 10** (SQL Injection e Cross-Site Scripting - XSS) utilizando FastAPI, SQLite e Pytest.

---

## 🛠️ Tecnologias

- **Python** (gerenciado com `uv`)
- **FastAPI**
- **SQLite**
- **Pytest** + **HTTPX**

---

## 🚀 Como Executar

### 1. Instalar Dependências
```bash
uv sync
```

### 2. Rodar a API
```bash
uv run uvicorn main:app --reload
```
Acesse a documentação interativa em: `http://127.0.0.1:8000/docs`

### 3. Rodar os Testes Automatizados
```bash
uv run pytest -v
```

---

## 🛡️ Cenários Implementados

| Tipo de Falha | Rota Vulnerável | Rota Segura (Mitigação) | Defesa Utilizada |
|---|---|---|---|
| **SQL Injection (Auth Bypass)** | `POST /vulneravel/login` | `POST /seguro/login` | *Prepared Statements* (`?`) |
| **SQL Injection (UNION SELECT)** | `GET /vulneravel/campanhas/buscar` | `GET /seguro/campanhas/buscar` | *Prepared Statements* com `LIKE ?` |
| **Stored XSS (`<script>`)** | `POST /vulneravel/comentarios` | `POST /seguro/comentarios` | Sanitização com `html.escape()` |
| **XSS via Atributo (`onerror`)** | `POST /vulneravel/comentarios` | `POST /seguro/comentarios` | Sanitização com `html.escape()` |

---

## 🧪 Estrutura dos Testes

Os testes em [`tests/test_seguranca.py`](tests/test_seguranca.py) seguem o padrão **AAA (Arrange, Act, Assert)** e a anotação `@pytest.mark.security`:
- **4 testes ofensivos:** comprovam que as rotas vulneráveis aceitam injeções e ataques.
- **4 testes defensivos:** comprovam que as rotas seguras bloqueiam injeções e sanitizam dados maliciosos.

