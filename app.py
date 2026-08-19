import os
import re
import ast
import random
import string
import socket
import secrets
from datetime import datetime
from functools import wraps

import requests
from flask import Flask, render_template, render_template_string, request, redirect, url_for, session, jsonify

app = Flask(__name__)

# Chave de sessão do Flask. Em produção defina a variável de ambiente
# SHADOW_SECRET_KEY. Se não existir, uma chave aleatória é gerada
# (mas ela muda toda vez que o app reinicia, o que derruba sessões antigas).
app.secret_key = os.environ.get("SHADOW_SECRET_KEY", secrets.token_hex(32))

# Usuário e senha do painel. Configure via variáveis de ambiente
# SHADOW_USER e SHADOW_PASS. Se não configurar, usa os valores padrão abaixo
# (troque-os antes de publicar o projeto).
SHADOW_USER = os.environ.get("SHADOW_USER", "admin")
SHADOW_PASS = os.environ.get("SHADOW_PASS", "shadow123")

# Usuário com permissão de ver/apagar sessões ativas (por padrão, o mesmo do login).
SHADOW_ADMIN = os.environ.get("SHADOW_ADMIN", SHADOW_USER)

# Registro de sessões ativas na memória do servidor.
SESSIONS = {}

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        sid = session.get("sid")
        if not session.get("logged_in") or sid not in SESSIONS:
            session.clear()
            return jsonify({"erro": "Não autenticado."}), 401
        SESSIONS[sid]["ultimo_acesso"] = datetime.now().strftime("%d/%m %H:%M:%S")
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in") or session.get("usuario") != SHADOW_ADMIN:
            return "Acesso negado.", 403
        return view(*args, **kwargs)
    return wrapped


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", logged_in=session.get("logged_in", False), erro=None)


@app.route("/login", methods=["POST"])
def login():
    usuario = request.form.get("usuario", "")
    senha = request.form.get("senha", "")

    usuario_ok = secrets.compare_digest(usuario, SHADOW_USER)
    senha_ok = secrets.compare_digest(senha, SHADOW_PASS)

    if usuario_ok and senha_ok:
        sid = secrets.token_hex(16)
        agora = datetime.now().strftime("%d/%m %H:%M:%S")
        SESSIONS[sid] = {
            "usuario": usuario,
            "ip": request.remote_addr,
            "login_em": agora,
            "ultimo_acesso": agora,
        }
        session["logged_in"] = True
        session["usuario"] = usuario
        session["sid"] = sid
        return redirect(url_for("index"))

    return render_template("index.html", logged_in=False, erro="Usuário ou senha incorretos.")


@app.route("/logout")
def logout():
    SESSIONS.pop(session.get("sid"), None)
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# APIs do painel (todas exigem login)
# ---------------------------------------------------------------------------

@app.route("/api/email-gerador", methods=["POST"])
@login_required
def api_email_gerador():
    """[01] Gera um e-mail fictício e uma senha aleatória para testes."""
    nome = ''.join(random.choices(string.ascii_lowercase, k=7))
    numero = ''.join(random.choices(string.digits, k=3))
    dominio = random.choice(["@exemplo.com", "@teste.dev", "@mailteste.com"])
    email = f"{nome}{numero}{dominio}"
    alfabeto = string.ascii_letters + string.digits + "!@#$%*"
    senha = ''.join(random.choices(alfabeto, k=12))
    return jsonify({"email": email, "senha": senha})


# --- [02] Calculadora segura (sem usar eval) --------------------------------

_OPERADORES_PERMITIDOS = (
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Pow,
    ast.USub, ast.UAdd, ast.Mod, ast.FloorDiv,
)


def _avaliar_no(no):
    if isinstance(no, ast.Expression):
        return _avaliar_no(no.body)

    if isinstance(no, ast.Constant) and isinstance(no.value, (int, float)):
        return no.value

    if isinstance(no, ast.UnaryOp) and isinstance(no.op, _OPERADORES_PERMITIDOS):
        valor = _avaliar_no(no.operand)
        return -valor if isinstance(no.op, ast.USub) else +valor

    if isinstance(no, ast.BinOp) and isinstance(no.op, _OPERADORES_PERMITIDOS):
        esquerda = _avaliar_no(no.left)
        direita = _avaliar_no(no.right)
        if isinstance(no.op, ast.Add):
            return esquerda + direita
        if isinstance(no.op, ast.Sub):
            return esquerda - direita
        if isinstance(no.op, ast.Mult):
            return esquerda * direita
        if isinstance(no.op, ast.Div):
            return esquerda / direita
        if isinstance(no.op, ast.FloorDiv):
            return esquerda // direita
        if isinstance(no.op, ast.Mod):
            return esquerda % direita
        if isinstance(no.op, ast.Pow):
            if abs(direita) > 1000:
                raise ValueError("Expoente muito grande.")
            return esquerda ** direita

    raise ValueError("Expressão contém termos não permitidos.")


def avaliar_expressao(expressao: str):
    arvore = ast.parse(expressao, mode="eval")
    return _avaliar_no(arvore)


@app.route("/api/calculadora", methods=["POST"])
@login_required
def api_calculadora():
    dados = request.get_json(silent=True) or {}
    expressao = str(dados.get("expressao", "")).strip()

    if not expressao or len(expressao) > 200:
        return jsonify({"erro": "Expressão inválida."}), 400

    try:
        resultado = avaliar_expressao(expressao)
        return jsonify({"resultado": resultado})
    except (ValueError, SyntaxError, ZeroDivisionError, TypeError) as exc:
        return jsonify({"erro": f"Erro: {exc}"}), 400


# --- [03] Verificação de headers HTTP ---------------------------------------

_HEADERS_ESPERADOS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]


@app.route("/api/headers", methods=["POST"])
@login_required
def api_headers():
    dados = request.get_json(silent=True) or {}
    alvo = str(dados.get("url", "")).strip()

    if not re.match(r"^https?://[\w\-.]+(:\d+)?(/.*)?$", alvo):
        return jsonify({"erro": "Informe uma URL válida começando com http:// ou https://"}), 400

    try:
        resposta = requests.get(alvo, timeout=6)
    except requests.RequestException as exc:
        return jsonify({"erro": f"Não foi possível acessar a URL: {exc}"}), 400

    presentes = []
    ausentes = []
    for nome in _HEADERS_ESPERADOS:
        if nome in resposta.headers:
            presentes.append({"nome": nome, "valor": resposta.headers[nome]})
        else:
            ausentes.append(nome)

    return jsonify({
        "status_code": resposta.status_code,
        "presentes": presentes,
        "ausentes": ausentes,
    })


# --- [04] Consulta de DNS / IP / DNS reverso --------------------------------

@app.route("/api/dns", methods=["POST"])
@login_required
def api_dns():
    dados = request.get_json(silent=True) or {}
    dominio = str(dados.get("dominio", "")).strip()

    if not re.match(r"^[a-zA-Z0-9.\-]+$", dominio):
        return jsonify({"erro": "Informe um domínio válido (ex: exemplo.com)."}), 400

    resultado = {"dominio": dominio}
    try:
        ip = socket.gethostbyname(dominio)
        resultado["ip"] = ip
    except socket.gaierror:
        return jsonify({"erro": "Não foi possível resolver esse domínio."}), 400

    try:
        resultado["dns_reverso"] = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        resultado["dns_reverso"] = "Não disponível para este IP."

    return jsonify(resultado)

# --- [13] Rastreador de IP (geolocalização aproximada via ipinfo.io) -------

@app.route("/api/ip-tracker", methods=["POST"])
@login_required
def api_ip_tracker():
    dados = request.get_json(silent=True) or {}
    ip = str(dados.get("ip", "")).strip()

    if not re.match(r"^[a-fA-F0-9.:]+$", ip):
        return jsonify({"erro": "Informe um endereço IP válido."}), 400

    try:
        resposta = requests.get(f"https://ipinfo.io/{ip}/json", timeout=6)
        info = resposta.json()
    except (requests.RequestException, ValueError) as exc:
        return jsonify({"erro": f"Não foi possível consultar esse IP: {exc}"}), 400

    if "loc" not in info:
        return jsonify({"erro": info.get("error", {}).get("message", "IP não encontrado ou sem dados de localização.")}), 400

    latitude, longitude = info["loc"].split(",")

    return jsonify({
        "ip": info.get("ip"),
        "cidade": info.get("city"),
        "regiao": info.get("region"),
        "pais": info.get("country"),
        "latitude": latitude,
        "longitude": longitude,
        "provedor": info.get("org"),
        "mapa_url": f"https://www.google.com/maps?q={latitude},{longitude}",
    })

# --- [05] Consulta CNPJ (dados públicos da Receita Federal via BrasilAPI) --

@app.route("/api/cnpj", methods=["POST"])
@login_required
def api_cnpj():
    dados = request.get_json(silent=True) or {}
    cnpj = re.sub(r"\D", "", str(dados.get("cnpj", "")))

    if len(cnpj) != 14:
        return jsonify({"erro": "CNPJ deve ter 14 dígitos (só números)."}), 400

    try:
        resposta = requests.get(f"https://brasilapi.com.br/api/cnpj/v1/{cnpj}", timeout=8)
    except requests.RequestException as exc:
        return jsonify({"erro": f"Não foi possível consultar: {exc}"}), 400

    if resposta.status_code != 200:
        return jsonify({"erro": "CNPJ não encontrado ou inválido."}), 400

    info = resposta.json()
    endereco = f"{info.get('logradouro', '')}, {info.get('numero', '')} - {info.get('municipio', '')}/{info.get('uf', '')}"

    return jsonify({
        "razao_social": info.get("razao_social"),
        "nome_fantasia": info.get("nome_fantasia") or "-",
        "situacao": info.get("descricao_situacao_cadastral"),
        "abertura": info.get("data_inicio_atividade"),
        "atividade_principal": info.get("cnae_fiscal_descricao"),
        "endereco": endereco,
        "telefone": info.get("ddd_telefone_1") or "-",
        "capital_social": info.get("capital_social"),
    })

if __name__ == "__main__":
    porta = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=porta, debug=False)
    
