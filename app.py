import os
import re
import ast
import random
import string
import socket
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

import requests
from flask import Flask, render_template, render_template_string, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)


def obter_ip_real():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr

# Chave de sessão do Flask. Em produção defina a variável de ambiente
# SHADOW_SECRET_KEY. Se não existir, uma chave aleatória é gerada
# (mas ela muda toda vez que o app reinicia, o que derruba sessões antigas).
app.secret_key = os.environ.get("SHADOW_SECRET_KEY", secrets.token_hex(32))

# Usuário e senha do painel. Configure via variáveis de ambiente
# SHADOW_USER e SHADOW_PASS. Se não configurar, usa os valores padrão abaixo
# (troque-os antes de publicar o projeto).
SHADOW_USER = os.environ.get("SHADOW_USER", "admin")
SHADOW_PASS = os.environ.get("SHADOW_PASS", "shadow123")

# Usuário com permissão de administrar (ver sessões, criar clientes novos).
SHADOW_ADMIN = os.environ.get("SHADOW_ADMIN", SHADOW_USER)

# Registro de sessões ativas na memória do servidor.
SESSIONS = {}

# Cadastro de usuários (você = admin, sem expiração; clientes = com prazo).
# ATENÇÃO: fica na memória do servidor — se o site reiniciar, essa lista
# zera e volta só o admin. Ok para essa fase manual/teste do projeto.
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")

def _supabase_headers():
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
    }


def carregar_usuarios():
    usuarios = {
        SHADOW_USER: {"senha_hash": generate_password_hash(SHADOW_PASS), "expira_em": None}
    }
    if not SUPABASE_URL or not SUPABASE_KEY:
        return usuarios
    try:
        resp = requests.get(
            f"{SUPABASE_URL}/rest/v1/clientes",
            headers=_supabase_headers(),
            params={"select": "*"},
            timeout=8,
        )
        resp.raise_for_status()
        for linha in resp.json():
            expira = linha.get("expira_em")
            expira_dt = None
            if expira:
                expira_dt = datetime.fromisoformat(expira)
                if expira_dt.tzinfo is None:
                    expira_dt = expira_dt.replace(tzinfo=timezone.utc)
            usuarios[linha["usuario"]] = {
                "senha_hash": linha["senha_hash"],
                "expira_em": expira_dt,
            }
    except requests.RequestException:
        pass
    return usuarios

def salvar_usuario_supabase(usuario, senha_hash, expira_em):
    if not SUPABASE_URL or not SUPABASE_KEY:
        return
    payload = {
        "usuario": usuario,
        "senha_hash": senha_hash,
        "expira_em": expira_em.isoformat() if expira_em else None,
    }
    requests.post(
        f"{SUPABASE_URL}/rest/v1/clientes",
        headers=_supabase_headers(),
        json=payload,
        timeout=8,
    )


USUARIOS = carregar_usuarios()

PLANOS = {
    "teste3": {"nome": "Teste 3 dias",      "dias": 3,  "preco": 20},
    "dez":    {"nome": "10 dias",           "dias": 10, "preco": 30},
    "quinze": {"nome": "15 dias",           "dias": 15, "preco": 40},
    "vinte":  {"nome": "20 dias",           "dias": 20, "preco": 45},
    "mes":    {"nome": "1 mês (30 dias)",   "dias": 30, "preco": 50},
}

WHATSAPP_NUMERO = "5588981785355"

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
    return render_template("index.html", logged_in=session.get("logged_in", False), erro=None, planos=PLANOS, whatsapp=WHATSAPP_NUMERO)


@app.route("/login", methods=["POST"])
def login():
    usuario = request.form.get("usuario", "")
    senha = request.form.get("senha", "")

    conta = USUARIOS.get(usuario)

    if not conta or not check_password_hash(conta["senha_hash"], senha):
        return render_template("index.html", logged_in=False, erro="Usuário ou senha incorretos.", planos=PLANOS, whatsapp=WHATSAPP_NUMERO)

    if conta["expira_em"] and datetime.now(timezone.utc) > conta["expira_em"]:
        return render_template("index.html", logged_in=False, erro="Seu acesso expirou. Fale com o suporte para renovar.", planos=PLANOS, whatsapp=WHATSAPP_NUMERO)

    sid = secrets.token_hex(16)
    agora = datetime.now().strftime("%d/%m %H:%M:%S")
    ip_real = obter_ip_real()
    dispositivo = request.headers.get("User-Agent", "Desconhecido")

    localizacao = "Desconhecida"
    try:
        geo = requests.get(f"https://ipinfo.io/{ip_real}/json", timeout=4).json()
        cidade = geo.get("city", "")
        pais = geo.get("country", "")
        if cidade or pais:
            localizacao = f"{cidade or '?'} / {pais or '?'}"
    except requests.RequestException:
        pass

    SESSIONS[sid] = {
        "usuario": usuario,
        "ip": ip_real,
        "localizacao": localizacao,
        "dispositivo": dispositivo,
        "login_em": agora,
        "ultimo_acesso": agora,
    }
    session["logged_in"] = True
    session["usuario"] = usuario
    session["sid"] = sid
    return redirect(url_for("index"))


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


# --- Simulação de consulta (dados fictícios) --------------------------------
# ATENÇÃO: URL_SIMULACAO ainda não configurada. Preencher só depois de
# confirmar que é uma API própria com dados 100% fictícios.
URL_SIMULACAO = "http://dabsistemas.saude.gov.br/sistemas/sadab/js/buscar_cpf_dbpessoa.json.php?cpf=..." # <- cola aqui a URL quando tiver, ex: "https://meusite.com/api/fake"


@app.route("/api/simulacao-cpf", methods=["POST"])
@login_required
def api_simulacao_cpf():
    dados_form = request.get_json(silent=True) or {}
    cpf = str(dados_form.get("cpf", "")).strip()

    if not URL_SIMULACAO:
        return jsonify({"erro": "URL da simulação ainda não configurada."}), 400

    try:
        resposta = requests.get(URL_SIMULACAO, params={"cpf": cpf}, timeout=8)
        resposta.raise_for_status()
        info = resposta.json()
    except (requests.RequestException, ValueError) as exc:
        return jsonify({"erro": f"Não foi possível consultar: {exc}"}), 400

    return jsonify({
        "aviso": "DADOS FICTÍCIOS — SIMULAÇÃO",
        "cpf": info.get("cpf", "-"),
        "nome": info.get("nome", "-"),
        "nascimento": info.get("nascimento", "-"),
        "mae": info.get("mae", "-"),
    })


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

_ADMIN_HTML = """
<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SHADOW SYSTEM — ADMIN</title>
<style>
  body { background:#0a0a0a; color:#33ff33; font-family:"Courier New",monospace; margin:0; padding:16px; }
  h1 { color:#0f0; text-shadow:0 0 6px #0f08; font-size:20px; }
  table { width:100%; border-collapse: collapse; margin-top:16px; font-size:12.5px; }
  th, td { border:1px solid #1f5f1f; padding:8px; text-align:left; word-break:break-word; }
  th { background:#0f2a0f; }
  tr.atual { background:#0f2a0f55; }
  form { display:inline; }
  button { background:#2a0f0f; color:#ff8888; border:1px solid #5f1f1f; border-radius:4px; padding:6px 10px; font-family:inherit; }
  a.voltar { color:#7dff7d; text-decoration:none; display:inline-block; margin-top:16px; }
</style>
</head>
<body>
  <h1>&gt; PAINEL ADMIN — SESSÕES ATIVAS</h1>
  <table>
    <tr><th>Usuário</th><th>IP</th><th>Local</th><th>Dispositivo</th><th>Login em</th><th>Último acesso</th><th>Ação</th></tr>
    {% for sid, dados in sessoes.items() %}
    <tr class="{{ 'atual' if sid == sid_atual else '' }}">
      <td>{{ dados.usuario }}{% if sid == sid_atual %} (você){% endif %}</td>
      <td>{{ dados.ip }}</td>
      <td>{{ dados.localizacao }}</td>
      <td style="font-size:10px;">{{ dados.dispositivo }}</td>
      <td>{{ dados.login_em }}</td>
      <td>{{ dados.ultimo_acesso }}</td>
      <td>
        <form method="POST" action="{{ url_for('admin_revogar', sid=sid) }}" onsubmit="return confirm('Apagar esta sessão?');">
          <button type="submit">APAGAR</button>
        </form>
      </td>
    </tr>
    {% endfor %}
  </table>
  <h1 style="margin-top:30px;">&gt; CADASTRAR CLIENTE NOVO</h1>
  <form method="POST" action="{{ url_for('admin_criar_cliente') }}" style="max-width:320px; margin-top:12px;">
    <label style="font-size:13px;">Usuário</label><br>
    <input type="text" name="usuario" required style="width:100%; background:#000; color:#33ff33; border:1px solid #1f5f1f; padding:8px; margin-top:4px; margin-bottom:10px;"><br>
    <label style="font-size:13px;">Senha</label><br>
    <input type="text" name="senha" required style="width:100%; background:#000; color:#33ff33; border:1px solid #1f5f1f; padding:8px; margin-top:4px; margin-bottom:10px;"><br>
    <label style="font-size:13px;">Plano</label><br>
    <select name="plano" style="width:100%; background:#000; color:#33ff33; border:1px solid #1f5f1f; padding:8px; margin-top:4px; margin-bottom:10px;">
      {% for id, p in planos.items() %}
      <option value="{{ id }}">{{ p.nome }} — R$ {{ p.preco }}</option>
      {% endfor %}
    </select><br>
    <button type="submit" style="background:#0f2a0f; color:#33ff33; border:1px solid #1f5f1f; padding:10px; width:100%;">CRIAR ACESSO</button>
  </form>

  <h1 style="margin-top:30px;">&gt; CLIENTES CADASTRADOS</h1>
  <table>
    <tr><th>Usuário</th><th>Expira em</th></tr>
    {% for u, dados in usuarios.items() %}
    <tr>
      <td>{{ u }}</td>
      <td>{{ dados.expira_em.strftime('%d/%m/%Y %H:%M') if dados.expira_em else 'Nunca (admin)' }}</td>
    </tr>
    {% endfor %}
  </table>
  <a class="voltar" href="{{ url_for('index') }}">&larr; Voltar ao painel</a>
</body>
</html>
"""


@app.route("/admin")
@admin_required
def admin_painel():
    return render_template_string(_ADMIN_HTML, sessoes=SESSIONS, sid_atual=session.get("sid"), usuarios=USUARIOS, planos=PLANOS)


@app.route("/admin/revogar/<sid>", methods=["POST"])
@admin_required
def admin_revogar(sid):
    SESSIONS.pop(sid, None)
    return redirect(url_for("admin_painel"))
    
@app.route("/admin/criar-cliente", methods=["POST"])
@admin_required
def admin_criar_cliente():
    usuario = request.form.get("usuario", "").strip()
    senha = request.form.get("senha", "").strip()
    plano_id = request.form.get("plano", "")

    if not usuario or not senha or plano_id not in PLANOS:
        return "Dados inválidos.", 400

    if usuario in USUARIOS:
        return "Esse usuário já existe.", 400

    dias = PLANOS[plano_id]["dias"]
    senha_hash = generate_password_hash(senha)
    expira_em = datetime.now(timezone.utc) + timedelta(days=dias)
    USUARIOS[usuario] = {"senha_hash": senha_hash, "expira_em": expira_em}
    salvar_usuario_supabase(usuario, senha_hash, expira_em)
    return redirect(url_for("admin_painel"))

if __name__ == "__main__":
    porta = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=porta, debug=False)
    
