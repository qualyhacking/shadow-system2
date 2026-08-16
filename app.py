from flask import Flask, render_template, request, redirect, session
import os

app = Flask(__name__)

# Troque por uma chave aleatória antes de publicar
app.secret_key = os.environ.get("SECRET_KEY", "chave-de-teste-shadow")

USUARIO = os.environ.get("SHADOW_USER", "lucas")
SENHA = os.environ.get("SHADOW_PASSWORD", "1234")


@app.route("/", methods=["GET", "POST"])
def login():
    erro = None

    if request.method == "POST":
        usuario = request.form.get("usuario", "")
        senha = request.form.get("senha", "")

        if usuario == USUARIO and senha == SENHA:
            session["logado"] = True
            return redirect("/painel")

        erro = "Usuário ou senha incorretos."

    return render_template("index.html", erro=erro)


@app.route("/painel")
def painel():
    if not session.get("logado"):
        return redirect("/")

    return """
    <html>
        <head>
            <title>SHADOW SYSTEM</title>
        </head>
        <body>
            <h1>SHADOW SYSTEM</h1>
            <p>Login realizado com sucesso.</p>
            <p>Painel conectado.</p>
        </body>
    </html>
    """


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
