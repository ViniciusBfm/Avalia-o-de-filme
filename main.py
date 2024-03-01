from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
from werkzeug.utils import secure_filename
import base64
from datetime import datetime
import random
import string
from flask_mail import Message, Mail
from config import email,senha
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'site_pega_visao'  # Chave secreta para o uso do session

# Configuração do Flask-Mail para o Gmail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = email
app.config['MAIL_PASSWORD'] = senha

mail = Mail(app)

def create_connection():
    conn = sqlite3.connect('pegavisao.db')
    return conn

# Função para converter a string em float
def str_to_float(value):
    try:
        return float(value)
    except ValueError:
        return 0.0  # Ou qualquer valor padrão que você queira

#gerar uma senha aleatória
def gerar_nova_senha():
    caracteres = string.ascii_letters + string.digits
    nova_senha = ''.join(random.choice(caracteres) for _ in range(6))
    return nova_senha

# Função para enviar um email com a nova senha
def enviar_email_senha(nome, email, nova_senha):
    msg = Message('Nova Senha', sender='your-email@example.com', recipients=[email])
    msg.body = f"Olá {nome},\n\nSua nova senha é: {nova_senha}\n\nAtenciosamente,\nSua Equipe de Suporte"
    mail.send(msg)

# Função para atualizar a senha de um usuário no banco de dados
def atualizar_senha(email, nova_senha):
    with create_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE usuarios SET senha = ? WHERE email = ?', (nova_senha, email))
        conn.commit()

@app.route("/", methods=["GET", "POST"])
@app.route("/home", methods=["GET", "POST"])
def home():
    tipos = ["Filme", "Serie"]  # Lista de opções para o tipo
    user_function = get_user_function()
    user_logged_in = 'user_id' in session
    user_name = session.get('user_name', '')  # Obtém o nome do usuário da sessão

    if user_function == 'admin':  # Verifica se o usuário é administrador
        if request.method == "POST":
            tipo = request.form["tipo"]
            titulo = request.form["titulo"]
            ano = request.form["ano"]
            dia_assistido = request.form["dia_assistido"]
            avaliacao = request.form["avaliacao"]
            opiniao = request.form["opiniao"]
            capa = request.files["capa"]  # Obtém o arquivo da capa

            # Salvar a capa no banco de dados
            if capa.filename != '':
                capa_base64 = base64.b64encode(capa.read()).decode('utf-8')
            else:
                flash('Selecione um arquivo de imagem para a capa.', 'error')
                return redirect(url_for('home'))

            # Inserir os dados do filme ou série no banco de dados
            with create_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO filmesseries (tipo, titulo, ano, dia_assistido, avaliacao, opiniao, capa)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (tipo, titulo, ano, dia_assistido, avaliacao, opiniao, capa_base64))
                conn.commit()

            flash('Filme ou série adicionado com sucesso!', 'success')
            return redirect(url_for('home'))
        
    
    # Recupera os dados dos filmes ou séries do banco de dados
    with create_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM filmesseries WHERE tipo = "Filme" ORDER BY id DESC LIMIT 6')
        fimes_recentes = cursor.fetchall()
    
    with create_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM filmesseries WHERE tipo = "Serie" ORDER BY id DESC LIMIT 6')
        series_recentes = cursor.fetchall()


    with sqlite3.connect('pegavisao.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT email FROM usuarios')
        usuario_email = [row[0] for row in cursor.fetchall()]
                         

    return render_template('pagina_inicial.html', user_function=user_function, user_logged_in=user_logged_in, user_name=user_name, usuario_email=usuario_email, tipos=tipos, fimes_recentes=fimes_recentes, series_recentes=series_recentes, str_to_float=str_to_float)

@app.route("/remover_filme/<int:filme_id>", methods=["POST"])
def remover_filme(filme_id):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM filmesseries WHERE id = ?', (filme_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('home'))

def get_user_function():
    if 'user_id' in session:
        user_id = session['user_id']
        with create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT nome, funcao FROM usuarios WHERE id = ?', (user_id,))
            user_data = cursor.fetchone()
            if user_data:
                user_name, user_function = user_data
                return user_function

    return 'visitante'

@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    # Defina os valores padrão para os campos
    nome = ''
    email = ''
    # Permitir que apenas visitantes acessem a página de cadastro
    if get_user_function() != 'visitante':
        return redirect(url_for('home'))

    funcoes = ["comentarista", "admin"]  # Defina os tipos de função disponíveis
    if request.method == "POST":
        nome = request.form["nome"].lower()
        email = request.form["email"].lower()
        senha = request.form["senha"]
        funcao = request.form["funcao"]

        # Verificar se o email já está cadastrado
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM usuarios WHERE email = ?', (email,))
        existing_user = cursor.fetchone()
        conn.close()

        if existing_user:
            flash('Email já cadastrado. Por favor, escolha outro email.', 'error')
        if len(senha) < 8 or not any(char.isalpha() for char in senha) or not any(char.isdigit() for char in senha):
            flash('A senha deve ter pelo menos 8 caracteres, incluindo letras e números.', 'error')
        else:
            # Inserir o novo usuário apenas se o email não estiver cadastrado e a senha for válida
            conn = create_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO usuarios (email, nome, funcao, senha)
                VALUES (?,?, ?, ?)
            ''', (email,nome, funcao, senha))
            conn.commit()
            conn.close()

            flash('Cadastro realizado com sucesso!', 'success')
            return redirect(url_for('login'))

    # Se houver um erro, devolva os valores dos campos de formulário
    return render_template('cadastro.html', funcoes=funcoes, nome=nome, email=email)

@app.route("/login", methods=["GET", "POST"])
def login():
    message = ''
    if request.method == "POST":
        email = request.form["email"].lower()
        senha = request.form["senha"]
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, nome, funcao FROM usuarios WHERE email = ? AND senha = ?
        ''', (email, senha))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['user_id'] = user[0]  # Armazenar o ID do usuário na sessão
            session['user_name'] = user[1]  # Armazena o nome do usuário na sessão
            session['user_function'] = user[2]  # Armazena a função do usuário na sessão
            return redirect(url_for('home'))
        else:
            message = 'Email ou senha incorretos. Tente novamente.'
            return redirect(url_for('home', message=message))

    return render_template('pagina_inicial.html', message=message)

@app.route("/logout", methods=["POST"])
def logout():
    # Remover o ID do usuário da sessão ao fazer logout
    session.pop('user_id', None)
    return redirect(url_for('home'))

# Rota para redefinir a senha
@app.route('/redefinir-senha', methods=['GET', 'POST'])
def redefinir_senha():
    if request.method == 'POST':
        email = request.form['email']
        
        # Verificar se o email existe na base de dados
        with create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM usuarios WHERE email = ?', (email,))
            usuario = cursor.fetchone()

        if usuario:
            nova_senha = gerar_nova_senha()
            atualizar_senha(email, nova_senha)
            enviar_email_senha(usuario[1], email, nova_senha)
            mensagem = "Uma nova senha foi enviada para o seu email."

            return render_template("pagina_inicial.html")
        else:
            mensagem = "Email não encontrado."

        return render_template("esqueci_minha_senha.html", mensagem=mensagem)

    return render_template("esqueci_minha_senha.html")

@app.route('/alterar-senha', methods=['GET', 'POST'])
def alterar_senha():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        senha_atual = request.form['senha_atual']
        nova_senha = request.form['nova_senha']

        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT senha FROM usuarios WHERE id = ?', (session['user_id'],))
        usuario = cursor.fetchone()

        if not usuario or not check_password_hash(usuario[0], senha_atual):
            flash('Senha atual incorreta', 'error')
            return redirect(url_for('alterar_senha'))

        # Atualiza a senha no banco de dados
        nova_hash_senha = generate_password_hash(nova_senha)
        cursor.execute('UPDATE usuarios SET senha = ? WHERE id = ?', (nova_hash_senha, session['user_id']))
        conn.commit()
        conn.close()

        flash('Senha alterada com sucesso', 'success')
        return redirect(url_for('home'))

    return render_template('pagina_inicial.html')

@app.route("/filmes")
def filmes():
    user_function = get_user_function()
    user_logged_in = 'user_id' in session
    user_name = session.get('user_name', '') 
    with create_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM filmesseries ORDER BY id DESC')
        filmes_series = cursor.fetchall()

    cursor.execute('''
        SELECT * FROM filmesseries
        WHERE tipo = 'Filme'
        ORDER BY CAST(avaliacao AS REAL) DESC
    ''')
    filmes_mais_avaliados = cursor.fetchall()

    return render_template('filmes.html',  filmes_series=filmes_series,user_function=user_function,filmes_mais_avaliados=filmes_mais_avaliados, str_to_float=str_to_float, user_logged_in=user_logged_in, user_name=user_name)

@app.route("/series")
def series():
    user_function = get_user_function()
    user_logged_in = 'user_id' in session
    user_name = session.get('user_name', '')
    with create_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM filmesseries ORDER BY id DESC')
        filmes_series = cursor.fetchall() 

    cursor.execute('''
        SELECT * FROM filmesseries
        WHERE tipo = 'Serie'
        ORDER BY CAST(avaliacao AS REAL) DESC
    ''')
    filmes_mais_avaliados = cursor.fetchall()


    return render_template('series.html',  filmes_series=filmes_series, filmes_mais_avaliados=filmes_mais_avaliados, user_function=user_function, str_to_float=str_to_float, user_logged_in=user_logged_in, user_name=user_name)

@app.route("/remover_comentario/<int:comentario_id>", methods=["POST"])
def remover_comentario(comentario_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user_function = get_user_function()

    with create_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT usuario_id FROM comentarios WHERE id = ?', (comentario_id,))
        comentario = cursor.fetchone()

        # Verifica se o usuário é o dono do comentário ou um admin
        if comentario and (user_function == 'admin' or comentario[0] == user_id):
            cursor.execute('DELETE FROM comentarios WHERE id = ?', (comentario_id,))
            conn.commit()
            flash('Comentário removido com sucesso.', 'success')
        else:
            flash('Você não tem permissão para remover este comentário.', 'danger')

    return redirect(url_for('detalhes', filme_id=request.form['filme_id']))

@app.route("/adicionar_comentario/<int:filme_id>", methods=["POST"])
def adicionar_comentario(filme_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    comentario = request.form['comentario']
    data_comentario = int(datetime.now().timestamp())  # Timestamp UNIX atual

    with create_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT nome FROM usuarios WHERE id = ?', (user_id,))
        nome_usuario = cursor.fetchone()[0]  # Obtém o nome do usuário
        cursor.execute('INSERT INTO comentarios (filme_id, usuario_id, nome_usuario, comentario, data_comentario) VALUES (?, ?, ?, ?, ?)', (filme_id, user_id, nome_usuario, comentario, data_comentario))
        conn.commit()

    return redirect(url_for('detalhes', filme_id=filme_id))

@app.route("/detalhes/<int:filme_id>", methods=["GET", "POST"])
def detalhes(filme_id):
    with create_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM filmesseries WHERE id = ?', (filme_id,))
        filme_serie = cursor.fetchone()

        cursor.execute('''
            SELECT comentarios.*, usuarios.nome as nome_usuario
            FROM comentarios
            INNER JOIN usuarios ON comentarios.usuario_id = usuarios.id
            WHERE comentarios.filme_id = ?
            ORDER BY comentarios.data_comentario DESC
        ''', (filme_id,))
        comentarios = cursor.fetchall()

    tipos = ["Filme", "Serie"]
    user_logged_in = 'user_id' in session
    user_name = session.get('user_name', '')
    user_function = get_user_function()

    if not filme_serie:
        return "Filme ou série não encontrado."

    if request.method == "POST":
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user_id = session['user_id']
        comentario = request.form['comentario']

        with create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT nome FROM usuarios WHERE id = ?', (user_id,))
            nome_usuario = cursor.fetchone()[0]  # Obtém o nome do usuário
            cursor.execute('INSERT INTO comentarios (filme_id, usuario_id, nome_usuario, comentario) VALUES (?, ?, ?, ?)', (filme_id, user_id, nome_usuario, comentario))
            conn.commit()
        return redirect(url_for('detalhes', filme_id=filme_id))

    return render_template('detalhes_filme.html', filme_serie=filme_serie, user_function=user_function, str_to_float=str_to_float, user_logged_in=user_logged_in, user_name=user_name, tipos=tipos, comentarios=comentarios)

@app.route("/pesquisar", methods=["GET"])
def pesquisar():
    termo_pesquisa = request.args.get('termo_pesquisa', '')

    print(termo_pesquisa)

    resultados = []  # Inicializa resultados como uma lista vazia

    if termo_pesquisa:
        with create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM filmesseries WHERE titulo LIKE ?', ('%' + termo_pesquisa + '%',))
            resultados = cursor.fetchall()

    user_logged_in = 'user_id' in session
    user_name = session.get('user_name', '')
    user_function = get_user_function()

    return render_template('resultado_pesquisa.html', resultados=resultados, str_to_float=str_to_float, termo_pesquisa=termo_pesquisa, user_logged_in=user_logged_in, user_name=user_name, user_function=user_function)


if __name__ == '__main__':
    # Criar tabela de usuários se não existir
    with create_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                funcao TEXT NOT NULL,
                senha TEXT NOT NULL,
                email TEXT NOT NULL
            );
        ''')
        conn.commit()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS filmesseries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tipo TEXT NOT NULL,
                titulo TEXT NOT NULL,
                ano TEXT NOT NULL,
                dia_assistido TEXT NOT NULL,
                avaliacao INTEGER NOT NULL,
                opiniao TEXT NOT NULL,
                capa TEXT NOT NULL,
                comentarios TEXT DEFAULT 'Nenhum comentário disponível.'
            );
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS comentarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT, --0
                filme_id INTEGER NOT NULL, --1
                usuario_id INTEGER NOT NULL, --2
                nome_usuario TEXT, --3
                comentario TEXT NOT NULL, --4
                data_comentario TEXT,  --5 
                FOREIGN KEY(filme_id) REFERENCES filmesseries(id), --6
                FOREIGN KEY(usuario_id) REFERENCES usuarios(id) --7
            );
        ''')





        conn.commit()
    app.run(debug=True)
