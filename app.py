from werkzeug.security import check_password_hash, generate_password_hash
from flask import Flask, render_template, redirect, render_template_string, request, flash, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from config import Config
from models import db, User, Question, UserAnswer
import random
import string
from flask_migrate import Migrate
from datetime import datetime, timedelta
import json
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from urllib.parse import urlparse, urljoin

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import logout_user

def generate_identifiant():
    while True:
        identifiant = ''.join(random.choices(string.ascii_letters + string.digits, k=15))
        if not User.query.filter_by(identifiant=identifiant).first():
            break
    return identifiant
# Configuration du Limiter

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz.db'
app.config['SECRET_KEY'] = 'votre_secret_key'
app.config.update(
    SESSION_COOKIE_SECURE=True,  # Le cookie sera envoyé uniquement en HTTPS
    REMEMBER_COOKIE_SECURE=True,  # Le cookie "se souvenir de moi" sera aussi sécurisé
    SESSION_COOKIE_HTTPONLY=True,  # Empêche l'accès au cookie via JavaScript
    SESSION_COOKIE_SAMESITE='Strict'  # Limite l'envoi du cookie aux requêtes provenant du même site
)
# Configuration du Limiter
limiter = Limiter(
    get_remote_address,  # Utilise l'adresse IP du client
    app=app,  # Lie le limiter à l'application Flask
    default_limits=["100 per hour"]  # Limite par défaut : 100 requêtes par heure
)
db.init_app(app)
migrate = Migrate(app, db)  # Initialisation de Flask-Migrate
app.config.from_object(Config)
mail = Mail(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@app.route('/')
def home():
    return render_template('login.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("30 per minute")  # Limite pour prévenir les attaques par force brute
def login():
    if request.method == 'POST':
        identifiant = request.form['identifiant']
        password = request.form['password']

        # Chercher l'utilisateur par identifiant
        found_user = User.query.filter_by(identifiant=identifiant).first()

        # Vérification du mot de passe
        if found_user and check_password_hash(found_user.password, password):
            login_user(found_user)
            session['user_id'] = found_user.id  # Ajouter l'ID de l'utilisateur à la session

            # Vérification du rôle de l'utilisateur et redirection
            if found_user.role == 'admin':
                session['is_admin'] = True  # Définir is_admin dans la session pour les admins
                return redirect(url_for('admin_dashboard'))  # Si admin, rediriger vers admin_dashboard
            elif found_user.role == 'student':
                session['is_admin'] = False  # Définir is_admin comme False pour les étudiants
                return redirect(url_for('quiz'))  # Si étudiant, rediriger vers quiz.html
        else:
            flash("Identifiant ou mot de passe incorrect", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')


# Vérification de la sécurité de l'URL
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


@app.route('/logout')
def logout():
    logout_user()  # Déconnexion de l'utilisateur
    return redirect(url_for('login'))  # Redirection vers la page de connexion
@app.route('/student_results/<int:user_id>', methods=['GET'])
def student_results(user_id):
    # Vérifiez si l'utilisateur connecté est un admin
    if not session.get('is_admin', False):
        return redirect(url_for('login'))  # Si l'utilisateur n'est pas admin, rediriger vers login
    
    # Récupérer l'utilisateur (étudiant)
    user = User.query.filter_by(id=user_id).first()

    if not user:
        return redirect(url_for('login'))  # Si l'utilisateur n'existe pas, rediriger vers login

    # Récupérer toutes les questions du quiz
    questions = Question.query.all()
    
    # Récupérer les réponses de l'utilisateur
    user_answers = {}
    for question in questions:
        answer = UserAnswer.query.filter_by(user_id=user_id, question_id=question.id).first()
        if answer:
            user_answers[question.id] = answer.answer
    
    # Initialisation des variables pour le score total et le score par question
    total_score = 0
    total_questions = len(questions)  # Nombre total de questions
    
    # Calculer le score total
    for question in questions:
        user_answer = user_answers.get(question.id)
        if user_answer == question.correct_answer:
            total_score += 1

    # Passer les résultats et données au template
    return render_template('student_results.html', 
                           user=user, 
                           total_score=total_score, 
                           total_questions=total_questions, 
                           questions=questions, 
                           user_answers=user_answers)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        username = request.form['username']
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Cet email est déjà enregistré.", "danger")
            return redirect(url_for('register'))

        identifiant = generate_identifiant()
        hashed_password = generate_password_hash(password)
        new_user = User(email=email, username=username, identifiant=identifiant, password=hashed_password, role='admin')

        db.session.add(new_user)
        db.session.commit()

        flash("Compte administrateur créé avec succès !", "success")
        return redirect(url_for('login'))

    return render_template('register.html')
@app.route('/create_quiz', methods=['GET', 'POST'])
@login_required
def create_quiz():
    if request.method == 'POST':
        question_text = request.form['question_text']
        choices = request.form['choices'].split(',')
        correct_answer = request.form['correct_answer']
        block_number = request.form['block_number']  # Obtient le bloc de la question

        # Créer une nouvelle question dans la base de données
        question = Question(
            text=question_text,
            choices=choices,
            correct_answer=correct_answer,
            block_number=block_number
        )
        db.session.add(question)
        db.session.commit()

        flash("Question ajoutée avec succès!", "success")
        return redirect(url_for('create_quiz'))

    return render_template('create_quiz.html')


@app.route('/send_email/<int:user_id>', methods=['POST'])
def send_email(user_id):
    # Récupérer l'utilisateur dans la base de données
    user = User.query.get_or_404(user_id)

    # Si l'utilisateur n'a pas d'identifiant ou de mot de passe, on les régénère
    if not user.identifiant or not user.password:
        # Regénérer l'identifiant et le mot de passe
        user.identifiant = generate_identifiant()
        user.password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))

        # Sauvegarder les modifications dans la base de données
        db.session.commit()

    # Contenu HTML pour l'email
    html_content = render_template_string('''
        <!DOCTYPE html>
            <html lang="fr">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Accès à votre quiz en ligne</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #f4f4f9;
                        color: #333;
                        margin: 0;
                        padding: 0;
                    }
                    .container {
                        width: 100%;
                        max-width: 600px;
                        margin: 20px auto;
                        background-color: #ffffff;
                        padding: 20px;
                        border-radius: 8px;
                        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                    }
                    h1 {
                        color: #4CAF50;
                        font-size: 24px;
                        margin-bottom: 20px;
                    }
                    p {
                        font-size: 16px;
                        line-height: 1.6;
                    }
                    .button {
                        display: inline-block;
                        background-color: #4CAF50;
                        color: white;
                        padding: 10px 20px;
                        text-decoration: none;
                        font-weight: bold;
                        border-radius: 5px;
                        margin-top: 20px;
                    }
                    .button:hover {
                        background-color: #45a049;
                    }
                    .footer {
                        text-align: center;
                        margin-top: 30px;
                        font-size: 14px;
                        color: #777;
                    }
                </style>
            </head>
            <body>

                <div class="container">
                    <h1>Accès à votre quiz en ligne</h1>
                    <p>Bonjour {{ user.email }},</p>
                    <p>Nous avons le plaisir de vous informer que votre quiz en ligne est maintenant disponible. Veuillez vous connecter en utilisant les informations ci-dessous :</p>

                    <p><strong>Identifiant :</strong> {{ user.identifiant }}</p>
                    <p><strong>Mot de passe :</strong> {{ password }}</p>

                    <p>Pour accéder au quiz, cliquez sur le lien suivant :</p>

                    <a href="http://127.0.0.1:5000/login" class="button">Accéder au quiz</a>

                    <p><strong>Date limite :</strong> 2h</p>

                    <p>Si vous avez des questions ou rencontrez des problèmes, n'hésitez pas à nous contacter à [adresse email de contact] ou à répondre directement à cet email.</p>

                    <p>Bonne chance pour votre quiz !</p>

                    <div class="footer">
                        <p>Cordialement,</p>
                        <p>EL HOUZI Mohammed <br>Formateur<br> EFSA</p>
                    </div>
                </div>

            </body>
            </html>
    ''', user=user, password=user.password)

    # Création du message à envoyer
    msg = Message("Vos identifiants pour le quiz en ligne", 
                  sender="votre_email@gmail.com", 
                  recipients=[user.email])

    # Contenu HTML de l'email
    msg.html = html_content

    try:
        # Envoi de l'email
        mail.send(msg)

        # Mettre à jour le mot de passe après l'envoi de l'email
        user.password = generate_password_hash(user.password)  # Hash du mot de passe

        # Sauvegarder la mise à jour du mot de passe
        db.session.commit()

        # Mettre à jour le statut de l'email envoyé (si nécessaire)
        user.email_sent = True
        db.session.commit()

        # Message flash de succès
        flash("Email envoyé avec succès et mot de passe mis à jour!", "success")
        return redirect(url_for('admin_dashboard'))  # Rediriger vers le tableau de bord
    except Exception as e:
        # Gestion des erreurs d'envoi d'email
        flash(f"Une erreur est survenue lors de l'envoi de l'email: {e}", "danger")
        return redirect(url_for('admin_dashboard'))


@app.route('/add_email', methods=['GET', 'POST'])
@login_required
def add_email():
    new_email = request.form.get('email')
    if new_email:
        # Vérifier si l'email existe déjà
        existing_user = User.query.filter_by(email=new_email).first()
        if existing_user:
            flash("Cet email est déjà enregistré.", "danger")
            return redirect(url_for('admin_dashboard'))

        # Générer un mot de passe aléatoire et un identifiant

        # Créer un nouvel utilisateur
        new_student = User(email=new_email, role='student', username="nom_par_défaut")
        db.session.add(new_student)
        db.session.commit()

        # Affichage du contenu HTML avec les informations générées dans la page
        html_content = render_template_string('''
            <!DOCTYPE html>
            <html lang="fr">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #f4f4f9;
                        color: #333;
                        margin: 0;
                        padding: 0;
                    }
                    .container {
                        width: 100%;
                        max-width: 600px;
                        margin: 20px auto;
                        background-color: #ffffff;
                        padding: 20px;
                        border-radius: 8px;
                        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                    }
                    h1 {
                        color: #4CAF50;
                        font-size: 24px;
                        margin-bottom: 20px;
                    }
                    p {
                        font-size: 16px;
                        line-height: 1.6;
                    }
                    .button {
                        display: inline-block;
                        background-color: #4CAF50;
                        color: white;
                        padding: 10px 20px;
                        text-decoration: none;
                        font-weight: bold;
                        border-radius: 5px;
                        margin-top: 20px;
                    }
                    .button:hover {
                        background-color: #45a049;
                    }
                    .footer {
                        text-align: center;
                        margin-top: 30px;
                        font-size: 14px;
                        color: #777;
                    }
                </style>
            </head>
            <body>

                <div class="container">
                    <p>Nouvel utilisateur ajouté avec succès !</p>

                    <a href="http://127.0.0.1:5000/admin_dashboard" class="button">Accéder page admin</a>

                    <div class="footer">
                        <p>Cordialement,</p>
                        <p>EL HOUZI Mohammed <br>Formateur<br> EFSA</p>
                    </div>
                </div>

            </body>
            </html>
        ''', new_student=new_student)

        # Afficher le contenu HTML dans le navigateur au lieu d'envoyer un email
        return html_content


        # Créer le message
        msg = Message("Vos identifiants pour le quiz en ligne", recipients=[new_student.email])
        msg.html = html_content  # Utilisation du contenu HTML dynamique
        mail.send(msg)

        flash("Nouvel utilisateur ajouté avec succès !", "success")
        return redirect(url_for('admin_dashboard'))

    flash("Veuillez fournir un email valide.", "danger")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    students = User.query.all()

    if request.method == 'POST':
        new_email = request.form.get('email')
        if new_email:
            new_student = User(email=new_email)
            db.session.add(new_student)
            db.session.commit()
            return redirect(url_for('admin_dashboard')) 
    students = User.query.filter_by(role='student').all()
    return render_template('admin_dashboard.html', students=students)



@app.route('/quiz', methods=['GET', 'POST'])
def quiz():
    current_block = int(request.args.get('block', 1))  # Récupérer le bloc actuel
    questions = Question.query.filter_by(block_number=current_block).all()

    if request.method == 'POST':
        # Récupérer les réponses soumises pour ce bloc
        user_answers = []
        for question in questions:
            answer = request.form.get(f'answer_{question.id}')
            if answer:
                # Vérification de la réponse correcte
                is_correct = answer == question.correct_answer  # Compare la réponse de l'utilisateur à la bonne réponse
                user_answers.append((question.id, answer, is_correct))  # Stocker avec l'état correct/incorrect

        # Vérifier si toutes les questions ont une réponse
        if len(user_answers) != len(questions):
            return render_template('quiz.html', questions=questions, current_block=current_block, error="Vous devez répondre à toutes les questions.")

        # Sauvegarder les réponses de l'utilisateur dans la base de données
        user_id = session.get('user_id')
        for question_id, answer, is_correct in user_answers:
            user_answer = UserAnswer(user_id=user_id, question_id=question_id, answer=answer, correct=is_correct)
            db.session.add(user_answer)
        db.session.commit()

        # Passer au bloc suivant ou rediriger vers les résultats si plus de questions
        if not Question.query.filter_by(block_number=current_block + 1).first():
            return redirect(url_for('results'))  # Si c'est le dernier bloc, rediriger vers les résultats
        return redirect(url_for('quiz', block=current_block + 1))  # Passer au bloc suivant

    return render_template('quiz.html', questions=questions, current_block=current_block)


# Fonction pour générer le PDF avec les résultats
def generate_pdf(user, total_score, total_questions, questions, user_answers, block_scores, block_totals):
    pdf_buffer = BytesIO()
    c = canvas.Canvas(pdf_buffer, pagesize=letter)
    width, height = letter

    # Ajouter le titre
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, height - 40, f"Résultats du quiz pour {user.username}")
    c.setFont("Helvetica", 12)

    # Ajouter le score global
    c.drawString(100, height - 60, f"Score total: {total_score} sur {total_questions}")
    
    # Ajouter les résultats des blocs
    y_position = height - 100
    for block_number, block_questions in Question.items():
        c.setFont("Helvetica-Bold", 12)
        c.drawString(100, y_position, f"Bloc {block_number}:")
        y_position -= 20
        
        c.setFont("Helvetica", 12)
        c.drawString(100, y_position, f"Score pour ce bloc: {block_scores[block_number]} sur {block_totals[block_number]}")
        y_position -= 40
        
        for question in block_questions:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(100, y_position, f"Question : {question.text}")
            y_position -= 20
            
            c.setFont("Helvetica", 12)
            user_answer = user_answers.get(question.id, "Aucune réponse")
            correct_answer = question.correct_answer
            c.drawString(100, y_position, f"Votre réponse : {user_answer}")
            c.drawString(100, y_position - 15, f"Réponse correcte : {correct_answer}")
            
            if user_answer == correct_answer:
                c.setFont("Helvetica", 10)
                c.setFillColorRGB(0, 1, 0)  # Vert pour correct
                c.drawString(100, y_position - 30, "Réponse correcte!")
            else:
                c.setFont("Helvetica", 10)
                c.setFillColorRGB(1, 0, 0)  # Rouge pour incorrect
                c.drawString(100, y_position - 30, "Réponse incorrecte!")
            
            y_position -= 50  # Espacement entre les questions
            
            if y_position < 100:
                c.showPage()
                y_position = height - 40

    c.save()
    pdf_buffer.seek(0)
    return pdf_buffer

@app.route('/results')
def results():
    user_id = session.get('user_id')
    if not user_id:  # Si l'ID de l'utilisateur n'est pas dans la session
        return redirect(url_for('login'))  # Rediriger vers la page de connexion

    user = User.query.filter_by(id=user_id).first()

    if not user:
        return redirect(url_for('login'))  # Si l'utilisateur n'existe pas, rediriger vers login

    # Récupérer toutes les questions et les réponses de l'utilisateur
    questions = Question.query.all()
    user_answers = {}
    
    for question in questions:
        answer = UserAnswer.query.filter_by(user_id=user_id, question_id=question.id).first()
        if answer:
            user_answers[question.id] = answer.answer

    # Calculer le score total et le score par bloc
    total_score = 0
    total_questions = len(questions)
    block_scores = {}
    block_totals = {}
    blocks = {}  # Define the blocks dictionary here
    
    for question in questions:
        block_number = question.block_number
        if block_number not in blocks:
            blocks[block_number] = []
            block_scores[block_number] = 0
            block_totals[block_number] = 0
        
        blocks[block_number].append(question)
        
        if user_answers.get(question.id) == question.correct_answer:
            block_scores[block_number] += 1
            total_score += 1
        
        block_totals[block_number] += 1

    # Générer le contenu de l'email avec les détails des réponses
    email_content = render_template_string('''
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Résultats du Quiz</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f9;
                    color: #333;
                    margin: 0;
                    padding: 0;
                }
                .container {
                    width: 100%;
                    max-width: 600px;
                    margin: 20px auto;
                    background-color: #ffffff;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                }
                h1 {
                    color: #4CAF50;
                    font-size: 24px;
                    margin-bottom: 20px;
                }
                p {
                    font-size: 16px;
                    line-height: 1.6;
                }
                .score {
                    font-size: 20px;
                    font-weight: bold;
                    color: #4CAF50;
                }
                .question-result {
                    margin-bottom: 20px;
                    padding: 10px;
                    background-color: #f9f9f9;
                    border-radius: 5px;
                }
                .question-result.correct {
                    border-left: 5px solid #4CAF50;
                }
                .question-result.incorrect {
                    border-left: 5px solid #f44336;
                }
                .footer {
                    text-align: center;
                    margin-top: 30px;
                    font-size: 14px;
                    color: #777;
                }
            </style>
        </head>
        <body>

            <div class="container">
                <h1>Félicitations {{ user.username }}!</h1>
                <p>Voici vos résultats du quiz :</p>

                <p><strong>Score total :</strong> {{ total_score }} / {{ total_questions }}</p>
                <p class="score">Votre score : {{ total_score }} sur {{ total_questions }}</p>

                <h3>Résultats détaillés des questions :</h3>
                
                {% for question in questions %}
                    <div class="question-result {% if user_answers[question.id] == question.correct_answer %}correct{% else %}incorrect{% endif %}">
                        <p><strong>{{ question.text }}</strong></p>
                        <p><strong>Votre réponse :</strong> {{ user_answers[question.id] if user_answers[question.id] else 'Aucune réponse' }}</p>
                        <p><strong>Réponse correcte :</strong> {{ question.correct_answer }}</p>
                        {% if user_answers[question.id] == question.correct_answer %}
                            <p style="color: #4CAF50;">Réponse correcte!</p>
                        {% else %}
                            <p style="color: #f44336;">Réponse incorrecte!</p>
                        {% endif %}
                    </div>
                {% endfor %}

                <p>Merci d'avoir participé au quiz. Si vous avez des questions, n'hésitez pas à nous contacter.</p>

                <div class="footer">
                    <p>Cordialement,</p>
                    <p>Équipe du quiz en ligne</p>
                </div>
            </div>

        </body>
        </html>
    ''', user=user, total_score=total_score, total_questions=total_questions, questions=questions, user_answers=user_answers)

    # Créer le message
    msg = Message("Résultats de votre quiz", recipients=[user.email])
    msg.html = email_content  # Contenu HTML de l'email
    mail.send(msg)

    return render_template('results.html', 
                           user=user, 
                           total_score=total_score, 
                           total_questions=total_questions, 
                           blocks=blocks,  # Ensure blocks is passed to the template
                           user_answers=user_answers,
                           block_scores=block_scores, 
                           block_totals=block_totals)

    
def load_questions_from_json(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        questions_data = json.load(f)
        
        for question_data in questions_data:
            question = Question(
                text=question_data['text'],  # Assurez-vous que le texte est correct
                correct_answer=question_data['correct_answer'],
                block_number=question_data['block_number'],
                choices=question_data['choices']
            )
            db.session.add(question)
        
        db.session.commit()
        
if __name__ == "__main__":
    with app.app_context():
        if not Question.query.first():  
            load_questions_from_json('questions.json')
    app.run(debug=True)