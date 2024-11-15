from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash  # Utilisation de werkzeug
from datetime import datetime


db = SQLAlchemy()

class User(db.Model, UserMixin):  # Ajout de UserMixin pour intégrer les fonctionnalités de Flask-Login
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    identifiant = db.Column(db.String(32), unique=True, nullable=True)  # Ajout de l'identifiant unique
    password = db.Column(db.String(128), nullable=True)
    score = db.Column(db.Integer, default=0)
    completed_at = db.Column(db.DateTime, default=None)
    role = db.Column(db.String(20), nullable=False, default='student')
    has_taken_quiz = db.Column(db.Boolean, default=False)
    email_sent = db.Column(db.Boolean, default=False)  # Nouvelle colonne pour savoir si l'email a été envoyé
    def __repr__(self):
        return f'<User {self.email}>'
    
    def set_password(self, password):
        """Hachage du mot de passe avant de l'enregistrer"""
        self.password = generate_password_hash(password)  # Utilisation de werkzeug pour le hachage

    def check_password(self, password):
        """Vérification du mot de passe lors de la connexion"""
        return check_password_hash(self.password, password)  # Vérification avec werkzeug
    
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String, nullable=False)
    correct_answer = db.Column(db.String, nullable=False)
    block_number = db.Column(db.Integer, nullable=False)
    choices = db.Column(db.JSON, nullable=False)
    
class UserAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user_email = db.Column(db.String(50), db.ForeignKey('user.email'))
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'))
    answer = db.Column(db.String(50))
    correct = db.Column(db.Boolean, default=False)
      # Relation avec le modèle Question
    question = db.relationship('Question', backref='user_answers', lazy=True)
    

def check_answer(self):
        """Vérifier si la réponse donnée est correcte"""
        question = Question.query.get(self.question_id)
        if question and self.answer == question.correct_answer:
            self.correct = True
            db.session.commit()
