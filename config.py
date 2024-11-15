class Config:
    SECRET_KEY = 'votre_cle_secrete'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///quiz.db'
    
    # Configuration de l'email pour Gmail
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587  
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'abdelmounaimelhouzi@gmail.com'  # Votre adresse email Gmail
    MAIL_PASSWORD = 'hoeq fade bafh iomr'  # Utilisez ici le mot de passe d'application généré
    MAIL_DEFAULT_SENDER = 'abdelmounaimelhouzi@gmail.com'  # L'adresse email utilisée pour envoyer les emails
   