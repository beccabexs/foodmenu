from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager

db = SQLAlchemy()
DB_NAME = "database.db"

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'hjshjhdjah kjshkjdhjs'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    db.init_app(app)

    # Register blueprints for views and auth
    from .home import home
    from .auth import auth
    app.register_blueprint(home, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    # Initialize the login manager
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'  # Redirect to 'auth.login' if not logged in
    login_manager.init_app(app)

    # Define user loader
    from .models import User
    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    # Create the database if it doesn't exist
    create_database(app)

    return app

def create_database(app):
    if not path.exists('website/' + DB_NAME):
        with app.app_context():
            db.create_all()
        print('Created Database!')
