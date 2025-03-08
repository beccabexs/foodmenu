

from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from . import db


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    security_answer = db.Column(db.String(150), nullable=False, default='')

    # Relationship to track quiz responses
    responses = db.relationship('quizresponse', backref='user', lazy=True)
    
    # Relationship to track the result
    result = db.relationship('result', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'


class quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(200), nullable=False)
    response_a = db.Column(db.String(200), nullable=False)  # First response option
    response_b = db.Column(db.String(200), nullable=False)  # Second response option
    trait_a = db.Column(db.String(50), nullable=False)  # Trait associated with response_a
    trait_b = db.Column(db.String(50), nullable=False)  # Trait associated with response_b

    def __repr__(self):
        return f'<Quiz {self.question}>'


class QuizOption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    option_text = db.Column(db.String(200), nullable=False)
    letter = db.Column(db.String(1), nullable=False)  # 'a', 'b', 'c', etc.
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)

    def __repr__(self):
        return f'<QuizOption {self.option_text}>'


# Quiz Response Model
class quizresponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    selected_trait = db.Column(db.String(200), nullable=False)  # Store the trait selected by the user
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)

    def __repr__(self):
        return f'<QuizResponse {self.selected_trait}>'


# Result Model
class result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    top_traits = db.Column(db.JSON, nullable=False)  # List of top traits (e.g., ['Analytical', 'Creative', 'Collaborative'])
    job_sectors = db.Column(db.JSON, nullable=False)  # List of top job sectors (e.g., ['Data Scientist', 'Software Developer'])
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Result User {self.user_id} - Traits {self.top_traits}>'

# Job Sector Model
class JobSector(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    realistic = db.Column(db.Integer, nullable=False)
    investigative = db.Column(db.Integer, nullable=False)
    artistic = db.Column(db.Integer, nullable=False)
    social = db.Column(db.Integer, nullable=False)
    enterprising = db.Column(db.Integer, nullable=False)
    conventional = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f'<JobSector {self.name}>'

class JobSector_detail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sector = db.Column(db.String(50), nullable=False)
    job_title = db.Column(db.String(100), nullable=False)
    average_salary = db.Column(db.Integer, nullable=False)
    summary = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f"<JobSector_detail {self.job_title} in {self.sector}>"