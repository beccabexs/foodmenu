from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from .models import User, quiz, quizresponse, result, JobSector_detail
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from website import db
from website.models import JobSector, quiz
from flask import render_template, request, redirect, url_for, session
from flask import get_flashed_messages, flash


from . import db  # Import the database instance


auth = Blueprint('auth', __name__)

from flask import get_flashed_messages, flash  # Import get_flashed_messages

# LOGIN ROUTE
@auth.route('/login', methods=['GET', 'POST'])
def login():
    # Clear any old flash messages before rendering the login page
    if 'Logged in successfully!' in get_flashed_messages(with_categories=False):
        # Remove 'Logged in successfully!' flash message to avoid showing on login page
        flash('')

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()  # query user from db

        if user and check_password_hash(user.password, password):
            flash('Logged in successfully!', category='success')
            login_user(user, remember=True)
            return redirect(url_for('home.homes'))  # Redirect to home (in home.py)
        else:
            flash('Invalid username or password.', category='error')

    return render_template("login.html", user=current_user)


# LOGOUT ROUTE
@auth.route('/logout')
@login_required
def logout():
    # Clear any old flash messages before redirecting
    flash('')  # Clears old flash messages
    
    logout_user()
    flash("Logged out successfully!", category="success")
    return redirect(url_for('auth.login'))  # Redirect to the login page




# SIGN-UP ROUTE
@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        username = request.form.get('username')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        security_answer = request.form.get('security_answer')

        user = User.query.filter_by(username=username).first()

        if user:
            flash('Username already exists.', category='error')
        elif len(username) < 4:
            flash('Username must be at least 4 characters.', category='error')
        elif password1 != password2:
            flash('Passwords do not match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(
                username=username,
                password=generate_password_hash(password1, method='pbkdf2:sha256'),
                security_answer=security_answer
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created successfully!', category='success')
            return redirect(url_for('auth.login'))

    return render_template("sign_up.html", user=current_user)


# FORGOT PASSWORD ROUTE
@auth.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username')
        security_answer = request.form.get('security_answer')

        user = User.query.filter_by(username=username).first()

        if user and security_answer.lower() == user.security_answer.lower():
            flash("Security answer correct! Reset your password.", category="success")
            return redirect(url_for('auth.reset_password', username=username))
        else:
            flash("Invalid username or security answer.", category="error")

    return render_template("forgot_password.html")


# RESET PASSWORD ROUTE
@auth.route('/reset-password/<username>', methods=['GET', 'POST'])
def reset_password(username):
    user = User.query.filter_by(username=username).first()

    if not user:
        flash("User not found.", category="error")
        return redirect(url_for('auth.forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password == confirm_password:
            user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
            db.session.commit()
            flash('Your password has been reset!', category='success')
            return redirect(url_for('auth.login'))
        else:
            flash('Passwords do not match.', category='error')

    return render_template("reset_password.html", username=username)


# Quiz Routes
@auth.route('/quiz', methods=['GET', 'POST'])
def quiz_page():
    question_number = request.args.get('question', 1, type=int)
    question = quiz.query.get(question_number)

    # Check if question exists
    if not question:
        flash('No more questions available!', category='error')
        return redirect(url_for('auth.quiz_results'))

    if request.method == 'POST':
        selected_answer = request.form['answer']

        # Save the selected answer to session or database
        session[f'question_{question_number}'] = selected_answer

        # Check if this is the last question (if the next question doesn't exist)
        next_question_number = question_number + 1
        next_question = quiz.query.get(next_question_number)

        # If this is the last question, set a session flag for quiz completion
        if not next_question:
            session['quiz_complete'] = True  # Set the flag to True when the quiz is completed

        return redirect(url_for('auth.quiz_page', question=next_question_number))

    # Pass 'question' and 'question_number' to the template
    return render_template('quiz.html', question=question, question_number=question_number)


#quiz results
@auth.route('/quiz/results', methods=['GET', 'POST'])
def quiz_results():
    try:
        # Retrieve quiz answers from the session.
        user_answers = {key: value for key, value in session.items() if key.startswith('question_')}

        # Check if the quiz has been completed.
        if not session.get("quiz_complete") or len(user_answers) < 25:
            flash("Please complete the quiz before viewing results.", category="error")
            return render_template("results.html", top_3_jobs=None)

        # Calculate the user's RIASEC scores.
        user_scores = {'R': 0, 'I': 0, 'A': 0, 'S': 0, 'E': 0, 'C': 0}
        trait_mapping = {
            'Realistic': 'R', 'Investigative': 'I', 'Artistic': 'A', 
            'Social': 'S', 'Enterprising': 'E', 'Conventional': 'C'
        }

        for question_id, response in user_answers.items():
            question_number = int(question_id.split('_')[1])
            question_obj = quiz.query.get(question_number)
            if not question_obj:
                continue  # Skip if the question doesn't exist.

            # Get the trait based on the selected answer.
            trait = getattr(question_obj, f'trait_{response}', None)
            if trait:
                trait_letter = trait_mapping.get(trait)
                if trait_letter:
                    user_scores[trait_letter] += 1

        # Retrieve all job sectors and calculate match scores.
        job_sectors = JobSector.query.all()
        job_matches = []
        trait_column_mapping = {'R': 'realistic', 'I': 'investigative', 'A': 'artistic', 
                                'S': 'social', 'E': 'enterprising', 'C': 'conventional'}

        for job in job_sectors:
            score_diff = 0
            for trait, column in trait_column_mapping.items():
                job_trait_value = getattr(job, column, 0)
                score_diff += abs(user_scores[trait] - job_trait_value)
            job_matches.append((job, score_diff))  # Store entire job object

        # Sort job sectors by score difference (lower is a better match).
        job_matches.sort(key=lambda x: x[1])
        top_3_jobs = [job[0] for job in job_matches[:3]]  # Extract top 3 job sector objects

        # Fetch full job sector details from JobSector_detail model
        job_details = JobSector_detail.query.filter(JobSector_detail.sector.in_([job.name for job in top_3_jobs])).all()
        
        return render_template("results.html", top_3_jobs=job_details)

    except Exception as e:
        print("An error occurred:", str(e))
        flash("An error occurred while processing your results. Please try again.", category="error")
        return redirect(url_for('auth.quiz_page', question=1))
