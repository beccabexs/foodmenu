from flask import Blueprint, render_template
from flask_login import login_required, current_user
from .models import JobSector_detail  # Import the JobSector_detail model

home = Blueprint('home', __name__)

# Home Route 
@home.route('/',  methods=['GET', 'POST'])
@login_required
def homes():
    job_sectors = JobSector_detail.query.all()  # Fetch all job sectors from the database
    return render_template("home.html", user=current_user, job_sectors=job_sectors)
 
