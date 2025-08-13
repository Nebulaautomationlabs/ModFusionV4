from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from config import Config

# Create the Flask application instance and load the configuration
app = Flask(__name__)
app.config.from_object(Config)

# Initialize the SQLAlchemy database object
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # The route name for our login page
login_manager.login_message_category = 'info'

# Define our User model for the database
# This model represents a user and their attributes
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='member') # Default role is 'member'
    is_approved = db.Column(db.Boolean, default=False)
    # New fields for ModFusion V4
    fusion_credits = db.Column(db.Integer, default=0)
    profile_picture = db.Column(db.String(255), default='default_profile.png')
    banner_image = db.Column(db.String(255), default='default_banner.png')
    callsign = db.Column(db.String(50))
    is_owner = db.Column(db.Boolean, default=False) # Helper for the default owner account

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(password, self.password_hash)
    
    def __repr__(self):
        return f"User('{self.username}', '{self.role}')"

# User loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Create the database and the default owner account
with app.app_context():
    # Drop existing tables and create new ones (for development)
    # db.drop_all() 
    db.create_all()

    # Create the default owner account if it doesn't exist
    owner_user = User.query.filter_by(username='Wade').first()
    if not owner_user:
        owner_user = User(
            username='Wade', 
            role='Owner/Developer', 
            is_approved=True, 
            is_owner=True
        )
        owner_user.set_password('Wadeowneradmin')
        db.session.add(owner_user)
        db.session.commit()
        print("Default owner account 'Wade' created successfully.")

# Route for the main application page
@app.route('/')
def home():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template('index.html', title='ModFusion V4 Dashboard')

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            # Check if the user's account has been approved
            if not user.is_approved:
                flash('Your account is pending approval. Please wait for an admin to approve it.', 'danger')
                return redirect(url_for('login'))

            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html', title='Login')

# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check if username already exists
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            flash('That username is already taken. Please choose another.', 'danger')
            return redirect(url_for('register'))

        # Create a new user with a 'member' role and set is_approved to False
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Your account is pending admin approval.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', title='Register')

# Route for logging out
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Custom decorator to restrict access to certain roles
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['Owner/Developer', 'Admin']:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# Route for the Admin Panel Dashboard
@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    # Fetch users waiting for approval
    pending_users = User.query.filter_by(is_approved=False).all()
    return render_template('admin.html', title='Admin Panel', pending_users=pending_users)

# Route to approve a user
@app.route('/admin/approve/<int:user_id>')
@login_required
@admin_required
def approve_user(user_id):
    user = db.session.get(User, user_id)
    if user:
        user.is_approved = True
        db.session.commit()
        flash(f'User {user.username} has been approved.', 'success')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('admin_panel'))

# Route to deny (and delete) a user registration
@app.route('/admin/deny/<int:user_id>')
@login_required
@admin_required
def deny_user(user_id):
    user = db.session.get(User, user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} has been denied and removed.', 'warning')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('admin_panel'))

# Run the app
if __name__ == '__main__':
    app.run(debug=True)