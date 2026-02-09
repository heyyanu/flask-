from flask import Flask, redirect, request, render_template, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    logout_user, login_required, current_user
)
import bcrypt
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect
import random
import os

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "supersecretkey"

# Enable Whitenoise for static file serving
from whitenoise import WhiteNoise
app.wsgi_app = WhiteNoise(app.wsgi_app, root='static/', prefix='static/')

db = SQLAlchemy(app)

# Enable CSRF Protection
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(500), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(6), nullable=True) # Added back

# --- Configuration ---
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False

app.config["MAIL_USERNAME"] = "heyyanudev@gmail.com"
app.config["MAIL_PASSWORD"] = "rjpd orvu jkem fdcl"
app.config["MAIL_DEFAULT_SENDER"] = "heyyanudev@gmail.com"

mail = Mail(app)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
        
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        user = Users.query.filter((Users.username == username) | (Users.email == username)).first()

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            if not user.is_verified:
                # If not verified, redirect to verify page
                session['email_to_verify'] = user.email
                flash("Please verify your email first.", "warning")
                return redirect(url_for("verify_code"))
            
            login_user(user)
            return redirect(url_for("dashboard"))

        error = "Invalid credentials"

    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        if Users.query.filter_by(username=username).first():
             return render_template("register.html", error="Username already taken!")
        
        if Users.query.filter_by(email=email).first():
             return render_template("register.html", error="Email already registered!")

        # Hash password with bcrypt
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
        
        # Generate 6-digit code
        code = str(random.randint(100000, 999999))

        new_user = Users(
            username=username,
            email=email,
            password=hashed_password,
            is_verified=False,
            verification_code=code
        )
        db.session.add(new_user)
        db.session.commit()

        # Send Email
        try:
            msg = Message(
                subject="Verify your account",
                recipients=[email],
                body=f"Your verification code is: {code}"
            )
            mail.send(msg)
            
            session['email_to_verify'] = email
            return redirect(url_for("verify_code"))
            
        except Exception as e:
            print(f"Email Error: {e}")
            return render_template("register.html", error=f"Could not send email. (Error: {e})")

    return render_template("register.html")

@app.route("/verify", methods=["GET", "POST"])
def verify_code():
    if 'email_to_verify' not in session:
        return redirect(url_for('login'))
    
    error = None
    if request.method == "POST":
        code = request.form.get("code")
        email = session['email_to_verify']
        
        user = Users.query.filter_by(email=email).first()
        
        if user and user.verification_code == code:
            user.is_verified = True
            user.verification_code = None
            db.session.commit()
            
            session.pop('email_to_verify', None)
            flash("Account verified! Please login.", "success")
            return redirect(url_for("login"))
        else:
            error = "Invalid verification code"

    return render_template("verify.html", error=error)

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
