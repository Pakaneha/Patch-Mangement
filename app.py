from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import joblib
import time
import hashlib
from functools import wraps
import random

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

def normalize_mobile(mobile):
    # Remove spaces, dashes, parentheses, plus sign, keep only digits
    return ''.join(filter(str.isdigit, mobile.strip()))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=True)
    mobile = db.Column(db.String(15), unique=True, nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(120), nullable=True)
    gender = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(255), nullable=True)
    otp = db.Column(db.String(6), nullable=True)

model = joblib.load("model/patch_classifier.pkl")
vectorizer = joblib.load("model/tfidf_vectorizer.pkl")

class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()
    def calculate_hash(self):
        block_string = f"{self.index}{self.timestamp}{self.data}{self.previous_hash}"
        return hashlib.sha256(block_string.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
    def create_genesis_block(self):
        return Block(0, time.time(), {"message": "Genesis Block"}, "0")
    def add_block(self, data):
        previous_block = self.chain[-1]
        new_block = Block(len(self.chain), time.time(), data, previous_block.hash)
        self.chain.append(new_block)

chain = Blockchain()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email'].strip()
        mobile = normalize_mobile(request.form['mobile'])
        password = request.form['password']
        if not email and not mobile:
            return render_template('signup.html', error="Provide either email or mobile!")
        user_by_email = User.query.filter_by(email=email).first() if email else None
        user_by_mobile = User.query.filter_by(mobile=mobile).first() if mobile else None

        if user_by_email:
            return render_template('signup.html', error="Account already exists for this email! Please login or use Forgot Password.")
        if user_by_mobile:
            return render_template('signup.html', error="Account already exists for this mobile! Please login or use Forgot Password.")
        hashed_pw = generate_password_hash(password)
        new_user = User(email=email if email else None, mobile=mobile if mobile else None, password_hash=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        session['user_id'] = new_user.id
        return redirect(url_for('complete_profile'))
    return render_template('signup.html', error=None)

@app.route('/complete_profile', methods=['GET', 'POST'])
@login_required
def complete_profile():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        email = request.form['email'].strip()
        mobile = normalize_mobile(request.form['mobile'])
        duplicate = User.query.filter(
            ((User.email == email) | (User.mobile == mobile)) & (User.id != user.id)
        ).first()
        if duplicate:
            return render_template('complete_profile.html', user=user, error="This email or mobile number is already linked to another account.")
        user.email = email
        user.mobile = mobile
        user.name = request.form.get('name')
        user.gender = request.form.get('gender')
        user.address = request.form.get('address')
        db.session.commit()
        return redirect(url_for('upload_patch'))
    return render_template('complete_profile.html', user=user, error=None)

@app.route('/profile')
@login_required
def profile():
    user = User.query.get(session['user_id'])
    success = request.args.get("success")
    return render_template('profile.html', user=user, success=success)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        contact = request.form['contact']
        otp = str(random.randint(100000, 999999))
        user.otp = otp
        db.session.commit()
        return render_template('verify_otp.html', info=contact, show_otp=otp, editing=True, user=user)
    return render_template('edit_profile.html', user=user)

@app.route('/save_profile', methods=['POST'])
@login_required
def save_profile():
    user = User.query.get(session['user_id'])
    otp_in = request.form["otp"]
    if user.otp != otp_in:
        return render_template('verify_otp.html', info="", error="Invalid OTP", editing=True)
    email = request.form.get('email', '').strip()
    mobile = normalize_mobile(request.form.get('mobile', ''))
    duplicate = User.query.filter(
        ((User.email == email) | (User.mobile == mobile)) & (User.id != user.id)
    ).first()
    if duplicate:
        return render_template('edit_profile.html', user=user, error="This email or mobile number is already linked to another account!")
    user.email = email
    user.mobile = mobile
    user.name = request.form.get('name')
    user.gender = request.form.get('gender')
    user.address = request.form.get('address')
    user.otp = None
    db.session.commit()
    return redirect(url_for('profile', success=1))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        info = request.form['info'].strip()
        info_mobile = normalize_mobile(info)
        user = User.query.filter((User.email == info) | (User.mobile == info_mobile)).first()
        password = request.form['password']
        if not user:
            return render_template('login.html', error="User not recognized. Go to sign up.")
        if not check_password_hash(user.password_hash, password):
            return render_template('login.html', error="Wrong password.")
        session['user_id'] = user.id
        return redirect(url_for('upload_patch'))
    return render_template('login.html', error=None)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('home'))

@app.route('/upload_patch')
@login_required
def upload_patch():
    return render_template('upload_patch.html')

@app.route('/predict_patch', methods=['POST'])
@login_required
def predict_patch():
    commit_message = request.form['commit_message']
    diff_code = request.form['diff_code']
    commit_message_clean = commit_message.replace("\xa0", " ").strip()
    diff_code_clean = diff_code.replace("\xa0", " ").strip()
    text = commit_message_clean + " " + diff_code_clean
    X = vectorizer.transform([text])
    prediction = model.predict(X)[0]
    if prediction == "non-security":
        status = "SAFE (Non-Security Patch)"
        data = {
            "patch_message": commit_message_clean,
            "diff_code": diff_code_clean,
            "status": status
        }
        chain.add_block(data)
        result = "✅ SAFE patch, stored in blockchain."
        block = chain.chain[-1]
    else:
        result = "⚠ SECURITY patch, NOT stored (requires review)."
        block = None
    return render_template("result.html", result=result, block=block)

@app.route('/blockchain')
@login_required
def blockchain():
    return render_template('blockchain.html', blocks=chain.chain)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        info = request.form['info'].strip()
        info_mobile = normalize_mobile(info)
        user = User.query.filter((User.email == info) | (User.mobile == info_mobile)).first()
        if not user:
            return render_template('forgot_password.html', error="User not found!")
        otp = str(random.randint(100000, 999999))
        user.otp = otp
        db.session.commit()
        return render_template('verify_otp.html', info=info, show_otp=otp, editing=None)
    return render_template('forgot_password.html')

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    info = request.form.get("info", "").strip()
    info_mobile = normalize_mobile(info)
    otp_in = request.form.get("otp")
    new_pw = request.form.get('new_password')
    editing = request.form.get('editing')
    user = User.query.filter((User.email == info) | (User.mobile == info_mobile)).first()
    if not user or user.otp != otp_in:
        return render_template('verify_otp.html', info=info, error="Invalid OTP", editing=editing)
    if new_pw:
        user.password_hash = generate_password_hash(new_pw)
    user.otp = None
    db.session.commit()
    if editing:
        return redirect(url_for('profile', success=1))
    return redirect(url_for('login'))

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
