from flask import Flask, request, render_template, redirect, session, render_template_string
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text, or_, literal
import os
import hmac
import hashlib
import requests
from werkzeug.security import check_password_hash, generate_password_hash
import time
import logging
from urllib.parse import urlparse
import re
# import requests  # Used for SSRF demo

app = Flask(__name__)
app.config['SECRET_KEY'] = 'insecure-secret-key'  # 🔓 Hardcoded secret
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
UPLOAD_FOLDER = 'uploaded_scripts'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)





db = SQLAlchemy(app)



#A02 Cryptographic failures — 
# WORKING CODE TO INCREASE HASHING SECURITY

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)



# A02: No hashing, stores plaintext passwords
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        #
        user = User(username=username, is_admin=False)
        user.set_password(password)  # Hash the password properly to align with user model
        # print(user.password)
        db.session.add(user)
        db.session.commit()
        return redirect('/login')
    return render_template('register.html')



@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect('/login')
        
    return render_template('dashboard.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


## A01 Access Control — Admin Page
@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect('/login')
    if not session.get('is_admin'):
        return "Access denied", 403
    return render_template('admin.html')




#A04, A07, A09
# In-memory example of failed attempts (for demo only — use Redis or DB in prod)
failed_logins = {}

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5 minutes


#A04, A07 and A09 implementation fix
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    ip_address = request.remote_addr
    now = time.time()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        #Check if IP is locked out
        if ip_address in failed_logins:
            attempts, first_attempt_time = failed_logins[ip_address]
            #If too many attempts and within lockout time
            if attempts >= MAX_FAILED_ATTEMPTS and (now - first_attempt_time) < LOCKOUT_TIME:
                error = "Too many failed attempts. Try again later."
                print(f"IP Address: {ip_address} locked out due to too many failed attempts. Wait {LOCKOUT_TIME - (now - first_attempt_time)}")
                return render_template('login.html', error=error)

        #Get user securely with authentication 
        user = User.query.filter_by(username=username).first()

        #hash checks
        if user and check_password_hash(user.password, password):
            # Reset failed attempts on successful login
            failed_logins.pop(ip_address, None)

            session['user_id'] = user.id
            #check admin privileges
            session['is_admin'] = user.is_admin
            return redirect('/')
        else:
            # Log failed login attempt (basic)
            logging.warning(f"Failed login attempt from IP Address:{ip_address} for user: {username}")

            # Increment failed attempts
            if ip_address in failed_logins:
                failed_logins[ip_address] = (
                    failed_logins[ip_address][0] + 1,
                    failed_logins[ip_address][1]
                )
            else:
                failed_logins[ip_address] = (1, now)

            error = "Invalid credentials"

    return render_template('login.html', error=error)






#A03 SQL Injection Protection
# Secure search with parameterised queries to prevent SQL Injection
# This is a secure way to handle user input in SQL queries.
@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'user_id' not in session:
        return redirect('/login')

    result = None
    error = None

    if request.method == 'POST':
        keyword = request.form.get('keyword', '').strip()

        if not keyword:
            error = "Please enter a search keyword"
        else:
            # Securely parameterised pattern matching
            safe_pattern = f"%{keyword.replace('%', '').replace('_', '')}%"
            result = User.query.filter(User.username.ilike(safe_pattern)).all()

    return render_template('search.html', result=result, error=error)




#A08 Data Integrity Failures 
#New secure form with HMAC signature verification
SECRET_KEY = b'super_secret_key'

def generate_signature(data: str) -> str:
    return hmac.new(SECRET_KEY, data.encode(), hashlib.sha256).hexdigest()

def verify_signature(data: str, signature: str) -> bool:
    expected = generate_signature(data)
    return hmac.compare_digest(expected, signature)


@app.route('/secret-form', methods=['GET', 'POST'])
def secure_form():
    if 'user_id' not in session:
        return redirect('/login')
    message = None

    if request.method == 'POST':
        name = request.form['name']
        action = request.form['action']
        signature = request.form['signature']
        full_data = f"{name}:{action}"

        if verify_signature(full_data, signature):
            message = f"Action approved for {name}: {action}"
        else:
            message = "Invalid signature. Action blocked!"

    return render_template('secret_form.html', message=message)







#A10 Server-Side Request Forgery (SSRF) Protection
# Example of a simple URL allowlist to prevent SSRF

ALLOWED_HOSTS = ['owasp.org']

def is_allowed_url(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        return hostname in ALLOWED_HOSTS
    except:
        return False

@app.route('/fetch', methods=['GET', 'POST'])
def fetch():
    content = ''
    if request.method == 'POST':
        url = request.form['url']
        if is_allowed_url(url):
            response = requests.get(url)
            content = response.text
        else:
            content = "URL not allowed."
    return render_template('fetch.html', content=content)
    # return render_template_string('''
    #     <h2>Fetch a URL</h2>
    #     <form method="post">
    #         URL: <input name="url">
    #         <button type="submit">Fetch</button>
    #     </form>
    #     <pre>{{ content }}</pre>
    # ''', content=content)


# A05: Security Misconfiguration — shows stack trace in production
@app.route('/debug')
def debug():
    raise Exception("This is a debug exception visible to the user!")

#This has to be last 
if __name__ == '__main__':
    # A05: Running with debug=False (should not be used in production)
    app.run(debug=False)




#A06 Example Vulnerable and Outdated Components, 
#See requirements.txt and pip-audit for version checks
