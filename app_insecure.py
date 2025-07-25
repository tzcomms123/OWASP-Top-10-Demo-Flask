from flask import Flask, request, render_template, redirect, session, render_template_string
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
import os
import hmac
import hashlib
import requests
from urllib.parse import urlparse

# import requests  # Used for SSRF demo

app = Flask(__name__)
app.config['SECRET_KEY'] = 'insecure-secret-key'  # Hardcoded secret
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
UPLOAD_FOLDER = 'uploaded_scripts'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)




db = SQLAlchemy(app)

# A02: Cryptographic failures — Passwords stored in plaintext
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)



# A02: No hashing, stores plaintext passwords
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        #password saved as a plaintext
        user = User(username=username, password=password, is_admin=False)
        db.session.add(user)
        db.session.commit()
        return redirect('/')
    return render_template('register.html')


# A04: Insecure Design 
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # A07: Auth Failures Hardcoded bypass/backdoor
        if username == 'admin' and password == 'letmein':
            session['user_id'] = 1
            session['is_admin'] = True
            return redirect('/admin')

        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['user_id'] = user.id
            #check admin privileges
            session['is_admin'] = user.is_admin
            return redirect('/')
        else:
            # A09: No logging of failed attempts
            error = "Invalid credentials"
    return render_template('login.html', error=error)






@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect('/login')
        
    return render_template('dashboard.html')




# A01: Broken Access Control — Anyone can access admin
@app.route('/admin')
def admin():

    # Checks if user but does not check admin role
    if 'user_id' not in session:  
        return redirect('/login')
    return render_template('admin.html')



@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')



# A03: SQL Injection vulnerability
@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'user_id' not in session:
        return redirect('/login')
    
    result = None
    if request.method == 'POST':
        keyword = request.form['keyword']
        query = text("SELECT * FROM user WHERE username LIKE :kw")
        result = db.session.execute(query, {"kw": f"%{keyword}%"}).fetchall()

        # result = db.session.execute(query).fetchall()
    return render_template('search.html', result=result)




# A05: Security Misconfiguration — shows stack trace in production
@app.route('/debug')
def debug():
    raise Exception("This is a debug exception visible to the user!")





# # A08: Data Integrity Failures 
SECRET_KEY = b'super_secret_key'

def generate_signature(data: str) -> str:
    return hmac.new(SECRET_KEY, data.encode(), hashlib.sha256).hexdigest()

def verify_signature(data: str, signature: str) -> bool:
    expected = generate_signature(data)
    return hmac.compare_digest(expected, signature)


@app.route('/secret-form', methods=['GET', 'POST'])
def unsafe_form():
    if request.method == 'POST':
        name = request.form['name']
        action = request.form['action']
        signature = request.form['signature']

        #INSECURE: Trusts signature without verifying it
        if signature == "trusted123":  # anyone can spoof this
            return f"Action approved for {name}: {action}"
        else:
            return "Signature invalid!"

    return render_template_string('''
        <h2>Submit Action</h2>
        <form method="post">
            Name: <input name="name"><br>
            Action: <input name="action"><br>
            Signature: <input name="signature"><br>
            <button type="submit">Submit</button>
        </form>
    ''') 








# # A10: SSRF
@app.route('/fetch', methods=['GET', 'POST'])
def fetch():
    if 'user_id' not in session:
        return redirect('/login')
    content = ''
    if request.method == 'POST':
        url = request.form['url']  #User controls URL
        response = requests.get(url)  #Server makes request
        content = response.text  # Show first 1000 chars
    return render_template('fetch.html', content=content)





if __name__ == '__main__':
    # A05: Running with debug=True (should not be used in production)
    app.run(debug=True)





#A06 Example Vulnerable and Outdated Components
# Flask==1.0  # Old version with known issues
# requests==2.19.1  # Vulnerable to CVEs

