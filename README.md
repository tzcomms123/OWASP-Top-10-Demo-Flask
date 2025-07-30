# Insecure OWASP TOP 10 Flask App COMP6441 Project

This intentionally insecure Flask web app demonstrates all 10 of the OWASP Top 10 (2021) vulnerabilities in a controlled environment. 

It is **strictly for educational and internal testing purposes only**.

---

## WARNING

> DO NOT deploy this app to the public internet.  
> DO NOT use in production or real environments.  
> DO use this in **sandboxed**, **offline**, or **virtualized** environments only.

---

## Features / OWASP Coverage

A01 | Broken Access Control | `/admin` — no role checks 

A02 | Cryptographic Failures | `/register` — passwords stored in plain text 

A03 | Injection | `/search` — vulnerable to SQL Injection 

A04 | Insecure Design | `/login` — no password policy, no lockout 

A05 | Security Misconfiguration | `/debug` — shows stack traces in production 

A06 | Vulnerable & Outdated Components | `requirements.txt` uses known-vulnerable packages 

A07 | Identification & Auth Failures | Login is easily bypassed, no session timeout 

A08 | Software/Data Integrity Failures | `/secret-form` — verifies file integrity using user input 

A09 | Logging & Monitoring Failures | No error logging or activity logging at all 

A10 | Server-Side Request Forgery (SSRF) | `/fetch?url=` — lets users request arbitrary URLs 

---

##  Quickstart

### 1. Clone and Setup Environment

```bash
git clone https://github.com/tzcomms123/OWASP-Top-10-Demo-Flask.git
cd OWASP-Top-10-Demo-Flask

python -m venv myenv
source myenv/bin/activate  # Windows (using powershell): myenv/Scripts/activate

pip install -r requirements.txt
```


### INSECURE VERSION

2. Initialize Database and Seed

In console run:

```bash
python seed_insecure.py  # Seeds users and simulates bad practices
```
You can now login with the test users with user name and password as shown in the seed file. 

3. Run App (INSECURE MODE)

In console run:

```bash
python app_insecure.py
Visit: http://127.0.0.1:5000
```





### SECURE VERSION

2. Initialize Database and Seed

In console run:

```bash
python seed_secure.py  # Seeds users with fixes to security
```

You can now login with the test users with user name and password as shown in the seed file. 


3. Run App (SECURE MODE)

In console run:

```bash
python app_secure.py
Visit: http://127.0.0.1:5000
```

