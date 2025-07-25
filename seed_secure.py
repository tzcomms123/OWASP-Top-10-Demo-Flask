
## Here's the `seed.py` file to create insecure users and bad states.


from app import db, User
from app import app
from werkzeug.security import check_password_hash, generate_password_hash

# Drop and recreate the database

with app.app_context():
    db.drop_all()
    db.create_all()



# Add users (passwords no hashed!)
users = [
    User(username='admin', password=generate_password_hash('admin123'), is_admin=True),
    User(username='guest', password=generate_password_hash('guest')),
    User(username='hacker', password=generate_password_hash('password')),
    User(username='test', password=generate_password_hash('abc123')),
]

with app.app_context():
    for user in users:
        db.session.add(user)
        db.session.commit()
print("Database seeded with secure users.")