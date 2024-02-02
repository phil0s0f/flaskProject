from flask import Flask
from werkzeug.security import generate_password_hash

from models import User, db

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db.init_app(app)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # добавление учетной записи администратора
        username = 'admin'
        password = 'admin'
        role = 'ADMINISTRATOR'
        hashed_password = generate_password_hash(password)
        administrator = User(username=username, password=hashed_password, role=role)
        db.session.add(administrator)
        db.session.commit()
    print('Создана база данных')
