from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='USER')
    unsuccessful_login_attempts = db.Column(db.Integer, nullable=False, default=0)
    end_time_out = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<User {self.username}>'


class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False)
    username = db.Column(db.String(50), nullable=True)
    user_ip = db.Column(db.String(50))
    action = db.Column(db.String(100))
    details = db.Column(db.Text)
    archive = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return f'<ID {self.id}>'


class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    count_failure_attempts = db.Column(db.Integer, nullable=False, default=3)
    time_lock = db.Column(db.Integer, nullable=False, default=5)
    afk_time = db.Column(db.Integer, nullable=False, default=10)
