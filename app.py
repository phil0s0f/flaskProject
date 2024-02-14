from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash

from logging_module import log_audit_event
from models import User, Settings, db
from password_generator import password_generate
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///my_database.db'
app.config['SECRET_KEY'] = 'SECRET-KEY'
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    # TODO: Добавить какой то функционал для обычных пользователей
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    else:
        return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    if request.method == 'POST':
        sec_settings = Settings.query.first()

        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        log_audit_event(username, request.environ.get('HTTP_X_REAL_IP', request.remote_addr), 'Вход',
                        'Пользователь пытается войти в свою учетную запись')
        if user:
            if user.end_time_out is not None and user.end_time_out > datetime.now():
                log_audit_event(username, request.environ.get('HTTP_X_REAL_IP', request.remote_addr), 'Вход',
                                'Попытка входа заблокированного пользователя')
                flash('The number of failed authorization attempts has been exceeded. Try later', 'warning')
                return render_template('login.html')

            if check_password_hash(user.password, password):
                login_user(user)
                user.end_time_out = None
                user.unsuccessful_login_attempts = 0  # Сброс счетчика неудачных попыток при успешной аутентификации
                db.session.commit()
                log_audit_event(username, request.environ.get('HTTP_X_REAL_IP', request.remote_addr), 'Вход',
                                'Пользователь успешно вошел в свою учетную запись')
                return redirect(url_for('profile'))
            else:
                log_audit_event(username, request.environ.get('HTTP_X_REAL_IP', request.remote_addr), 'Вход',
                                'Пользователь ввел некорректный логин или пароль')
                flash('Invalid username or password', 'warning')

                user.unsuccessful_login_attempts += 1  # Увеличение счетчика неудачных попыток
                db.session.commit()

                # Проверка и блокировка учетной записи после трех неудачных попыток
                if user.unsuccessful_login_attempts >= sec_settings.count_failure_attempts:
                    time_out = timedelta(minutes=sec_settings.time_lock)
                    user.end_time_out = datetime.now() + time_out
                    db.session.commit()

                    log_audit_event(username, request.environ.get('HTTP_X_REAL_IP', request.remote_addr),
                                    'Блокировка учетной записи',
                                    'Превышено количество неудачных попыток входа')
                    flash('The number of failed authorization attempts has been exceeded. Try later', 'warning')
        else:
            log_audit_event(username, request.environ.get('HTTP_X_REAL_IP', request.remote_addr), 'Вход',
                            'Пользователь ввел некорректный логин или пароль')
            flash('Invalid username or password', 'warning')

    return render_template('login.html')


@app.route('/logout')
def logout():
    log_audit_event(current_user.username, request.environ.get('HTTP_X_REAL_IP', request.remote_addr),
                    'Выход',
                    'Пользователь вышел из своей учетной записи')
    logout_user()
    return redirect(url_for('index'))


@app.route('/admin_panel')
@login_required
def admin_panel():
    if current_user.role != 'ADMINISTRATOR':
        log_audit_event(current_user.username, request.environ.get('HTTP_X_REAL_IP', request.remote_addr),
                        'Открытие панели администратора',
                        'Пользователь пытался открыть панель администратора')
        return redirect(url_for('login'))
    log_audit_event(current_user.username, request.environ.get('HTTP_X_REAL_IP', request.remote_addr),
                    'Открытие панели администратора',
                    'Пользователь открыл панель администратора')
    return render_template('admin_panel.html')


@app.route('/admin_panel/create_new_user', methods=['GET', 'POST'])
@login_required
def create_new_user():
    if current_user.role != 'ADMINISTRATOR':
        log_audit_event(current_user.username, request.environ.get('HTTP_X_REAL_IP', request.remote_addr),
                        'Создание учетных записей',
                        'Пользователь пытался получить доступ к созданию учетных записей')
        return redirect(url_for('login'))
    log_audit_event(current_user.username, request.environ.get('HTTP_X_REAL_IP', request.remote_addr),
                    'Создание учетных записей',
                    'Пользователь открыл создание учетных записей')
    if request.method == 'POST':
        username = request.form['username']
        password = password_generate(username)
        user = User.query.filter_by(username=username).first()
        if user:
            log_audit_event(current_user.username, request.environ.get('HTTP_X_REAL_IP', request.remote_addr),
                            'Создание учетных записей',
                            'Пользователь попытался создать учетную запись с уже существующем логином')
            flash('Username already exist', 'warning')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            log_audit_event(current_user.username, request.environ.get('HTTP_X_REAL_IP', request.remote_addr),
                            'Создание учетных записей',
                            'Пользователь создал новую учетную запись')
            flash(' Account created successfully.\nLogin: ' + username + '\nPassword: ' + password, 'info')
    return render_template('create_new_user.html')


@app.route('/admin_panel/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if current_user.role != 'ADMINISTRATOR':
        log_audit_event(current_user.username, request.environ.get('HTTP_X_REAL_IP', request.remote_addr),
                        'Настройки безопасности',
                        'Пользователь пытался получить доступ к настройкам безопасности')
        return redirect(url_for('login'))
    sec_settings = Settings.query.first()
    if request.method == 'POST':
        count_failure_attempts = request.form['count_failure_attempts']
        time_lock = request.form['time_lock']
        afk_time = request.form['afk_time']
        sec_settings.count_failure_attempts = count_failure_attempts
        sec_settings.time_lock = time_lock
        sec_settings.afk_time = afk_time
        db.session.commit()

    return render_template('settings.html', sec_settings=sec_settings)


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
