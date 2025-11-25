from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import string

app = Flask(__name__)
app.secret_key = 'zxczxczxc'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passwords.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class SavedPassword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    site = db.Column(db.String(100), nullable=False)
    login = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(128), nullable=False)
    complexity = db.Column(db.String(20), nullable=False)
    length = db.Column(db.Integer, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_password(complexity: str, length: int) -> str:
    if length < 4:
        length = 4
    elif length > 64:
        length = 64

    if complexity == 'low':
        chars = string.ascii_lowercase
    elif complexity == 'medium':
        chars = string.ascii_letters + string.digits
    elif complexity == 'high':
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
    else:
        raise ValueError("Invalid complexity")

    return ''.join(secrets.choice(chars) for _ in range(length))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует.')
            return redirect(url_for('register'))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Регистрация прошла успешно! Войдите в систему.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Неверное имя пользователя или пароль.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        site = request.form.get('site', '').strip()
        login_val = request.form.get('login', '').strip()
        complexity = request.form.get('complexity', 'high')
        try:
            length = int(request.form.get('length', 12))
        except (TypeError, ValueError):
            length = 12

        if not site or not login_val:
            flash('Укажите сайт и логин.')
        else:
            try:
                pwd = generate_password(complexity, length)
                record = SavedPassword(
                    user_id=current_user.id,
                    site=site,
                    login=login_val,
                    password=pwd,
                    complexity=complexity,
                    length=length  # <-- сохраняем длину
                )
                db.session.add(record)
                db.session.commit()
                flash(f'Пароль для {site} сгенерирован!')
            except Exception as e:
                flash('Ошибка при генерации пароля.')
                print(e)

    history = SavedPassword.query.filter_by(user_id=current_user.id).order_by(SavedPassword.id.desc()).all()
    return render_template('index.html', history=history)


    history = SavedPassword.query.filter_by(user_id=current_user.id).order_by(SavedPassword.id.desc()).all()
    return render_template('index.html', history=history)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)