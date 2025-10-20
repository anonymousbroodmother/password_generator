from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import secrets
import string
import os

app = Flask(__name__)
app.secret_key = 'zxczxczcxqweqweqwe'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passwords.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)



class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), nullable=False)
    password = db.Column(db.String(128), nullable=False)
    complexity = db.Column(db.String(20), nullable=False)



with app.app_context():
    db.create_all()


def generate_password(complexity: str) -> str:
    if complexity == 'low':
        chars = string.ascii_lowercase
        length = 8
    elif complexity == 'medium':
        chars = string.ascii_letters + string.digits
        length = 10
    elif complexity == 'high':
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        length = 12
    else:
        raise ValueError("Invalid complexity level")

    return ''.join(secrets.choice(chars) for _ in range(length))


@app.route('/', methods=['GET', 'POST'])
def index():

    if 'user_id' not in session:
        session['user_id'] = str(secrets.token_hex(16))

    user_id = session['user_id']

    if request.method == 'POST':
        complexity = request.form.get('complexity', 'medium')
        try:
            pwd = generate_password(complexity)

            new_pwd = Password(user_id=user_id, password=pwd, complexity=complexity)
            db.session.add(new_pwd)
            db.session.commit()
        except ValueError:
            pwd = "Ошибка: неверный уровень сложности"
    else:
        pwd = None


    history = Password.query.filter_by(user_id=user_id).order_by(Password.id.desc()).all()

    return render_template('index.html', password=pwd, history=history)


if __name__ == '__main__':
    app.run(debug=True)