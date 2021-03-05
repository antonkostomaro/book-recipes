from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, login_required, logout_user, LoginManager
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from flask_admin import Admin





app = Flask(__name__)
app.secret_key = 'kkkkfgfhfghdfsdf'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
manager = LoginManager(app)
admin = Admin(app)



class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(20000), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return '<Task %r>' % self.id



class User (db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)


@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


db.create_all()

@app.route('/post.html', methods=['POST', 'GET'])
def post():
    if request.method == 'POST':
        task_content = request.form['content']
        new_task = Todo(content=task_content)

        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect('post.html')
        except:
            return 'There was an issue adding your task'

    else:
        tasks = Todo.query.order_by(Todo.date_created).all()
        return render_template('/post.html', tasks=tasks)

@app.route('/delete/<int:id>')
def delete(id):
    task_to_delete = Todo.query.get_or_404(id)

    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect('/post.html')
    except:
        return 'There was a problem deleting that task'

@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    task = Todo.query.get_or_404(id)

    if request.method == 'POST':
        task.content = request.form['content']

        try:
            db.session.commit()
            return redirect('/post.html')
        except:
            return 'There was an issue updating your task'

    else:
        return render_template('update.html', task=task)



@app.route('/index.html', methods=['GET'])
def hello_world():
    return render_template('index.html')

@app.route('/new.html', methods=['GET'])
def new():
    return render_template('new.html')

@app.route('/signin.html', methods=['GET'])
def signin():
    return render_template('signin.html')


@app.route('/about.html')
def about():
    return render_template('about.html')



@app.route('/categories-grid.html')
def categories_grid():
    return render_template('categories-grid.html')


@app.route('/categories-list.html')
def categories_list():
    return render_template('categories-list.html')


@app.route('/index.html', methods=['GET'])
@login_required
def main():
    return render_template('index.html')





@app.route('/signin.html', methods=['GET', 'POST'])
def login_page():
    login = request.form.get('login')
    password = request.form.get('password')

    if login and password:
        user = User.query.filter_by(login=login).first()

        if user and check_password_hash(user.password, password):
            login_user(user)

            next_page = request.args.get('next')

            return redirect(next_page or url_for('main'))
        else:
            flash('Логин или пароль неверный')
    else:
        flash('Пожалуйста, заполните поля логина и пароля')

    return render_template('signin.html')


@app.route('/register.html', methods=['GET', 'POST'])
def register():
    login = request.form.get('login')
    password = request.form.get('password')
    password2 = request.form.get('password2')

    if request.method == 'POST':
        if not (login or password or password2):
            flash('Пожалуйста заполните все поля!2')
        elif password != password2:
            flash('Пароли не Совпадают!')
        else:
            hash_pwd = generate_password_hash(password)
            new_user = User(login=login, password=hash_pwd)
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('login_page'))

    return render_template('register.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('hello_world'))


@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login_page') + '?next=' + request.url)

    return response

@app.route('/profile/<path:username>')
def profile(username):
    return f"Пользователь {username}"


if __name__ == "__main__":
    app.run(debug=True)