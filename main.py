from flask import Flask, render_template, redirect, Blueprint
import datetime
from data import db_session, jobs_api
from flask_login import LoginManager, login_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import PasswordField, BooleanField, SubmitField, EmailField, StringField, IntegerField, DateTimeField

from wtforms.validators import DataRequired
from data import db_session
from requests import get
from data.users import User
from data.users import User
from flask_restful import Api

app = Flask(__name__)
api = Api(app)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=365)

login_manager = LoginManager()
login_manager.init_app(app)

db_session.global_init("db/blogs.db")
dbs = db_session.create_session()

dbs.commit()


class LoginForm(FlaskForm):
    email = EmailField('Почта', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')


class JobForm(FlaskForm):
    email = StringField('Почта', validators=[DataRequired()])
    name = StringField('Назвние', validators=[DataRequired()])
    about = StringField('Описание', validators=[DataRequired()])
    size = IntegerField('Объем', validators=[DataRequired()])
    collaborators = StringField('Участники')
    start = DateTimeField('Дата начала', format='Дата:%Y-%m-%d Время:%H:%M:%S')
    end = DateTimeField('Дата конца', format='Дата:%Y-%m-%d Время:%H:%M:%S')
    finished = BooleanField('Работа завершена?')
    submit = SubmitField('Submit')


class RegisterForm(FlaskForm):
    email = EmailField('Login / email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    verificatepassword = PasswordField('Repeat password', validators=[DataRequired()])
    surname = StringField('Surname', validators=[DataRequired()])
    name = StringField('Name', validators=[DataRequired()])
    age = IntegerField('Age')
    position = StringField('Position')
    speciality = StringField('Speciality')
    address = StringField("Address")
    submit = SubmitField('Register')


@login_manager.user_loader
def load_user(user_id):
    db_sess = db_session.create_session()
    return db_sess.query(User).get(user_id)


@app.route("/")
@app.route("/index")
def index():
    return render_template('base.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        user = db_sess.query(User).filter(User.email == form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect("/")
        return render_template('login.html',
                               message="Неправильный логин или пароль", form=form)
    return render_template('login.html', title='Авторизация', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.verificatepassword.data:
            return render_template('register.html', title='Register form',
                                   form=form, message="Пароли не совпадают")
        db_sess = db_session.create_session()
        if db_sess.query(User).filter(User.email == form.email.data).first():
            return render_template('register.html', title='Register form',
                                   form=form, message="Такой пользователь уже есть")
        user = User(name=form.name.data, email=form.email.data, surname=form.surname.data, age=form.age.data,
                    speciality=form.speciality.data, address=form.address.data, position=form.position.data)
        user.set_password(form.password.data)
        db_sess.add(user)
        db_sess.commit()
        return redirect('/')
    return render_template('register.html', title='регистрация', form=form)


@app.route('/addjob', methods=['GET', 'POST'])
@login_required
def addjob():
    form = JobForm()

    return render_template('addjob.html', form=form, title='Добавление работы')





if __name__ == '__main__':
    db_session.global_init("db/blogs.db")
    app.register_blueprint(jobs_api.blueprint)

    app.run()

