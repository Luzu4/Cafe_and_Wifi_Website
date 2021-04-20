from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_login import login_user, LoginManager, current_user, UserMixin, logout_user
from flask_ckeditor import CKEditor
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email
from werkzeug.security import generate_password_hash, check_password_hash

SECRET_KEY = 'tssss'

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
Bootstrap(app)
ckeditor = CKEditor(app)
login_manager = LoginManager()
login_manager.init_app(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cafes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Cafe(db.Model):
    __tablename__ = 'cafe'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=True, nullable=False)
    location = db.Column(db.String(250))
    coffee_price = db.Column(db.Float)
    img_url = db.Column(db.String(2500))
    map_url = db.Column(db.String(2500))
    has_sockets = db.Column(db.Integer)
    has_toilet = db.Column(db.Integer)
    has_wifi = db.Column(db.Integer)
    can_take_calls = db.Column(db.Integer)
    seats = db.Column(db.String(250))


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)


class AddCafe(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    location = StringField(':Location', validators=[DataRequired()])
    coffee_price = StringField('Coffee Price', validators=[DataRequired()])
    img_url = StringField('Image URL', validators=[DataRequired(), URL()])
    map_url = StringField('Map URL', validators=[DataRequired(), URL()])
    has_sockets = StringField('Sockets', validators=[DataRequired()])
    has_toilet = StringField('Toilet', validators=[DataRequired()])
    has_wifi = StringField('Wi-Fi', validators=[DataRequired()])
    can_take_calls = StringField('Can take calls', validators=[DataRequired()])
    seats = StringField('Seats', validators=[DataRequired()])
    submit = SubmitField('Submit')


class RegisterUser(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')


class LoginForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField("Submit")


# Function to print variable in jinja
@app.context_processor
def utility_functions():
    def print_in_console(message):
        print(str(message))

    return dict(mdebug=print_in_console)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route("/")
def home():
    all_cafes = db.session.query(Cafe).all()
    all_users = db.session.query(User).all()
    current_user_id = current_user.get_id()
    return render_template("index.html", cafes=all_cafes, users=all_users, logged_in=current_user.is_authenticated,
                           user_id=current_user_id)


@app.route("/add-cafe", methods=["POST", "GET"])
def add_new_cafe():
    form = AddCafe()
    if form.validate_on_submit():
        new_cafe = Cafe(
            name=form.name.data,
            location=form.location.data,
            coffee_price=form.coffee_price.data,
            img_url=form.img_url.data,
            map_url=form.map_url.data,
            has_sockets=form.has_sockets.data,
            has_toilet=form.has_toilet.data,
            has_wifi=form.has_wifi.data,
            can_take_calls=form.can_take_calls.data,
            seats=form.seats.data,
        )
        db.session.add(new_cafe)
        db.session.commit()
        return redirect(url_for('home'))
    current_user_id = current_user.get_id()
    all_users = db.session.query(User).all()
    return render_template('wtf_form.html', form=form, info='Add new Cafe', logged_in=current_user.is_authenticated,
                           user_id=current_user_id, users=all_users)


@app.route("/add-user", methods=['POST', 'GET'])
def add_new_user():
    form = RegisterUser()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('NOOOOPE, email already exist')
        else:
            password = generate_password_hash(form.password.data,
                                              method='pbkdf2:sha256',
                                              salt_length=8)
            new_user = User(
                name=form.name.data,
                email=form.email.data,
                password=password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('home'))
    return render_template('wtf_form.html', form=form, info='Sign up')


@app.route("/delete/<int:cafe_id>")
def delete_cafe(cafe_id):
    cafe_to_delete = Cafe.query.get(cafe_id)
    db.session.delete(cafe_to_delete)
    db.session.commit()
    return redirect(url_for('home'))


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user is None:
            flash("Nooooope, wrong mail")
        else:
            if check_password_hash(user.password, password):
                login_user(user)
                flash("You are logged in")
                return redirect(url_for('home'))
            else:
                flash('Wrong password')
    return render_template("wtf_form.html", form=form, info='Login')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
