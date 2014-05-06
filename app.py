#!env/bin/python
from flask import Flask, render_template, url_for, redirect, g
from flask.ext.compass import Compass
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.bcrypt import Bcrypt
from flask.ext.admin import Admin, AdminIndexView, expose
from flask.ext.admin.contrib.sqla import ModelView
from flask.ext.login import LoginManager, current_user, login_user, logout_user, UserMixin
from flask_wtf import Form
from wtforms.fields import PasswordField, TextField
from wtforms.validators import ValidationError, Required
import os

BASE_DIR = os.path.dirname(__file__)

# Admin views
class ModelAuthView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated()

class AdminForm(Form):
    username = TextField('username', validators=[Required()])
    password = PasswordField('password', validators=[Required()])

class AdminView(ModelAuthView):
    form = AdminForm


class LoginForm(AdminForm):
    def validate_username(self, field):
        user = self.get_user()

        if user is None:
            raise ValidationError('Invalid User')

        if not user.check_password(self.password.data):
            raise ValidationError('Invalid Password')

    def get_user(self):
        return db.session.query(Admin).filter_by(username=self.username.data).first()

class MyAdminIndexView(AdminIndexView):
    @expose('/') 
    def index(self):
        if not current_user.is_authenticated():
            return redirect(url_for('.login_view'))
        return super(MyAdminIndexView, self).index()

    @expose('/login/', methods=('GET', 'POST'))
    def login_view(self):
        form = LoginForm()

        if form.validate_on_submit():
            user = form.get_user()
            login_user(user)

        if current_user.is_authenticated():
            return redirect(url_for('.index'))

        self._template_args['form'] = form
        return super(MyAdminIndexView, self).index()

    @expose('/logout/')
    def logout_view(self):
        logout_user()
        return redirect(url_for('.index'))


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'db.sqlite3')
app.config['SECRET_KEY'] = ';pfkkfvjerhb vdhj'
app.config['DEBUG'] = True
app.config['FREEZER_BASE_URL'] = 'http://severeoverfl0w.github.io/BreachPVP/'
admin = Admin(app, name='BreachPVP Admin', index_view=MyAdminIndexView())
db = SQLAlchemy(app)
lm = LoginManager(app)
bcrypt = Bcrypt(app)
compass = Compass(app)

# Models (Are sexy)
class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32))
    _password = db.Column(db.String(65))

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, pwd):
        self._password = bcrypt.generate_password_hash(pwd)

    def check_password(self, pwd):
        return bcrypt.check_password_hash(self._password, pwd)

class Site(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32))
    url = db.Column(db.String(255))

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32))
    weight = db.Column(db.Integer)

    def __unicode__(self):
        return self.name

class Staff(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mcname = db.Column(db.String(16))
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    group = db.relationship('Group', backref=db.backref('staff', lazy='dynamic'))



# User stuff
@lm.user_loader
def load_user(userid):
    return Admin.query.filter_by(id=userid).first()

admin.add_view(AdminView(Admin, db.session))
admin.add_view(ModelAuthView(Site, db.session))
admin.add_view(ModelAuthView(Group, db.session))
admin.add_view(ModelAuthView(Staff, db.session))

@app.before_request
def before_request():
    g.user = current_user

@app.route('/')
def index():
    return render_template('index.html', 
            site_list=Site.query.all(),
            group_list=Group.query.order_by('weight').all(),)

if __name__ == '__main__':
    app.run(debug=True, port=5500, host='192.168.1.32')
