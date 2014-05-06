#!env/bin/python

from flask.ext.script import Manager, prompt_pass, prompt
from app import app, db, Admin

manager = Manager(app)

@manager.command
def initdb():
    print("Wiping DB")
    db.drop_all()
    print("Creating DB")
    db.create_all()
    print("Done.")

@manager.command
def addadmin():
    user = prompt('Username')
    pwd = prompt_pass('Password')
    admin = Admin(username=user, password=pwd)
    db.session.add(admin)
    db.session.commit()


if __name__ == "__main__":
    manager.run()
