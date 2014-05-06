from flask_frozen import Freezer
from app import app

freezer = Freezer(app, log_url_for=False, with_no_argument_rules=False)

@freezer.register_generator
def index():
    yield {'': ''}

if __name__ == '__main__':
    freezer.freeze()
