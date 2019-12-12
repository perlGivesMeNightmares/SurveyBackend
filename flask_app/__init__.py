from flask import Flask, request, redirect
from flask_cors import CORS, cross_origin
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from flask_sqlalchemy import SQLAlchemy
from hashlib import sha256
from uuid import uuid4
import os
import jwt
import json
from datetime import datetime, timedelta

def setup_db(app):
	POSTGRES_URL = os.environ['POSTGRES_URL']
	POSTGRES_USER = os.environ['POSTGRES_USER']
	POSTGRES_PW = os.environ['POSTGRES_PW']
	POSTGRES_DB = os.environ['POSTGRES_DB']

	engine = create_engine('postgresql://{}:{}@{}/{}'.format(POSTGRES_USER, POSTGRES_PW, POSTGRES_URL, POSTGRES_DB))
	# engine = create_engine('postgresql+psycopg2://{}:{}@{}/{}'.format(POSTGRES_USER, POSTGRES_PW, POSTGRES_URL, POSTGRES_DB))
	Session = sessionmaker(bind=engine)
	session = Session()

	# DB_URL = 'postgresql+psycopg2://{user}:{pw}@{url}/{db}'.format(user=POSTGRES_USER, pw=POSTGRES_PW, url=POSTGRES_URL, db=POSTGRES_DB)
	DB_URL = 'postgresql://{user}:{pw}@{url}/{db}'.format(user=POSTGRES_USER, pw=POSTGRES_PW, url=POSTGRES_URL, db=POSTGRES_DB)

	app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
	app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # silence the deprecation warning

	db = SQLAlchemy(app)
	return engine, session, db


def run_query(db, sql_text):
	return db.engine.execute(text(sql_text)).execution_options(autocommit=True)


def build_flask_app():
	app = Flask(__name__)
	CORS(app)
	
	# cors = CORS(app, resources={r"/api/*": {"origins": "*"}})
	app.secret_key = os.environ['durr']

	engine, session, db = setup_db(app)
	conn = engine.connect()
	conn.execute("CREATE TABLE IF NOT EXISTS users(user_id serial PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT UNIQUE NOT NULL);")

	conn.execute("INSERT INTO users (username, password) VALUES ('testuser', 'b822f1cd2dcfc685b47e83e3980289fd5d8e3ff3a82def24d7d1d68bb272eb32') "
		"ON CONFLICT DO NOTHING;")

	conn.execute("CREATE TABLE IF NOT EXISTS surveys(id serial PRIMARY KEY, link_id TEXT UNIQUE NOT NULL, content JSON NOT NULL,"
		" user_id INTEGER NOT NULL, created_dt TIMESTAMP DEFAULT NOW());")

	return app, conn

app, db = build_flask_app()


@app.route('/getSurveyInfo', methods=('GET',))
def get_survey_info():
	survey_info = {
		'title': 'My Blurst Survey',
		'description': 'Test of survey',
		'questions': [1, 2, 3]
	}
	return survey_info


@app.route('/upload_survey', methods=('POST',))
def upload_survey():
	survey_json = request.get_json()['surveyJson']
	# print(survey_json)
	token = request.get_json()['token']
	res = authenticate(token)
	if not res.get('success'):
		return res
	link_text = str(uuid4())[:7]
	db.execute("INSERT INTO surveys (link_id, content, user_id) VALUES (%s, %s, %s);", link_text, survey_json, res['user'])
	return {'success': True}


@app.route('/test', methods=('GET',))
def test():
	return {'success': True}


@app.route('/login', methods=('POST',))
def login():
	username = request.get_json()['username']
	password = request.get_json()['password']
	if not (username and password):
		return {'success': False, 'msg': 'Error: must fill out both fields'}
	password = sha256(password.encode()).hexdigest()
	if (any(c in username for c in ('"', "'", ';', '\\'))):
		return {'success': False, 'msg': 'Invalid characters used'}

	user_match = db.execute("SELECT * FROM users WHERE username=%s AND password=%s", username, password).fetchone()
	if not user_match:
		return {'success': False, 'msg': 'Invalid creds'}

	token = create_auth_token(user_match['user_id'])
	print('new token {}'.format(token))

	return {'success': True, 'user': user_match['user_id'], 'token': token}


@app.route('/register', methods=('POST',))
def register():
	username = request.get_json()['username']
	password = request.get_json()['password']
	if not (username and password):
		return {'success': False, 'msg': 'Error: must fill out both fields'}
	password = sha256(password.encode()).hexdigest()
	if (any(c in username for c in ('"', "'", ';', '\\'))):
		return {'success': False, 'msg': 'Invalid characters used'}
	user_match = db.execute("SELECT * FROM users WHERE username=%s;", username).fetchone()
	if user_match:
		return {'success': False, 'msg': 'User already exists'}

	db.execute("INSERT INTO users (username, password) VALUES (%s, %s);", username, password)

	return {'success': True}



# @app.route('/login/login_payload', methods=('POST',))
# def login():
# 	if 'email' in login_payload and 'password' in login_payload:
# 		login_user()

# 	form = LoginForm()
# 	if form.validate_on_submit():
# 		# Login and validate the user.
# 		# user should be an instance of your `User` class
# 		login_user(user)

# 		flask.flash('Logged in successfully.')

# 		next = flask.request.args.get('next')
# 		# is_safe_url should check if the url is safe for redirects.
# 		# See http://flask.pocoo.org/snippets/62/ for an example.
# 		if not is_safe_url(next):
# 			return flask.abort(400)

# 		return flask.redirect(next or flask.url_for('index'))
# 	return flask.render_template('login.html', form=form)


# @login_manager.user_loader
# def load_user(user_id):
#     return User.get(user_id)

def create_auth_token(user_id):
    """
    Generates the Auth Token
    :return: string
    """
    payload = {
        'exp': datetime.utcnow() + timedelta(days=10),
        'iat': datetime.utcnow(),
        'sub': user_id
    }
    token = jwt.encode(
        payload,
        os.environ['durr'],
        algorithm='HS256'
    )
    return token.decode('utf-8')

def authenticate(token):
	try:
		payload = jwt.decode(token, os.environ['durr'], algorithm='HS256')
	except (jwt.DecodeError, jwt.ExpiredSignatureError):
		return {'success': False, 'message': 'invalid token'}

	return {'success': True, 'user': payload['sub']}
