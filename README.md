# IAWS Project
design and deploy a quiz application on the web

## To start
create a virtualenv with `python -m venv env`

activate your venv with the `activate` script in venv/Scripts (on unix use `source activate`)

install the requirements with `pip install -r requirements.txt`

set your FLASK_APP env variable to flask_app `export FLASK_APP=flask_app` on unix, `setx` on windows
set durr to some secret 16-character key

## To run
flask run (-h 0.0.0.0)
test with http://127.0.0.1:5000/test/ok
run "C:\Program Files\PostgreSQL\10\scripts\runpsql.bat"
ng build