from flask import Flask

import db

app = Flask(__name__)
db.init_app(app)


@app.route("/weather")
def weather():
    return "Shield is running"