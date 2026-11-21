from flask import Flask

app = Flask(__name__)
@app.route("/weather")
def weather():
    return "Shield is running"