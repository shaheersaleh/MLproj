
from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "Welcome to the REAL backend!"

@app.route("/search")
def search():
    return "Search endpoint reached."

@app.route("/admin")
def admin():
    return "Admin page (should be blocked if WAF works)."

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
