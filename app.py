from flask import Flask
from routes.policy_routes import policy_routes

app = Flask(__name__, 
            static_folder='static',
            template_folder='templates')

app.register_blueprint(policy_routes)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5001)
