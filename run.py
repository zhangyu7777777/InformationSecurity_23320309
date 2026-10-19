from app import create_app
from app.db import seed_demo_data

app = create_app()

with app.app_context():
    seed_demo_data()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
