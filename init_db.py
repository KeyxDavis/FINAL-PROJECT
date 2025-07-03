from app import db, app

with app.app_context():
    db.create_all()
    print("Database tables created successfully!")
    # You can also add initial data here if needed
