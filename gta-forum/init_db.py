from app import create_app
from models import db, User, Category
from flask_bcrypt import Bcrypt

app = create_app()
bcrypt = Bcrypt(app)

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        pw = bcrypt.generate_password_hash('adminpass').decode('utf-8')
        admin = User(username='admin', email='admin@example.com', password_hash=pw, role='admin', in_game_name='Admin')
        db.session.add(admin)
    if Category.query.count() == 0:
        cats = [
            Category(name='Announcements', description='Server news & announcements'),
            Category(name='General Discussion', description='Talk about anything GTA SA-MP'),
            Category(name='Server Updates', description='Patch notes, downtime alerts'),
            Category(name='Gang Recruitment', description='Find crews & gangs')
        ]
        db.session.add_all(cats)
    db.session.commit()
    print("DB initialized.")
