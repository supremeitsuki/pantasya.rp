import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, abort
from config import Config
from models import db, User, Category, Thread, Post
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import markdown

def allowed_file(filename, allowed):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    db.init_app(app)
    bcrypt = Bcrypt(app)
    login_manager = LoginManager(app)
    login_manager.login_view = 'login'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @app.template_filter('markdown')
    def _markdown_to_html(text):
        return markdown.markdown(text or '', extensions=['fenced_code','tables'])

    # ---------- Index / Latest posts -----------
    @app.route('/')
    def index():
        latest_posts = Post.query.order_by(Post.created_at.desc()).limit(8).all()
        categories = Category.query.order_by(Category.name).all()
        return render_template('index.html', latest_posts=latest_posts, categories=categories)

    # ---------- Auth -----------
    @app.route('/register', methods=['GET','POST'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        if request.method == 'POST':
            username = request.form.get('username','').strip()
            email = request.form.get('email','').strip().lower()
            password = request.form.get('password','')
            in_game = request.form.get('in_game_name','').strip()
            # simple server-side validation
            if not username or not email or not password:
                flash('Please fill all required fields.', 'danger')
                return render_template('register.html')
            if User.query.filter_by(username=username).first():
                flash('Username already taken.', 'danger')
                return render_template('register.html')
            if User.query.filter_by(email=email).first():
                flash('Email already registered.', 'danger')
                return render_template('register.html')
            pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(username=username, email=email, password_hash=pw_hash, in_game_name=in_game)
            db.session.add(user)
            db.session.commit()
            flash('Account created. You can now login.', 'success')
            return redirect(url_for('login'))
        return render_template('register.html')

    @app.route('/login', methods=['GET','POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        if request.method == 'POST':
            username = request.form.get('username','').strip()
            password = request.form.get('password','')
            user = User.query.filter_by(username=username).first()
            if user and bcrypt.check_password_hash(user.password_hash, password):
                login_user(user)
                flash('Logged in successfully.', 'success')
                return redirect(url_for('index'))
            flash('Invalid username/password.', 'danger')
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('Logged out.', 'info')
        return redirect(url_for('index'))

    # ---------- Categories & Threads ----------
    @app.route('/categories')
    def categories():
        categories = Category.query.order_by(Category.name).all()
        return render_template('categories.html', categories=categories)

    @app.route('/category/<int:cat_id>')
    def view_category(cat_id):
        page = request.args.get('page', 1, type=int)
        cat = Category.query.get_or_404(cat_id)
        per_page = 8
        pagination = Thread.query.filter_by(category_id=cat_id).order_by(Thread.created_at.desc()).paginate(page, per_page, False)
        threads = pagination.items
        return render_template('category.html', category=cat, threads=threads, pagination=pagination)

    @app.route('/thread/<int:thread_id>')
    def view_thread(thread_id):
        page = request.args.get('page', 1, type=int)
        per_page = 6
        thread = Thread.query.get_or_404(thread_id)
        pagination = Post.query.filter_by(thread_id=thread_id).order_by(Post.created_at).paginate(page, per_page, False)
        posts = pagination.items
        return render_template('thread.html', thread=thread, posts=posts, pagination=pagination)

    @app.route('/category/<int:cat_id>/create_thread', methods=['GET','POST'])
    @login_required
    def create_thread(cat_id):
        cat = Category.query.get_or_404(cat_id)
        if request.method == 'POST':
            title = request.form.get('title','').strip()
            content = request.form.get('content','').strip()
            if not title or not content:
                flash('Title and message required.', 'danger')
                return render_template('create_thread.html', category=cat)
            thread = Thread(category_id=cat.id, title=title, author_id=current_user.id)
            db.session.add(thread)
            db.session.flush()  # get thread.id
            post = Post(thread_id=thread.id, author_id=current_user.id, content=content)
            db.session.add(post)
            db.session.commit()
            return redirect(url_for('view_thread', thread_id=thread.id))
        return render_template('create_thread.html', category=cat)

    # ---------- Posting / Editing / Deleting ----------
    @app.route('/thread/<int:thread_id>/reply', methods=['GET','POST'])
    @login_required
    def reply(thread_id):
        thread = Thread.query.get_or_404(thread_id)
        if request.method == 'POST':
            content = request.form.get('content','').strip()
            if not content:
                flash('Message cannot be empty', 'danger')
                return redirect(url_for('view_thread', thread_id=thread.id))
            image = request.files.get('image')
            filename = None
            if image and image.filename != '':
                if not allowed_file(image.filename, app.config['ALLOWED_EXTENSIONS']):
                    flash('Unsupported image type.', 'danger')
                    return redirect(url_for('view_thread', thread_id=thread.id))
                filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            post = Post(thread_id=thread.id, author_id=current_user.id, content=content, image_filename=filename)
            db.session.add(post)
            db.session.commit()
            flash('Reply posted.', 'success')
            return redirect(url_for('view_thread', thread_id=thread.id))
        return render_template('create_post.html', thread=thread)

    @app.route('/post/<int:post_id>/edit', methods=['GET','POST'])
    @login_required
    def edit_post(post_id):
        post = Post.query.get_or_404(post_id)
        if current_user.id != post.author_id and current_user.role != 'admin':
            abort(403)
        if request.method == 'POST':
            content = request.form.get('content','').strip()
            if not content:
                flash('Message cannot be empty', 'danger')
                return render_template('edit_post.html', post=post)
            post.content = content
            db.session.commit()
            flash('Post updated.', 'success')
            return redirect(url_for('view_thread', thread_id=post.thread_id))
        return render_template('edit_post.html', post=post)

    @app.route('/post/<int:post_id>/delete', methods=['POST'])
    @login_required
    def delete_post(post_id):
        post = Post.query.get_or_404(post_id)
        if current_user.id != post.author_id and current_user.role != 'admin':
            abort(403)
        thread_id = post.thread_id
        db.session.delete(post)
        db.session.commit()
        flash('Post deleted.', 'info')
        return redirect(url_for('view_thread', thread_id=thread_id))

    # ---------- Admin: Create Category ----------
    def admin_required(func):
        from functools import wraps
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != 'admin':
                abort(403)
            return func(*args, **kwargs)
        return wrapper

    @app.route('/admin/create_category', methods=['GET','POST'])
    @login_required
    @admin_required
    def create_category():
        if request.method == 'POST':
            name = request.form.get('name','').strip()
            desc = request.form.get('description','').strip()
            if not name:
                flash('Name required.', 'danger')
                return render_template('admin_create_category.html')
            if Category.query.filter_by(name=name).first():
                flash('Category already exists.', 'danger')
                return render_template('admin_create_category.html')
            cat = Category(name=name, description=desc)
            db.session.add(cat)
            db.session.commit()
            flash('Category created.', 'success')
            return redirect(url_for('categories'))
        return render_template('admin_create_category.html')

    # ---------- Profiles ----------
    @app.route('/user/<username>')
    def profile(username):
        user = User.query.filter_by(username=username).first_or_404()
        page = request.args.get('page', 1, type=int)
        pagination = Post.query.filter_by(author_id=user.id).order_by(Post.created_at.desc()).paginate(page, 8, False)
        posts = pagination.items
        return render_template('profile.html', user=user, posts=posts, pagination=pagination)

    # ---------- Serve uploaded images ----------
    @app.route('/uploads/<filename>')
    def uploaded_file(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

    # ---------- Simple search (optional) ----------
    @app.route('/search')
    def search():
        q = request.args.get('q','').strip()
        results = []
        if q:
            results = Thread.query.filter(Thread.title.ilike(f'%{q}%')).limit(30).all()
        return render_template('search.html', query=q, results=results)

    return app

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(debug=True)
