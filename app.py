#!/usr/bin/env python3
"""READORA - Netflix-Style eBook Store"""

import os, secrets, json
from datetime import datetime, timedelta
from flask import (Flask, render_template, request, redirect, url_for, 
    flash, session, abort, send_file, jsonify)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user, 
    login_required, current_user)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import requests

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///readora.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 52428800))

os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'books'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'covers'), exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'admin_login'
login_manager.login_message = None

limiter = Limiter(app=app, key_func=get_remote_address, 
    default_limits=["200 per day", "50 per hour"])

MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', 3))
LOCKOUT_DURATION = int(os.getenv('LOCKOUT_DURATION_MINUTES', 30)) * 60
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD_HASH = generate_password_hash(os.getenv('ADMIN_PASSWORD', 'change-me-now'))
BLOCKONOMICS_API_KEY = os.getenv('BLOCKONOMICS_API_KEY', '')

# ========== MODELS ==========
class AdminUser(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, default=0.0)
    category = db.Column(db.String(100), nullable=False)
    tags = db.Column(db.String(500))
    cover_image = db.Column(db.String(255))
    book_file = db.Column(db.String(255))
    is_featured = db.Column(db.Boolean, default=False)
    is_trending = db.Column(db.Boolean, default=False)
    is_new_release = db.Column(db.Boolean, default=False)
    page_count = db.Column(db.Integer, default=0)
    rating = db.Column(db.Float, default=0.0)
    download_count = db.Column(db.Integer, default=0)
    view_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    display_order = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    bitcoin_address = db.Column(db.String(100))
    payment_status = db.Column(db.String(20), default='pending')
    amount_btc = db.Column(db.Float)
    amount_usd = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    paid_at = db.Column(db.DateTime)
    download_token = db.Column(db.String(64), unique=True)
    download_used = db.Column(db.Boolean, default=False)
    download_expires = db.Column(db.DateTime)
    email = db.Column(db.String(120))

class FailedLoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    attempt_count = db.Column(db.Integer, default=1)
    last_attempt = db.Column(db.DateTime, default=datetime.utcnow)
    is_locked = db.Column(db.Boolean, default=False)
    lockout_until = db.Column(db.DateTime)

@login_manager.user_loader
def load_user(user_id):
    return AdminUser.query.get(int(user_id))

# ========== SECURITY HELPERS ==========
def is_ip_locked(ip_address):
    attempt = FailedLoginAttempt.query.filter_by(ip_address=ip_address).first()
    if not attempt: return False
    if attempt.is_locked and attempt.lockout_until:
        if datetime.utcnow() < attempt.lockout_until: return True
        attempt.is_locked = False
        attempt.attempt_count = 0
        attempt.lockout_until = None
        db.session.commit()
    return False

def record_failed_attempt(ip_address):
    attempt = FailedLoginAttempt.query.filter_by(ip_address=ip_address).first()
    now = datetime.utcnow()
    if not attempt:
        attempt = FailedLoginAttempt(ip_address=ip_address, attempt_count=1, last_attempt=now)
        db.session.add(attempt)
    else:
        attempt.attempt_count += 1
        attempt.last_attempt = now
        if attempt.attempt_count >= MAX_LOGIN_ATTEMPTS:
            attempt.is_locked = True
            attempt.lockout_until = now + timedelta(seconds=LOCKOUT_DURATION)
    db.session.commit()
    return attempt.attempt_count

def reset_failed_attempts(ip_address):
    attempt = FailedLoginAttempt.query.filter_by(ip_address=ip_address).first()
    if attempt:
        db.session.delete(attempt)
        db.session.commit()

def generate_download_token():
    return secrets.token_urlsafe(32)

def verify_download_token(token):
    order = Order.query.filter_by(download_token=token).first()
    if not order or order.download_used: return None
    if order.download_expires and datetime.utcnow() > order.download_expires: return None
    return order

# ========== CONTEXT PROCESSOR ==========
@app.context_processor
def inject_globals():
    categories = Category.query.filter_by(is_active=True).order_by(Category.display_order).all()
    featured_books = Book.query.filter_by(is_featured=True, is_active=True).limit(6).all()
    return {
        'app_name': os.getenv('APP_NAME', 'Readora'),
        'categories': categories,
        'featured_books': featured_books,
        'current_year': datetime.now().year
    }

# ========== PUBLIC ROUTES ==========
@app.route('/')
def index():
    hero_book = Book.query.filter_by(is_featured=True, is_active=True).order_by(db.func.random()).first()
    trending = Book.query.filter_by(is_trending=True, is_active=True).limit(12).all()
    new_releases = Book.query.filter_by(is_new_release=True, is_active=True).limit(12).all()
    category_rows = []
    for cat in Category.query.filter_by(is_active=True).order_by(Category.display_order).limit(6).all():
        books = Book.query.filter_by(category=cat.name, is_active=True).limit(10).all()
        if books: category_rows.append({'category': cat, 'books': books})
    free_books = Book.query.filter_by(price=0.0, is_active=True).order_by(Book.created_at.desc()).limit(10).all()
    return render_template('index.html', hero_book=hero_book, trending=trending,
                         new_releases=new_releases, category_rows=category_rows, free_books=free_books)

@app.route('/browse')
def browse():
    category = request.args.get('category', '')
    search = request.args.get('search', '')
    sort = request.args.get('sort', 'newest')
    price_filter = request.args.get('price', '')
    query = Book.query.filter_by(is_active=True)
    if category: query = query.filter_by(category=category)
    if search:
        st = f"%{search}%"
        query = query.filter(db.or_(Book.title.ilike(st), Book.author.ilike(st), Book.description.ilike(st)))
    if price_filter == 'free': query = query.filter_by(price=0.0)
    elif price_filter == 'paid': query = query.filter(Book.price > 0)
    if sort == 'newest': query = query.order_by(Book.created_at.desc())
    elif sort == 'popular': query = query.order_by(Book.download_count.desc())
    elif sort == 'price_low': query = query.order_by(Book.price.asc())
    elif sort == 'price_high': query = query.order_by(Book.price.desc())
    elif sort == 'rating': query = query.order_by(Book.rating.desc())
    books = query.paginate(page=request.args.get('page', 1, type=int), per_page=24, error_out=False)
    return render_template('browse.html', books=books, category=category, search=search)

@app.route('/book/<int:book_id>')
def book_detail(book_id):
    book = Book.query.get_or_404(book_id)
    if not book.is_active: abort(404)
    book.view_count += 1
    db.session.commit()
    related = Book.query.filter(Book.category == book.category, Book.id != book.id, Book.is_active == True).limit(6).all()
    wishlist = json.loads(request.cookies.get('wishlist', '[]'))
    return render_template('book_detail.html', book=book, related=related, in_wishlist=book_id in wishlist)

@app.route('/read/<int:book_id>')
def read_book(book_id):
    book = Book.query.get_or_404(book_id)
    if not book.is_active: abort(404)
    if book.price > 0:
        flash('Online reading is only available for free books.', 'error')
        return redirect(url_for('book_detail', book_id=book_id))
    if not book.book_file: abort(404)
    return render_template('reader.html', book=book)

@app.route('/api/serve-pdf/<int:book_id>')
def serve_pdf(book_id):
    book = Book.query.get_or_404(book_id)
    if book.price > 0 or not book.book_file: abort(403)
    fp = os.path.join(app.config['UPLOAD_FOLDER'], 'books', book.book_file)
    if not os.path.exists(fp): abort(404)
    return send_file(fp, mimetype='application/pdf')

@app.route('/purchase/<int:book_id>', methods=['GET', 'POST'])
def purchase(book_id):
    book = Book.query.get_or_404(book_id)
    if book.price == 0:
        flash('This book is free! Download it directly.', 'info')
        return redirect(url_for('book_detail', book_id=book_id))
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email or '@' not in email:
            flash('Please enter a valid email address.', 'error')
            return redirect(url_for('purchase', book_id=book_id))
        if BLOCKONOMICS_API_KEY:
            try:
                headers = {'Authorization': f'Bearer {BLOCKONOMICS_API_KEY}'}
                resp = requests.post('https://www.blockonomics.co/api/new_address',
                    headers=headers, json={'match_account': True})
                data = resp.json()
                if 'address' in data:
                    order = Order(book_id=book.id, bitcoin_address=data['address'],
                        amount_usd=book.price, email=email,
                        download_token=generate_download_token(),
                        download_expires=datetime.utcnow() + timedelta(days=7))
                    db.session.add(order)
                    db.session.commit()
                    return render_template('payment.html', book=book, order=order, btc_address=data['address'])
                else: flash('Unable to generate payment address.', 'error')
            except Exception as e:
                app.logger.error(f"Payment error: {e}")
                flash('Payment system temporarily unavailable.', 'error')
        else: flash('Payment system not configured. Demo mode.', 'warning')
    return render_template('purchase.html', book=book)

@app.route('/download/<token>')
def download_book(token):
    order = verify_download_token(token)
    if not order:
        flash('This download link has expired or already been used.', 'error')
        return redirect(url_for('index'))
    book = Book.query.get(order.book_id)
    if not book or not book.book_file: abort(404)
    fp = os.path.join(app.config['UPLOAD_FOLDER'], 'books', book.book_file)
    if not os.path.exists(fp): abort(404)
    order.download_used = True
    db.session.commit()
    book.download_count += 1
    db.session.commit()
    return send_file(fp, as_attachment=True, download_name=f"{secure_filename(book.title)}.pdf")

@app.route('/api/check-payment/<int:order_id>')
def check_payment(order_id):
    order = Order.query.get_or_404(order_id)
    if BLOCKONOMICS_API_KEY and order.payment_status == 'pending':
        try:
            headers = {'Authorization': f'Bearer {BLOCKONOMICS_API_KEY}'}
            resp = requests.get(f'https://www.blockonomics.co/api/merchant_order/{order.bitcoin_address}', headers=headers)
            data = resp.json()
            if data.get('status') == 2:
                order.payment_status = 'paid'
                order.paid_at = datetime.utcnow()
                db.session.commit()
        except: pass
    return jsonify({'status': order.payment_status,
        'download_url': url_for('download_book', token=order.download_token, _external=True) if order.payment_status == 'paid' else None})

# ========== WISHLIST ==========
@app.route('/wishlist')
def wishlist():
    wishlist_ids = json.loads(request.cookies.get('wishlist', '[]'))
    books = Book.query.filter(Book.id.in_(wishlist_ids), Book.is_active == True).all() if wishlist_ids else []
    return render_template('wishlist.html', books=books)

@app.route('/api/wishlist/toggle/<int:book_id>', methods=['POST'])
def toggle_wishlist(book_id):
    wishlist = json.loads(request.cookies.get('wishlist', '[]'))
    if book_id in wishlist:
        wishlist.remove(book_id); status = 'removed'
    else:
        wishlist.append(book_id); status = 'added'
    resp = jsonify({'status': status, 'count': len(wishlist)})
    resp.set_cookie('wishlist', json.dumps(wishlist), max_age=60*60*24*365)
    return resp

# ========== ADMIN ROUTES ==========
@app.route('/readora-admin')
def admin_login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))
    ip = request.remote_addr
    if is_ip_locked(ip):
        rem = FailedLoginAttempt.query.filter_by(ip_address=ip).first()
        mins = int((rem.lockout_until - datetime.utcnow()).total_seconds() / 60)
        flash(f'Too many failed attempts. Try again in {mins} minutes.', 'error')
        return render_template('admin/login.html', locked=True), 429
    return render_template('admin/login.html')

@app.route('/readora-admin/login', methods=['POST'])
@limiter.limit("5 per minute")
def admin_login_post():
    ip = request.remote_addr
    if is_ip_locked(ip): abort(429)
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
        admin = AdminUser.query.filter_by(username=username).first()
        if not admin:
            admin = AdminUser(username=username, password_hash=ADMIN_PASSWORD_HASH)
            db.session.add(admin); db.session.commit()
        admin.last_login = datetime.utcnow(); db.session.commit()
        reset_failed_attempts(ip)
        login_user(admin, remember=False)
        app.logger.info(f"Admin login from {ip}")
        return redirect(request.args.get('next') or url_for('admin_dashboard'))
    else:
        attempts = record_failed_attempt(ip)
        rem = MAX_LOGIN_ATTEMPTS - attempts
        if rem > 0: flash(f'Invalid credentials. {rem} attempts remaining.', 'error')
        else: flash('Account locked. Try again in 30 minutes.', 'error')
        app.logger.warning(f"Failed login attempt {attempts} from {ip}")
        return redirect(url_for('admin_login'))

@app.route('/readora-admin/logout')
@login_required
def admin_logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('admin_login'))

@app.route('/readora-admin/dashboard')
@login_required
def admin_dashboard():
    stats = {
        'total_books': Book.query.count(),
        'total_orders': Order.query.count(),
        'total_revenue': db.session.query(db.func.sum(Order.amount_usd)).filter_by(payment_status='paid').scalar() or 0,
        'total_downloads': db.session.query(db.func.sum(Book.download_count)).scalar() or 0,
        'pending_orders': Order.query.filter_by(payment_status='pending').count(),
        'recent_orders': Order.query.order_by(Order.created_at.desc()).limit(10).all()
    }
    return render_template('admin/dashboard.html', stats=stats)

@app.route('/readora-admin/books')
@login_required
def admin_books():
    books = Book.query.order_by(Book.created_at.desc()).all()
    return render_template('admin/books.html', books=books)

@app.route('/readora-admin/book/new', methods=['GET', 'POST'])
@login_required
def admin_new_book():
    categories = Category.query.filter_by(is_active=True).all()
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        author = request.form.get('author', '').strip()
        description = request.form.get('description', '').strip()
        price = float(request.form.get('price', 0))
        category = request.form.get('category', '').strip()
        tags = request.form.get('tags', '').strip()
        page_count = int(request.form.get('page_count', 0) or 0)
        is_featured = bool(request.form.get('is_featured'))
        is_trending = bool(request.form.get('is_trending'))
        is_new_release = bool(request.form.get('is_new_release'))
        cover_file = request.files.get('cover_image')
        book_file = request.files.get('book_file')
        cover_filename = None; book_filename = None
        if cover_file and cover_file.filename:
            ext = secure_filename(cover_file.filename).rsplit('.', 1)[1].lower()
            cover_filename = f"cover_{secrets.token_hex(8)}.{ext}"
            cp = os.path.join(app.config['UPLOAD_FOLDER'], 'covers', cover_filename)
            cover_file.save(cp)
            try:
                img = Image.open(cp)
                img.thumbnail((800, 1200))
                img.save(cp, optimize=True, quality=85)
            except: pass
        if book_file and book_file.filename:
            ext = secure_filename(book_file.filename).rsplit('.', 1)[1].lower()
            if ext != 'pdf':
                flash('Only PDF files allowed.', 'error')
                return redirect(url_for('admin_new_book'))
            book_filename = f"book_{secrets.token_hex(8)}.pdf"
            bp = os.path.join(app.config['UPLOAD_FOLDER'], 'books', book_filename)
            book_file.save(bp)
        book = Book(title=title, author=author, description=description, price=price,
            category=category, tags=tags, cover_image=cover_filename, book_file=book_filename,
            is_featured=is_featured, is_trending=is_trending, is_new_release=is_new_release, page_count=page_count)
        db.session.add(book); db.session.commit()
        flash('Book added!', 'success')
        return redirect(url_for('admin_books'))
    return render_template('admin/book_form.html', categories=categories, book=None)

@app.route('/readora-admin/book/edit/<int:book_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_book(book_id):
    book = Book.query.get_or_404(book_id)
    categories = Category.query.filter_by(is_active=True).all()
    if request.method == 'POST':
        book.title = request.form.get('title', '').strip()
        book.author = request.form.get('author', '').strip()
        book.description = request.form.get('description', '').strip()
        book.price = float(request.form.get('price', 0))
        book.category = request.form.get('category', '').strip()
        book.tags = request.form.get('tags', '').strip()
        book.page_count = int(request.form.get('page_count', 0) or 0)
        book.is_featured = bool(request.form.get('is_featured'))
        book.is_trending = bool(request.form.get('is_trending'))
        book.is_new_release = bool(request.form.get('is_new_release'))
        book.is_active = bool(request.form.get('is_active'))
        book.updated_at = datetime.utcnow()
        cover_file = request.files.get('cover_image')
        book_file = request.files.get('book_file')
        if cover_file and cover_file.filename:
            ext = secure_filename(cover_file.filename).rsplit('.', 1)[1].lower()
            cf = f"cover_{secrets.token_hex(8)}.{ext}"
            cp = os.path.join(app.config['UPLOAD_FOLDER'], 'covers', cf)
            cover_file.save(cp)
            book.cover_image = cf
        if book_file and book_file.filename:
            ext = secure_filename(book_file.filename).rsplit('.', 1)[1].lower()
            if ext != 'pdf':
                flash('Only PDF files allowed.', 'error')
                return redirect(url_for('admin_edit_book', book_id=book_id))
            bf = f"book_{secrets.token_hex(8)}.pdf"
            bp = os.path.join(app.config['UPLOAD_FOLDER'], 'books', bf)
            book_file.save(bp)
            book.book_file = bf
        db.session.commit()
        flash('Book updated!', 'success')
        return redirect(url_for('admin_books'))
    return render_template('admin/book_form.html', categories=categories, book=book)

@app.route('/readora-admin/book/delete/<int:book_id>', methods=['POST'])
@login_required
def admin_delete_book(book_id):
    book = Book.query.get_or_404(book_id)
    book.is_active = False; db.session.commit()
    flash('Book removed.', 'success')
    return redirect(url_for('admin_books'))

@app.route('/readora-admin/categories')
@login_required
def admin_categories():
    categories = Category.query.order_by(Category.display_order).all()
    return render_template('admin/categories.html', categories=categories)

@app.route('/readora-admin/category/new', methods=['POST'])
@login_required
def admin_new_category():
    name = request.form.get('name', '').strip()
    slug = request.form.get('slug', '').strip().lower().replace(' ', '-')
    description = request.form.get('description', '').strip()
    if Category.query.filter_by(slug=slug).first():
        flash('Category slug exists.', 'error')
        return redirect(url_for('admin_categories'))
    cat = Category(name=name, slug=slug, description=description)
    db.session.add(cat); db.session.commit()
    flash('Category added!', 'success')
    return redirect(url_for('admin_categories'))

@app.route('/readora-admin/category/delete/<int:cat_id>', methods=['POST'])
@login_required
def admin_delete_category(cat_id):
    cat = Category.query.get_or_404(cat_id)
    db.session.delete(cat); db.session.commit()
    flash('Category deleted.', 'success')
    return redirect(url_for('admin_categories'))

@app.route('/readora-admin/orders')
@login_required
def admin_orders():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template('admin/orders.html', orders=orders)

# ========== ERROR HANDLERS ==========
@app.errorhandler(404)
def not_found(e): return render_template('errors/404.html'), 404

@app.errorhandler(429)
def too_many_requests(e): return render_template('errors/429.html'), 429

@app.errorhandler(500)
def server_error(e): return render_template('errors/500.html'), 500

# ========== CLI ==========
@app.cli.command('init-db')
def init_db():
    db.create_all()
    defaults = [
        ('Fiction', 'fiction'), ('Science Fiction', 'science-fiction'),
        ('Mystery & Thriller', 'mystery-thriller'), ('Romance', 'romance'),
        ('Business & Finance', 'business-finance'), ('Self-Help', 'self-help'),
        ('Programming & Tech', 'programming-tech'), ('Biography', 'biography')
    ]
    for name, slug in defaults:
        if not Category.query.filter_by(slug=slug).first():
            db.session.add(Category(name=name, slug=slug, display_order=defaults.index((name, slug))))
    db.session.commit()
    print("Database initialized.")

# ========== MAIN ==========
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False, host='0.0.0.0', port=5000)
