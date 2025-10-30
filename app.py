# app.py - DÜZELTİLMİŞ (f-string hatası yok)
import os
import re
import random
import string
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, abort, send_file, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = 'DeaTHLesS_Secret_2025!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# MODELLER
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    token = db.Column(db.String(20), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password=generate_password_hash('DeaTHLesS2025'),
            token=''.join(random.choices(string.ascii_letters + string.digits, k=12)),
            expires_at=datetime.utcnow() + timedelta(days=365),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

# M3U ÜRETİCİ
class M3UGenerator:
    def __init__(self):
        self.m3u = "#EXTM3U\n"
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})

    def get_html(self, url):
        try:
            r = self.session.get(url, timeout=15, verify=False)
            r.raise_for_status()
            return r.text
        except:
            return None

    def generate(self):
        main_url = "https://seep.eu.org/https://www.selcuksportshd.is/"
        html = self.get_html(main_url)
        if not html:
            return False, "Ana sayfa yüklenemedi."

        domain_match = re.search(r'href=["\'](https?://[^"\']*selcuksportshd[^"\']+)["\']', html)
        if not domain_match:
            return False, "Domain bulunamadı."
        active_domain = domain_match.group(1)

        domain_html = self.get_html(active_domain)
        if not domain_html:
            return False, "Domain sayfası yüklenemedi."

        player_match = re.search(r'data-url="(https?://[^"]+id=[^"]+)"', domain_html)
        if not player_match:
            return False, "Player URL bulunamadı."
        player_url = player_match.group(1)

        player_html = self.get_html(player_url)
        if not player_html:
            return False, "Player sayfası yüklenemedi."

        base_match = re.search(r'this\.baseStreamUrl\s*=\s*[\'"](https://[^\'"]+)[\'"]', player_html)
        if not base_match:
            return False, "Base stream bulunamadı."
        base = base_match.group(1)

        channels = [
            ("BEIN 1", "selcukbeinsports1"), ("BEIN 2", "selcukbeinsports2"),
            ("BEIN 3", "selcukbeinsports3"), ("BEIN 4", "selcukbeinsports4"),
            ("BEIN 5", "selcukbeinsports5"), ("MAX 1", "selcukbeinsportsmax1"),
            ("MAX 2", "selcukbeinsportsmax2"), ("S SPORT", "selcukssport"),
            ("S SPORT 2", "selcukssport2"), ("SMART", "selcuksmartspor"),
            ("SMART 2", "selcuksmartspor2"), ("TIVIBU 1", "selcuktivibuspor1"),
            ("TIVIBU 2", "selcuktivibuspor2"), ("TIVIBU 3", "selcuktivibuspor3"),
            ("TIVIBU 4", "selcuktivibuspor4")
        ]

        for name, cid in channels:
            url = f"{base}{cid}/playlist.m3u8"
            self.m3u += f'#EXTINF:-1 tvg-logo="https://i.hizliresim.com/b6xqz10.jpg" group-title="TÜRKIYE",{name} HD\n'
            self.m3u += f'#EXTVLCOPT:http-referrer={active_domain}\n'
            self.m3u += f'{url}\n\n'

        return True, active_domain

    def get_buffer(self):
        buffer = BytesIO()
        buffer.write(self.m3u.encode('utf-8'))
        buffer.seek(0)
        return buffer

# DECORATORS
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))
        user = User.query.get(user_id)
        if not user or not user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated

from functools import wraps  # <-- EKLENDİ!

# ROTALAR
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            if user.is_admin:
                return redirect(url_for('admin_panel'))
            return redirect(url_for('user_panel', token=user.token))
        flash('Geçersiz giriş!')
    return render_template('login.html')

@app.route('/u/<token>')
def user_panel(token):
    user = User.query.filter_by(token=token).first_or_404()
    if datetime.utcnow() > user.expires_at:
        return render_template('expired.html', username=user.username), 403
    return render_template('user.html', user=user)

@app.route('/playlist/<token
