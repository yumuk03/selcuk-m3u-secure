# app.py - POLLING-ONLY TELEGRAM BOT (502 ÇÖZÜLDÜ)
import os
import re
import urllib3
import warnings
import threading
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from functools import wraps
from telegram.ext import Application, CommandHandler
from telegram import Update
from telegram.ext import ContextTypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'DeaTHLesS_Secret_2025!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# TELEGRAM TOKEN (Render Environment'dan al)
TELEGRAM_TOKEN = os.environ.get('TELEGRAM_TOKEN')
if not TELEGRAM_TOKEN:
    app.logger.error("TELEGRAM_TOKEN EKLE! Render Environment Variables'a git.")

# MODELLER
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    telegram_id = db.Column(db.Integer, unique=True)

class SiteStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    is_active = db.Column(db.Boolean, default=True)
    message = db.Column(db.Text, default="Sistem aktif.")

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', password=generate_password_hash('DeaTHLesS2025'), is_admin=True)
        db.session.add(admin)
        db.session.commit()
    if not SiteStatus.query.first():
        status = SiteStatus(is_active=True, message="Sistem aktif.")
        db.session.add(status)
        db.session.commit()

# M3U ÜRETİCİ
class M3UGenerator:
    def __init__(self):
        self.channels = []
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36'})
    
    def get_html(self, url):
        try:
            response = self.session.get(url, timeout=20, verify=False)
            response.raise_for_status()
            return response.text
        except: return None
    
    def selcuksports_streams(self):
        self.channels.clear()
        url = "https://seep.eu.org/https://www.selcuksportshd.is/"
        channel_ids = ["selcukbeinsports1","selcukbeinsports2","selcukbeinsports3","selcukbeinsports4","selcukbeinsports5","selcukbeinsportsmax1","selcukbeinsportsmax2","selcukssport","selcukssport2","selcuksmartspor","selcuksmartspor2","selcuktivibuspor1","selcuktivibuspor2","selcuktivibuspor3","selcuktivibuspor4"]
        
        html = self.get_html(url)
        if not html: return False

        active_domain = ""
        section_match = re.search(r'data-device-mobile[^>]*>(.*?)</div>\s*</div>', html, re.DOTALL)
        if section_match:
            link_match = re.search(r'href=["\'](https?://[^"\']*selcuksportshd[^"\']+)["\']', section_match.group(1))
            if link_match: active_domain = link_match.group(1)

        if not active_domain: return False
        
        domain_html = self.get_html(active_domain)
        if not domain_html: return False

        player_links = re.findall(r'data-url="(https?://[^"]+id=[^"]+)"', domain_html)
        if not player_links: return False

        for player_url in player_links:
            html_player = self.get_html(player_url)
            if html_player:
                stream_match = re.search(r'this\.baseStreamUrl\s*=\s*[\'"](https://[^\'"]+)[\'"]', html_player)
                if stream_match:
                    base_stream_url = stream_match.group(1)
                    for cid in channel_ids:
                        stream_url = base_stream_url + cid + "/playlist.m3u8"
                        clean_name = re.sub(r'^selcuk', '', cid, flags=re.IGNORECASE).upper() + " HD"
                        channel_name = "TR: " + clean_name
                        self.channels.append((channel_name, stream_url))
                    return True
        return False

    def get_channels(self):
        return self.channels

# BOT HANDLER'LAR (Polling için async)
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Hoş geldin! /login <user> <pass> ile giriş yap.\n/register <user> <pass> ile kayıt ol.\n/channels ile linkleri al.")

async def login_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) != 2:
        await update.message.reply_text("Kullanım: /login <kullanıcı> <şifre>")
        return
    username, password = context.args
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        user.telegram_id = update.effective_user.id
        db.session.commit()
        await update.message.reply_text(f"Giriş başarılı! /channels dene.")
    else:
        await update.message.reply_text("Hatalı! /register dene.")

async def register_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) != 2:
        await update.message.reply_text("Kullanım: /register <kullanıcı> <şifre>")
        return
    username, password = context.args
    if User.query.filter_by(username=username).first():
        await update.message.reply_text("Kullanıcı alınmış!")
    else:
        user = User(username=username, password=generate_password_hash(password), telegram_id=update.effective_user.id)
        db.session.add(user)
        db.session.commit()
        await update.message.reply_text("Kayıt OK! /login ile gir.")

async def channels_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user = User.query.filter_by(telegram_id=user_id).first()
    if not user: 
        await update.message.reply_text("Önce /login!")
        return
    status = SiteStatus.query.first()
    if not status or not status.is_active:
        await update.message.reply_text(f"Site kapalı: {status.message}")
        return

    generator = M3UGenerator()
    if not generator.selcuksports_streams():
        await update.message.reply_text("Kanallar yüklenemiyor.")
        return

    channels = generator.get_channels()
    msg = "📺 SELCUKEPORT KANALLARI:\n\n"
    for name, url in channels:
        msg += f"🔗 {name}\n{url}\n\n"
    await update.message.reply_text(msg)

async def admin_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user = User.query.filter_by(telegram_id=user_id).first()
    if not user or not user.is_admin:
        await update.message.reply_text("Admin değilsin!")
        return
    status = SiteStatus.query.first()
    state = "AKTİF" if status.is_active else "KAPALI"
    await update.message.reply_text(f"Durum: {state}\n/admin_close <mesaj> - Kapat\n/admin_open <mesaj> - Aç")

async def admin_close(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user = User.query.filter_by(telegram_id=user_id).first()
    if not user or not user.is_admin: return
    status = SiteStatus.query.first()
    status.is_active = False
    status.message = ' '.join(context.args) or "Bakım."
    db.session.commit()
    await update.message.reply_text("Site KAPATILDI!")

async def admin_open(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user = User.query.filter_by(telegram_id=user_id).first()
    if not user or not user.is_admin: return
    status = SiteStatus.query.first()
    status.is_active = True
    status.message = ' '.join(context.args) or "Aktif."
    db.session.commit()
    await update.message.reply_text("Site AÇILDI!")

# BOT SETUP (Polling)
application = None
def setup_bot():
    global application
    if not TELEGRAM_TOKEN:
        app.logger.error("Token eksik!")
        return None
    application = Application.builder().token(TELEGRAM_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("login", login_handler))
    application.add_handler(CommandHandler("register", register_handler))
    application.add_handler(CommandHandler("channels", channels_handler))
    application.add_handler(CommandHandler("admin", admin_handler))
    application.add_handler(CommandHandler("admin_close", admin_close))
    application.add_handler(CommandHandler("admin_open", admin_open))
    return application

# WEB ROTALARI (Önceki gibi, kısalttım)
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session: return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user.is_admin: abort(403)
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    status = SiteStatus.query.first()
    if not status or not status.is_active:
        return render_template('closed.html', message=getattr(status, 'message', 'Site kapalı.'))
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('channels'))
        flash('Hatalı!')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Alınmış!')
        else:
            user = User(username=username, password=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            flash('Kayıt OK!')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/channels')
@login_required
def channels():
    status = SiteStatus.query.first()
    if not status or not status.is_active:
        return render_template('closed.html', message=getattr(status, 'message', 'Site kapalı.'))
    generator = M3UGenerator()
    if not generator.selcuksports_streams():
        flash('Yüklenemiyor.')
        return render_template('channels.html', channels=[])
    return render_template('channels.html', channels=generator.get_channels())

@app.route('/admin')
@admin_required
def admin_panel():
    status = SiteStatus.query.first()
    return render_template('admin.html', status=status)

@app.route('/admin/toggle', methods=['POST'])
@admin_required
def toggle_site():
    status = SiteStatus.query.first()
    if status:
        status.is_active = not status.is_active
        status.message = request.form.get('message', 'Değiştirildi.')
        db.session.commit()
    flash('Güncellendi!')
    return redirect(url_for('admin_panel'))

# HTML Şablonları (Önceki mesajlardan kopyala: home.html, login.html, register.html, channels.html, admin.html, closed.html)

if __name__ == '__main__':
    setup_bot()
    if application:
        # Polling'i ayrı thread'de başlat
        def run_bot():
            app.logger.info("Bot polling başlıyor...")
            application.run_polling(drop_pending_updates=True)
        bot_thread = threading.Thread(target=run_bot, daemon=True)
        bot_thread.start()
        app.logger.info("Bot thread başlatıldı!")
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
