import os
import re
import urllib3
import warnings
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from io import StringIO
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'DeaTHLesS_Secret_2025!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

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

class M3UGenerator:
    def __init__(self):
        self.m3u_content = "#EXTM3U\n"
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36'})
    
    def get_html(self, url):
        try:
            response = self.session.get(url, timeout=20, verify=False)
            response.raise_for_status()
            return response.text
        except: return None
    
    def selcuksports_streams(self):
        url = "https://seep.eu.org/https://www.selcuksportshd.is/"
        channel_ids = ["selcukbeinsports1","selcukbeinsports2","selcukbeinsports3","selcukbeinsports4","selcukbeinsports5",
                       "selcukbeinsportsmax1","selcukbeinsportsmax2","selcukssport","selcukssport2","selcuksmartspor",
                       "selcuksmartspor2","selcuktivibuspor1","selcuktivibuspor2","selcuktivibuspor3","selcuktivibuspor4"]
        
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
                        channel_name = "TR:" + clean_name
                        self.m3u_content += f'#EXTINF:-1 tvg-name="{channel_name}" tvg-logo="https://i.hizliresim.com/b6xqz10.jpg" group-title="TURKIYE",{channel_name}\n'
                        self.m3u_content += f'#EXTVLCOPT:http-referrer={active_domain}\n'
                        self.m3u_content += f'{stream_url}\n'
                    return True
        return False

    def get_m3u(self):
        return self.m3u_content

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    from functools import wraps
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
    if not status.is_active:
        return render_template('closed.html', message=status.message)
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            return redirect(url_for('dashboard'))
        flash('Geçersiz giriş!')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Kullanıcı adı alınmış!')
        else:
            user = User(username=username, password=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            flash('Kayıt başarılı!')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    status = SiteStatus.query.first()
    if not status.is_active:
        return render_template('closed.html', message=status.message)
    return render_template('index.html')

@app.route('/generate')
@login_required
def generate():
    status = SiteStatus.query.first()
    if not status.is_active:
        return render_template('closed.html', message=status.message)

    gen = M3UGenerator()
    if not gen.selcuksports_streams():
        flash('Kanallar yüklenemedi.')
        return redirect(url_for('dashboard'))

    buffer = StringIO()
    buffer.write(gen.get_m3u())
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name="DeaTHLesS-Selcuksport.m3u", mimetype='audio/x-mpegurl')

@app.route('/admin')
@admin_required
def admin_panel():
    status = SiteStatus.query.first()
    return render_template('admin.html', status=status)

@app.route('/admin/toggle', methods=['POST'])
@admin_required
def toggle_site():
    status = SiteStatus.query.first()
    status.is_active = not status.is_active
    status.message = request.form['message']
    db.session.commit()
    flash('Durum güncellendi!')
    return redirect(url_for('admin_panel'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
