# app.py - TEK M3U + TELEGRAM BOT (ÇALIŞIR)
import os
import re
import urllib3
import warnings
import threading
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO
import requests
from functools import wraps
from telegram.ext import Application, CommandHandler
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'DeaTHLesS_Secret_2025!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# TELEGRAM TOKEN
TELEGRAM_TOKEN = os.environ.get('TELEGRAM_TOKEN')
if not TELEGRAM_TOKEN:
    print("TELEGRAM_TOKEN EKSİK! Render Environment'a ekle.")

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
        db.session.add(status
