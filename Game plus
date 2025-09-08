# ----------------------------------------------------
# Zone54 - Offline Wallet Demo (Colab Flask Prototype)
# ----------------------------------------------------
# This is a full, runnable prototype you can paste directly into a Google Colab cell and run.
#
# Key Features:
# - SQLite Database: Replaces in-memory storage for persistent data.
# - PIN-based Authentication: Secure user login and transaction signing.
# - Enhanced Escrow: Buyer can explicitly confirm delivery to release funds.
# - AI Marketplace Insights: Uses Gemini to generate smart suggestions for sellers.
# - Refined UI: A more polished dashboard for investors and demo purposes.
# - All original features are retained and updated to use the database.
#
# NOTE: This is a demo/prototype for presentation only. Do NOT use in production
# without proper security, persistence, and legal compliance.
# ----------------------------------------------------

# -------------------------
# Install dependencies (Colab)
# -------------------------
!pip install --quiet flask flask-ngrok pandas networkx matplotlib cryptography werkzeug google-generativeai

# -------------------------
# Imports
# -------------------------
import time
import threading
import datetime
import random
import os
import json
import sqlite3
from io import BytesIO

import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
from flask import Flask, request, redirect, render_template_string, send_file, jsonify, session
from flask_ngrok import run_with_ngrok
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from werkzeug.security import generate_password_hash, check_password_hash

# IMPORTANT: You can provide your Gemini API key here.
# Otherwise, the Canvas environment will provide one at runtime.
# This app is for demonstration purposes only and should not be used in production.
# The API key is stored locally for this demonstration and should not be hardcoded in a real application.
import google.generativeai as genai
api_key = ""
if api_key:
    genai.configure(api_key=api_key)

# -------------------------
# Flask app & ngrok
# -------------------------
app = Flask(__name__)
app.secret_key = os.urandom(24) # Secret key for sessions
run_with_ngrok(app)

# -------------------------
# Database Setup (SQLite)
# -------------------------
DB_FILE = "zone54.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            uid TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            gh_card TEXT NOT NULL,
            pin_hash TEXT NOT NULL,
            cedi REAL NOT NULL,
            credits REAL NOT NULL,
            public_key BLOB NOT NULL,
            private_key BLOB NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS nfc_users (
            card_id TEXT PRIMARY KEY,
            uid TEXT NOT NULL,
            FOREIGN KEY(uid) REFERENCES users(uid)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS marketplace (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            currency TEXT NOT NULL,
            seller_uid TEXT NOT NULL,
            available INTEGER NOT NULL,
            escrow INTEGER NOT NULL,
            FOREIGN KEY(seller_uid) REFERENCES users(uid)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id TEXT PRIMARY KEY,
            from_uid TEXT NOT NULL,
            to_uid TEXT NOT NULL,
            amount REAL NOT NULL,
            currency TEXT NOT NULL,
            type TEXT NOT NULL,
            status TEXT NOT NULL,
            signature BLOB,
            created_at TEXT NOT NULL,
            escrow INTEGER NOT NULL,
            item_id TEXT,
            released_at TEXT,
            failed_reason TEXT,
            disputed INTEGER,
            FOREIGN KEY(from_uid) REFERENCES users(uid)
        )
    """)
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# -------------------------
# Utility: Digital keys & signatures
# -------------------------
def generate_keys():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    return priv, pub

def serialize_public_key(pub):
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pub_bytes):
    return serialization.load_pem_public_key(pub_bytes)

def serialize_private_key(priv):
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def deserialize_private_key(priv_bytes):
    return serialization.load_pem_private_key(priv_bytes, password=None)

def sign_message(private_key, message: str) -> bytes:
    sig = private_key.sign(
        message.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return sig

def verify_message(public_key, message: str, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# -------------------------
# Helper functions
# -------------------------
def uid_from_name(name: str) -> str:
    return name.lower().strip().replace(" ", "_")

def now_ts():
    return datetime.datetime.utcnow().isoformat() + "Z"

def _get_user(uid):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE uid = ?", (uid,)).fetchone()
    conn.close()
    return user

def _get_user_keys(uid):
    conn = get_db()
    keys_row = conn.execute("SELECT public_key, private_key FROM users WHERE uid = ?", (uid,)).fetchone()
    conn.close()
    if keys_row:
        priv_key = deserialize_private_key(keys_row["private_key"])
        pub_key = deserialize_public_key(keys_row["public_key"])
        return {"private": priv_key, "public": pub_key}
    return None

def add_market_item(name, price, currency, seller_uid):
    conn = get_db()
    item_id = f"item{conn.execute('SELECT COUNT(*) FROM marketplace').fetchone()[0]+1:03d}"
    conn.execute("INSERT INTO marketplace (id, name, price, currency, seller_uid, available, escrow) VALUES (?, ?, ?, ?, ?, ?, ?)",
                 (item_id, name, price, currency, seller_uid, 1, 1))
    conn.commit()
    conn.close()
    return item_id

def log_transaction(txn):
    conn = get_db()
    conn.execute("INSERT INTO transactions (id, from_uid, to_uid, amount, currency, type, status, signature, created_at, escrow, item_id, disputed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                 (txn["id"], txn["from"], txn["to"], txn["amount"], txn["currency"], txn["type"], txn["status"], txn["signature"], txn["created_at"], txn["escrow"], txn.get("item_id"), txn.get("disputed", 0)))
    conn.commit()
    conn.close()

# -------------------------
# Offline sync engine
# -------------------------
def process_pending_for_user(uid):
    conn = get_db()
    pending_txns = conn.execute("SELECT * FROM transactions WHERE status = 'PENDING' AND (from_uid = ? OR to_uid = ?)", (uid, uid)).fetchall()
    
    for txn in pending_txns:
        try:
            tx_from = txn["from_uid"]
            tx_to = txn["to_uid"]
            amount = float(txn["amount"])
            currency = txn["currency"]
            
            # verify signature
            pub = _get_user_keys(tx_from)["public"]
            msg = f"{tx_from}->{tx_to}:{amount}:{currency}"
            if not verify_message(pub, msg, txn["signature"]):
                conn.execute("UPDATE transactions SET status = 'FAILED', failed_reason = 'signature_invalid' WHERE id = ?", (txn["id"],))
                continue
            
            # Escrow handling
            if txn["escrow"]:
                if txn["status"] == "PENDING":
                    conn.execute("UPDATE transactions SET status = 'ESCROW' WHERE id = ?", (txn["id"],))
                    continue

                if txn["status"] == "CONFIRM_PENDING":
                    sender_row = conn.execute("SELECT cedi, credits FROM users WHERE uid = ?", (tx_from,)).fetchone()
                    if (currency == "cedi" and sender_row["cedi"] >= amount) or \
                       (currency == "credits" and sender_row["credits"] >= amount):
                        # Debit sender
                        if currency == "cedi":
                            conn.execute("UPDATE users SET cedi = cedi - ? WHERE uid = ?", (amount, tx_from))
                        else:
                            conn.execute("UPDATE users SET credits = credits - ? WHERE uid = ?", (amount, tx_from))
                        
                        # Credit receiver
                        conn.execute("UPDATE users SET cedi = cedi + ? WHERE uid = ?", (amount, tx_to))
                        conn.execute("UPDATE transactions SET status = 'CONFIRMED', released_at = ? WHERE id = ?", (now_ts(), txn["id"]))
                    else:
                        conn.execute("UPDATE transactions SET status = 'FAILED', failed_reason = 'insufficient_funds' WHERE id = ?", (txn["id"],))
                continue
            
            # Non-escrow immediate transfers
            sender_row = conn.execute("SELECT cedi, credits FROM users WHERE uid = ?", (tx_from,)).fetchone()
            if (currency == "cedi" and sender_row["cedi"] >= amount) or \
               (currency == "credits" and sender_row["credits"] >= amount):
                # Debit sender
                if currency == "cedi":
                    conn.execute("UPDATE users SET cedi = cedi - ? WHERE uid = ?", (amount, tx_from))
                else:
                    conn.execute("UPDATE users SET credits = credits - ? WHERE uid = ?", (amount, tx_from))
                
                # Credit receiver
                if tx_to != "marketplace":
                    if currency == "cedi":
                        conn.execute("UPDATE users SET cedi = cedi + ? WHERE uid = ?", (amount, tx_to))
                    else:
                        conn.execute("UPDATE users SET credits = credits + ? WHERE uid = ?", (amount, tx_to))
                conn.execute("UPDATE transactions SET status = 'CONFIRMED', confirmed_at = ? WHERE id = ?", (now_ts(), txn["id"]))
            else:
                conn.execute("UPDATE transactions SET status = 'FAILED', failed_reason = 'insufficient_funds' WHERE id = ?", (txn["id"],))
        except Exception as e:
            print(f"Error processing transaction {txn['id']}: {str(e)}")
            conn.execute("UPDATE transactions SET status = 'FAILED', failed_reason = ? WHERE id = ?", (f"error:{str(e)}", txn["id"]))
    
    conn.commit()
    conn.close()

def sync_all():
    conn = get_db()
    uids = [row["uid"] for row in conn.execute("SELECT uid FROM users").fetchall()]
    conn.close()
    for uid in uids:
        process_pending_for_user(uid)

# -------------------------
# Routes: Dashboard + actions
# -------------------------
dashboard_template = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zone 54 - Offline Wallet Demo</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; padding: 20px; background-color: #f7f7f7; color: #333; }
        .container { max-width: 900px; margin: auto; background: #fff; padding: 20px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1, h2, h3 { color: #1a202c; }
        form { background: #f2f4f8; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        input[type="text"], input[type="number"], input[type="submit"], select, button { padding: 10px; border-radius: 6px; border: 1px solid #ccc; margin-right: 10px; font-size: 1em; }
        input[type="submit"], button { background-color: #4a5568; color: white; cursor: pointer; border: none; }
        input[type="submit"]:hover, button:hover { background-color: #2d3748; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #edf2f7; }
        .alert { background-color: #ffcccc; color: #cc0000; padding: 10px; border-radius: 8px; margin-bottom: 15px; }
        .success { background-color: #ccffcc; color: #006600; padding: 10px; border-radius: 8px; margin-bottom: 15px; }
        .logout-form { display: inline; }
        .action-buttons { margin-top: 20px; }
        .action-buttons a, .action-buttons button { margin-right: 10px; }
        img { border: 1px solid #ddd; padding: 5px; background-color: #fff; }
    </style>
</head>
<body>
<div class="container">
    <h1>Zone 54 - Offline Wallet Demo</h1>
    
    {% if alert %}
        <div class="alert">{{ alert }}</div>
    {% endif %}
    {% if success %}
        <div class="success">{{ success }}</div>
    {% endif %}

    {% if not session.get('user_uid') %}
    <h2>Login / Register</h2>
    <form action="/login" method="post" style="display:inline;">
        Login as: <select name="user_uid">
            {% for uid in users.keys() %}
            <option value="{{ uid }}">{{ users[uid]['name'] }}</option>
            {% endfor %}
        </select>
        PIN: <input type="password" name="pin" required>
        <input type="submit" value="Login">
    </form>
    <form action="/register" method="post" style="display:inline;">
        <h3>New User Registration</h3>
        Name: <input name="name" required>
        Ghana Card ID: <input name="gh_card" required>
        PIN: <input name="pin" type="password" required>
        Initial Cedi: <input name="cedi" type="number" step="0.01" value="0">
        Initial Credits: <input name="credits" type="number" step="0.01" value="0">
        <input type="submit" value="Register">
    </form>
    {% else %}
    <h2>Logged in as: <b>{{ users[session['user_uid']]['name'] }}</b></h2>
    <p>UID: <b>{{ session['user_uid'] }}</b></p>
    <form action="/logout" method="post" class="logout-form">
        <input type="submit" value="Logout">
    </form>
    
    ---
    
    <h2>Balances & Pending Transactions</h2>
    <p><b>Cedi:</b> {{ "%.2f"|format(users[session['user_uid']]['cedi']) }}</p>
    <p><b>Credits:</b> {{ "%.2f"|format(users[session['user_uid']]['credits']) }}</p>
    
    <h3>Pending Transactions</h3>
    {% if pending_txns %}
    <table border=1 cellpadding=6>
        <tr>
            <th>ID</th><th>From</th><th>To</th><th>Amount</th><th>Status</th><th>Actions</th>
        </tr>
        {% for txn in pending_txns %}
        <tr>
            <td>{{ txn['id'] }}</td>
            <td>{{ users[txn['from_uid']]['name'] }}</td>
            <td>{{ users.get(txn['to_uid'], {'name': 'Marketplace'})['name'] }}</td>
            <td>{{ "%.2f"|format(txn['amount']) }} {{ txn['currency'] }}</td>
            <td>{{ txn['status'] }}</td>
            <td>
                {% if txn['status'] == 'ESCROW' and txn['to_uid'] == session['user_uid'] %}
                    <form action="/confirm_delivery" method="post" style="display:inline;">
                        <input type="hidden" name="txn_id" value="{{ txn['id'] }}">
                        <input type="hidden" name="pin" value="{{ session.get('last_pin') }}">
                        <button type="submit">Confirm Delivery</button>
                    </form>
                    <form action="/dispute" method="post" style="display:inline;">
                        <input type="hidden" name="txn_id" value="{{ txn['id'] }}">
                        <input type="hidden" name="pin" value="{{ session.get('last_pin') }}">
                        <button type="submit">Dispute</button>
                    </form>
                {% endif %}
            </td>
        </tr>
        {% endfor %}
    </table>
    {% else %}
    <p>No pending transactions.</p>
    {% endif %}

    ---

    <h2>Payment Features</h2>

    <h3>Smartphone Send (Queues offline)</h3>
    <form action="/send" method="post">
        To: <select name="to">{% for uid in users.keys() %}<option value="{{ uid }}">{{ users[uid]['name'] }}</option>{% endfor %}</select>
        Amount: <input name="amount" type="number" step="0.01" required>
        Currency: <select name="currency"><option value="cedi">Cedi</option><option value="credits">Credits</option></select>
        Escrow: <input type="checkbox" name="escrow">
        PIN: <input type="password" name="pin" required>
        <input type="submit" value="Send">
    </form>
    
    <h3>Feature Phone / USSD Simulation</h3>
    <form action="/ussd" method="post">
        Command: <input name="cmd" placeholder="BALANCE or SEND:recipient:amount:currency" required>
        PIN: <input type="password" name="pin" required>
        <input type="submit" value="Run USSD">
    </form>
    
    <h3>NFC/Card Simulation</h3>
    <p>Logged in user's card ID: <b>{{ nfc_users.get(session['user_uid']) }}</b></p>
    <form action="/nfc" method="post">
        To Card ID: <input name="to_card" placeholder="card002" required>
        Amount: <input name="amount" type="number" step="0.01" required>
        Currency: <select name="currency"><option value="cedi">Cedi</option><option value="credits">Credits</option></select>
        PIN: <input type="password" name="pin" required>
        <input type="submit" value="Send NFC">
    </form>

    ---

    <h2>Marketplace</h2>
    <form action="/add_item" method="post">
        <h3>Add an Item</h3>
        Item name: <input name="name" required>
        Price: <input name="price" type="number" step="0.01" required>
        Currency: <select name="currency"><option value="cedi">Cedi</option><option value="credits">Credits</option></select>
        <input type="submit" value="Add Item">
    </form>
    
    <h3>Marketplace Items</h3>
    <table border=1 cellpadding=6>
        <tr><th>Item</th><th>Price</th><th>Currency</th><th>Seller</th><th>Action</th></tr>
        {% for it in marketplace %}
        <tr>
            <td>{{ it['name'] }}</td>
            <td>{{ "%.2f"|format(it['price']) }}</td>
            <td>{{ it['currency'] }}</td>
            <td>{{ users[it['seller_uid']]['name'] }}</td>
            <td>
                {% if it['available'] %}
                <form action="/buy" method="post" style="display:inline">
                    <input type="hidden" name="item_id" value="{{ it['id'] }}">
                    PIN: <input type="password" name="pin" required>
                    <input type="submit" value="Buy (uses escrow)">
                </form>
                {% else %}
                    Sold
                {% endif %}
            </td>
        </tr>
        {% endfor %}
    </table>
    
    <div class="action-buttons">
        <h3>AI-Powered Marketplace Insights</h3>
        <button id="get-suggestions">Get AI Suggestions</button>
        <div id="ai-suggestions-output"></div>
    </div>
    
    ---

    <h2>Sync / Analytics / Export</h2>
    <div class="action-buttons">
        <form action="/sync" method="post" style="display:inline;">
            <input type="submit" value="Sync (Process pending)">
        </form>
        <a href="/export"><button type="button">Export Transactions CSV</button></a>
        <a href="/analytics"><button type="button">View Analytics</button></a>
    </div>

    <h3>Live Network Diagram</h3>
    <p>Visualizing the last 50 transactions.</p>
    <img src="/network.png?t={{ timestamp }}" style="max-width:800px;display:block;margin-top:10px">

</div>
<script>
document.getElementById('get-suggestions').addEventListener('click', async () => {
    const outputDiv = document.getElementById('ai-suggestions-output');
    outputDiv.innerHTML = 'Thinking...';
    try {
        const response = await fetch('/marketplace_suggestions');
        const data = await response.json();
        outputDiv.innerHTML = '';
        const list = document.createElement('ul');
        data.forEach(item => {
            const listItem = document.createElement('li');
            listItem.textContent = item;
            list.appendChild(listItem);
        });
        outputDiv.appendChild(list);
    } catch (error) {
        outputDiv.innerHTML = 'Error fetching suggestions.';
        console.error('Error:', error);
    }
});
</script>
</body>
</html>
"""

@app.route("/")
def index():
    conn = get_db()
    users_db = {row['uid']: dict(row) for row in conn.execute("SELECT * FROM users").fetchall()}
    marketplace = conn.execute("SELECT * FROM marketplace").fetchall()
    
    # Get pending transactions for the logged-in user
    pending_txns = []
    if session.get('user_uid'):
        pending_txns = conn.execute("SELECT * FROM transactions WHERE status IN ('PENDING', 'ESCROW') AND (from_uid = ? OR to_uid = ?)", (session['user_uid'], session['user_uid'])).fetchall()
    
    nfc_map = {row['uid']: row['card_id'] for row in conn.execute("SELECT * FROM nfc_users").fetchall()}

    conn.close()
    
    return render_template_string(dashboard_template, 
                                  users=users_db, 
                                  marketplace=marketplace,
                                  pending_txns=pending_txns,
                                  nfc_users=nfc_map,
                                  timestamp=int(time.time()),
                                  alert=request.args.get('alert'),
                                  success=request.args.get('success'))

# -------------------------
# Authentication Routes
# -------------------------
@app.route("/register", methods=["POST"])
def register():
    name = request.form.get("name")
    gh_card = request.form.get("gh_card")
    pin = request.form.get("pin")
    cedi = float(request.form.get("cedi") or 0)
    credits = float(request.form.get("credits") or 0)
    uid = uid_from_name(name)
    
    conn = get_db()
    if conn.execute("SELECT uid FROM users WHERE uid = ?", (uid,)).fetchone():
        conn.close()
        return redirect("/?alert=User%20already%20exists.")
        
    pin_hash = generate_password_hash(pin)
    priv, pub = generate_keys()
    priv_bytes = serialize_private_key(priv)
    pub_bytes = serialize_public_key(pub)
    
    conn.execute("INSERT INTO users (uid, name, gh_card, pin_hash, cedi, credits, public_key, private_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                 (uid, name, gh_card, pin_hash, cedi, credits, pub_bytes, priv_bytes))
    
    card_id = f"card{conn.execute('SELECT COUNT(*) FROM nfc_users').fetchone()[0]+1:03d}"
    conn.execute("INSERT INTO nfc_users (card_id, uid) VALUES (?, ?)", (card_id, uid))
    
    conn.commit()
    conn.close()
    return redirect(f"/?success=User%20{name}%20registered%20successfully.")

@app.route("/login", methods=["POST"])
def login():
    uid = request.form.get("user_uid")
    pin = request.form.get("pin")
    conn = get_db()
    user_row = conn.execute("SELECT pin_hash FROM users WHERE uid = ?", (uid,)).fetchone()
    conn.close()
    
    if user_row and check_password_hash(user_row['pin_hash'], pin):
        session['user_uid'] = uid
        session['last_pin'] = pin
        return redirect("/?success=Login%20successful.")
    else:
        return redirect("/?alert=Invalid%20PIN%20or%20user.")

@app.route("/logout", methods=["POST"])
def logout():
    session.pop('user_uid', None)
    session.pop('last_pin', None)
    return redirect("/?success=Logged%20out%20successfully.")

# -------------------------
# Transaction Routes
# -------------------------
@app.route("/send", methods=["POST"])
def send():
    sender = session.get("user_uid")
    if not sender or not check_password_hash(_get_user(sender)['pin_hash'], request.form.get('pin')):
        return redirect("/?alert=Authentication%20failed.")

    receiver = request.form.get("to")
    amount = float(request.form.get("amount"))
    currency = request.form.get("currency")
    escrow = 'escrow' in request.form
    
    if _get_user(receiver) is None:
        return redirect("/?alert=Invalid%20receiver.")

    priv_key = _get_user_keys(sender)['private']
    msg = f"{sender}->{receiver}:{amount}:{currency}"
    signature = sign_message(priv_key, msg)
    
    txn_id = f"tx{sqlite3.connect(DB_FILE).execute('SELECT COUNT(*) FROM transactions').fetchone()[0]+1}"
    txn = {
        "id": txn_id,
        "from": sender,
        "to": receiver,
        "amount": amount,
        "currency": currency,
        "type": "transfer",
        "status": "PENDING",
        "signature": signature,
        "created_at": now_ts(),
        "escrow": escrow,
        "disputed": 0
    }
    
    log_transaction(txn)
    return redirect(f"/?success=Transaction%20queued%20for%20{receiver}.")

@app.route("/ussd", methods=["POST"])
def ussd():
    user = session.get("user_uid")
    if not user or not check_password_hash(_get_user(user)['pin_hash'], request.form.get('pin')):
        return redirect("/?alert=Authentication%20failed.")

    cmd = request.form.get("cmd") or ""
    cmd = cmd.strip()
    
    if cmd.upper() == "BALANCE":
        u = _get_user(user)
        return f"<p>BALANCE - Cedi: {u['cedi']:.2f}, Credits: {u['credits']:.2f}</p><p><a href='/'>Back</a></p>"
    elif cmd.upper().startswith("SEND:"):
        try:
            parts = cmd.split(":")
            _, recipient, amount_str, currency = parts
            recipient_uid = uid_from_name(recipient)
            amount = float(amount_str)
            
            if _get_user(recipient_uid) is None:
                return "<p>Recipient not found.</p><p><a href='/'>Back</a></p>"

            priv_key = _get_user_keys(user)['private']
            msg = f"{user}->{recipient_uid}:{amount}:{currency}"
            sig = sign_message(priv_key, msg)
            
            txn_id = f"tx{sqlite3.connect(DB_FILE).execute('SELECT COUNT(*) FROM transactions').fetchone()[0]+1}"
            txn = {
                "id": txn_id,
                "from": user,
                "to": recipient_uid,
                "amount": amount,
                "currency": currency,
                "type": "ussd",
                "status": "PENDING",
                "signature": sig,
                "created_at": now_ts(),
                "escrow": False,
                "disputed": 0
            }
            log_transaction(txn)
            return f"<p>Queued SEND to {recipient_uid} for {amount} {currency}.</p><p><a href='/'>Back</a></p>"
        except Exception:
            return "<p>Invalid SEND format. Use SEND:recipient:amount:currency.</p><p><a href='/'>Back</a></p>"
    else:
        return "<p>Unknown USSD command.</p><p><a href='/'>Back</a></p>"

@app.route("/nfc", methods=["POST"])
def nfc():
    sender = session.get("user_uid")
    if not sender or not check_password_hash(_get_user(sender)['pin_hash'], request.form.get('pin')):
        return redirect("/?alert=Authentication%20failed.")
        
    to_card = request.form.get("to_card")
    conn = get_db()
    receiver_uid_row = conn.execute("SELECT uid FROM nfc_users WHERE card_id = ?", (to_card,)).fetchone()
    conn.close()

    if not receiver_uid_row:
        return redirect("/?alert=Invalid%20card%20ID.")
    
    receiver = receiver_uid_row['uid']
    amount = float(request.form.get("amount") or 0)
    currency = request.form.get("currency")
    
    priv_key = _get_user_keys(sender)['private']
    msg = f"{sender}->{receiver}:{amount}:{currency}"
    sig = sign_message(priv_key, msg)
    
    txn_id = f"tx{sqlite3.connect(DB_FILE).execute('SELECT COUNT(*) FROM transactions').fetchone()[0]+1}"
    txn = {
        "id": txn_id,
        "from": sender,
        "to": receiver,
        "amount": amount,
        "currency": currency,
        "type": "nfc",
        "status": "PENDING",
        "signature": sig,
        "created_at": now_ts(),
        "escrow": False,
        "disputed": 0
    }
    log_transaction(txn)
    return redirect(f"/?success=NFC%20transaction%20queued.")

# -------------------------
# Marketplace & Escrow
# -------------------------
@app.route("/add_item", methods=["POST"])
def add_item():
    seller_uid = session.get("user_uid")
    if not seller_uid:
        return redirect("/?alert=Please%20log%20in%20to%20add%20an%20item.")
        
    name = request.form.get("name")
    price = float(request.form.get("price") or 0)
    currency = request.form.get("currency")
    
    add_market_item(name, price, currency, seller_uid)
    return redirect(f"/?success=Item%20added%20to%20marketplace.")

@app.route("/buy", methods=["POST"])
def buy():
    buyer = session.get("user_uid")
    if not buyer or not check_password_hash(_get_user(buyer)['pin_hash'], request.form.get('pin')):
        return redirect("/?alert=Authentication%20failed.")

    item_id = request.form.get("item_id")
    conn = get_db()
    item = conn.execute("SELECT * FROM marketplace WHERE id = ? AND available = 1", (item_id,)).fetchone()

    if not item:
        conn.close()
        return redirect("/?alert=Item%20not%20available.")
        
    seller = item['seller_uid']
    price = item['price']
    currency = item['currency']
    
    conn.execute("UPDATE marketplace SET available = 0 WHERE id = ?", (item_id,))
    
    priv_key = _get_user_keys(buyer)['private']
    msg = f"{buyer}->{seller}:{price}:{currency}"
    sig = sign_message(priv_key, msg)
    
    txn_id = f"tx{conn.execute('SELECT COUNT(*) FROM transactions').fetchone()[0]+1}"
    txn = {
        "id": txn_id,
        "from": buyer,
        "to": seller,
        "amount": price,
        "currency": currency,
        "type": "marketplace",
        "status": "ESCROW",
        "signature": sig,
        "created_at": now_ts(),
        "escrow": True,
        "item_id": item_id,
        "disputed": 0
    }
    
    log_transaction(txn)
    conn.commit()
    conn.close()
    return redirect(f"/?success=Item%20purchased.%20Funds%20are%20in%20escrow.")

@app.route("/confirm_delivery", methods=["POST"])
def confirm_delivery():
    user = session.get("user_uid")
    if not user or not check_password_hash(_get_user(user)['pin_hash'], request.form.get('pin')):
        return redirect("/?alert=Authentication%20failed.")

    txn_id = request.form.get("txn_id")
    conn = get_db()
    txn = conn.execute("SELECT * FROM transactions WHERE id = ? AND to_uid = ?", (txn_id, user)).fetchone()
    if not txn or txn['status'] != 'ESCROW':
        conn.close()
        return redirect("/?alert=Transaction%20not%20found%20or%20not%20in%20escrow.")

    conn.execute("UPDATE transactions SET status = 'CONFIRM_PENDING' WHERE id = ?", (txn_id,))
    conn.commit()
    conn.close()
    
    sync_all() # Immediately process this specific transaction
    return redirect(f"/?success=Delivery%20confirmed.%20Syncing%20funds%20to%20seller.")

@app.route("/dispute", methods=["POST"])
def dispute():
    user = session.get("user_uid")
    if not user or not check_password_hash(_get_user(user)['pin_hash'], request.form.get('pin')):
        return redirect("/?alert=Authentication%20failed.")

    txn_id = request.form.get("txn_id")
    conn = get_db()
    txn = conn.execute("SELECT * FROM transactions WHERE id = ? AND to_uid = ?", (txn_id, user)).fetchone()
    if not txn or txn['status'] != 'ESCROW':
        conn.close()
        return redirect("/?alert=Transaction%20not%20found%20or%20not%20in%20escrow.")

    conn.execute("UPDATE transactions SET status = 'DISPUTED', disputed = 1 WHERE id = ?", (txn_id,))
    conn.commit()
    conn.close()
    return redirect(f"/?alert=Transaction%20disputed.%20Further%20action%20required.")

# -------------------------
# Marketplace AI
# -------------------------
@app.route("/marketplace_suggestions")
def marketplace_suggestions():
    try:
        conn = get_db()
        marketplace_items = conn.execute("SELECT name, price, currency FROM marketplace").fetchall()
        users_info = conn.execute("SELECT name, cedi, credits FROM users").fetchall()
        conn.close()

        marketplace_data = [dict(row) for row in marketplace_items]
        users_data = [dict(row) for row in users_info]
        
        user_prompt = f"""
        Given the current marketplace items and user balances, provide market-based suggestions.
        Focus on suggestions for new items to add to the marketplace, based on user spending habits and balances.

        Current marketplace items:
        {json.dumps(marketplace_data, indent=2)}

        Current user balances:
        {json.dumps(users_data, indent=2)}

        Provide three concise, high-impact suggestions in a simple list.
        Each suggestion should be a sentence starting with a call to action.
        """
        
        system_prompt = "You are a world-class financial analyst and market strategist for a community-based payment system. Your goal is to provide actionable, insightful suggestions to improve the marketplace."
        
        payload = {
            "contents": [{ "parts": [{ "text": user_prompt }] }],
            "tools": [{ "google_search": {} }],
            "systemInstruction": { "parts": [{ "text": system_prompt }] },
        }
        
        response = genai.GenerativeModel('gemini-2.5-flash-preview-05-20').generate_content(
            contents=payload['contents'],
            tools=payload['tools'],
            system_instruction=payload['systemInstruction']
        )
        
        text_response = response.text.split('\n')
        suggestions = [line.strip() for line in text_response if line.strip()]
        
        return jsonify(suggestions)

    except Exception as e:
        print(f"Error fetching AI suggestions: {e}")
        return jsonify(["Failed to get AI suggestions."]), 500

# -------------------------
# Analytics / Export
# -------------------------
@app.route("/sync", methods=["POST"])
def sync_route():
    sync_all()
    return redirect(f"/?success=All%20pending%20transactions%20synced.")

@app.route("/analytics")
def analytics():
    conn = get_db()
    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    total_cedi = conn.execute("SELECT SUM(cedi) FROM users").fetchone()[0] or 0
    total_credits = conn.execute("SELECT SUM(credits) FROM users").fetchone()[0] or 0
    total_pending = conn.execute("SELECT COUNT(*) FROM transactions WHERE status IN ('PENDING', 'ESCROW')").fetchone()[0]
    conn.close()
    
    return jsonify({
        "total_users": total_users,
        "total_cedi": total_cedi,
        "total_credits": total_credits,
        "total_pending": total_pending
    })

@app.route("/export")
def export_route():
    conn = get_db()
    df = pd.read_sql_query("SELECT * FROM transactions", conn)
    conn.close()
    
    if df.empty:
        df = pd.DataFrame([{"info":"no transactions yet"}])
        
    buf = BytesIO()
    df.to_csv(buf, index=False)
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name="transactions.csv", mimetype="text/csv")

@app.route("/network.png")
def network_png():
    conn = get_db()
    transactions = conn.execute("SELECT from_uid, to_uid, amount, currency, status FROM transactions ORDER BY created_at DESC LIMIT 50").fetchall()
    users_names = {row['uid']: row['name'] for row in conn.execute("SELECT uid, name FROM users").fetchall()}
    conn.close()
    
    G = nx.DiGraph()
    for uid, name in users_names.items():
        G.add_node(name)
    
    edges = []
    for txn in transactions:
        try:
            sender = users_names[txn["from_uid"]]
            receiver = users_names.get(txn["to_uid"], 'Marketplace')
            label = f"{txn['amount']} {txn['currency']} ({txn['status']})"
            edges.append((sender, receiver, label))
        except KeyError:
            continue
    
    pos = nx.spring_layout(G, seed=42, k=0.8)
    plt.figure(figsize=(10,6))
    nx.draw(G, pos, with_labels=True, node_color='lightblue', node_size=2000, font_size=9)
    if edges:
        edge_labels = {(u,v):lbl for (u,v,lbl) in edges}
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8)
    
    buf = BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format="png")
    plt.close()
    buf.seek(0)
    return send_file(buf, mimetype="image/png")

# -------------------------
# Background demo generator
# -------------------------
def demo_activity_loop():
    while True:
        try:
            time.sleep(5)
            conn = get_db()
            uids = [row["uid"] for row in conn.execute("SELECT uid FROM users").fetchall()]
            marketplace_items = conn.execute("SELECT id FROM marketplace WHERE available = 1").fetchall()
            conn.close()
            
            if len(uids) >= 2:
                sender = random.choice(uids)
                receiver = random.choice([u for u in uids if u != sender])
                amount = round(random.uniform(0.5, 5.0), 2)
                currency = random.choice(["credits", "cedi"])
                
                priv_key = _get_user_keys(sender)['private']
                msg = f"{sender}->{receiver}:{amount}:{currency}"
                sig = sign_message(priv_key, msg)
                
                txn_id = f"tx{sqlite3.connect(DB_FILE).execute('SELECT COUNT(*) FROM transactions').fetchone()[0]+1}"
                txn = {
                    "id": txn_id, "from": sender, "to": receiver, "amount": amount, "currency": currency,
                    "type": "demo", "status": "PENDING", "signature": sig, "created_at": now_ts(),
                    "escrow": False, "disputed": 0
                }
                log_transaction(txn)

            if marketplace_items and random.random() < 0.2:
                item_id = random.choice(marketplace_items)['id']
                buyer = random.choice(uids)
                conn = get_db()
                item = conn.execute("SELECT * FROM marketplace WHERE id = ?", (item_id,)).fetchone()
                if item:
                    seller = item['seller_uid']
                    price = item['price']
                    currency = item['currency']
                    
                    priv_key = _get_user_keys(buyer)['private']
                    msg = f"{buyer}->{seller}:{price}:{currency}"
                    sig = sign_message(priv_key, msg)
                    
                    txn_id = f"tx{conn.execute('SELECT COUNT(*) FROM transactions').fetchone()[0]+1}"
                    txn = {
                        "id": txn_id, "from": buyer, "to": seller, "amount": price, "currency": currency,
                        "type": "marketplace", "status": "ESCROW", "signature": sig, "created_at": now_ts(),
                        "escrow": True, "item_id": item_id, "disputed": 0
                    }
                    log_transaction(txn)
                    conn.execute("UPDATE marketplace SET available = 0 WHERE id = ?", (item_id,))
                    conn.commit()
                conn.close()
            
            if random.random() < 0.6:
                sync_all()
        except Exception as e:
            print(f"Demo loop error: {e}")
            pass

demo_thread = threading.Thread(target=demo_activity_loop, daemon=True)

# -------------------------
# Preload demo users & items
# -------------------------
def preload_demo_data():
    conn = get_db()
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        demo_people = [
            ("Alice Farmer", "GH001", "1234", 100.0, 50.0),
            ("Bob Trader", "GH002", "1234", 60.0, 120.0),
            ("Charlie Tailor", "GH003", "1234", 40.0, 30.0),
            ("Dora Carpenter", "GH004", "1234", 80.0, 20.0)
        ]
        for name, gh, pin, cedi, credits in demo_people:
            uid = uid_from_name(name)
            pin_hash = generate_password_hash(pin)
            priv, pub = generate_keys()
            conn.execute("INSERT INTO users (uid, name, gh_card, pin_hash, cedi, credits, public_key, private_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                         (uid, name, gh, pin_hash, cedi, credits, serialize_public_key(pub), serialize_private_key(priv)))
            card_id = f"card{conn.execute('SELECT COUNT(*) FROM nfc_users').fetchone()[0]+1:03d}"
            conn.execute("INSERT INTO nfc_users (card_id, uid) VALUES (?, ?)", (card_id, uid))
        
        market_items = [
            ("Maize Sack", 20.0, "cedi", uid_from_name("Bob Trader")),
            ("Tailoring Service (1hr)", 15.0, "credits", uid_from_name("Alice Farmer")),
            ("Carpentry - stool", 25.0, "cedi", uid_from_name("Dora Carpenter"))
        ]
        for name, price, currency, seller_uid in market_items:
            add_market_item(name, price, currency, seller_uid)
            
        conn.commit()
    conn.close()

# -------------------------
# Run the Flask app
# -------------------------
if __name__ == "__main__":
    init_db()
    preload_demo_data()
    if not demo_thread.is_alive():
        demo_thread.start()
    app.run()
