import sqlite3
import datetime
import jwt # PyJWT - pip install PyJWT
from functools import wraps
from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash

# --- CONFIGURATION ---
DATABASE = 'chat_server.db'
SECRET_KEY = 'a-very-secret-key-that-you-should-change' # Used for signing JWT tokens

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY

# --- DATABASE HELPERS ---

def get_db():
    """Get a database connection from the Flask global context."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Close the database connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize the database schema."""
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# --- AUTHENTICATION & DECORATORS ---

def token_required(f):
    """A decorator to protect routes that require authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            # Expected format: "Bearer <token>"
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            # Decode the token using the app's secret key
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            db = get_db()
            current_user = db.execute(
                'SELECT * FROM users WHERE id = ?', (data['user_id'],)
            ).fetchone()
            if not current_user:
                 return jsonify({'message': 'Token is invalid!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
            
        return f(current_user, *args, **kwargs)
    return decorated

# --- API ENDPOINTS ---

@app.route('/register', methods=['POST'])
def register_user():
    """
    Register a new user.
    JSON: { "username": "...", "password": "..." }
    """
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing username or password'}), 400

    username = data.get('username')
    # Hash the password for security
    password_hash = generate_password_hash(data.get('password'), method='pbkdf2:sha256')

    db = get_db()
    try:
        db.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            (username, password_hash)
        )
        db.commit()
        return jsonify({'message': 'New user registered successfully!'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Username already exists.'}), 409

@app.route('/login', methods=['POST'])
def login():
    """
    Log in a user and return a JWT token.
    JSON: { "username": "...", "password": "..." }
    """
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Could not verify'}), 401

    db = get_db()
    user = db.execute(
        'SELECT * FROM users WHERE username = ?', (data['username'],)
    ).fetchone()

    if not user or not check_password_hash(user['password_hash'], data['password']):
        return jsonify({'message': 'Could not verify! Check username/password.'}), 401

    # Create a JWT token that expires in 24 hours
    token = jwt.encode({
        'user_id': user['id'],
        'username': user['username'],
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({'token': token})

@app.route('/upload_key', methods=['POST'])
@token_required
def upload_key(current_user):
    """
    Upload or update a user's public key for E2EE.
    Protected route. Requires "Authorization: Bearer <token>" header.
    JSON: { "public_key": "..." }
    """
    data = request.get_json()
    if not data or not data.get('public_key'):
        return jsonify({'message': 'Missing public_key'}), 400

    db = get_db()
    # Use INSERT OR REPLACE to handle both new keys and updates
    db.execute(
        'INSERT OR REPLACE INTO public_keys (user_id, public_key) VALUES (?, ?)',
        (current_user['id'], data['public_key'])
    )
    db.commit()
    return jsonify({'message': 'Public key uploaded successfully.'}), 200

@app.route('/get_key', methods=['GET'])
@token_required
def get_key(current_user):
    """
    Get the public key for a given username.
    Protected route. Requires token.
    Query: /get_key?username=bob
    """
    username_to_find = request.args.get('username')
    if not username_to_find:
        return jsonify({'message': 'Missing username query parameter.'}), 400

    db = get_db()
    key_data = db.execute(
        'SELECT pk.public_key FROM public_keys pk JOIN users u ON u.id = pk.user_id WHERE u.username = ?',
        (username_to_find,)
    ).fetchone()

    if not key_data:
        return jsonify({'message': 'User not found or has no public key.'}), 404
    
    return jsonify({'username': username_to_find, 'public_key': key_data['public_key']})

@app.route('/request_chat', methods=['POST'])
@token_required
def request_chat(current_user):
    """
    Send a chat request to another user.
    This fulfills the "flag that user for a conversation request" logic.
    JSON: { "recipient_username": "..." }
    """
    data = request.get_json()
    recipient_username = data.get('recipient_username')
    if not recipient_username:
        return jsonify({'message': 'Missing recipient_username'}), 400

    db = get_db()
    recipient = db.execute('SELECT id FROM users WHERE username = ?', (recipient_username,)).fetchone()
    if not recipient:
        return jsonify({'message': 'Recipient user not found.'}), 404

    # Check if a request already exists
    existing = db.execute(
        'SELECT * FROM chat_requests WHERE requester_id = ? AND requested_id = ?',
        (current_user['id'], recipient['id'])
    ).fetchone()

    if existing:
        return jsonify({'message': 'Chat request already pending or accepted.'}), 409

    db.execute(
        'INSERT INTO chat_requests (requester_id, requested_id, status) VALUES (?, ?, ?)',
        (current_user['id'], recipient['id'], 'pending')
    )
    db.commit()
    return jsonify({'message': f'Chat request sent to {recipient_username}.'}), 201

@app.route('/get_chat_requests', methods=['GET'])
@token_required
def get_chat_requests(current_user):
    """
    Get all pending chat requests for the logged-in user.
    """
    db = get_db()
    requests = db.execute(
        """
        SELECT u.username AS requester_username, cr.status
        FROM chat_requests cr
        JOIN users u ON u.id = cr.requester_id
        WHERE cr.requested_id = ? AND cr.status = 'pending'
        """, (current_user['id'],)
    ).fetchall()
    
    # Convert list of Row objects to a list of dicts
    pending_requests = [dict(row) for row in requests]
    return jsonify({'pending_requests': pending_requests})

@app.route('/accept_chat', methods=['POST'])
@token_required
def accept_chat(current_user):
    """
    Accept a pending chat request.
    This "activates" the conversation.
    JSON: { "requester_username": "..." }
    """
    data = request.get_json()
    requester_username = data.get('requester_username')
    if not requester_username:
        return jsonify({'message': 'Missing requester_username'}), 400

    db = get_db()
    requester = db.execute('SELECT id FROM users WHERE username = ?', (requester_username,)).fetchone()
    if not requester:
        return jsonify({'message': 'Requester user not found.'}), 404
        
    # --- FIX: Capture the cursor object ---
    cursor = db.execute(
        """
        UPDATE chat_requests
        SET status = 'accepted'
        WHERE requester_id = ? AND requested_id = ? AND status = 'pending'
        """,
        (requester['id'], current_user['id'])
    )
    db.commit()
    
    # --- FIX: Check the cursor.rowcount attribute ---
    if cursor.rowcount == 0:
        return jsonify({'message': 'No pending request found from that user.'}), 404
        
    return jsonify({'message': f'Chat request from {requester_username} accepted!'}), 200


@app.route('/get_contacts', methods=['GET'])
@token_required
def get_contacts(current_user):
    """
    Get all users with whom the current user has an 'accepted' chat.
    This includes chats they requested and chats they accepted.
    """
    db = get_db()
    my_id = current_user['id']
    
    # Find users I requested and were accepted
    i_requested = db.execute(
        """
        SELECT u.username
        FROM chat_requests cr
        JOIN users u ON u.id = cr.requested_id
        WHERE cr.requester_id = ? AND cr.status = 'accepted'
        """, (my_id,)
    ).fetchall()
    
    # Find users who requested me and I accepted
    they_requested = db.execute(
        """
        SELECT u.username
        FROM chat_requests cr
        JOIN users u ON u.id = cr.requester_id
        WHERE cr.requested_id = ? AND cr.status = 'accepted'
        """, (my_id,)
    ).fetchall()

    # Combine the lists and remove duplicates
    contacts = set(row['username'] for row in i_requested)
    contacts.update(row['username'] for row in they_requested)
    
    return jsonify({'contacts': list(contacts)})


@app.route('/send_message', methods=['POST'])
@token_required
def send_message(current_user):
    """
    Send an encrypted message to a user.
    The server stores a blob for the sender and one for the recipient.
    JSON: { "recipient_username": "...", "sender_blob": "...", "recipient_blob": "..." }
    """
    data = request.get_json()
    recipient_username = data.get('recipient_username')
    sender_blob = data.get('sender_blob')
    recipient_blob = data.get('recipient_blob')
    
    if not recipient_username or not sender_blob or not recipient_blob:
        return jsonify({'message': 'Missing recipient_username, sender_blob, or recipient_blob'}), 400

    db = get_db()
    recipient = db.execute('SELECT id FROM users WHERE username = ?', (recipient_username,)).fetchone()
    if not recipient:
        return jsonify({'message': 'Recipient user not found.'}), 404

    # Here you might check if the chat is "active" (request accepted)
    # For simplicity, we'll allow any user to message any other user for now.
    
    db.execute(
        'INSERT INTO messages (sender_id, recipient_id, sender_blob, recipient_blob, timestamp) VALUES (?, ?, ?, ?, ?)',
        (current_user['id'], recipient['id'], sender_blob, recipient_blob, datetime.datetime.now(datetime.timezone.utc))
    )
    db.commit()
    return jsonify({'message': 'Message sent successfully.'}), 201

@app.route('/get_messages', methods=['GET'])
@token_required
def get_messages(current_user):
    """
    Get all messages between the logged-in user and another user.
    Query: /get_messages?username=bob
    Query (optional): /get_messages?username=bob&since_id=10
    """
    partner_username = request.args.get('username')
    # Get since_id, default to 0 if not provided
    since_id = request.args.get('since_id', 0, type=int) 
    
    if not partner_username:
        return jsonify({'message': 'Missing username query parameter.'}), 400

    db = get_db()
    partner = db.execute('SELECT id FROM users WHERE username = ?', (partner_username,)).fetchone()
    if not partner:
        return jsonify({'message': 'Partner user not found.'}), 404

    my_id = current_user['id']
    partner_id = partner['id']

    # --- UPDATED QUERY ---
    # We add the "AND m.id > ?" to the WHERE clause
    messages_rows = db.execute(
        """
        SELECT 
            m.id, 
            m.sender_id, 
            m.recipient_id, 
            m.timestamp, 
            u_sender.username AS sender_username,
            CASE
                WHEN m.sender_id = ? THEN m.sender_blob
                ELSE m.recipient_blob
            END AS encrypted_blob
        FROM messages m
        JOIN users u_sender ON u_sender.id = m.sender_id
        WHERE 
            ((m.sender_id = ? AND m.recipient_id = ?) OR (m.sender_id = ? AND m.recipient_id = ?))
            AND m.id > ?
        ORDER BY m.timestamp ASC
        """,
        # Parameters match the '?' marks in order
        (my_id, my_id, partner_id, partner_id, my_id, since_id)
    ).fetchall()

    messages = [dict(row) for row in messages_rows]
    return jsonify({'messages': messages})

# --- Main ---

if __name__ == '__main__':
    print("Initializing database...")
    init_db() # Create the database tables if they don't exist
    print("Starting Flask server at http://127.0.0.1:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)
