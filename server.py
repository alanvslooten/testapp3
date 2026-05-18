#!/usr/bin/env python3
"""
KinderKompas — Backend API
Flask + SQLite, JWT authentication, full REST API
"""
import sqlite3, os, json, hashlib, hmac, base64, time, re
from datetime import datetime, timedelta, date
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, send_file


app = Flask(__name__, static_folder='frontend/dist', static_url_path='')

# ── CONFIG ──
SECRET = os.environ.get('JWT_SECRET', 'kinderkompas-secret-2025-xK9mP')
DB_PATH = os.path.join(os.path.dirname(__file__), 'kinderkompas.db')
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ── CORS helper ──
def cors(resp):
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    resp.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,PATCH,OPTIONS'
    return resp

@app.after_request
def after(resp): return cors(resp)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    # API routes handled before this
    static_dir = os.path.join(os.path.dirname(__file__), 'static')
    if path and os.path.exists(os.path.join(static_dir, path)):
        return send_from_directory(static_dir, path)
    return send_from_directory(static_dir, 'index.html')

# ── SIMPLE JWT (no external lib) ──
def b64url_encode(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(s):
    pad = 4 - len(s) % 4
    if pad != 4: s += '=' * pad
    return base64.urlsafe_b64decode(s)

def make_token(payload):
    header = b64url_encode(json.dumps({'alg':'HS256','typ':'JWT'}))
    payload['exp'] = time.time() + 86400 * 7
    body = b64url_encode(json.dumps(payload))
    sig = hmac.new(SECRET.encode(), f'{header}.{body}'.encode(), 'sha256').digest()
    return f'{header}.{body}.{b64url_encode(sig)}'

def verify_token(token):
    try:
        parts = token.split('.')
        if len(parts) != 3: return None
        header, body, sig = parts
        expected = hmac.new(SECRET.encode(), f'{header}.{body}'.encode(), 'sha256').digest()
        if not hmac.compare_digest(b64url_decode(sig), expected): return None
        payload = json.loads(b64url_decode(body))
        if payload.get('exp', 0) < time.time(): return None
        return payload
    except: return None

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization','')
        if not auth.startswith('Bearer '): return jsonify({'error':'Unauthorized'}), 401
        payload = verify_token(auth[7:])
        if not payload: return jsonify({'error':'Invalid token'}), 401
        request.user = payload
        return f(*args, **kwargs)
    return wrapper

def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization','')
        if not auth.startswith('Bearer '): return jsonify({'error':'Unauthorized'}), 401
        payload = verify_token(auth[7:])
        if not payload: return jsonify({'error':'Invalid token'}), 401
        if payload.get('role') != 'admin': return jsonify({'error':'Admin required'}), 403
        request.user = payload
        return f(*args, **kwargs)
    return wrapper

# ── DATABASE ──
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    c.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'staff',
        initials TEXT,
        color TEXT DEFAULT '#1B8A5A',
        contract_hours INTEGER DEFAULT 32,
        vacation_hours_total INTEGER DEFAULT 160,
        vacation_hours_used INTEGER DEFAULT 0,
        worked_hours_month INTEGER DEFAULT 0,
        qualifications TEXT DEFAULT '[]',
        active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS children (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        dob TEXT NOT NULL,
        group_name TEXT NOT NULL,
        group_color TEXT DEFAULT '#1B8A5A',
        assigned_leidster_id INTEGER REFERENCES users(id),
        days TEXT DEFAULT '[0,0,0,0,0]',
        contact_name TEXT,
        contact_phone TEXT,
        notes TEXT,
        active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS observations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        child_id INTEGER NOT NULL REFERENCES children(id),
        leidster_id INTEGER REFERENCES users(id),
        obs_date TEXT NOT NULL,
        next_due TEXT,
        notes TEXT,
        completed INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS observation_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        observation_id INTEGER NOT NULL REFERENCES observations(id),
        filename TEXT NOT NULL,
        original_name TEXT NOT NULL,
        file_type TEXT,
        file_size INTEGER,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS shifts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        shift_date TEXT NOT NULL,
        shift_type TEXT DEFAULT 'werk',
        start_time TEXT,
        end_time TEXT,
        notes TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS leave_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        leave_type TEXT DEFAULT 'vakantie',
        from_date TEXT NOT NULL,
        to_date TEXT NOT NULL,
        days INTEGER DEFAULT 1,
        status TEXT DEFAULT 'pending',
        notes TEXT,
        reviewed_by INTEGER REFERENCES users(id),
        reviewed_at TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS availability (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        day_of_week INTEGER NOT NULL,
        session TEXT NOT NULL,
        UNIQUE(user_id, day_of_week, session)
    );

    CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER REFERENCES users(id),
        action TEXT NOT NULL,
        details TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    ''')

    # Seed data
    def hash_pw(pw):
        return hashlib.sha256(f'{pw}{SECRET}'.encode()).hexdigest()

    users_seed = [
        ('Beheerder', 'beheerder@kdv.nl', hash_pw('admin123'), 'admin', 'BH', '#1B8A5A', 40, 200, 0, 0),
        ('Lisa de Bruin', 'lisa@kdv.nl', hash_pw('leidster1'), 'staff', 'LB', '#7C4DFF', 32, 160, 24, 88),
        ('Sarah Jansen', 'sarah@kdv.nl', hash_pw('leidster2'), 'staff', 'SJ', '#0B9BB5', 28, 140, 16, 74),
        ('Mieke van Dijk', 'mieke@kdv.nl', hash_pw('leidster3'), 'staff', 'MV', '#E91E8C', 36, 180, 40, 96),
        ('Tom Hartman', 'tom@kdv.nl', hash_pw('stagair1'), 'staff', 'TH', '#F5841F', 16, 0, 0, 42),
    ]
    for u in users_seed:
        c.execute('''INSERT OR IGNORE INTO users 
            (name,email,password_hash,role,initials,color,contract_hours,vacation_hours_total,vacation_hours_used,worked_hours_month)
            VALUES (?,?,?,?,?,?,?,?,?,?)''', u)

    c.execute("SELECT id FROM users WHERE email='lisa@kdv.nl'")
    lisa_id = c.fetchone()
    c.execute("SELECT id FROM users WHERE email='sarah@kdv.nl'")
    sarah_id = c.fetchone()
    c.execute("SELECT id FROM users WHERE email='mieke@kdv.nl'")
    mieke_id = c.fetchone()

    if lisa_id and sarah_id and mieke_id:
        lid, sid, mid = lisa_id[0], sarah_id[0], mieke_id[0]
        children_seed = [
            ('Emma de Jong',      '2024-03-15', 'Babygroep',   '#1B8A5A', lid,  '[1,0,1,0,1]', 'Maria de Jong',  '06-12345678'),
            ('Liam Bakker',       '2023-08-22', 'Dreumesgroep','#7C4DFF', sid,  '[1,1,0,1,0]', 'Jan Bakker',     '06-23456789'),
            ('Sophie van den Berg','2023-01-10','Dreumesgroep','#7C4DFF', lid,  '[0,1,1,1,0]', 'Karin v.d. Berg','06-34567890'),
            ('Noah Smit',         '2022-11-05', 'Peutergroep', '#0B9BB5', mid,  '[1,0,0,1,1]', 'Peter Smit',     '06-45678901'),
            ('Olivia Visser',     '2022-06-18', 'Peutergroep', '#0B9BB5', sid,  '[1,1,1,0,0]', 'Anne Visser',    '06-56789012'),
            ('Lucas de Boer',     '2024-01-20', 'Babygroep',   '#1B8A5A', mid,  '[0,1,0,1,1]', 'Rob de Boer',    '06-67890123'),
            ('Mia Janssen',       '2023-04-12', 'Dreumesgroep','#7C4DFF', lid,  '[1,0,1,0,1]', 'Els Janssen',    '06-78901234'),
            ('Finn de Wit',       '2022-09-30', 'Peutergroep', '#0B9BB5', mid,  '[0,0,1,1,1]', 'Mark de Wit',    '06-89012345'),
            ('Zoë Mulder',        '2024-06-07', 'Babygroep',   '#1B8A5A', sid,  '[1,1,0,0,0]', 'Linda Mulder',   '06-90123456'),
            ('Lars Hendriks',     '2023-02-14', 'Dreumesgroep','#7C4DFF', lid,  '[1,0,0,1,1]', 'Daan Hendriks',  '06-01234567'),
            ('Noor Pietersen',    '2022-12-01', 'Peutergroep', '#0B9BB5', mid,  '[0,1,1,0,1]', 'Lies Pietersen', '06-11223344'),
            ('Sam de Graaf',      '2024-04-25', 'Babygroep',   '#1B8A5A', sid,  '[1,1,1,0,0]', 'Tom de Graaf',   '06-22334455'),
        ]
        for ch in children_seed:
            c.execute('''INSERT OR IGNORE INTO children 
                (name,dob,group_name,group_color,assigned_leidster_id,days,contact_name,contact_phone)
                VALUES (?,?,?,?,?,?,?,?)''', ch)

        # Observations
        obs_seed = [
            (1, lid, '2024-09-15', '2025-03-15', 'Emma ontwikkelt goed. Motoriek goed op schema voor haar leeftijd. Ze reageert positief op vaste leidsters en lacht veel. Eetpatroon is stabiel.'),
            (2, sid, '2024-08-22', '2025-02-22', 'Liam is erg actief en nieuwsgierig. Taalontwikkeling loopt iets achter maar motorisch is hij sterk.'),
            (4, mid, '2025-02-05', '2025-08-05', 'Noah is een vrolijke peuter. Speelt goed samen met andere kinderen. Spreekt al in zinnen van drie woorden.'),
            (5, sid, '2024-12-18', '2025-06-18', 'Olivia is erg sociaal. Ze helpt graag andere kinderen en is goed in puzzelen.'),
            (7, lid, '2024-04-12', '2024-10-12', 'Mia toont veel interesse in boeken en tekenen. Concentratie is goed voor haar leeftijd.'),
            (8, mid, '2025-03-30', '2025-09-30', 'Finn is een stille maar oplettende peuter. Wordt goed meegenomen door de groep.'),
        ]
        for obs in obs_seed:
            child_id, leid_id, obs_date, next_due, notes = obs
            c.execute('''INSERT OR IGNORE INTO observations (child_id,leidster_id,obs_date,next_due,notes,completed)
                VALUES (?,?,?,?,?,1)''', (child_id, leid_id, obs_date, next_due, notes))

        # Shifts current week
        today = date.today()
        monday = today - timedelta(days=today.weekday())
        week_shifts = [
            (lid, 0, 'werk', '07:30', '16:00'),
            (lid, 1, 'werk', '07:30', '16:00'),
            (lid, 3, 'werk', '07:30', '14:00'),
            (lid, 4, 'werk', '07:30', '16:00'),
            (sid, 0, 'werk', '09:00', '18:30'),
            (sid, 2, 'werk', '09:00', '18:30'),
            (sid, 3, 'werk', '09:00', '18:30'),
            (mid, 1, 'werk', '08:00', '17:00'),
            (mid, 2, 'werk', '08:00', '17:00'),
            (mid, 4, 'werk', '08:00', '17:00'),
        ]
        for user_id, day_off, stype, start, end in week_shifts:
            shift_date = (monday + timedelta(days=day_off)).isoformat()
            c.execute('''INSERT OR IGNORE INTO shifts (user_id,shift_date,shift_type,start_time,end_time)
                VALUES (?,?,?,?,?)''', (user_id, shift_date, stype, start, end))

        # Leave requests
        c.execute('''INSERT OR IGNORE INTO leave_requests (user_id,leave_type,from_date,to_date,days,notes)
            VALUES (?,?,?,?,?,?)''', (sid,'vakantie','2025-06-12','2025-06-16',3,'Zomervakantie familietrip'))
        c.execute('''INSERT OR IGNORE INTO leave_requests (user_id,leave_type,from_date,to_date,days,notes)
            VALUES (?,?,?,?,?,?)''', (lid,'verlof','2025-05-28','2025-05-28',1,'Arts afspraak'))

        # Availability
        avail_seed = [
            (lid, 0,'ochtend'), (lid,0,'middag'), (lid,1,'ochtend'),
            (lid,3,'ochtend'), (lid,3,'middag'), (lid,4,'ochtend'), (lid,4,'middag'),
            (sid,0,'middag'), (sid,1,'ochtend'), (sid,1,'middag'),
            (sid,2,'middag'), (sid,3,'ochtend'),
            (mid,1,'ochtend'), (mid,1,'middag'), (mid,2,'ochtend'), (mid,2,'middag'),
            (mid,4,'ochtend'), (mid,4,'middag'),
        ]
        for av in avail_seed:
            c.execute('INSERT OR IGNORE INTO availability (user_id,day_of_week,session) VALUES (?,?,?)', av)

        # Activity log
        log_entries = [
            (lid, 'Observatie afgerond', 'Emma de Jong — observatie gemarkeerd als voltooid'),
            (sid, 'Verlofaanvraag ingediend', '3 vakantiedagen aangevraagd: 12-16 juni'),
            (None, 'Nieuwe aanmelding', 'Kind toegevoegd: Sam de Graaf (Babygroep)'),
            (None, 'BKR waarschuwing', 'Dreumesgroep: 3-uursregeling actief 14:00-16:00'),
            (mid, 'Rooster gepubliceerd', 'Week 22 rooster gepubliceerd door beheerder'),
        ]
        for entry in log_entries:
            c.execute('INSERT OR IGNORE INTO activity_log (user_id,action,details) VALUES (?,?,?)', entry)

    conn.commit()
    conn.close()
    print('✓ Database initialized')

# ── HELPERS ──
def row_to_dict(row):
    if row is None: return None
    d = dict(row)
    for k, v in d.items():
        if isinstance(v, str):
            try: d[k] = json.loads(v)
            except: pass
    return d

def calc_obs_status(child_id, conn):
    row = conn.execute(
        'SELECT obs_date, next_due FROM observations WHERE child_id=? ORDER BY obs_date DESC LIMIT 1',
        (child_id,)
    ).fetchone()
    if not row:
        return 'overdue', None, None
    next_due = row['next_due']
    if not next_due:
        return 'done', row['obs_date'], None
    due = datetime.strptime(next_due, '%Y-%m-%d').date()
    today = date.today()
    diff = (due - today).days
    if diff < 0:   return 'overdue', row['obs_date'], next_due
    if diff <= 30: return 'needed',  row['obs_date'], next_due
    return 'done', row['obs_date'], next_due

def log_action(user_id, action, details=''):
    conn = get_db()
    conn.execute('INSERT INTO activity_log (user_id,action,details) VALUES (?,?,?)',
                 (user_id, action, details))
    conn.commit()
    conn.close()

# ══════════════════════════════════════════
# AUTH ROUTES
# ══════════════════════════════════════════

@app.route('/api/auth/login', methods=['POST','OPTIONS'])
def login():
    if request.method == 'OPTIONS': return jsonify({}), 200
    data = request.get_json()
    email = (data.get('email') or '').lower().strip()
    password = data.get('password', '')
    pw_hash = hashlib.sha256(f'{password}{SECRET}'.encode()).hexdigest()
    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE email=? AND password_hash=? AND active=1',
        (email, pw_hash)
    ).fetchone()
    conn.close()
    if not user:
        return jsonify({'error': 'Ongeldige inloggegevens'}), 401
    u = row_to_dict(user)
    token = make_token({'id': u['id'], 'email': u['email'], 'role': u['role'], 'name': u['name']})
    return jsonify({'token': token, 'user': {
        'id': u['id'], 'name': u['name'], 'email': u['email'],
        'role': u['role'], 'initials': u['initials'], 'color': u['color']
    }})

@app.route('/api/auth/me', methods=['GET'])
@require_auth
def me():
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id=?', (request.user['id'],)).fetchone()
    conn.close()
    if not user: return jsonify({'error': 'Not found'}), 404
    u = row_to_dict(user)
    u.pop('password_hash', None)
    return jsonify(u)

# ══════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════

@app.route('/api/dashboard', methods=['GET'])
@require_auth
def dashboard():
    conn = get_db()
    today = date.today().isoformat()
    
    total_children = conn.execute('SELECT COUNT(*) FROM children WHERE active=1').fetchone()[0]
    
    day_of_week = date.today().weekday()
    today_children_rows = conn.execute('SELECT days FROM children WHERE active=1').fetchall()
    today_children = sum(1 for r in today_children_rows if json.loads(r['days'])[day_of_week] == 1)
    
    staff_today = conn.execute(
        'SELECT COUNT(*) FROM shifts WHERE shift_date=? AND shift_type="werk"', (today,)
    ).fetchone()[0]
    
    pending_leave = conn.execute(
        'SELECT COUNT(*) FROM leave_requests WHERE status="pending"'
    ).fetchone()[0]
    
    # Observations needing attention
    children = conn.execute('SELECT id FROM children WHERE active=1').fetchall()
    obs_needed = 0
    obs_overdue = 0
    obs_done = 0
    for child in children:
        status, _, _ = calc_obs_status(child['id'], conn)
        if status == 'overdue': obs_overdue += 1
        elif status == 'needed': obs_needed += 1
        else: obs_done += 1
    
    # Activity log
    activities = conn.execute('''
        SELECT al.*, u.name as user_name, u.color
        FROM activity_log al
        LEFT JOIN users u ON al.user_id = u.id
        ORDER BY al.created_at DESC LIMIT 8
    ''').fetchall()
    
    # BKR status today
    babies    = sum(1 for r in today_children_rows if len(json.loads(r['days'])) > day_of_week and json.loads(r['days'])[day_of_week] and True) 
    # simplified BKR
    bkr_required = max(1, round(today_children / 5))
    
    conn.close()
    return jsonify({
        'total_children': total_children,
        'today_children': today_children,
        'staff_today': staff_today,
        'pending_leave': pending_leave,
        'obs_needed': obs_needed,
        'obs_overdue': obs_overdue,
        'obs_done': obs_done,
        'bkr_required': bkr_required,
        'bkr_present': staff_today,
        'activities': [row_to_dict(a) for a in activities]
    })

# ══════════════════════════════════════════
# CHILDREN
# ══════════════════════════════════════════

@app.route('/api/children', methods=['GET'])
@require_auth
def get_children():
    conn = get_db()
    group = request.args.get('group')
    user_id = request.user.get('id')
    role = request.user.get('role')
    
    if role == 'staff':
        rows = conn.execute('''
            SELECT c.*, u.name as leidster_name, u.color as leidster_color, u.initials as leidster_initials
            FROM children c
            LEFT JOIN users u ON c.assigned_leidster_id = u.id
            WHERE c.active=1 AND c.assigned_leidster_id=?
            ORDER BY c.name
        ''', (user_id,)).fetchall()
    else:
        if group:
            rows = conn.execute('''
                SELECT c.*, u.name as leidster_name, u.color as leidster_color, u.initials as leidster_initials
                FROM children c
                LEFT JOIN users u ON c.assigned_leidster_id = u.id
                WHERE c.active=1 AND c.group_name=?
                ORDER BY c.name
            ''', (group,)).fetchall()
        else:
            rows = conn.execute('''
                SELECT c.*, u.name as leidster_name, u.color as leidster_color, u.initials as leidster_initials
                FROM children c
                LEFT JOIN users u ON c.assigned_leidster_id = u.id
                WHERE c.active=1
                ORDER BY c.group_name, c.name
            ''').fetchall()

    children = []
    for r in rows:
        d = row_to_dict(r)
        status, last_obs, next_due = calc_obs_status(d['id'], conn)
        d['obs_status'] = status
        d['last_obs'] = last_obs
        d['next_obs_due'] = next_due
        children.append(d)
    conn.close()
    return jsonify(children)

@app.route('/api/children', methods=['POST'])
@require_auth
def add_child():
    data = request.get_json()
    conn = get_db()
    cur = conn.execute('''
        INSERT INTO children (name,dob,group_name,group_color,assigned_leidster_id,days,contact_name,contact_phone,notes)
        VALUES (?,?,?,?,?,?,?,?,?)
    ''', (
        data['name'], data['dob'], data['group_name'],
        data.get('group_color', '#1B8A5A'),
        data.get('assigned_leidster_id'),
        json.dumps(data.get('days', [0,0,0,0,0])),
        data.get('contact_name'), data.get('contact_phone'), data.get('notes')
    ))
    child_id = cur.lastrowid
    conn.commit()
    conn.close()
    log_action(request.user['id'], 'Kind toegevoegd', f'{data["name"]} ({data["group_name"]})')
    return jsonify({'id': child_id, 'message': 'Kind toegevoegd'}), 201

@app.route('/api/children/<int:cid>', methods=['GET'])
@require_auth
def get_child(cid):
    conn = get_db()
    row = conn.execute('''
        SELECT c.*, u.name as leidster_name, u.color as leidster_color
        FROM children c LEFT JOIN users u ON c.assigned_leidster_id=u.id
        WHERE c.id=?
    ''', (cid,)).fetchone()
    if not row: return jsonify({'error':'Not found'}),404
    d = row_to_dict(row)
    d['obs_status'], d['last_obs'], d['next_obs_due'] = calc_obs_status(cid, conn)
    obs = conn.execute('''
        SELECT o.*, u.name as leidster_name
        FROM observations o LEFT JOIN users u ON o.leidster_id=u.id
        WHERE o.child_id=? ORDER BY o.obs_date DESC
    ''', (cid,)).fetchall()
    d['observations'] = [row_to_dict(o) for o in obs]
    conn.close()
    return jsonify(d)

@app.route('/api/children/<int:cid>', methods=['PUT'])
@require_auth
def update_child(cid):
    data = request.get_json()
    conn = get_db()
    fields = []
    values = []
    allowed = ['name','dob','group_name','group_color','assigned_leidster_id','days','contact_name','contact_phone','notes']
    for f in allowed:
        if f in data:
            fields.append(f'{f}=?')
            val = data[f]
            if isinstance(val, list): val = json.dumps(val)
            values.append(val)
    if not fields: return jsonify({'error':'No fields'}),400
    values.append(cid)
    conn.execute(f'UPDATE children SET {",".join(fields)} WHERE id=?', values)
    conn.commit()
    conn.close()
    return jsonify({'message':'Updated'})

@app.route('/api/children/<int:cid>/assign', methods=['PATCH'])
@require_admin
def assign_child(cid):
    data = request.get_json()
    leidster_id = data.get('leidster_id')
    conn = get_db()
    conn.execute('UPDATE children SET assigned_leidster_id=? WHERE id=?', (leidster_id, cid))
    conn.commit()
    child = conn.execute('SELECT name FROM children WHERE id=?',(cid,)).fetchone()
    leid = conn.execute('SELECT name FROM users WHERE id=?',(leidster_id,)).fetchone()
    conn.close()
    log_action(request.user['id'],'Kind toegewezen',f'{child["name"]} aan {leid["name"]}')
    return jsonify({'message':'Assigned'})

# ══════════════════════════════════════════
# OBSERVATIONS
# ══════════════════════════════════════════

@app.route('/api/observations', methods=['GET'])
@require_auth
def get_observations():
    conn = get_db()
    rows = conn.execute('''
        SELECT o.*, c.name as child_name, c.group_name, c.dob, c.group_color,
               u.name as leidster_name
        FROM observations o
        JOIN children c ON o.child_id=c.id
        LEFT JOIN users u ON o.leidster_id=u.id
        ORDER BY o.obs_date DESC
    ''').fetchall()
    result = []
    for r in rows:
        d = row_to_dict(r)
        files = conn.execute('SELECT * FROM observation_files WHERE observation_id=?',(r['id'],)).fetchall()
        d['files'] = [row_to_dict(f) for f in files]
        result.append(d)
    conn.close()
    return jsonify(result)

@app.route('/api/observations/overview', methods=['GET'])
@require_auth
def obs_overview():
    """All children with their observation status"""
    conn = get_db()
    children = conn.execute('''
        SELECT c.*, u.name as leidster_name, u.initials as leidster_initials, u.color as leidster_color
        FROM children c LEFT JOIN users u ON c.assigned_leidster_id=u.id
        WHERE c.active=1 ORDER BY c.name
    ''').fetchall()
    result = []
    for ch in children:
        d = row_to_dict(ch)
        status, last_obs, next_due = calc_obs_status(d['id'], conn)
        d['obs_status'] = status
        d['last_obs'] = last_obs
        d['next_obs_due'] = next_due
        obs = conn.execute('''
            SELECT o.*, u.name as leidster_name
            FROM observations o LEFT JOIN users u ON o.leidster_id=u.id
            WHERE o.child_id=? ORDER BY o.obs_date DESC
        ''', (d['id'],)).fetchall()
        d['all_observations'] = [row_to_dict(o) for o in obs]
        result.append(d)
    conn.close()
    return jsonify(result)

@app.route('/api/observations', methods=['POST'])
@require_auth
def add_observation():
    data = request.get_json()
    obs_date = data.get('obs_date', date.today().isoformat())
    obs_dt = datetime.strptime(obs_date, '%Y-%m-%d')
    next_due = (obs_dt + timedelta(days=183)).strftime('%Y-%m-%d')
    conn = get_db()
    cur = conn.execute('''
        INSERT INTO observations (child_id,leidster_id,obs_date,next_due,notes,completed)
        VALUES (?,?,?,?,?,1)
    ''', (data['child_id'], request.user['id'], obs_date, next_due, data.get('notes','')))
    obs_id = cur.lastrowid
    conn.commit()
    child = conn.execute('SELECT name FROM children WHERE id=?',(data['child_id'],)).fetchone()
    conn.close()
    log_action(request.user['id'],'Observatie toegevoegd',f'{child["name"]} — {obs_date}')
    return jsonify({'id': obs_id, 'next_due': next_due}), 201

@app.route('/api/observations/<int:oid>/upload', methods=['POST'])
@require_auth
def upload_obs_file(oid):
    import uuid
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    file = request.files['file']
    if not file.filename: return jsonify({'error': 'No filename'}), 400
    
    allowed = {'.jpg','.jpeg','.png','.heic','.heif','.pdf','.docx'}
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in allowed:
        return jsonify({'error': f'Bestandstype {ext} niet toegestaan'}), 400
    
    unique_name = f'{uuid.uuid4().hex}{ext}'
    file_path = os.path.join(UPLOAD_DIR, unique_name)
    file.save(file_path)
    size = os.path.getsize(file_path)
    
    conn = get_db()
    cur = conn.execute('''
        INSERT INTO observation_files (observation_id,filename,original_name,file_type,file_size)
        VALUES (?,?,?,?,?)
    ''', (oid, unique_name, file.filename, ext, size))
    file_id = cur.lastrowid
    conn.commit()
    conn.close()
    return jsonify({'id': file_id, 'filename': unique_name, 'original_name': file.filename}), 201

@app.route('/api/uploads/<filename>')
@require_auth
def serve_upload(filename):
    return send_from_directory(UPLOAD_DIR, filename)

# ══════════════════════════════════════════
# STAFF / USERS
# ══════════════════════════════════════════

@app.route('/api/staff', methods=['GET'])
@require_auth
def get_staff():
    conn = get_db()
    rows = conn.execute('SELECT * FROM users WHERE active=1 ORDER BY name').fetchall()
    result = []
    for r in rows:
        d = row_to_dict(r)
        d.pop('password_hash', None)
        # Count children
        d['children_count'] = conn.execute(
            'SELECT COUNT(*) FROM children WHERE assigned_leidster_id=? AND active=1',(r['id'],)
        ).fetchone()[0]
        # Availability
        avail = conn.execute(
            'SELECT day_of_week, session FROM availability WHERE user_id=? ORDER BY day_of_week',(r['id'],)
        ).fetchall()
        d['availability'] = [row_to_dict(a) for a in avail]
        result.append(d)
    conn.close()
    return jsonify(result)

@app.route('/api/staff', methods=['POST'])
@require_admin
def add_staff():
    import hashlib
    data = request.get_json()
    pw = data.get('password', 'welkom123')
    pw_hash = hashlib.sha256(f'{pw}{SECRET}'.encode()).hexdigest()
    name = data['name']
    initials = ''.join(w[0].upper() for w in name.split()[:2])
    conn = get_db()
    cur = conn.execute('''
        INSERT INTO users (name,email,password_hash,role,initials,color,contract_hours,vacation_hours_total)
        VALUES (?,?,?,?,?,?,?,?)
    ''', (name, data['email'], pw_hash, data.get('role','staff'), initials,
          data.get('color','#1B8A5A'), data.get('contract_hours',32), data.get('vacation_hours',160)))
    uid = cur.lastrowid
    conn.commit()
    conn.close()
    log_action(request.user['id'],'Medewerker toegevoegd',name)
    return jsonify({'id': uid}), 201

@app.route('/api/staff/<int:uid>/children', methods=['GET'])
@require_auth
def staff_children(uid):
    conn = get_db()
    children = conn.execute('''
        SELECT c.* FROM children c
        WHERE c.assigned_leidster_id=? AND c.active=1
        ORDER BY c.name
    ''', (uid,)).fetchall()
    result = []
    for ch in children:
        d = row_to_dict(ch)
        d['obs_status'], d['last_obs'], d['next_obs_due'] = calc_obs_status(d['id'], conn)
        result.append(d)
    conn.close()
    return jsonify(result)

# ══════════════════════════════════════════
# SHIFTS / ROOSTER
# ══════════════════════════════════════════

@app.route('/api/shifts', methods=['GET'])
@require_auth
def get_shifts():
    from_date = request.args.get('from')
    to_date = request.args.get('to')
    user_id = request.args.get('user_id')
    conn = get_db()
    query = '''
        SELECT s.*, u.name as user_name, u.color, u.initials
        FROM shifts s JOIN users u ON s.user_id=u.id
        WHERE 1=1
    '''
    params = []
    if from_date: query += ' AND s.shift_date>=?'; params.append(from_date)
    if to_date:   query += ' AND s.shift_date<=?'; params.append(to_date)
    if user_id:   query += ' AND s.user_id=?';     params.append(user_id)
    query += ' ORDER BY s.shift_date, u.name'
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return jsonify([row_to_dict(r) for r in rows])

@app.route('/api/shifts', methods=['POST'])
@require_auth
def add_shift():
    data = request.get_json()
    conn = get_db()
    cur = conn.execute('''
        INSERT INTO shifts (user_id,shift_date,shift_type,start_time,end_time,notes)
        VALUES (?,?,?,?,?,?)
    ''', (data['user_id'], data['shift_date'], data.get('shift_type','werk'),
          data.get('start_time'), data.get('end_time'), data.get('notes')))
    sid = cur.lastrowid
    conn.commit()
    conn.close()
    return jsonify({'id': sid}), 201

@app.route('/api/shifts/auto-schedule', methods=['POST'])
@require_admin
def auto_schedule():
    """Auto-generate shifts based on availability and BKR requirements"""
    data = request.get_json()
    week_start = data.get('week_start', date.today().strftime('%Y-%m-%d'))
    start = datetime.strptime(week_start, '%Y-%m-%d').date()
    
    conn = get_db()
    avail = conn.execute('SELECT * FROM availability ORDER BY user_id, day_of_week').fetchall()
    
    created = 0
    for day_off in range(5):
        shift_date = (start + timedelta(days=day_off)).isoformat()
        day_avail = [a for a in avail if a['day_of_week'] == day_off]
        
        for av in day_avail:
            existing = conn.execute(
                'SELECT id FROM shifts WHERE user_id=? AND shift_date=?',
                (av['user_id'], shift_date)
            ).fetchone()
            if not existing:
                start_t = '07:30' if av['session'] == 'ochtend' else '12:00'
                end_t = '13:00' if av['session'] == 'ochtend' else '18:30'
                conn.execute('''
                    INSERT INTO shifts (user_id,shift_date,shift_type,start_time,end_time,notes)
                    VALUES (?,?,?,?,?,?)
                ''', (av['user_id'], shift_date, 'werk', start_t, end_t, 'Auto-gepland'))
                created += 1
    
    conn.commit()
    conn.close()
    log_action(request.user['id'],'Rooster auto-gegenereerd',f'Week {week_start}: {created} diensten aangemaakt')
    return jsonify({'created': created, 'message': f'{created} diensten automatisch ingepland'})

# ══════════════════════════════════════════
# LEAVE REQUESTS
# ══════════════════════════════════════════

@app.route('/api/leave', methods=['GET'])
@require_auth
def get_leave():
    conn = get_db()
    rows = conn.execute('''
        SELECT lr.*, u.name as user_name, u.initials, u.color
        FROM leave_requests lr JOIN users u ON lr.user_id=u.id
        ORDER BY lr.created_at DESC
    ''').fetchall()
    conn.close()
    return jsonify([row_to_dict(r) for r in rows])

@app.route('/api/leave', methods=['POST'])
@require_auth
def add_leave():
    data = request.get_json()
    from_dt = datetime.strptime(data['from_date'], '%Y-%m-%d')
    to_dt   = datetime.strptime(data['to_date'],   '%Y-%m-%d')
    days = max(1, (to_dt - from_dt).days + 1)
    conn = get_db()
    cur = conn.execute('''
        INSERT INTO leave_requests (user_id,leave_type,from_date,to_date,days,notes)
        VALUES (?,?,?,?,?,?)
    ''', (request.user['id'], data.get('leave_type','vakantie'),
          data['from_date'], data['to_date'], days, data.get('notes','')))
    lid = cur.lastrowid
    conn.commit()
    conn.close()
    log_action(request.user['id'],'Verlofaanvraag ingediend',
               f'{data["from_date"]} t/m {data["to_date"]} ({days} dag{"en" if days>1 else ""})')
    return jsonify({'id': lid}), 201

@app.route('/api/leave/<int:lid>/review', methods=['PATCH'])
@require_admin
def review_leave(lid):
    data = request.get_json()
    action = data.get('action')
    if action not in ('approve','deny'): return jsonify({'error':'Invalid action'}),400
    status = 'approved' if action == 'approve' else 'denied'
    conn = get_db()
    lr = conn.execute('SELECT * FROM leave_requests WHERE id=?',(lid,)).fetchone()
    conn.execute('''
        UPDATE leave_requests SET status=?,reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP
        WHERE id=?
    ''', (status, request.user['id'], lid))
    if action == 'approve' and lr:
        conn.execute(
            'UPDATE users SET vacation_hours_used=vacation_hours_used+? WHERE id=?',
            (lr['days']*8, lr['user_id'])
        )
    conn.commit()
    conn.close()
    return jsonify({'status': status})

# ══════════════════════════════════════════
# AVAILABILITY
# ══════════════════════════════════════════

@app.route('/api/availability', methods=['GET'])
@require_auth
def get_availability():
    user_id = request.args.get('user_id', request.user['id'])
    conn = get_db()
    rows = conn.execute(
        'SELECT * FROM availability WHERE user_id=? ORDER BY day_of_week',
        (user_id,)
    ).fetchall()
    conn.close()
    return jsonify([row_to_dict(r) for r in rows])

@app.route('/api/availability', methods=['PUT'])
@require_auth
def set_availability():
    data = request.get_json()
    user_id = request.user['id']
    entries = data.get('availability', [])
    conn = get_db()
    conn.execute('DELETE FROM availability WHERE user_id=?', (user_id,))
    for e in entries:
        conn.execute(
            'INSERT INTO availability (user_id,day_of_week,session) VALUES (?,?,?)',
            (user_id, e['day_of_week'], e['session'])
        )
    conn.commit()
    conn.close()
    log_action(user_id,'Beschikbaarheid bijgewerkt','')
    return jsonify({'message': 'Beschikbaarheid opgeslagen'})

# ══════════════════════════════════════════
# BKR CALCULATOR
# ══════════════════════════════════════════

@app.route('/api/bkr/calculate', methods=['POST'])
@require_auth
def bkr_calculate():
    data = request.get_json()
    counts = {
        '0-1': data.get('age_0_1', 0),
        '1-2': data.get('age_1_2', 0),
        '2-3': data.get('age_2_3', 0),
        '3-4': data.get('age_3_4', 0),
        'bso': data.get('age_4_12', 0),
    }
    ratios = {'0-1':3,'1-2':5,'2-3':6,'3-4':8,'bso':10}
    breakdown = {}
    total_required = 0
    for age, count in counts.items():
        if count > 0:
            req = -(-count // ratios[age])  # ceiling division
            breakdown[age] = {'children': count, 'ratio': ratios[age], 'required': req}
            total_required += req
    
    present = data.get('present', 0)
    half = -(-total_required // 2)
    if present >= total_required: status = 'ok'
    elif present >= half:          status = 'three_hour_rule'
    else:                          status = 'violation'
    
    return jsonify({
        'required': total_required,
        'present': present,
        'status': status,
        'breakdown': breakdown,
        'warnings': [] if status == 'ok' else [
            '3-uursregeling van toepassing' if status == 'three_hour_rule'
            else 'BKR overschreden! Direct actie vereist.'
        ]
    })

# ══════════════════════════════════════════
# STATS / REPORTS
# ══════════════════════════════════════════

@app.route('/api/stats/hours', methods=['GET'])
@require_auth
def hours_stats():
    conn = get_db()
    staff = conn.execute('SELECT * FROM users WHERE active=1 ORDER BY name').fetchall()
    result = []
    for s in staff:
        d = row_to_dict(s)
        d.pop('password_hash', None)
        expected = round(s['contract_hours'] * 4.3)
        saldo = s['worked_hours_month'] - expected
        vac_left = s['vacation_hours_total'] - s['vacation_hours_used']
        d['expected_hours'] = expected
        d['saldo'] = saldo
        d['vacation_left'] = vac_left
        result.append(d)
    conn.close()
    return jsonify(result)

init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
