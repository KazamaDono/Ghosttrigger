from flask import Flask, request, session, redirect, url_for, render_template_string, make_response
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Simple in-memory user store (only one user for demo)
USERS = {'admin': 'admin'}

# ---------- Templates (inline for simplicity) ----------
LOGIN_PAGE = '''
<!DOCTYPE html>
<html>
<head><title>Vulnerable Login</title></head>
<body>
<h2>Login</h2>
<form method="POST" action="/login">
    <input type="text" name="username" placeholder="Username" required><br>
    <input type="password" name="password" placeholder="Password" required><br>
    <input type="submit" value="Login">
</form>

<!-- This commented-out Guest button is the vulnerability! -->
<!-- <input type="button" name="btnGuest" value="Guest" onclick="__doPostBack('btnGuest','')"> -->

<script>
function __doPostBack(target, arg) {
    // Simulate ASP.NET __doPostBack behavior
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = '/postback';
    var targetField = document.createElement('input');
    targetField.type = 'hidden';
    targetField.name = '__EVENTTARGET';
    targetField.value = target;
    var argField = document.createElement('input');
    argField.type = 'hidden';
    argField.name = '__EVENTARGUMENT';
    argField.value = arg;
    form.appendChild(targetField);
    form.appendChild(argField);
    document.body.appendChild(form);
    form.submit();
}
</script>
</body>
</html>
'''

DASHBOARD = '''
<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body>
<h2>Welcome, {{ username }}!</h2>
<p>You are logged in.</p>
<a href="/logout">Logout</a>
</body>
</html>
'''

# ---------- Routes ----------
@app.route('/')
def index():
    if 'username' in session:
        return render_template_string(DASHBOARD, username=session['username'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in USERS and USERS[username] == password:
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return "Invalid credentials", 401
    return render_template_string(LOGIN_PAGE)

@app.route('/postback', methods=['POST'])
def postback():
    # Simulate ASP.NET postback handling
    event_target = request.form.get('__EVENTTARGET')
    if event_target == 'btnGuest':
        # Grant guest access
        session['username'] = 'guest'
        return redirect(url_for('index'))
    else:
        return "Invalid postback", 400

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
