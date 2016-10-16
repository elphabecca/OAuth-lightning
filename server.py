from flask import Flask, render_template, redirect, url_for, session
from flask_oauth import OAuth
import os

app = Flask(__name__)

# one of the Redirect URIs from Google APIs console
REDIRECT_URI = "/oauth2callback"
SECRET_KEY = "raindropsonroses"

app.secret_key = SECRET_KEY

oauth = OAuth()
google = oauth.remote_app('google',
                          base_url='https://www.google.com/accounts/',
                          authorize_url='https://accounts.google.com/o/oauth2/auth',
                          request_token_url=None,
                          request_token_params={'scope': 'https://www.googleapis.com/auth/userinfo.email',
                                                'response_type': 'code'},
                          access_token_url='https://accounts.google.com/o/oauth2/token',
                          access_token_method='POST',
                          access_token_params={'grant_type': 'authorization_code'},
                          consumer_key=os.environ["GOOGLE_CLIENT_ID"],
                          consumer_secret=os.environ["GOOGLE_CLIENT_SECRET"])

@app.route('/')
def button():
    """Google OAuth Code and give me a button."""

    return render_template("button.html")


@app.route('/OAuth')
def google_crap():
    """Ummmm googleOauth???"""
 
    access_token = session.get('access_token')
    if access_token is None:
        return redirect(url_for('login'))

    access_token = access_token[0]
    from urllib2 import Request, urlopen, URLError
 
    headers = {'Authorization': 'OAuth '+access_token}
    req = Request('https://www.googleapis.com/oauth2/v1/userinfo',
                  None, headers)

    try:
        res = urlopen(req)
    except URLError, e:
        if e.code == 401:
            # Unauthorized - bad token
            session.pop('access_token', None)
            return redirect(url_for('login'))
        return res.read()

@app.route('/login')
def login():
    callback=url_for('authorized', _external=True)
    return google.authorize(callback=callback)


@app.route(REDIRECT_URI)
@google.authorized_handler
def authorized(resp):
    access_token = resp['access_token']
    session['access_token'] = access_token, ''
    return redirect(url_for('yay'))

@app.route("/success")
def yay():
  return render_template("success.html")


@google.tokengetter
def get_access_token():
    return session.get('access_token')


if __name__ == "__main__":
    app.run(debug=True)