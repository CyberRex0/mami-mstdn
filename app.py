from flask import Flask, request
from flask.helpers import make_response
from flask.templating import render_template
import urllib.parse
import json
import mysql.connector as msql
from requests.sessions import session
import config_env
import uuid
import requests
import re
import time, random
from misskey import Misskey

app = Flask(__name__, static_url_path='/')
db = msql.connect(
    host=config_env.DB_HOST,
    port=3306,
    username=config_env.DB_USER,
    password=config_env.DB_PASS,
    database=config_env.DB_NAME
)
db.ping(reconnect=True)

drive_mediaid_table = {}

def build_query(**kwargs):
    prms = set()
    for k in kwargs.keys():
        prms.add(f'{k}={urllib.parse.quote(kwargs[k])}')
    return '&'.join(prms)


@app.route('/')
def root():
    return '<h1>MaMi</h1>API Converting System between Mastodon and Misskey'

@app.route('/api/v1/apps', methods=['POST'])
def api_v1_apps():
    db.ping(reconnect=True)
    print(request.form)
    uid = str(uuid.uuid4())
    with db.cursor() as cur:
        cur.execute('INSERT INTO oauth_pending(session_id, client_name, scope, redirect_uri, instance_domain) VALUES(%s, %s, %s, %s, %s)',
        (uid, request.form['client_name'], request.form['scopes'], request.form['redirect_uris'], None))
        cur.execute('commit')
    return json.dumps({
        'id': 'fakeoauthid001',
        'client_name': request.form['client_name'],
        'redirect_uri': request.form['redirect_uris'],
        'client_id': uid,
        'client_secret': 'fake123'
    })

@app.route('/oauth/authorize')
def select_instance():
    db.ping(reconnect=True)
    client_id = request.args['client_id']
    scope = request.args['scope']
    redirect_uri = request.args['redirect_uri']
    return render_template('select_instance.html', session_id=client_id)

@app.route('/oauth/integration_do', methods=['POST'])
def oauth_do_integration():
    db.ping(reconnect=True)
    fdata = request.form
    if (not fdata.get('session_id')) or (not fdata.get('domain')):
        return make_response('BAD REQUEST', 400)
    session_id = fdata['session_id']
    instance_domain = fdata['domain']
    if re.findall(r'(&|=|\/)', instance_domain):
        return make_response('Malformed domain name detected', 400)
    # セッションがあるか確認
    with db.cursor(dictionary=True) as cur:
        cur.execute('SELECT * FROM oauth_pending WHERE session_id = %s', (fdata['session_id'],))
        sesinfo = cur.fetchone()
        if not sesinfo:
            return make_response('No such session id', 400)
        cur.execute('UPDATE oauth_pending SET instance_domain = %s WHERE session_id = %s', (instance_domain, fdata['session_id']))
        cur.execute('commit')
    
    res = make_response('', 302)
    res.headers['Location'] = f'https://{instance_domain}/miauth/{session_id}?' + build_query(
        name=sesinfo['client_name']+' (via MaMi Integration)',
        callback=f'https://{request.host}/oauth/integration_callback/{instance_domain}',
        permission='read:account,write:notes,write:drive,read:drive'
    )
    return res

@app.route('/oauth/integration_callback/<string:domain>')
def oauth_integration_callback(domain):
    db.ping(reconnect=True)
    args = request.args
    if not args.get('session'):
        return make_response('No session id', 400)
    auth_code = str(uuid.uuid4())
    # セッションがあるか確認
    with db.cursor(dictionary=True) as cur:
        cur.execute('SELECT * FROM oauth_pending WHERE session_id = %s', (args['session'],))
        sesinfo = cur.fetchone()
        if not sesinfo:
            return make_response('No such session id', 400)
        cur.execute('UPDATE oauth_pending SET authcode = %s WHERE session_id = %s', (auth_code, args['session']))
        cur.execute('commit')
    # インスタンスにセッション照会
    oauth_req = requests.post(f'https://{domain}/api/miauth/{args["session"]}/check')
    if oauth_req.status_code != 200:
        return make_response('セッションが正当なものであることを確認できませんでした。(MIAUTH_FAILED_'+str(oauth_req.status_code)+')', 500)
    data = oauth_req.json()
    if not data['ok']:
        return make_response('セッションが無効です。(MIAUTH_INVALID_SESSION)', 403)
    
    with db.cursor() as cur:
        cur.execute('UPDATE oauth_pending SET misskey_token = %s WHERE session_id = %s', (data['token'], args['session']))
        cur.execute('commit')

    res = make_response('', 302)
    res.headers['Location'] = sesinfo['redirect_uri'] + '?code=' + auth_code
    return res
    
@app.route('/oauth/token', methods=['POST'])
def oauth_token():
    db.ping(reconnect=True)
    data = request.form
    print(data)
    if (not data.get('client_id')) or (not data.get('code')) or (not data.get('grant_type')):
        return make_response('Bad Request', 400)
    if data['grant_type'] != 'authorization_code':
        return make_response('This grnat type is not supported', 400)
    # セッションがあるか確認
    session_id = data['client_id']
    with db.cursor(dictionary=True) as cur:
        cur.execute('SELECT * FROM oauth_pending WHERE session_id = %s', (session_id,))
        sesinfo = cur.fetchone()
        if not sesinfo:
            return make_response('No such session id', 400)
        if sesinfo['authcode'] != data['code']:
            return make_response('Invalid code', 400)
    # ベアラートークン登録
    access_token = str(uuid.uuid4())
    with db.cursor() as cur:
        cur.execute('INSERT INTO oauth(misskey_token, mstdn_token, instance_domain) VALUES (%s, %s, %s)'
            , (sesinfo['misskey_token'], access_token, sesinfo['instance_domain']))
        cur.execute('commit')
    return json.dumps({
        'access_token': access_token,
        'token_type': 'bearer',
        'scope': 'read write',
        'created_at': int(time.time())
    })

@app.route('/api/v1/accounts/verify_credentials')
def api_verify_credentials():
    db.ping(reconnect=True)
    headers = request.headers
    auth_header = headers.get('Authorization')
    if not auth_header:
        return make_response('No authorization header', 401)
    auth_header = auth_header.split(' ')
    if len(auth_header) != 2:
        return make_response('Invalid authorization header', 401)
    if auth_header[0] != 'Bearer':
        return make_response('Invalid authorization header', 401)
    access_token = auth_header[1] # Mastodon側のトークン
    with db.cursor(dictionary=True) as cur:
        cur.execute('SELECT * FROM oauth WHERE mstdn_token = %s', (access_token,))
        oauth_info = cur.fetchone()
        if not oauth_info:
            return make_response('Invalid access token', 401)
    # Misskeyインスタンスに問い合わせ
    m = Misskey(address=oauth_info['instance_domain'] ,i=oauth_info['misskey_token'])
    try:
        profile = m.i()
    except:
        return make_response('Misskey API error', 500)
    # プロフィールデータ再構成
    profile_mastodon = {
        'id': profile['id'],
        'username': profile['username'],
        'acct': profile['username'],
        'display_name': profile['name'],
        'avatar': profile['avatarUrl'],
        'avatar_static': profile['avatarUrl'],
        'header': profile['bannerUrl'],
        'header_static': profile['bannerUrl'],
        'note': profile['description'],
        'url': profile['url'],
        'locked': profile['isLocked'],
        'bot': profile['isBot'],
        'followers_count': profile['followersCount'],
        'following_count': profile['followingCount'],
        'statuses_count': profile['notesCount'],
        'fields': profile['fields']
    }

    res = make_response(json.dumps(profile_mastodon), 200)
    res.headers['Content-Type'] = 'application/json'
    return res

@app.route('/api/v1/media', methods=['POST'])
def api_v1_media():
    db.ping(reconnect=True)
    headers = request.headers
    auth_header = headers.get('Authorization')
    if not auth_header:
        return make_response('No authorization header', 401)
    auth_header = auth_header.split(' ')
    if len(auth_header) != 2:
        return make_response('Invalid authorization header', 401)
    if auth_header[0] != 'Bearer':
        return make_response('Invalid authorization header', 401)
    access_token = auth_header[1] # Mastodon側のトークン
    with db.cursor(dictionary=True) as cur:
        cur.execute('SELECT * FROM oauth WHERE mstdn_token = %s', (access_token,))
        oauth_info = cur.fetchone()
        if not oauth_info:
            return make_response('Invalid access token', 401)
    # Misskeyのドライブにアップロード
    m = Misskey(address=oauth_info['instance_domain'] ,i=oauth_info['misskey_token'])
    try:
        drive_file = m.drive_files_create(request.files['file'].stream)
    except Exception as e:
        print(e)
        return make_response('Misskey API error', 500)
    
    # Mastodonは数字のメディアIDのみ受け付けるため、変換テーブルに登録して投稿用に備える
    fake_drive_id = f'{time.time():.0f}{random.randint(0,999999)}'
    drive_mediaid_table[fake_drive_id] = drive_file['id']


    res = make_response(json.dumps({
        'id': fake_drive_id,
        'type': 'image',
        'url': drive_file['url'],
        'preview_url': drive_file['thumbnailUrl'],
        'remote_url': None,
        'text_url': None,
        'meta': {},
        'description': None,
        'blurhash': 'UFBWY:8_0Jxv4mx]t8t64.%M-:IUWGWAt6M}'
    }))
    return res

@app.route('/api/v1/statuses', methods=['POST'])
def api_v1_statuses():
    db.ping(reconnect=True)
    print(request.form)
    data = request.form
    text = data.get('status')
    sensitive = data.get('sensitive')
    visibility = data.get('visibility')
    if visibility == 'private':
        visibility = 'followers'
    elif visibility == 'unlisted':
        visibility = 'home'
    media_ids = data.getlist('media_ids[]')
    if not text:
        return make_response('No text', 400)
    headers = request.headers
    auth_header = headers.get('Authorization')
    if not auth_header:
        return make_response('No authorization header', 401)
    auth_header = auth_header.split(' ')
    if len(auth_header) != 2:
        return make_response('Invalid authorization header', 401)
    if auth_header[0] != 'Bearer':
        return make_response('Invalid authorization header', 401)
    access_token = auth_header[1] # Mastodon側のトークン
    with db.cursor(dictionary=True) as cur:
        cur.execute('SELECT * FROM oauth WHERE mstdn_token = %s', (access_token,))
        oauth_info = cur.fetchone()
        if not oauth_info:
            return make_response('Invalid access token', 401)
    drive_ids = []
    for mid in media_ids:
        if mid in list(drive_mediaid_table.keys()):
            drive_ids.append(drive_mediaid_table[mid])
    # Misskeyにノート投稿
    m = Misskey(address=oauth_info['instance_domain'] ,i=oauth_info['misskey_token'])
    try:
        if drive_ids:
            note_d = m.notes_create(text, file_ids=drive_ids, visibility=visibility)
        else:
            note_d = m.notes_create(text, visibility=visibility)
    except Exception as e:
        print(e)
        return make_response('Misskey API error', 500)
    
    note = note_d['createdNote']

    toot_data = {
        'id': note['id'],
        'created_at': note['createdAt'],
        'in_reply_to_id': None,
        'in_reply_to_account_id': None,
        'sensitive': sensitive,
        'spoiler_text': None,
        'visibility': visibility,
        'language': None,
        'content': text,
        'reblog': None
    }
    return make_response(json.dumps(toot_data), 200)

@app.route('/api/v1/instance', methods=['GET'])
def api_v1_instances():
    data = {
        'uri': request.host,
        'title': 'MaMi Emulated Instance',
        'short_description': 'このインスタンスは実体を持っておらず、エミュレートされています。',
        'description': 'このインスタンスは実体を持っておらず、エミュレートされています。',
        'email': 'postmaster@' + request.host,
        'version': '3.4.1',
        'configurations': {
            'statuses': {
                'max_characters': 999999,
                'max_media_attachments': 10,
                'characters_reserved_per_url': 21,
                'min_expiration': 60,
                'max_expiration': 86400,
                'supported_expires_actions': ['mark', 'delete']
            }
        },
        'urls': {
            'streaming_api': 'wss://' + request.host,
        },
        'stats': {
            'user_count': 1,
            'status_count': 1,
            'domain_count': 1
        },
        'thumbnail': None,
        'languages': ['ja'],
        'registrations': False,
        'approval_required': False,
        'contact_account': None
    }
    res = make_response(json.dumps(data), 200)
    res.headers['Content-Type'] = 'application/json'
    return res

if config_env.DEBUG:
    app.run(host='0.0.0.0', port=2222, debug=True, threaded=True)
else:
    app.run(host='0.0.0.0', port=config_env.PORT, debug=False, threaded=True)