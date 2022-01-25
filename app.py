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
import base64
import datetime
import hashlib
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

def get_token_from_header(h):
    auth_header = h.get('Authorization')
    if not auth_header:
        return None
    auth_header = auth_header.split(' ')
    if len(auth_header) != 2:
        return None
    if auth_header[0] != 'Bearer':
        return None
    return auth_header[1]

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
    
    session_id = fdata['session_id'] # セッションID
    miauth_session_id = str(uuid.uuid4()) # MiAuthのセッションID (session_idと混同しない)

    instance_domain = fdata['domain']
    if re.findall(r'(&|=|\/)', instance_domain):
        return make_response('Malformed domain name detected', 400)
    # セッションがあるか確認
    with db.cursor(dictionary=True) as cur:
        cur.execute('SELECT * FROM oauth_pending WHERE session_id = %s', (fdata['session_id'],))
        sesinfo = cur.fetchone()
        if not sesinfo:
            return make_response('No such session id', 400)
        cur.execute('UPDATE oauth_pending SET instance_domain = %s, miauth_session_id = %s WHERE session_id = %s', (instance_domain, miauth_session_id, fdata['session_id']))
        cur.execute('commit')
    
    # MiAuth対応確認
    try:
        r = requests.post(f'https://{instance_domain}/api/meta', json={'detail': True})
        meta = r.json()
    except:
        return make_response('インスタンスの情報取得に失敗しました。', 500)
    
    # MiAuth非対応の場合、レガシーモードで認証するように
    if not meta['features'].get('miauth'):
        with db.cursor(dictionary=True) as cur:
            cur.execute('UPDATE oauth_pending SET legacy_mode = %s WHERE session_id = %s', (True, fdata['session_id']))
            cur.execute('commit')
        
        # アプリケーション作成
        r = requests.post(f'https://{instance_domain}/api/app/create', json={
            'name': sesinfo['client_name'],
            'description': 'Created via MaMi Integration (Legacy Mode)',
            'permission': [
                'read:account',
                'read:drive',
                'write:drive',
                'write:notes'
            ],
            'callbackUrl': f'https://{request.host}/misskey/legacy_callback'
        })

        if r.status_code != 200:
            return make_response('インスタンスにアプリケーションを作成できませんでした。', 500)

        app_info = r.json()

        # セッション作成
        r = requests.post(f'https://{instance_domain}/api/auth/session/generate', json={
            'appSecret': app_info['secret']
        })

        if r.status_code != 200:
            return make_response('認証セッションを作成できませんでした。', 500)

        session_info = r.json()
        token = session_info['token']

        with db.cursor(dictionary=True) as cur:
            cur.execute('UPDATE oauth_pending SET legacy_token = %s, legacy_secret = %s WHERE session_id = %s', (token, app_info['secret'], fdata['session_id']))
            cur.execute('commit')
        
        res = make_response('', 302)
        res.headers['Location'] = session_info['url']
        return res


    res = make_response('', 302)
    res.headers['Location'] = f'https://{instance_domain}/miauth/{miauth_session_id}?' + build_query(
        name=sesinfo['client_name']+' (via MaMi Integration)',
        callback=f'https://{request.host}/oauth/integration_callback/{instance_domain}',
        permission='read:account,write:notes,write:drive,read:drive,write:notifications'
    )
    return res

# MiAuth非対応インスタンス用コールバック
@app.route('/misskey/legacy_callback')
def misskey_legacy_callback():

    if not request.args.get('token'):
        return make_response('アクセストークンがありません。', 400)

    token = request.args.get('token')

    with db.cursor(dictionary=True) as cur:
        cur.execute('SELECT * FROM oauth_pending WHERE legacy_token = %s', (token,))
        sesinfo = cur.fetchone()
        if not sesinfo:
            return make_response('No such session', 400)
    
    # ユーザーキー取得
    r = requests.post(f'https://{sesinfo["instance_domain"]}/api/auth/session/userkey', json={
        'token': token,
        'appSecret': sesinfo['legacy_secret']
    })

    if r.status_code != 200:
        return make_response('アクセストークンが無効です。', 400)
    
    keyinfo = r.json()
    user_key = keyinfo['accessToken']

    # アクセストークン生成(ユーザーキー+シークレットキー結合の上SHA256に変換)
    access_token = hashlib.sha256((user_key+sesinfo['legacy_secret']).encode()).hexdigest()

    auth_code = str(uuid.uuid4())
    
    with db.cursor() as cur:
        cur.execute('UPDATE oauth_pending SET misskey_token = %s, authcode = %s WHERE legacy_token = %s', (access_token, auth_code, token))
        cur.execute('commit')

    res = make_response('', 302)
    res.headers['Location'] = sesinfo['redirect_uri'] + '?code=' + auth_code
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
        cur.execute('SELECT * FROM oauth_pending WHERE miauth_session_id = %s', (args['session'],))
        sesinfo = cur.fetchone()
        if not sesinfo:
            return make_response('No such session id', 400)
        cur.execute('UPDATE oauth_pending SET authcode = %s WHERE miauth_session_id = %s', (auth_code, args['session']))
        cur.execute('commit')
    # インスタンスにセッション照会
    oauth_req = requests.post(f'https://{domain}/api/miauth/{args["session"]}/check')
    if oauth_req.status_code != 200:
        return make_response('セッションが正当なものであることを確認できませんでした。(MIAUTH_FAILED_'+str(oauth_req.status_code)+')', 500)
    data = oauth_req.json()
    if not data['ok']:
        return make_response('セッションが無効です。(MIAUTH_INVALID_SESSION)', 403)
    
    with db.cursor() as cur:
        cur.execute('UPDATE oauth_pending SET misskey_token = %s WHERE miauth_session_id = %s', (data['token'], args['session']))
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
        return make_response('This grant type is not supported', 400)
    
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
        cur.execute('INSERT INTO oauth(misskey_token, mstdn_token, instance_domain, legacy_mode, app_name) VALUES (%s, %s, %s, %s, %s)'
            , (sesinfo['misskey_token'], access_token, sesinfo['instance_domain'], sesinfo['legacy_mode'], sesinfo['client_name']))
        cur.execute('commit')

        # 仮セッションはちゃんと削除しよう（戒め）
        cur.execute('DELETE FROM oauth_pending WHERE session_id = %s', (session_id,))
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

    access_token = get_token_from_header(request.headers) # Mastodon側のトークン
    if not access_token:
        return make_response('Invalid authorization header', 401)
    
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
        'url': profile.get('url'),
        'locked': profile['isLocked'],
        'bot': profile['isBot'],
        'followers_count': profile['followersCount'],
        'following_count': profile['followingCount'],
        'statuses_count': profile['notesCount'],
        'fields': profile['fields']
    }

    # ユーザーにログイン成功通知を送る
    now = datetime.datetime.utcnow() + datetime.timedelta(hours=9)
    app_name = oauth_info['app_name']
    r = requests.post(f'https://{oauth_info["instance_domain"]}/api/notifications/create', json={
        'i': oauth_info['misskey_token'],
        'header': 'MaMi Integration',
        'body': f'MaMiの連携が行われました。\nアプリケーション名: {app_name}\n日時: {now.strftime("%Y/%m/%d %H:%M:%S")}'
    })

    res = make_response(json.dumps(profile_mastodon), 200)
    res.headers['Content-Type'] = 'application/json'
    return res

@app.route('/api/v1/media', methods=['POST'])
def api_v1_media():
    db.ping(reconnect=True)
    access_token = get_token_from_header(request.headers) # Mastodon側のトークン
    if not access_token:
        return make_response('Invalid authorization header', 401)
    
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
    
    access_token = get_token_from_header(request.headers) # Mastodon側のトークン
    if not access_token:
        return make_response('Invalid authorization header', 401)

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

@app.route('/api/v1/accounts/<str:account_id>/statuses', methods=['GET'])
def api_v1_account_statuses(account_id):
    db.ping(reconnect=True)
    access_token = get_token_from_header(request.headers)

    query = request.args

    if not access_token:
        return make_response('{"error": "The access token is invalid"}', 401)
    
    with db.cursor(dictionary=True) as cur:
        cur.execute('SELECT * FROM oauth WHERE mstdn_token = %s', (access_token,))
        oauth_info = cur.fetchone()
        if not oauth_info:
            return make_response('{"error": "The access token is invalid"}', 401)
    
    m = Misskey(address=oauth_info['instance_domain'] ,i=oauth_info['misskey_token'])

    try:
        notes = m.users_notes(account_id, limit=query.get('limit') or 100)
        toots = []
        for note in notes:
            toots.append({
                'id': note['id'],
                'created_at': note['createdAt'],
                'in_reply_to_id': None,
                'in_reply_to_account_id': None,
                'sensitive': False,
                'visibliity': note['visibility'],
                'replies_count': note['repliesCount'],
                'reblogs_count': note['renoteCount'],
                'favourites_count': 0,
                'favourited': False,
                'reblogged': False,
                'muted': False,
                'pinned': False,
                'content': note['text'],
                'reblog': None,
                'application': None
            })
        
        r = make_response(json.dumps(toots), 200)
        r.headers['Content-Type'] = 'application/json'
        return r
        
    except:
        return make_response('Misskey API error', 500)

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
            },
            'media_attachments': {
                'supported_mime_types': [
                    'image/jpeg',
                    'image/png',
                    'image/gif',
                    'image/webp',
                    'image/heif',
                    'image/heic',
                    'video/webm',
                    'video/mp4',
                    'video/quicktime',
                    'video/ogg',
                    'audio/wave',
                    'audio/wav',
                    'audio/x-wav',
                    'audio/x-pn-wave',
                    'audio/ogg',
                    'audio/mpeg',
                    'audio/mp3',
                    'audio/webm',
                    'audio/flac',
                    'audio/aac',
                    'audio/m4a',
                    'audio/x-m4a',
                    'audio/mp4',
                    'audio/3gpp',
                    'video/x-ms-asf'
                ],
                'image_size_limit': 10485760,
                'image_matrix_limit': 16777216,
                'video_size_limit': 41943040,
                'video_frame_rate_limit': 60,
                'video_matrix_limit': 2304000,
            },
            'polls': {
                'max_options': 4,
                'max_characters_per_option': 50,
                'min_expiration': 300,
                'max_expiration': 2629746
            },
            'emoji_reactions': {
                'max_reactions': 20
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
        'contact_account': {
            'id': '1',
            'username': 'emulatedadmin',
            'acct': 'emulatedadmin',
            'display_name': 'emulatedadmin',
            'locked': False,
            'bot': False,
            'discoverable': True,
            'group': False,
            'created_at': '2019-01-01T00:00:00+00:00',
            'followers_count': 1,
            'following_count': 1,
            'statuses_count': 1,
            'note': '',
            'url': 'https://' + request.host,
            'avatar': 'https://' + request.host + '/avatar/original',
            'avatar_static': 'https://' + request.host + '/avatar/original',
            'header': 'https://' + request.host + '/header/original',
            'header_static': 'https://' + request.host + '/header/original',
            'subscribing_count': 0,
            'last_status_at': '2021-11-01',
            'emojis': [],
            'fields': []
        }
    }
    res = make_response(json.dumps(data), 200)
    res.headers['Content-Type'] = 'application/json'
    res.headers['Access-Control-Allow-Origin'] = '*'
    return res

@app.route('/share', methods=['GET'])
def api_share():
    instance_domain = 'misskey.io'
    if request.cookies.get('instance_domain'):
        instance_domain = request.cookies.get('instance_domain')
    res = make_response(render_template('share.html', instance_domain=instance_domain, data=base64.b64encode(request.args['text'].encode()).decode()), 200)
    return res

@app.route('/share/do', methods=['POST'])
def api_share_do():
    if (not request.form.get('domain')) or (not request.form.get('text')):
        return make_response('Invalid parameters', 400)
    if re.findall(r'(&|=|\/)', request.form.get('domain')):
        return make_response('Malformed domain name detected', 400)
    try:
        text = base64.b64decode(request.form.get('text')).decode()
    except:
        return make_response('Text decode failed', 500)
    res = make_response('', 302)
    res.set_cookie('instance_domain', request.form['domain'], datetime.timedelta(days=365))
    res.headers['Location'] = 'https://' + request.form['domain'] + '/share?text=' + urllib.parse.quote(text)
    return res

if config_env.DEBUG:
    app.run(host='0.0.0.0', port=2222, debug=True, threaded=True)
else:
    app.run(host='0.0.0.0', port=config_env.PORT, debug=False, threaded=True)