from flask import Flask, request, jsonify
import asyncio, json, binascii, requests, aiohttp, urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad as pad_
from google.protobuf.json_format import MessageToJson
from google.protobuf.message import DecodeError
import like_pb2, like_count_pb2, uid_generator_pb2
from config import URLS_INFO ,URLS_LIKE,FILES
import httpx
from google.protobuf import json_format, message
from google.protobuf.message import Message
import base64
from flask_cors import CORS
from cachetools import TTLCache
from collections import defaultdict
import FreeFire_pb2
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)

MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB50"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"

TOKEN_REFRESH_TIME = 0
TOKEN_CREATED_TIME = 0


def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)


def load_tokens(server):
    files = FILES
    return json.load(open(f"tokens/{files.get(server,'token.json')}"))

def get_headers(token):
    return {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB50",
        }

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))


def encrypt_message(data):
    cipher = AES.new(b'Yg&tc%DEuh6%Zc^8', AES.MODE_CBC, b'6oyZDr22E3ychjM%')
    return binascii.hexlify(cipher.encrypt(pad_(data, AES.block_size))).decode()

def create_like(uid, region):
    m = like_pb2.like(); m.uid, m.region = int(uid), region
    print(m)
    return m.SerializeToString()

def create_uid(uid):
    m = uid_generator_pb2.uid_generator(); m.saturn_, m.garena = int(uid), 1
    print(m)
    return m.SerializeToString()

async def send(token, url, data):
    headers =get_headers(token)
    async with aiohttp.ClientSession() as s:
        async with s.post(url, data=bytes.fromhex(data), headers=headers) as r: return await r.text() if r.status==200 else None

async def multi(uid, server, url):
    enc = encrypt_message(create_like(uid, server))
    tokens = load_tokens(server)
    return await asyncio.gather(*[send(tokens[i%len(tokens)]['token'], url, enc) for i in range(105)])

def get_info(enc, server, token):
    urls =URLS_INFO
    r = requests.post(urls.get(server,"https://clientbp.ggblueshark.com/GetPlayerPersonalShow"),
                      data=bytes.fromhex(enc), headers=get_headers(token), verify=False)
    try: p = like_count_pb2.Info(); p.ParseFromString(r.content); return p
    except DecodeError: return None

@app.route("/like")
def like():
    uid, server = request.args.get("uid"), request.args.get("server","").upper()
    if not uid or not server: return jsonify(error="UID and server required"),400
    tokens = load_tokens(server); enc = encrypt_message(create_uid(uid))
    before, tok = None, None
    for t in tokens[:10]:
        before = get_info(enc, server, t["token"])
        if before: tok = t["token"]; break
    if not before:
        return jsonify(error="Player not found"),500
    
    before_like = int(json.loads(MessageToJson(before)).get('AccountInfo',{}).get('Likes',0))
    urls =URLS_LIKE
    asyncio.run(multi(uid, server, urls.get(server,"https://clientbp.ggblueshark.com/LikeProfile")))
    after = json.loads(MessageToJson(get_info(enc, server, tok)))
    after_like = int(after.get('AccountInfo',{}).get('Likes',0))
    return jsonify({
        "credits":"nighthawks",
        "likes_added": after_like - before_like,
        "likes_before": before_like,
        "likes_after": after_like,
        "player": after.get('AccountInfo',{}).get('PlayerNickname',''),
        "uid": after.get('AccountInfo',{}).get('UID',0),
        "status": 1 if after_like-before_like else 2,
    })


        
async def initialize_tokens():
    try:
        tasks = [GenerateJWT()]
        await asyncio.gather(*tasks, return_exceptions=True)
    except DecodeError:
        pass


async def refresh_tokens_periodically():
    while True:
        # refresh tokens after 7 hours !
        await asyncio.sleep(25200)
        await initialize_tokens()


def get_accounts():
    accounts = []
    with open("accounts.json", 'r') as account_:
        data = json.load(account_)

    for ii in data:
        account = f"uid={ii['uid']}&password={ii['password']}"
        accounts.append(account)
        
    return accounts


async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded"}
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")



async def GenerateJWT():
    total_jwt = []
    accounts = get_accounts()

    async with httpx.AsyncClient() as client:  
        async def fetch_token(account):
            token_val, open_id = await get_access_token(account)
            body = json.dumps({
                "open_id": open_id,
                "open_id_type": "4",
                "login_token": token_val,
                "orign_platform_type": "4"
            })

            
            proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
            payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
            url = "https://loginbp.ggblueshark.com/MajorLogin"
            headers = {
                'User-Agent': USERAGENT,
                'Connection': "Keep-Alive",
                'Accept-Encoding': "gzip",
                'Content-Type': "application/octet-stream",
                'Expect': "100-continue",
                'X-Unity-Version': "2018.4.11f1",
                'X-GA': "v1 1",
                'ReleaseVersion': RELEASEVERSION
            }
            resp = await client.post(url, data=payload, headers=headers)

            # If response is not valid protobuf, log for debug
            try:
                msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))

                cached_tokens


                return f"Bearer {msg.get('token','0')}"
            except Exception as e:
                print(f"Failed for account {account}: {resp.text[:200]}")
                return None

        tokens = await asyncio.gather(*(fetch_token(acc) for acc in accounts))

        data = [{"token": t.replace("Bearer ", "")} for t in tokens if t]  # list of dicts

        # write tokens in the file 
        tokens_file = os.path.join(os.path.dirname(__file__), "tokens", "token.json")

        with open(tokens_file, "w") as token_file:
            json.dump(data, token_file, indent=2)



@app.route("/refresh-tokens")
def refresh_token():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({'status': "all tokens refreshed..."}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


async def startup():
    await initialize_tokens()
    asyncio.create_task(refresh_tokens_periodically())


if __name__ == "__main__":
    asyncio.run(startup())
    app.run(host='0.0.0.0', port=8000, debug=True)





