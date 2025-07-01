# Ton Proof Generator: github.com/yummy1gay/ton-connect

import asyncio, re, requests, json
from bs4 import BeautifulSoup
import hashlib
import time
import base64
import json
from urllib.parse import urlencode
from tonsdk.contract.wallet import Wallets, WalletVersionEnum
from tonsdk.utils import bytes_to_b64str
from nacl.signing import SigningKey

from typing import Optional, List

async def wallet(mnemonic: Optional[List[str]] = None):
    if mnemonic is None:
        mnemonic, pub_k, priv_k, wallet = Wallets.create(WalletVersionEnum.v4r2, workchain=0)
    else:
        mnemonic, pub_k, priv_k, wallet = Wallets.from_mnemonics(mnemonic, WalletVersionEnum.v4r2, workchain=0)
    
    state = wallet.create_state_init()
    init = state["state_init"]

    address = wallet.address.to_string(is_user_friendly=False)
    secret_key = priv_k[:32]
    mnemonics = " ".join(mnemonic)
    address_ton = wallet.address.to_string(True, True, False)
    public_key = pub_k.hex()
    private_key = priv_k.hex()
    state_init = bytes_to_b64str(init.to_boc(has_idx=False))

    return address, secret_key, mnemonics, address_ton, public_key, private_key, state_init

async def proof(manifest_url: str, payload: str, mnemonic: Optional[str] = None):
    if mnemonic is not None:
        phrase = mnemonic.split()
    else:
        phrase = None

    address, secret_key, mnemonics, address_ton, public_key, private_key, state_init = await wallet(phrase)
    try:
        timestamp = int(time.time())
        timestamp_bytes = timestamp.to_bytes(8, 'little')

        domain = manifest_url
        domain_bytes = domain.encode('utf-8')
        domain_len_bytes = len(domain_bytes).to_bytes(4, 'little')

        workchain, addr_hash = address.split(':')
        workchain_bytes = int(workchain).to_bytes(4, 'big')
        address_bytes = workchain_bytes + bytes.fromhex(addr_hash)

        msg_bytes = b''.join([
            b'ton-proof-item-v2/',
            address_bytes,
            domain_len_bytes,
            domain_bytes,
            timestamp_bytes,
            payload.encode('utf-8') if payload else b'',
        ])

        msg_hash = hashlib.sha256(msg_bytes).digest()

        buffer_bytes = b''.join([
            bytes.fromhex('ffff'),
            b'ton-connect',
            msg_hash
        ])

        key = SigningKey(secret_key)
        data = key.sign(hashlib.sha256(buffer_bytes).digest())
        signature = base64.b64encode(data.signature).decode('utf-8')
        
        proof = {"wallet": {"mnemonics": mnemonics,
                            "ton_address": address_ton},
                 "address": address,
                 "network": "-239",
                 "public_key": public_key,
                 "private_key": private_key,
                 "proof": {"name": "ton_proof",
                           "timestamp": timestamp,
                           "domain": {"lengthBytes": len(domain_bytes), "value": domain},
                 "signature": signature,
                 "payload": payload,
                 "state_init": state_init}}

        return json.dumps(proof, indent=4)
    
    except Exception as e:
        print(f"CreateTonProof: {e} | {str(e)}")
        return None

async def generate(mnemonic, payload):
    result = json.loads(await proof("fragment.com", payload, mnemonic))

    return {
        "method": "checkTonProofAuth",
        "account": json.dumps({
            "address": result["address"],
            "chain": result["network"],
            "walletStateInit": result["proof"]["state_init"],
            "publicKey": result["public_key"],
        }),
        "device": json.dumps({
            "platform": "iphone",
            "appName": "Tonkeeper",
            "appVersion": "4.12.3",
            "maxProtocolVersion": 2,
            "features": ["SendTransaction", {"name": "SendTransaction", "maxMessages": 4}]
        }),
        "proof": json.dumps({
            "timestamp": result["proof"]["timestamp"],
            "domain": result["proof"]["domain"],
            "signature": result["proof"]["signature"],
            "payload": result["proof"]["payload"]
        })
    }

def extract(html: str):
    soup = BeautifulSoup(html, "html.parser")
    script_tags = soup.find_all("script")

    api_url = version = ton_proof = None

    for tag in script_tags:
        content = tag.string or tag.text
        if "ajInit" in content:
            api_url_match = re.search(r'"apiUrl":"\\/api\?hash=(.*?)"', content)
            version_match = re.search(r'"version":(\d+)', content)
            if api_url_match: api_url = api_url_match.group(1)
            if version_match: version = int(version_match.group(1))
        if "Wallet.init" in content:
            ton_proof_match = re.search(r'"ton_proof":"(.*?)"', content)
            if ton_proof_match: ton_proof = ton_proof_match.group(1)
    return api_url, version, ton_proof

async def auth(phone: str, mnemonic: str):
    h = {"User-Agent": "Mozilla/5.0"}
    html = requests.get("https://fragment.com", headers=h)
    hash, version, ton_proof = extract(html.text)

    r = requests.post("https://oauth.telegram.org/auth/request", params={
        "bot_id": "5444323279", "origin": "https://fragment.com",
        "request_access": "write", "return_to": "https://fragment.com"
    }, data={"phone": phone}, headers=h)

    s, t = r.cookies.get("stel_ssid"), r.cookies.get("stel_tsession")
    print(f"Confirm login for {phone}...")
    token = None
    for _ in range(300):
        r = requests.post("https://oauth.telegram.org/auth/login", params={
            "bot_id": "5444323279", "origin": "https://fragment.com",
            "request_access": "write", "return_to": "https://fragment.com"
        }, cookies={
            "stel_ssid": s, f"stel_tsession_{phone.strip('+ ')}": t, "stel_tsession": t
        }, headers=h)

        if r.ok:
            try:
                token = r.cookies.get("stel_token")
            except Exception:
                token = None
        if token:
            break
        await asyncio.sleep(1)

    data = await generate(mnemonic, ton_proof)
    payload = urlencode(data)

    for cookie in html.headers.get("Set-Cookie", "").split(","):
        if "stel_ssid=" in cookie:
            stel_ssid = re.search(r"stel_ssid=([^;]+)", cookie).group(1)

    resp = requests.post(f"https://fragment.com/api?hash={hash}",
        headers={"content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                 "x-requested-with": "XMLHttpRequest",
                 "user-agent": "Mozilla/5.0 (Linux; Android 6.0)",
                 "origin": "https://fragment.com",
                 "referer": "https://fragment.com/"},
        cookies={"stel_ssid": stel_ssid, "stel_dt": "-120"},
        data=payload)

    return json.dumps({"stel_ton_token": resp.cookies.get("stel_ton_token"),
                       "stel_ssid": stel_ssid,
                       "stel_dt": "-120",
                       "tg_stel_ssid": s,
                       "tg_stel_tsession": t,
                       "tg_stel_token": token,
                       "api_hash": hash,
                       "version": version}, indent=4)

result = asyncio.run(auth(phone="+441632960123",
                          mnemonic="silent noble timber brave eagle cherry trend globe music royal vapor kingdom clutch skate patch lemon clutch orbit vapor travel ripple cloud wisdom steel"))
print(result)