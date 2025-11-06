import asyncio
import json
import time
import base64
import aiofiles
import aiohttp
import uvicorn
from fastapi import FastAPI
from urllib.parse import urlencode

SPOTIFY_CLIENT_ID = '880ea6a211c04b28abb979e9858a50f3'
SPOTIFY_CLIENT_SECRET = '82ade7eda89f4bdaa491329dfd87e35f'
SPOTIFY_CLIENT_REDIRECT_URI = 'http://127.0.0.1:9001/callback'

app = FastAPI()


async def generate_token(code: str):
    async with aiohttp.ClientSession() as session:
        resp = await session.post('https://accounts.spotify.com/api/token', headers={"Authorization": f"Basic {base64.b64encode(f'{SPOTIFY_CLIENT_ID}:{SPOTIFY_CLIENT_SECRET}'.encode('ascii')).decode('ascii')}"}, data={'redirect_uri': SPOTIFY_CLIENT_REDIRECT_URI, 'code': code, 'grant_type': 'authorization_code'})
        if resp.status == 200:
            token = await resp.json()
            token["expires_at"] = int(time.time()) + token["expires_in"]
            return token
        try:
            return (await resp.json()).get("error_description", "Server error")
        except:
            return "Server error"

@app.get("/callback")
async def callback(code: str):
    token = await generate_token(code)
    if not token:
        return {"message": "Server error"}
    async with aiofiles.open('.cache', mode="w") as f:
        await f.write(json.dumps(token))
    return token

@app.get("/get_auth_url")
async def get_auth_url():
    scopes = ['user-read-recently-played']
    params = {
        "redirect_uri": SPOTIFY_CLIENT_REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(scopes),
        "show_dialog": "true",
        "client_id": SPOTIFY_CLIENT_ID,
    }
    return {"url": "https://accounts.spotify.com/ru/authorize?" + urlencode(params)}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=9001)