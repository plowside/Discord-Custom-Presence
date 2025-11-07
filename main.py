import webbrowser
import aiofiles
import aiohttp
import browser_cookie3, win32process, pypresence, threading, traceback, win32gui, win32con, requests, asyncio, spotipy, logging, hashlib, psutil, httpx, json, base64, time, sys, os, re
from urllib.parse import parse_qsl, urlparse, urlencode

from adodbapi.ado_consts import adModeShareDenyWrite
from spotipy.oauth2 import SpotifyOAuth
from cachetools import TTLCache

from config import *

import uvicorn
from fastapi import FastAPI
import threading

#####################################################################
open('log.log', 'w', encoding='utf-8')
logging.basicConfig(format=u'%(filename)s [LINE:%(lineno)d] #%(levelname)-8s [%(asctime)s]  %(message)s', level=logging.DEBUG, handlers=[logging.StreamHandler(), logging.FileHandler("log.log", mode='w', encoding='utf-8')])
logging.getLogger('spotipy').setLevel(logging.DEBUG)
logging.getLogger('requests').setLevel(logging.INFO)
logging.getLogger('httpx').setLevel(logging.ERROR)
logging.getLogger('httpcore').setLevel(logging.ERROR)
logging.getLogger('urllib3').setLevel(logging.INFO)

def crash_handler(exctype, value, traceback_):
	logging.error(''.join(traceback.format_exception(exctype, value, traceback_)))
sys.excepthook = crash_handler

#####################################################################
spf_client = None

app = FastAPI()

@app.get("/callback")
async def callback(code: str):
	token = await generate_token(code)
	if not token:
		return {"message": "Server error"}
	logging.info('Saving token to .cache')
	async with aiofiles.open('.cache', mode="w") as f:
		await f.write(json.dumps(token))

	global spf_client
	if spf_client:
		logging.info('Calling spf_client.auth() after token save')
		try:
			threading.Thread(target=spf_client.auth, daemon=True).start()
		except Exception as e:
			logging.error(f'Error calling spf_client.auth(): {e}')

	return token

@app.get("/get_auth_url")
async def get_auth_url():
	scopes = ['user-read-playback-state']
	params = {
		"redirect_uri": SPOTIFY_CLIENT_REDIRECT_URI,
		"response_type": "code",
		"scope": " ".join(scopes),
		"show_dialog": "true",
		"client_id": SPOTIFY_CLIENT_ID,
	}
	return {"url": "https://accounts.spotify.com/ru/authorize?" + urlencode(params)}

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

def run_server():
	"""Функция для запуска сервера в отдельном потоке"""
	uvicorn.run(app, host="127.0.0.1", port=9001, log_level="info")

#####################################################################
class custom_presence: # client
	def __init__(self):
		self.rpc = None
		self.rpc_connected = False
		self.rpc_id = None
		self.is_idle = True
		self.pid = None
		self.cache = TTLCache(maxsize=100, ttl=7200)
		self.check_data = {}
		self.detections = {}

	def create_rpc(self, bot_id = discord_bot_id):
		if self.rpc:
			logging.debug('[custom_presence] Closing RPC')
			try:
				self.rpc.close()
				logging.debug('[custom_presence] RPC closed')
			except pypresence.exceptions.PipeClosed: pass
			except Exception as e: logging.error(f'[custom_presence] Error on closing RPC: {e}')
			self.rpc_connected = False

		self.rpc = pypresence.Presence(bot_id)
		logging.debug('[custom_presence] Connecting to RPC')
		self.rpc_connect()
		logging.debug('[custom_presence] Connected to RPC')

		self.rpc_id = bot_id

	def rpc_connect(self):
		if self.rpc_connected: return
		try:
			self.rpc.connect()
			self.rpc_connected = True
		except pypresence.exceptions.DiscordNotFound: self.await_discord()
		except Exception as error:
			logging.error(f'[custom_presence] Error on connecting RPC: {error}')
			if 'Message: User logged out' in str(error):
				return self.create_rpc()
		finally: self.rpc_connect()

	def update_rpc(self, is_idle = False, **kwargs):
		self.is_idle = is_idle

		try: self.rpc.update(**kwargs)
		except pypresence.exceptions.DiscordNotFound: self.await_discord()
		except pypresence.exceptions.PipeClosed: self.create_rpc(discord_bot_id)
		except Exception as error: return logging.error(f'[custom_presence] Error on updating RPC: {error}')
		finally: self.rpc.update(**kwargs)

	def get_start(self, proc):
		ts = self.cache.get(proc)
		if not ts: self.cache[proc] = time.time()
		else: self.cache[proc] = ts
		return self.cache.get(proc)

	def await_discord(self):
		logging.debug('[custom_presence] No running copies of the discord were found')
		pattern = re.compile(r'.*discord.*\.exe$')
		while True:
			try:
				while not pattern.match(', '.join([x.name().lower() for x in psutil.process_iter()])):
					time.sleep(1)
				break
			except: ...
		logging.debug('[custom_presence] A copy of the running discord was found')
		time.sleep(10)

	def detections_checker(self):
		try: self.detections = json.loads(open('.detections.json', 'r', encoding='utf-8').read())
		except Exception as error: logging.error(f'[custom_presence] Error on detections_watcher: {error}')

class spotify_client: # spf_client
	def __init__(self, spotify_client_id = None, spotify_client_secret = None, spotify_client_redirect_uri = None, proxies = None):
		self.spotify_client_id = spotify_client_id
		self.spotify_client_secret = spotify_client_secret
		self.spotify_client_redirect_uri = spotify_client_redirect_uri
		self.authed = False
		self.spy_client: spotipy.Spotify | None = None
		self.proxies = proxies or []

		self.session = requests.Session()
		self.auth()

	def auth(self):
		logging.info('Starting Spotify authentication')
		self.change_proxy()
		try:
			if os.path.exists('.cache'):
				try:
					with open('.cache','r') as f:
						cache_data = json.loads(f.read())
					bearer = cache_data.get('access_token')

					if bearer:
						req = self.session.get('https://api.spotify.com/v1/me', headers={'Authorization': f'Bearer {bearer}'})
						logging.info(f'[v1/me] {req.status_code} | {req.text}')

						if req.status_code == 200 or (req.status_code == 403 and 'Spotify is unavailable in this country' in req.text):
							self.authed = True
							self.spy_client = spotipy.Spotify(auth_manager=SpotifyOAuth(client_id=self.spotify_client_id, client_secret=self.spotify_client_secret, redirect_uri=self.spotify_client_redirect_uri, scope='user-read-playback-state'))
							logging.info('[spf_client] Connected to existing session')
							return
				except Exception as e:
					logging.warning(f'Error reading cache: {e}')
					try:
						os.remove('.cache')
						logging.info('Removed invalid .cache file')
					except: pass

			logging.info('[spf_client] Creating new session')

			try:
				auth_url_response = requests.get('http://127.0.0.1:9001/get_auth_url', timeout=5)
				if auth_url_response.status_code == 200:
					auth_url = auth_url_response.json()['url']
					logging.info(f'[spf_client] Opening in browser: {auth_url}')
					webbrowser.open(auth_url, new=0, autoraise=True)

					i = 0
					while not os.path.exists('.cache'):
						logging.info(f'[spf_client] Waiting for authentication... {i}')
						if i > 60:  # Увеличил время ожидания до 60 секунд
							logging.error('[spf_client] Authentication timeout')
							return False
						time.sleep(1)
						i += 1

					logging.info('[spf_client] Authentication successful, token received')

					if os.path.exists('.cache'):
						with open('.cache','r') as f:
							cache_data = json.loads(f.read())
						if cache_data.get('access_token'):
							self.spy_client = spotipy.Spotify(auth_manager=SpotifyOAuth(client_id=self.spotify_client_id, client_secret=self.spotify_client_secret, redirect_uri=self.spotify_client_redirect_uri, scope='user-read-playback-state'))
							self.authed = True
							logging.info('[spf_client] Connected to new session')
				else:
					logging.error(f'[spf_client] Failed to get auth URL: {auth_url_response.status_code}')
			except requests.exceptions.ConnectionError:
				logging.error('[spf_client] Authentication server not available')
			except Exception as e:
				logging.error(f'[spf_client] Error during authentication: {e}')

		except requests.exceptions.ConnectionError:
			logging.debug('[spf_client] Bad proxy, changing')
			self.change_proxy()
		except requests.exceptions.ConnectTimeout:
			logging.debug('[spf_client] Bad proxy, changing')
			self.change_proxy()
		except requests.exceptions.ProxyError:
			logging.debug('[spf_client] Bad proxy, changing')
			self.change_proxy()
		except PermissionError:
			self.authed = False
			logging.warning('[spf_client] Error while getting cookies from browser, using manually mode for Spotify')
		except browser_cookie3.BrowserCookieError:
			self.authed = False
			logging.warning('[spf_client] Error while parsing cookies, using manually mode for Spotify')
		except Exception as error:
			self.authed = False
			logging.error(f'[spf_client] Error while creating session: {error} | {type(error)}')

	def current_track(self, force_manually = False):
		skip = False
		track_id = None
		track_name = None
		track_artist = None
		track_url = None
		album_picture = None

		try:
			if self.authed and not force_manually:
				try:
					current_track = self.spy_client.current_user_playing_track()['item']
				except:
					return self.current_track(True)

				track_id = current_track['id']
				track_name = current_track['name']
				track_artist = current_track['album']['artists'][0]['name']
				track_url = current_track['external_urls']['spotify']
				album_picture = current_track['album']['images'][0]['url']
			else:
				proc_data = getWindowSizes('spotify.exe')
				if len(proc_data) == 0: skip = True
				else:
					track_id: str = proc_data[0]['text']
					if track_id.lower() in ['spotify free', 'spotify premium', 'spotify']:
						skip = True
					else:
						track_artist = track_id.split(' - ')[0]
						track_name = track_id.split(' - ')[1]
						track_url = SPOTIFY_PROFILE_URL
						album_picture = None
		except Exception as error:
			logging.info(f'spf_client.current_track(force_manually={force_manually}) skip cuz except: {error}')
			skip = True

		return {'skip': skip, 'track_id': track_id, 'track_name': track_name, 'track_artist': track_artist, 'track_url': track_url, 'album_picture': album_picture if album_picture else 'https://raw.githubusercontent.com/plowside/plowside/main/assets/shpotify.png'}

	def change_proxy(self):
		return
		logging.debug('[spf_client] Changing proxy')
		if len(self.proxies) == 0:
			if proxy_auto_scrape:
				logging.info('[spf_client] No proxies, getting new')
				self.proxies = asyncio.new_event_loop().run_until_complete(proxy_scraper().get_proxy())
			else:
				logging.info('[spf_client] No proxies')
				return

		proxy = self.proxies.pop(0)
		_proxy = proxy if ('@' in proxy or len(proxy.split(':')) == 2) else f"{proxy.split(':')[2]}:{proxy.split(':')[3]}@{proxy.split(':')[0]}:{proxy.split(':')[1]}"
		self.session.proxies = {'http':f'http://{_proxy}','https':f'http://{_proxy}'}

class proxy_scraper:
	def __init__(self):
		self.proxies = []
		self.valid = []

	async def get_proxy(self):
		await self.parse_proxy()
		return await self.checker()

	async def parse_proxy(self):
		logging.debug('[proxy_scraper] Parsing proxy')
		async with httpx.AsyncClient() as client:
			req = (await client.get('https://spys.me/proxy.txt')).text
			self.proxies = re.findall(re.compile(r"\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?"), req)
			logging.debug(f'[proxy_scraper] Parsed {len(self.proxies)} proxies')
			return self.proxies

	async def checker(self, proxies = None):
		if not proxies: proxies = self.proxies
		tasks = []
		logging.debug(f'[proxy_scraper] Checking {len(proxies)} proxies')
		for x in proxies: tasks.append(asyncio.ensure_future(self.check(x, self.valid)))
		await asyncio.gather(*tasks)
		logging.debug(f'[proxy_scraper] Scraped {len(self.valid)} valid proxies')

		return self.valid

	async def check(self, proxy, valid = None):
		if not valid: valid = self.valid
		try:
			async with httpx.AsyncClient(proxies={'http://':f'http://{proxy}', 'https://':f'http://{proxy}'}, timeout=5) as client:
				if (await client.get('https://eth0.me')).status_code == 200:
					valid.append(proxy)
		except: pass


def isRealWindow(hWnd):
	if not win32gui.IsWindowVisible(hWnd) or win32gui.GetParent(hWnd) != 0: return False
	if (((win32gui.GetWindowLong(hWnd, win32con.GWL_EXSTYLE) & win32con.WS_EX_TOOLWINDOW) == 0 and win32gui.GetWindow(hWnd, win32con.GW_OWNER) == 0) or ((win32gui.GetWindowLong(hWnd, win32con.GWL_EXSTYLE) & win32con.WS_EX_APPWINDOW != 0) and not win32gui.GetWindow(hWnd, win32con.GW_OWNER) == 0)):
		if win32gui.GetWindowText(hWnd): return True
	else: return False

def getWindowSizes(proc_name = None):
	def callback(hWnd, windows):
		if not isRealWindow(hWnd): return
		name = psutil.Process(win32process.GetWindowThreadProcessId(hWnd)[1]).name().lower()
		if proc_name and name != proc_name: return

		windows.append({'text': win32gui.GetWindowText(hWnd), 'hwnd': hWnd, 'process': name})

	windows = []
	win32gui.EnumWindows(callback, windows)
	return windows

def kwargs_to_dict(base_dict = None, **kwargs):
	if not base_dict: base_dict = {}
	base_dict.update(kwargs)

	return base_dict

def replace_values(data, replacements):
	if isinstance(data, dict):
		for key, value in data.items():
			data[key] = replace_values(value, replacements)
	elif isinstance(data, list):
		for i, item in enumerate(data):
			data[i] = replace_values(item, replacements)
	elif isinstance(data, str):
		for pattern, replacement in replacements:
			data = data.replace(pattern, replacement)
	return data

#####################################################################
server_thread = threading.Thread(target=run_server, daemon=True)
server_thread.start()
logging.info("FastAPI server started on http://127.0.0.1:9001")

client = custom_presence()

spf_client = spotify_client(SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET, SPOTIFY_CLIENT_REDIRECT_URI, proxies)

client.create_rpc(discord_bot_id)
#####################################################################
repeats = 11
while True:
	try:
		if repeats > 5:
			client.detections_checker()
			repeats = 0
		temp_procs = psutil.process_iter()
		procs = {x.name().lower(): x.pid for x in temp_procs}
		activity_data = {}
		client.is_idle = True

		ts = int(time.time())

		for i, process_name in enumerate(client.detections):
			if process_name in procs:
				client.is_idle = False

				preset_data = client.detections[process_name].copy()

				if preset_data.get('start') == 'current_timestamp':
					preset_data['start'] = client.get_start(process_name)

				match process_name:
					case 'pycharm64.exe':
						filename = getWindowSizes('pycharm64.exe')
						if len(filename) == 0: continue
						filename = filename[0]['text']

						if not (client.pid == procs[process_name] and client.check_data.get('filename') == filename):
							client.check_data = {'filename': filename}

							if len(filename) > 0:
								project_name = filename.split(' – ')[0]
								working_filename = filename.split(' – ')[-1]
								activity_data = replace_values(preset_data, [('{filename}', project_name)])

					case 'sublime_text.exe':
						filename = [process_name for process_name in getWindowSizes() if '- Sublime Text' in process_name['text']]
						if len(filename) == 0: continue
						filename = filename[0]['text']

						if not (client.pid == procs[process_name] and client.check_data.get('filename') == filename):
							client.check_data = {'filename': filename}

							if len(filename) > 0:
								activity_data = replace_values(preset_data, [('{filename}', filename.split('\\')[-1].split(' ')[0])])

					case 'robloxstudiobeta.exe':
						filename = [process_name for process_name in getWindowSizes() if '- Roblox Studio' in process_name['text']]
						if len(filename) == 0: continue
						filename = filename[0]['text']

						if not (client.pid == procs[process_name] and client.check_data.get('filename') == filename):
							client.check_data = {'filename': filename}

							if len(filename) > 0:
								activity_data = replace_values(preset_data, [('{filename}', filename.split('-')[0].strip())])

					case 'spotify.exe':
						track_data = spf_client.current_track()
						if track_data['skip']: continue
						track_id = track_data['track_id']
						track_artist = track_data['track_artist']
						track_name = track_data['track_name']
						track_url = track_data['track_url']
						album_picture = track_data['album_picture']

						if track_id == client.check_data.get('track_id'):
							break

						client.check_data = {'track_id': track_id}
						activity_data = replace_values(preset_data, [('{track_artist}', track_artist), ('{track_name}', track_name), ('{track_url}', track_url), ('{album_picture}', album_picture)])

					case 'chrome.exe':
						tab_name = [process_name for process_name in getWindowSizes() if '- Google Chrome' in process_name['text'] and 'ornhub' not in process_name['text'] and 'орнхаб' not in process_name['text'].lower()]
						if len(tab_name) == 0: continue
						tab_name = tab_name[0]['text'][:-16][0:128]

						if not (client.pid == procs[process_name] and client.check_data.get('tab_name') == tab_name):
							client.check_data = {'tab_name': tab_name}
							activity_data = replace_values(preset_data, [('{tab_name}', tab_name)])

					case _:
						item_hash = hashlib.sha256(json.dumps(preset_data, sort_keys=True).encode()).hexdigest()
						if client.check_data.get('index') != i or client.check_data.get('hash') != item_hash:
							client.check_data = {'index': i, 'hash': item_hash}
							activity_data = preset_data

				if len(activity_data) > 0:
					client.pid = procs[process_name]
					logging.info(f'New activity: {process_name}')
				break

		if client.is_idle:
			client.check_data = {}
			activity_data = client.detections['idle']
		if len(activity_data) > 0: client.update_rpc(client.is_idle, **activity_data)
	except pypresence.exceptions.PipeClosed: client.create_rpc(discord_bot_id)
	except Exception as error: logging.error(f'Error on proces watcher: {error}\n{traceback.format_exc()}')
	time.sleep(2)
	repeats += 1