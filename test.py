import browser_cookie3, win32process, pypresence, threading, traceback, win32gui, win32con, requests, asyncio, spotipy, logging, hashlib, psutil, httpx, json, base64, time, sys, os, re
from urllib.parse import parse_qsl, urlparse
from spotipy.oauth2 import SpotifyOAuth
from cachetools import TTLCache

from config import *


class spotify_client: # spf_client
	def __init__(self, spotify_client_id = None, spotify_client_secret = None, spotify_client_redirect_uri = None, proxies = list()):
		self.spotify_client_id = spotify_client_id
		self.spotify_client_secret = spotify_client_secret
		self.spotify_client_redirect_uri = spotify_client_redirect_uri
		self.authed = False
		self.spy_client = None
		self.proxies = proxies

		self.session = requests.Session()
		self.auth()

	def auth(self):
		self.change_proxy()
		try:
			if os.path.exists('.cache'):
				bearer = json.loads(open('.cache','r').read()).get('access_token')
				req = self.session.get('https://api.spotify.com/v1/me', headers={'Authorization': f'Bearer {bearer}'})

				if req.status_code == 200:
					self.authed = True
					self.spy_client = spotipy.Spotify(auth_manager=SpotifyOAuth(client_id=self.spotify_client_id, client_secret=self.spotify_client_secret, redirect_uri=self.spotify_client_redirect_uri, scope='user-read-playback-state'))

					return logging.info('[spf_client] Connected to session')

			logging.info('[spf_client] Creating session')
			try: cookies = {cookie.name: cookie.value for cookie in browser_cookie3.chrome(domain_name="spotify.com")}
			except: cookies = {cookie.get('name', None): cookie.get('value', None)  for cookie in json.loads(open(spotify_cookies, 'r').read())}

			req = self.session.get(f'https://accounts.spotify.com/authorize?client_id={self.spotify_client_id}&response_type=code&redirect_uri={self.spotify_client_redirect_uri}&scope=user-read-playback-state', cookies=cookies, headers={'authority': 'accounts.spotify.com','accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7','accept-language': 'ru,en-US;q=0.9,en;q=0.8,ru-RU;q=0.7','sec-ch-ua': '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"','sec-ch-ua-mobile': '?0','sec-ch-ua-platform': '"Windows"','sec-fetch-dest': 'document','sec-fetch-mode': 'navigate','sec-fetch-site': 'none','sec-fetch-user': '?1','upgrade-insecure-requests': '1','user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'})
			if 'smallImageUrl":"' in req.text:
				csrf = req.headers['set-cookie'].split('csrf_token=')[1].split(';')[0]
				req = self.session.post(f'https://accounts.spotify.com/ru/authorize/accept?ajax_redirect=1', data={'request': '', 'client_id': self.spotify_client_id, 'response_type': 'code', 'redirect_uri': self.spotify_client_redirect_uri, 'scope': 'user-read-playback-state', 'csrf_token': csrf}, cookies=cookies, headers={'authority': 'accounts.spotify.com','accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7','accept-language': 'ru,en-US;q=0.9,en;q=0.8,ru-RU;q=0.7','sec-ch-ua': '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"','sec-ch-ua-mobile': '?0','sec-ch-ua-platform': '"Windows"','sec-fetch-dest': 'document','sec-fetch-mode': 'navigate','sec-fetch-site': 'none','sec-fetch-user': '?1','upgrade-insecure-requests': '1','user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'})
			url = req.url

			code = [dict(parse_qsl(urlparse(url).query)).get(param) for param in ["state", "code"]][1]
			if not code: return logging.warning('[spf_client] Invalid credentials, using manually mode for Spotify')

			token = self.session.post('https://accounts.spotify.com/api/token', headers={"Authorization": f"Basic {base64.b64encode(f'{self.spotify_client_id}:{self.spotify_client_secret}'.encode('ascii')).decode('ascii')}"}, data={'redirect_uri': self.spotify_client_redirect_uri,'code':code, 'grant_type': 'authorization_code'}).json()
			token["expires_at"] = int(time.time()) + token["expires_in"]
			open('.cache', 'w').write(json.dumps(token))
			logging.info('[spf_client] Session created')

			self.spy_client = spotipy.Spotify(auth_manager=SpotifyOAuth(client_id=self.spotify_client_id, client_secret=self.spotify_client_secret, redirect_uri=self.spotify_client_redirect_uri, scope='user-read-playback-state'))
			self.authed = True
			logging.info('[spf_client] Connected to session')
		except requests.exceptions.ConnectionError:
			logging.debug('[spf_client] Bad proxy, changing')
			self.change_proxy()
			self.auth()
		except requests.exceptions.ConnectTimeout:
			logging.debug('[spf_client] Bad proxy, changing')
			self.change_proxy()
			self.auth()
		except requests.exceptions.ProxyError:
			logging.debug('[spf_client] Bad proxy, changing')
			self.change_proxy()
			self.auth()
		except KeyError:
			self.authed = False
			logging.warning('[spf_client] Invalid credentials, using manually mode for Spotify')
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
				try: current_track = self.spy_client.current_user_playing_track()['item']
				except: return self.current_track(True)

				track_id = current_track['id']
				track_name = current_track['name']
				track_artist = current_track['album']['artists'][0]['name']
				track_url = current_track['external_urls']['spotify']
				album_picture = current_track['album']['images'][0]['url']
			else:
				proc_data = getWindowSizes('spotify.exe')
				if len(proc_data) == 0: skip = True
				else:
					track_id = proc_data[0]['text']
					track_artist = track_id.split(' - ')[0]
					track_name = track_id.split(' - ')[1]
					track_url = spotify_profile_url
					album_picture = None
		except: skip = True

		return {'skip': skip, 'track_id': track_id, 'track_name': track_name, 'track_artist': track_artist, 'track_url': track_url, 'album_picture': album_picture if album_picture else 'https://raw.githubusercontent.com/plowside/plowside/main/assets/shpotify.png'}

	def change_proxy(self):
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

		windows.append({'text':win32gui.GetWindowText(hWnd),'hwnd':hWnd, 'process': name})

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
				if (await client.get('http://ip.bablosoft.com')).status_code != 409:
					valid.append(proxy)
		except: pass


spf_client = spotify_client(spotify_client_id, spotify_client_secret, spotify_client_redirect_uri, proxies)
print(spf_client.current_track())