############################## SCRIPT SETTINGS ###########################
proxy_auto_scrape = False # Automatic proxy scraping from third-party resources [BETA]
proxies = [] # HTTP Proxy in one of the specified formats: [ip:port:login:password, login:password@ip:port] or None

discord_bot_id = 1356296211908264129 # https://discord.com/developers/applications ==> Create application ==> General Information ==> APPLICATION ID

############################## SPOTIFY SETTINGS - NOT NECESSARY ##########################
'''
1. Open https://developer.spotify.com/dashboard/applications.
2. Log in with your Spotify account.
3. Click on `Create an app`.
4. In `Redirect URIs` enter `http://127.0.0.1:9001/callback` then fill `App name` and ‘App description’ of your choice and mark the checkboxes.
5. After creation, you see your `Client Id` and you can click on `Show client secret` to unhide your `Client secret`.
'''
SPOTIFY_CLIENT_ID = '880ea6a211c04b28abb979e9858a50f3' # Spotify Client ID
SPOTIFY_CLIENT_SECRET = '82ade7eda89f4bdaa491329dfd87e35f' # Spotify Client Secret
SPOTIFY_CLIENT_REDIRECT_URI = 'http://127.0.0.1:9001/callback' # Spotify Redirect Uri
SPOTIFY_PROFILE_URL = 'https://open.spotify.com/user/31il3gpmorrtonzrblwy4sg4ydki' # Your spotify profile url