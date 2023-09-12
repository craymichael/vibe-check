# vibe-check (bot)

Do you frequently share music with colleagues/friends over Slack? Then check out the Vibe Check bot! The bot monitors a channel(s) for links to music on YouTube and Spotify, then updates a YouTube playlist. Listen to all your space's music at one link!

```shell
pip install -r requirements.txt
python run.py
```

To run this project, you will need to create the following files with appropriate contents:

- `google_client_secret.json` Client secret JSON for Google API app/project
- `google_api_key.txt` Google API key for API app/project
- `slack_bot_user_oauth_token.txt` OAuth token for the Slack bot user/app
- `yt_music_headers_auth.json` following instructions here: https://ytmusicapi.readthedocs.io/en/latest/setup.html
- `spotify_client_auth.json` Spotify app client ID and secret (using the keys "client_id" and "client_secret" respectively)
