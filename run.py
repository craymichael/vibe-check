import os
import socket
import time
import threading
import re
import logging
import json
from datetime import timedelta
from decimal import Decimal

import urllib.error

from requests.exceptions import ConnectionError

import pydata_google_auth
import googleapiclient.discovery
import googleapiclient.discovery_cache
import googleapiclient.errors

import slack_sdk
from slack_sdk.errors import SlackApiError

import spotipy
from spotipy.oauth2 import SpotifyClientCredentials

from ytmusicapi import YTMusic

OAUTH = True


def read_key(path):
    with open(path, 'r') as f:
        return f.read().strip()


def read_client_secrets(path, key=None):
    with open(path, 'r') as f:
        data = json.load(f)
    if key:
        data = data['installed']
    return data['client_id'], data['client_secret']


GOOGLE_YT_DATA_API_KEY = read_key('google_api_key.txt')
# CLIENT_SECRETS_FILE = 'google_client_secret.json'
GOOGLE_APP_CLIENT_ID, GOOGLE_APP_CLIENT_SECRET = read_client_secrets(
    'google_client_secret.json', 'installed')
YT_API_SCOPES = ['https://www.googleapis.com/auth/youtube.force-ssl']

SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET = read_client_secrets(
    'spotify_client_auth.json')

SLACK_BOT_TOKEN = read_key('slack_bot_user_oauth_token.txt')
SLACK_CHANNEL = 'C032LTMTP47'  # vibe-check
SLACK_MESSAGES_PER_PAGE = 200

TIMESTAMP_LOCK = threading.Lock()
TIMESTAMP_PATH = 'latest_message_timestamp.txt'

# Naive YT link regex.
# Help from:
# https://webapps.stackexchange.com/questions/54443/format-for-id-of-youtube-video
# Examples:
# https://www.youtube.com/watch?v=RanWHeHgH0k
# https://www.youtube.com/watch?v=RanWHeHgH0k&list=PLzvmpzXLAkthyaiDbI6c_35KDZ1bu5Fp-&index=9
# https://youtu.be/RanWHeHgH0k
YT_REGEX = re.compile(r'(?:youtube\.com/watch\?v=|youtu\.be/)([\dA-Za-z_-]+)')
SP_REGEX = re.compile(r'spotify\.com/track/([\dA-Za-z]+)')

VIBE_CHECK_PLAYLIST_ID = 'PLzvmpzXLAktitNV3k0LguHX9s7_k3q1j0'
VIBE_CHECK_PLAYLIST_ID_LONG = 'PLzvmpzXLAktiaojjoPTOJZ7E0WzpXkYmq'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: '
           '%(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger('run')


def build_yt_client():
    # Disable OAuthlib's HTTPS verification when running locally.
    # *DO NOT* leave this option enabled in production.
    # os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    api_service_name = 'youtube'
    api_version = 'v3'

    # Get credentials and create an API client
    if OAUTH:
        credentials = pydata_google_auth.get_user_credentials(
            scopes=YT_API_SCOPES,
            client_id=GOOGLE_APP_CLIENT_ID,
            client_secret=GOOGLE_APP_CLIENT_SECRET,
        )
        youtube = googleapiclient.discovery.build(
            api_service_name, api_version, credentials=credentials,
            cache_discovery=True,
            cache=googleapiclient.discovery_cache.autodetect(),
        )
    else:
        youtube = googleapiclient.discovery.build(
            api_service_name, api_version, developerKey=GOOGLE_YT_DATA_API_KEY)
    return youtube


def build_slack_client():
    slack = slack_sdk.WebClient(token=SLACK_BOT_TOKEN)
    return slack


def build_spotify_client():
    os.environ['SPOTIPY_CLIENT_ID'] = SPOTIFY_CLIENT_ID
    os.environ['SPOTIPY_CLIENT_SECRET'] = SPOTIFY_CLIENT_SECRET
    return spotipy.Spotify(
        client_credentials_manager=SpotifyClientCredentials())


def build_ytmusic_client():
    ytmusic = YTMusic('yt_music_headers_auth.json')
    return ytmusic


def read_timestamp():
    with TIMESTAMP_LOCK:
        with open(TIMESTAMP_PATH, 'r') as f:
            return f.read().strip()


def write_timestamp(timestamp):
    with TIMESTAMP_LOCK:
        with open(TIMESTAMP_PATH, 'w') as f:
            f.write(timestamp)


def retrieve_slack_history(slack, last_timestamp):
    messages = []
    cursor = None
    while True:
        try:
            kwargs = {} if cursor is None else {'cursor': cursor}
            response = slack.conversations_history(
                channel=SLACK_CHANNEL,
                limit=SLACK_MESSAGES_PER_PAGE,
                oldest=last_timestamp,
                # latest=str(time.time()),
                inclusive=False,
                **kwargs,
            )
        except SlackApiError as e:
            assert e.response['ok'] is False
            assert e.response['error']
            if e.response.status_code == 429:
                delay = int(e.response.headers['Retry-After'])
                logger.warning(f'Rate limited. Retrying in {delay} seconds')
                time.sleep(delay)
            else:
                # other errors
                logger.error(f'Got an error: {e.response["error"]}')
                raise e
        except urllib.error.URLError as e:
            print('e.reason', e.reason)
            print('type(e.reason)', type(e.reason))
            e_reason_str = str(e.reason)
            if isinstance(e_reason_str, str) and re.match(
                    r'timed out', e_reason_str):
                logger.warning('Connection timed out, sleeping for a minute')
                time.sleep(60)
            elif (isinstance(e.reason, socket.gaierror) and
                  re.match('[Tt]emporary failure', e_reason_str)):
                logger.warning(f'Connection temporary failure: '
                               f'{e.reason.args[0]}')
                time.sleep(60)
            else:
                raise e
        else:
            assert response['ok']
            meta = response.get('response_metadata')
            if meta:
                cursor = meta.get('next_cursor')
            messages += response['messages']

            if not response['has_more']:
                break
    messages = sorted(messages, key=lambda m: float(m['ts']))
    return messages


ISO8601_PERIOD_REGEX = re.compile(
    r'^(?P<sign>[+-])?'
    r'P(?!\b)'
    r'(?P<years>\d+([,.]\d+)?Y)?'
    r'(?P<months>\d+([,.]\d+)?M)?'
    r'(?P<weeks>\d+([,.]\d+)?W)?'
    r'(?P<days>\d+([,.]\d+)?D)?'
    r'((?P<separator>T)(?P<hours>\d+([,.]\d+)?H)?'
    r'(?P<minutes>\d+([,.]\d+)?M)?'
    r'(?P<seconds>\d+([,.]\d+)?S)?)?$'
)


class VideoDoesNotExistError(ValueError):
    pass


class InvalidDurationError(ValueError):
    pass


def get_video_duration(youtube, video_id):
    request = youtube.videos().list(
        part='contentDetails',
        id=video_id,
    )
    response = request.execute()
    if len(response['items']) != 1:
        raise VideoDoesNotExistError(f'{video_id} does not exist or is not '
                                     f'public')
    duration_str = response['items'][0]['contentDetails']['duration']
    duration_match = ISO8601_PERIOD_REGEX.match(duration_str)
    if duration_match is None:
        raise InvalidDurationError(duration_str)
    duration_dict = duration_match.groupdict()
    for key, val in duration_dict.items():
        if key not in ('separator', 'sign'):
            if val is None:
                val = '0n'
            val = val[:-1].replace(',', '.')
            if key in {'years', 'months'}:
                duration_dict[key] = float(Decimal(val))
            else:
                duration_dict[key] = float(val)

    extra_days = 0
    if duration_dict['years'] != 0:
        extra_days_from_years = 365 * duration_dict['years']
        logger.warning(f'video_id {video_id} has duration that specified '
                       f'years={duration_dict["years"]}, which we will say is '
                       f'equivalent to {extra_days_from_years} days.')
        extra_days += extra_days_from_years
    if duration_dict['months'] != 0:
        extra_days_from_months = (365 / 12) * duration_dict['months']
        logger.warning(f'video_id {video_id} has duration that specified '
                       f'months={duration_dict["months"]}, which we will say '
                       f'is equivalent to {extra_days_from_months} days.')
        extra_days += extra_days_from_months
    duration_secs = timedelta(
        weeks=duration_dict['weeks'],
        days=duration_dict['days'] + extra_days,
        hours=duration_dict['hours'],
        minutes=duration_dict['minutes'],
        seconds=duration_dict['seconds'],
    ).seconds
    return duration_secs


SAFEWORD = 'orang'
SAFEWORD_REGEX = re.compile(rf'(^|\s){SAFEWORD}($|\s)')


def handle_message(message, youtube, spotify, ytmusic):
    if SAFEWORD_REGEX.search(message['text']):
        logger.info('Safeword detected in message! Will ignore video IDs '
                    'within.')
        track_ids_sp = []
        video_ids = []
    else:
        track_ids_sp = SP_REGEX.findall(message['text'])
        video_ids = YT_REGEX.findall(message['text'])

    for track_id_sp in sorted(set(track_ids_sp)):
        logger.info(f'Handle SP track ID={track_id_sp}')
        spotify_request_retries = 10
        for spotify_request_retry in range(spotify_request_retries):
            try:
                track_info = spotify.track(track_id_sp)
            except ConnectionError:
                continue
            else:
                break
        else:
            logger.error(f'Could not connect to spotify API after '
                         f'{spotify_request_retry} retries to request '
                         f'track {track_id_sp}')
            raise RuntimeError('fuck')
        yt_music_query = (
                track_info['name'] + ', ' +
                ' AND '.join(artist['name'] for artist in track_info['artists'])
                + ', ' + track_info['album']['name']
        )
        ytm_search_results = ytmusic.search(yt_music_query)
        for ytm_search_result in ytm_search_results:
            if ytm_search_result['resultType'] != 'song':
                continue
            video_ids.append(ytm_search_result['videoId'])
            break
        else:
            logger.info(f'Could not find a YouTube Music video corresponding '
                        f'to the Spotify-derived query "{yt_music_query}" '
                        f'(Spotify track ID {track_id_sp})')

    for video_id in sorted(set(video_ids)):  # unique video IDs
        logger.info(f'Handle YT video ID={video_id}')

        try:
            duration = get_video_duration(youtube, video_id)
            if duration > (60 * 30):
                playlist_id = VIBE_CHECK_PLAYLIST_ID_LONG
            else:
                playlist_id = VIBE_CHECK_PLAYLIST_ID
            youtube.playlistItems().insert(
                part='snippet',
                body={
                    'snippet': {
                        'playlistId': playlist_id,
                        'resourceId': {
                            'kind': 'youtube#video',
                            'videoId': video_id
                        },
                        'position': 0,
                    }
                }
            ).execute()
        except googleapiclient.errors.HttpError as e:
            logger.warning(f'  Broken: {video_id}\n{e}')
            if e.status_code == 403:
                raise
        except (VideoDoesNotExistError, InvalidDurationError) as e:
            logger.warning(f'Video duration parsing error:\n{e}')

    with TIMESTAMP_LOCK:
        with open(TIMESTAMP_PATH, 'r') as f:
            timestamp = f.read()
        message_timestamp = message['ts']
        if float(timestamp) > float(message_timestamp):
            logger.warning(f'{TIMESTAMP_PATH} contains timestamp={timestamp} '
                           f'but message contains older timestamp '
                           f'{message_timestamp}. This should never happen '
                           f'and we will not update the timestamp in the file.')
        else:
            with open(TIMESTAMP_PATH, 'w') as f:
                f.write(message_timestamp)


def main():
    if not os.path.exists(TIMESTAMP_PATH):
        write_timestamp('0')

    youtube = build_yt_client()
    slack = build_slack_client()
    spotify = build_spotify_client()
    ytmusic = build_ytmusic_client()

    while True:
        last_timestamp = read_timestamp()
        # retrieve messages we have missed since last time the script was run
        missed_messages = retrieve_slack_history(slack, last_timestamp)

        if missed_messages:
            for message in missed_messages:
                handle_message(message, youtube, spotify, ytmusic)
        else:
            logger.info('No new messages')

        time.sleep(60)


if __name__ == '__main__':
    while True:
        try:
            main()
        except Exception:
            logger.exception('Exception in main loop!')
