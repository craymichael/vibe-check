# Sample Python code for youtube.channels.list
# See instructions for running these code samples locally:
# https://developers.google.com/explorer-help/code-samples#python

import os
import time
import threading
# import warnings
import re

import google_auth_oauthlib.flow
import googleapiclient.discovery
import googleapiclient.errors

import slack_sdk
from slack_sdk.errors import SlackApiError

OAUTH = True


def read_key(path):
    with open(path, 'r') as f:
        return f.read().strip()


GOOGLE_YT_DATA_API_KEY = read_key('google_api_key.txt')
CLIENT_SECRETS_FILE = 'google_client_secret.json'
# YT_API_SCOPES = ['https://www.googleapis.com/auth/youtube.readonly']
YT_API_SCOPES = ['https://www.googleapis.com/auth/youtube.force-ssl']

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
YT_REGEX = re.compile(r'(?:youtube\.com/watch\?v=|youtu\.be/)([0-9A-Za-z_-]+)')

VIBE_CHECK_PLAYLIST_ID = 'PLzvmpzXLAktitNV3k0LguHX9s7_k3q1j0'


def build_yt_client():
    # Disable OAuthlib's HTTPS verification when running locally.
    # *DO NOT* leave this option enabled in production.
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    api_service_name = 'youtube'
    api_version = 'v3'

    # Get credentials and create an API client
    if OAUTH:
        flow = google_auth_oauthlib.flow.InstalledAppFlow.from_client_secrets_file(
            CLIENT_SECRETS_FILE, YT_API_SCOPES)
        credentials = flow.run_console()
        youtube = googleapiclient.discovery.build(
            api_service_name, api_version, credentials=credentials)
    else:
        youtube = googleapiclient.discovery.build(
            api_service_name, api_version, developerKey=GOOGLE_YT_DATA_API_KEY)
    return youtube


def build_slack_client():
    slack = slack_sdk.WebClient(token=SLACK_BOT_TOKEN)
    return slack


def handle_message(message, youtube):
    video_ids = YT_REGEX.findall(message['text'])
    for video_id in sorted(set(video_ids)):  # unique video IDs
        print('YT', video_id)

        try:
            youtube.playlistItems().insert(
                part='snippet',
                body={
                    'snippet': {
                        'playlistId': VIBE_CHECK_PLAYLIST_ID,
                        'resourceId': {
                            'kind': 'youtube#video',
                            'videoId': video_id
                        },
                        'position': 0,
                    }
                }
            ).execute()
        except googleapiclient.errors.HttpError as e:
            # googleapiclient.errors.HttpError: <HttpError 404 when requesting
            #  https://youtube.googleapis.com/youtube/v3/playlistItems?part=snippet&alt=json
            #  returned "Video not found.". Details: "[{'message': 'Video not
            #  found.', 'domain': 'youtube.playlistItem', 'reason':
            #  'videoNotFound'}]">
            # Broken: akuVjWjEYFs <HttpError 403 when requesting
            #  https://youtube.googleapis.com/youtube/v3/playlistItems?part=snippet&alt=json
            #  returned "The request cannot be completed because you have
            #  exceeded your
            #  <a href="/youtube/v3/getting-started#quota">quota</a>.". Details:
            #  "[{'message': 'The request cannot be completed because you have
            #  exceeded your
            #  <a href="/youtube/v3/getting-started#quota">quota</a>.',
            # 'domain': 'youtube.quota', 'reason': 'quotaExceeded'}]">
            print(f'  Broken: {video_id}\n{e}')
            if e.status_code == 403:
                raise

    with TIMESTAMP_LOCK:
        with open(TIMESTAMP_PATH, 'r') as f:
            timestamp = f.read()
        message_timestamp = message['ts']
        if float(timestamp) > float(message_timestamp):
            pass
            # warnings.warn(f'{TIMESTAMP_PATH} contains timestamp={timestamp} '
            #               f'but message contains older timestamp '
            #               f'{message_timestamp}. This should never happen '
            #               f'and we will not update the timestamp in the file.')
        else:
            with open(TIMESTAMP_PATH, 'w') as f:
                f.write(message_timestamp)


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
                print(f'Rate limited. Retrying in {delay} seconds')
                time.sleep(delay)
            else:
                # other errors
                print(f'Got an error: {e.response["error"]}')
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


def main():
    if not os.path.exists(TIMESTAMP_PATH):
        write_timestamp('0')

    youtube = build_yt_client()
    slack = build_slack_client()

    # request = youtube.channels().list(
    #     part='snippet,contentDetails,statistics',
    #     forUsername='ZachCarmichael',
    # )
    # response = request.execute()
    # print(response)

    while True:
        last_timestamp = read_timestamp()
        # retrieve messages we have missed since last time the script was run
        missed_messages = retrieve_slack_history(slack, last_timestamp)

        for message in missed_messages:
            handle_message(message, youtube)

        time.sleep(10)


if __name__ == '__main__':
    main()
