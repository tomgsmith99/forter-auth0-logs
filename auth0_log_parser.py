#!/usr/bin/python3

import dateutil.parser
import json
import requests
import time

############################

def push_event_to_forter(r):

  print(r)

  # convert Auth0 date (unix timestamp) to Forter date format (ms since unix epoch)
  parsed_time = dateutil.parser.parse(r['date'])
  timestamp = parsed_time.timestamp() * 1000

  base_url = 'https://api.forter-secure.com/v2/accounts'

  user_id = r['user_id']

  event = {
    "accountId": user_id,
    "connectionInformation": {
      "customerIP": r['ip'],
      "userAgent": r['user_agent']
    },
    "eventTime": timestamp
  }

  # event type: incorrect password
  if r['type'] == 'fp':
    url = f'{base_url}/login/{user_id}'

    event['loginMethodType'] = "PASSWORD"
    event['loginStatus'] = "FAILED"
    event['userInput']= {
      "inputType": "EMAIL",
      "email": r['user_name']
    }

  # event type: mfa success
  if r['type'] == 'gd_auth_succeed':
    url = f'{base_url}/authentication-result/{user_id}'

    event['additionalAuthenticationMethod'] = {
      "verificationOutcome": "SUCCESS",
      "correlationId": str(timestamp), # need a better value here
      "oneTimePasswordVerification": {
        "verificationMethod": "SMS_OTP",
        "verified": True,
        "timeVerified": timestamp
      }
    }

  headers = {
    'api-version': forter_api_version,
    'x-forter-siteid': forter_site_id,
    'Authorization': 'Basic ' + forter_encoded_creds,
    'Content-Type': 'application/json'
  }

  response = requests.request("POST", url, headers=headers, data=json.dumps(event))

  print("\nFORTER RESPONSE:")

  print(response.text)

############################
# config

# Auth0 settings
auth0_tenant = 'dev-paq-xqhq.us.auth0.com'
client_id = '4dF7bBTm7iRsMb4GrEp1GpIlQyyXCqxh'
logs_url = f'https://{auth0_tenant}/api/v2/logs'
oauth_url = f'https://{auth0_tenant}/oauth/token'

with open('auth0_client_secret_py') as file:
   client_secret = file.read()

take = 25 # how many records to retrieve with every request

# Forter settings

forter_site_id = '63bf0782ae27'
forter_api_version = '2.48'

with open('forter_secret') as file:
  forter_encoded_creds = file.read()

############################
# get an Auth0 access token

payload = json.dumps({
  "client_id": client_id,
  "client_secret": client_secret,
  "audience": f'https://{auth0_tenant}/api/v2/',
  "grant_type": "client_credentials"
})

headers = {
  'Content-Type': 'application/json'
}

response = requests.request("POST", oauth_url, headers=headers, data=payload)

d = response.json()

access_token = d['access_token']

############################
# pull the logs

# need to add pagination

filter_string = 'q=type:fp OR type:gd_auth_succeed'

url = f'{logs_url}?take={take}&{filter_string}'

headers = {
  'Authorization': f'Bearer {access_token}',
  'Content-Type': 'application/json'
}

print("the url is: ")

print(url)

response = requests.request("GET", url, headers=headers)

records = response.json()

for r in records:
  push_event_to_forter(r)

exit()
