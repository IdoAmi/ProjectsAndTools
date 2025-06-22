

import requests
import os


def check_file_with_virustotal(file_path, api_key):
    url = 'https://www.virustotal.com/api/v3/files'
    with open(file_path, 'rb') as file:
        files = {'file' : file}
        headers = { 'apikey' : api_key}

        response = requests.post(url, headers=headers, files=files)
        if response.status_code == 200:
            return response.json()
        else:
             print(f"Failed to upload file. Status code: {response.status_code}")
             


api_key = "My Api Key"
file_path = "File/path"
result = check_file_with_virustotal(file_path, api_key)