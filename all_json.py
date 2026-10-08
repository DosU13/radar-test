import requests
from requests.auth import HTTPDigestAuth

url = (
    "http://172.17.83.60/"
    # "http://localhost:8060/"
    "cgi-bin/eventManager.cgi?action=attach&codes=[All]"
)

response = requests.get(
    url,
    auth=HTTPDigestAuth("admin", "admin123"),
    stream=True,
)
stop = False
for line in response.iter_lines():
    if line:
        text = line.decode()
        if 'Speed' in text:
            print(text)
