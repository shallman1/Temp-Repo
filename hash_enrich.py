import requests
import hashlib
import hmac
from datetime import datetime, timezone

class HmacSignatureGenerator:
    def __init__(self, api_username, api_key):
        self.api_username = api_username
        self.api_key = api_key

    def create_iso8601_timestamp(self):
        return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    
    def generate_signature(self, uri):
        timestamp = self.create_iso8601_timestamp()
        params = f'{self.api_username}{timestamp}{uri}'
        signature = hmac.new(self.api_key.encode('utf-8'), params.encode('utf-8'), hashlib.sha256).hexdigest()
        return signature, timestamp

def get_domain_info(domain, api_username, api_key):
    uri = "/v1/iris-enrich/"
    generator = HmacSignatureGenerator(api_username, api_key)
    signature, timestamp = generator.generate_signature(uri)
    
    url = (
        f"https://api.domaintools.com{uri}"
        f"?api_username={api_username}&timestamp={timestamp}&signature={signature}&domain={domain}"
    )
    
    response = requests.get(url)
    response.raise_for_status()
    return response.json()

if __name__ == "__main__":
    domain = "google.com"
    api_username = "api_username_here"
    api_key = "api_key_here"

    try:
        domain_info = get_domain_info(domain, api_username, api_key)
        print(domain_info)
    except requests.exceptions.HTTPError as err:
        print(f"HTTP error occurred: {err}")
    except Exception as err:
        print(f"Other error occurred: {err}")
