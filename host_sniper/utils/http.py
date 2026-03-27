"""
HTTP request utilities
"""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class HTTPClient:
    """HTTP client with retry and timeout handling"""
    
    @staticmethod
    def create_session():
        """Create requests session with retry strategy"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD", "POST", "PUT", "DELETE"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    @staticmethod
    def request(method, url, **kwargs):
        """Make HTTP request"""
        session = HTTPClient.create_session()
        try:
            response = session.request(method, url, **kwargs)
            return response
        except requests.RequestException as e:
            return None
        finally:
            session.close()
    
    @staticmethod
    def get(url, **kwargs):
        """Make GET request"""
        return HTTPClient.request('GET', url, **kwargs)
    
    @staticmethod
    def post(url, **kwargs):
        """Make POST request"""
        return HTTPClient.request('POST', url, **kwargs)
    
    @staticmethod
    def head(url, **kwargs):
        """Make HEAD request"""
        return HTTPClient.request('HEAD', url, **kwargs)
