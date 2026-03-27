"""Lightweight multithreading utility for Host Sniper compatibility."""
import requests

class MultiThreadRequest:
    def __init__(self, *args, **kwargs):
        self.threads = kwargs.get('threads', 10)
        self._threads = self.threads

    @staticmethod
    def filter_list(input_list):
        if input_list is None:
            return []
        if isinstance(input_list, str):
            return [x.strip() for x in input_list.split(',') if x.strip()]
        if isinstance(input_list, (list, tuple, set)):
            return list(input_list)
        return [input_list]

    def request_connection_error(self, *args, **kwargs):
        return 1

    def request_read_timeout(self, *args, **kwargs):
        return 1

    def request_timeout(self, *args, **kwargs):
        return 1

    def request(self, method, url, retry=1, timeout=10, allow_redirects=True, **kwargs):
        method = method.lower()
        for _ in range(retry):
            try:
                return requests.request(method, url, timeout=timeout, allow_redirects=allow_redirects, **kwargs)
            except requests.exceptions.RequestException:
                continue
        return None

    @staticmethod
    def dict_merge(d1, d2):
        result = dict(d1)
        result.update(d2)
        return result

    def log(self, msg):
        print(msg)

    def task_success(self, payload):
        pass
