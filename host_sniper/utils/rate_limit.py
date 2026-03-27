"""
Rate limiting and retry utilities
"""
import time
import random
from functools import wraps


class RateLimiter:
    """Rate limiting utility"""
    
    def __init__(self, calls_per_minute=60, burst_limit=10):
        self.calls_per_minute = calls_per_minute
        self.burst_limit = burst_limit
        self.call_times = []
        self.burst_count = 0
        self.burst_start = time.time()
    
    def wait_if_needed(self):
        """Wait if rate limit would be exceeded"""
        current_time = time.time()
        
        # Clean old call times
        self.call_times = [t for t in self.call_times if current_time - t < 60]
        
        # Check burst limit
        if current_time - self.burst_start > 1:  # Reset burst every second
            self.burst_count = 0
            self.burst_start = current_time
        
        if self.burst_count >= self.burst_limit:
            sleep_time = 1 - (current_time - self.burst_start)
            if sleep_time > 0:
                time.sleep(sleep_time)
            self.burst_count = 0
            self.burst_start = time.time()
        
        # Check overall rate limit
        if len(self.call_times) >= self.calls_per_minute:
            oldest_call = min(self.call_times)
            sleep_time = 60 - (current_time - oldest_call)
            if sleep_time > 0:
                time.sleep(sleep_time)
        
        self.call_times.append(current_time)
        self.burst_count += 1


class RetryMechanism:
    """Retry mechanism with exponential backoff"""
    
    def __init__(self, max_retries=3, base_delay=1, max_delay=30):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
    
    def retry(self, func, *args, **kwargs):
        """Execute function with retry logic"""
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                
                if attempt < self.max_retries:
                    delay = min(self.base_delay * (2 ** attempt) + random.uniform(0, 1), self.max_delay)
                    time.sleep(delay)
                else:
                    raise last_exception
        
        raise last_exception


# Global rate limiter instances
api_limiter = RateLimiter(calls_per_minute=60, burst_limit=5)
dns_limiter = RateLimiter(calls_per_minute=100, burst_limit=10)

def rate_limited(limiter=api_limiter):
    """Decorator for rate limiting"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            limiter.wait_if_needed()
            return func(*args, **kwargs)
        return wrapper
    return decorator