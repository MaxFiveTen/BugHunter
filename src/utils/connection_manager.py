"""
Advanced connection manager with rate limiting, stealth mode, and anti-detection features.
"""

import asyncio
import aiohttp
import random
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import ssl
import json
from datetime import datetime, timedelta

@dataclass
class RequestStats:
    """Track request statistics for rate limiting."""
    requests_made: int = 0
    last_request_time: float = 0
    requests_per_minute: int = 0
    blocked_requests: int = 0

class StealthConnectionManager:
    """Advanced connection manager with stealth and rate limiting capabilities."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.request_stats = RequestStats()
        self.user_agents = self._load_user_agents()
        self.session: Optional[aiohttp.ClientSession] = None
        self.rate_limit_delay = config.get('rate_limit_delay', 2.0)  # Base delay between requests
        self.max_requests_per_minute = config.get('max_requests_per_minute', 30)
        self.stealth_mode = config.get('stealth_mode', True)
        self.retry_attempts = config.get('retry_attempts', 3)
        self.timeout = config.get('request_timeout', 30)
        self.proxy_list = config.get('proxies', [])
        self.current_proxy_index = 0
        
    def _load_user_agents(self) -> List[str]:
        """Load realistic user agents for rotation."""
        return [
            # Chrome browsers
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            
            # Firefox browsers
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
            
            # Safari browsers
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
            
            # Edge browsers
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            
            # Mobile browsers
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            
            # Bot-like but legitimate
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        ]
    
    async def initialize_session(self):
        """Initialize the aiohttp session with stealth configurations."""
        if self.session:
            await self.session.close()
            
        # SSL context with relaxed settings for testing
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Connection settings
        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            limit=100,  # Total connection pool size
            limit_per_host=10,  # Per-host connection limit
            keepalive_timeout=30,
            enable_cleanup_closed=True,
            use_dns_cache=True,
            ttl_dns_cache=300,
        )
        
        # Timeout settings
        timeout = aiohttp.ClientTimeout(
            total=self.timeout,
            connect=10,
            sock_read=20
        )
        
        # Headers with realistic browser fingerprint (removed br to avoid Brotli issues)
        headers = {
            'User-Agent': self._get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Proxy configuration
        proxy = self._get_next_proxy() if self.proxy_list else None
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers,
            proxy=proxy,
            auto_decompress=True,
            raise_for_status=False,
        )
        
    def _get_random_user_agent(self) -> str:
        """Get a random user agent."""
        return random.choice(self.user_agents)
    
    def _get_next_proxy(self) -> Optional[str]:
        """Get the next proxy in rotation."""
        if not self.proxy_list:
            return None
        proxy = self.proxy_list[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxy_list)
        return proxy
    
    async def _rate_limit_delay(self):
        """Implement intelligent rate limiting."""
        current_time = time.time()
        
        # Reset minute counter if needed
        if current_time - self.request_stats.last_request_time > 60:
            self.request_stats.requests_per_minute = 0
        
        # Check if we're hitting rate limits
        if self.request_stats.requests_per_minute >= self.max_requests_per_minute:
            sleep_time = 60 - (current_time - self.request_stats.last_request_time)
            if sleep_time > 0:
                print(f"⏳ Rate limit reached, sleeping for {sleep_time:.1f} seconds...")
                await asyncio.sleep(sleep_time)
                self.request_stats.requests_per_minute = 0
        
        # Base delay with randomization
        base_delay = self.rate_limit_delay
        if self.stealth_mode:
            # Add random delay between 0.5x and 2x base delay
            delay = base_delay * (0.5 + random.random() * 1.5)
            try:
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                # Handle cancellation gracefully
                return
        
        self.request_stats.last_request_time = current_time
        self.request_stats.requests_per_minute += 1
    
    async def make_request(self, method: str, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make a request with rate limiting and retry logic."""
        for attempt in range(self.retry_attempts):
            try:
                # Rate limiting
                await self._rate_limit_delay()
                
                # Rotate user agent occasionally
                if random.random() < 0.1:  # 10% chance to rotate
                    if self.session:
                        self.session.headers.update({'User-Agent': self._get_random_user_agent()})
                
                # Make the request
                if not self.session:
                    await self.initialize_session()
                
                response = await self.session.request(method, url, **kwargs)
                
                # Handle common blocking responses
                if response.status in [429, 503, 502, 504]:
                    self.request_stats.blocked_requests += 1
                    wait_time = min(2 ** attempt, 10)  # Cap exponential backoff at 10 seconds
                    print(f"⚠️ Request blocked (HTTP {response.status}), retrying in {wait_time}s...")
                    try:
                        await asyncio.sleep(wait_time)
                    except asyncio.CancelledError:
                        return None
                    continue
                
                # Success
                self.request_stats.requests_made += 1
                return response
                
            except (aiohttp.ClientError, asyncio.TimeoutError, asyncio.CancelledError) as e:
                if isinstance(e, asyncio.CancelledError):
                    print(f"⚠️ Request cancelled")
                    return None
                print(f"⚠️ Request failed (attempt {attempt + 1}/{self.retry_attempts}): {str(e)}")
                if attempt < self.retry_attempts - 1:
                    wait_time = min(2 ** attempt, 5)  # Cap retry delay at 5 seconds
                    try:
                        await asyncio.sleep(wait_time)
                    except asyncio.CancelledError:
                        return None
                else:
                    self.request_stats.blocked_requests += 1
                    return None
        
        return None
    
    async def get(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make a GET request."""
        return await self.make_request('GET', url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make a POST request."""
        return await self.make_request('POST', url, **kwargs)
    
    async def close(self):
        """Close the session."""
        if self.session:
            await self.session.close()
            self.session = None
    
    def get_stats(self) -> Dict[str, Any]:
        """Get request statistics."""
        return {
            'requests_made': self.request_stats.requests_made,
            'requests_per_minute': self.request_stats.requests_per_minute,
            'blocked_requests': self.request_stats.blocked_requests,
            'success_rate': (
                self.request_stats.requests_made / 
                max(1, self.request_stats.requests_made + self.request_stats.blocked_requests)
            ) * 100
        }
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.initialize_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
