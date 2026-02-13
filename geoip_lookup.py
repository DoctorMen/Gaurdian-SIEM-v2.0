"""
Guardian SIEM v2.0 — GeoIP Lookup Module
Resolves IP addresses to geographic locations using MaxMind GeoLite2.
Falls back to ip-api.com (free, no key required) when GeoLite2 DB is unavailable.
"""

import os
import json
import sqlite3
import time
from datetime import datetime

try:
    import geoip2.database
    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class GeoIPCache:
    """Local cache for GeoIP lookups to avoid repeated queries."""

    def __init__(self, db_path):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute('''CREATE TABLE IF NOT EXISTS geoip_cache (
            ip TEXT PRIMARY KEY,
            country TEXT,
            country_code TEXT,
            city TEXT,
            region TEXT,
            latitude REAL,
            longitude REAL,
            isp TEXT,
            cached_at REAL
        )''')
        conn.commit()
        conn.close()

    def get(self, ip, ttl_hours=168):
        """Retrieve cached GeoIP data (default TTL: 7 days)."""
        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT country, country_code, city, region, latitude, longitude, isp, cached_at "
            "FROM geoip_cache WHERE ip=?", (ip,)
        ).fetchone()
        conn.close()

        if row is None:
            return None
        if time.time() - row[7] > ttl_hours * 3600:
            return None

        return {
            "ip": ip, "country": row[0], "country_code": row[1],
            "city": row[2], "region": row[3],
            "latitude": row[4], "longitude": row[5], "isp": row[6],
            "cached": True,
        }

    def put(self, ip, data):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT OR REPLACE INTO geoip_cache "
            "(ip, country, country_code, city, region, latitude, longitude, isp, cached_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ip, data.get("country", ""), data.get("country_code", ""),
             data.get("city", ""), data.get("region", ""),
             data.get("latitude", 0), data.get("longitude", 0),
             data.get("isp", ""), time.time())
        )
        conn.commit()
        conn.close()


class GeoIPLookup:
    """Resolves IP addresses to geographic locations."""

    def __init__(self, geoip_db_path=None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        if geoip_db_path is None:
            geoip_db_path = os.path.join(base_dir, "database", "GeoLite2-City.mmdb")

        self.geoip_db_path = geoip_db_path
        self.reader = None
        self.cache = GeoIPCache(os.path.join(base_dir, "database", "geoip_cache.db"))

        if HAS_GEOIP2 and os.path.exists(geoip_db_path):
            try:
                self.reader = geoip2.database.Reader(geoip_db_path)
                print("[GeoIP] MaxMind GeoLite2 database loaded")
            except Exception as e:
                print(f"[GeoIP] Failed to load GeoLite2: {e}. Falling back to ip-api.com")
        else:
            print("[GeoIP] GeoLite2 not available. Using ip-api.com fallback (rate-limited: 45 req/min)")

    def lookup(self, ip_address):
        """
        Look up geographic location for an IP address.

        Args:
            ip_address: IPv4 or IPv6 address string

        Returns:
            Dict with country, city, lat/lon, ISP, etc.
        """
        # Skip private/reserved IPs
        if self._is_private(ip_address):
            return {
                "ip": ip_address, "country": "Private", "country_code": "--",
                "city": "Local Network", "region": "", "latitude": 0, "longitude": 0,
                "isp": "Private Network", "cached": False,
            }

        # Check cache
        cached = self.cache.get(ip_address)
        if cached:
            return cached

        # Try MaxMind first, then fallback
        if self.reader:
            result = self._lookup_maxmind(ip_address)
        else:
            result = self._lookup_ipapi(ip_address)

        if result:
            self.cache.put(ip_address, result)

        return result or {
            "ip": ip_address, "country": "Unknown", "country_code": "??",
            "city": "Unknown", "region": "", "latitude": 0, "longitude": 0,
            "isp": "Unknown", "cached": False,
        }

    def _lookup_maxmind(self, ip_address):
        """Query local MaxMind GeoLite2 database."""
        try:
            response = self.reader.city(ip_address)
            return {
                "ip": ip_address,
                "country": response.country.name or "Unknown",
                "country_code": response.country.iso_code or "??",
                "city": response.city.name or "Unknown",
                "region": response.subdivisions.most_specific.name if response.subdivisions else "",
                "latitude": response.location.latitude or 0,
                "longitude": response.location.longitude or 0,
                "isp": "",
                "cached": False,
            }
        except Exception:
            return self._lookup_ipapi(ip_address)

    def _lookup_ipapi(self, ip_address):
        """Fallback: query ip-api.com (free, no API key, 45 req/min)."""
        if not HAS_REQUESTS:
            return None
        try:
            resp = requests.get(
                f"http://ip-api.com/json/{ip_address}?fields=status,country,countryCode,regionName,city,lat,lon,isp",
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "ip": ip_address,
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("countryCode", "??"),
                        "city": data.get("city", "Unknown"),
                        "region": data.get("regionName", ""),
                        "latitude": data.get("lat", 0),
                        "longitude": data.get("lon", 0),
                        "isp": data.get("isp", "Unknown"),
                        "cached": False,
                    }
        except Exception:
            pass
        return None

    @staticmethod
    def _is_private(ip_address):
        """Check if an IP is in a private/reserved range."""
        parts = ip_address.split(".")
        if len(parts) != 4:
            return False
        try:
            first, second = int(parts[0]), int(parts[1])
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:
                return True
        except ValueError:
            return False
        return False

    def __del__(self):
        if self.reader:
            try:
                self.reader.close()
            except Exception:
                pass


if __name__ == "__main__":
    geo = GeoIPLookup()
    print("\n--- GeoIP Lookup Test ---")
    test_ips = ["8.8.8.8", "1.1.1.1", "192.168.1.1", "104.26.10.78"]
    for ip in test_ips:
        result = geo.lookup(ip)
        print(f"  {ip}: {result['city']}, {result['country']} ({result['country_code']}) "
              f"[{result['latitude']}, {result['longitude']}]")
