#!/usr/bin/env python3
"""
rule_engine.py - Complete rule matching with geosite, geoip, regex support
"""

import re
import socket
import ipaddress
from typing import Set, Tuple, Optional, List, Dict
from geosite_parser import GeositeManager
from geoip_parser import GeoIPManager
import logging

log = logging.getLogger("GeoParser")

_GEOSITE_MANAGER = GeositeManager("geosite.dat")
_GEOIP_MANAGER = GeoIPManager("geoip.dat")


class GeoIPChecker:
    """Simple geoip checker - IPv4 only"""
    
    def __init__(self, geoip_manager):
        self.geoip_manager = geoip_manager
        self._cidr_cache: Dict[str, List[Tuple[int, int]]] = {}
    
    def _ip_to_int(self, ip: str) -> Optional[int]:
        """Convert IPv4 to integer - IPv6 not supported"""
        if ':' in ip:
            return None
        
        parts = ip.split('.')
        if len(parts) != 4:
            return None
        
        try:
            return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
        except:
            return None
    
    def _cidr_to_range(self, cidr: str) -> Tuple[Optional[int], Optional[int]]:
        """Convert CIDR to (start_int, end_int) - IPv4 only"""
        if ':' in cidr:
            return (None, None)
        
        if '/' in cidr:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                if ':' in str(network.network_address):
                    return (None, None)
                
                start = self._ip_to_int(str(network.network_address))
                end = self._ip_to_int(str(network.broadcast_address))
                if start is None or end is None:
                    return (None, None)
                return (start, end)
            except:
                return (None, None)
        else:
            ip_int = self._ip_to_int(cidr)
            if ip_int is None:
                return (None, None)
            return (ip_int, ip_int)
    
    def _get_country_ranges(self, country_code: str) -> List[Tuple[int, int]]:
        """Get IP ranges for country as integer ranges - IPv4 only"""
        country_upper = country_code.upper()
        
        if country_upper in self._cidr_cache:
            return self._cidr_cache[country_upper]
        
        ranges = []
        cidrs = self.geoip_manager.get_ip_ranges_by_country(country_code)
        
        for cidr in cidrs:
            if ':' not in cidr:
                start, end = self._cidr_to_range(cidr)
                if start is not None:
                    ranges.append((start, end))
        
        ranges.sort(key=lambda x: x[0])
        self._cidr_cache[country_upper] = ranges
        return ranges
    
    def _get_ip(self, host: str) -> Optional[str]:
        """Get IP from host (domain or IP)"""
        try:
            ipaddress.ip_address(host)
            return host
        except:
            pass
        
        try:
            return socket.gethostbyname(host)
        except:
            return None
    
    def check(self, host: str, country_code: str) -> bool:
        """Check if host IP belongs to country - IPv4 only"""
        ip = self._get_ip(host)
        if ip is None or ':' in ip:
            return False
        
        ip_int = self._ip_to_int(ip)
        if ip_int is None:
            return False
        
        ranges = self._get_country_ranges(country_code)
        
        left, right = 0, len(ranges) - 1
        while left <= right:
            mid = (left + right) // 2
            start, end = ranges[mid]
            
            if ip_int < start:
                right = mid - 1
            elif ip_int > end:
                left = mid + 1
            else:
                return True
        
        return False


class RuleEngine:
    """Main rule matching engine"""
    
    def __init__(self, geosite_manager=None, geoip_manager=None):
        self.geosite_manager = geosite_manager
        self.geoip_checker = GeoIPChecker(geoip_manager) if geoip_manager else None
        self._geosite_cache: Dict[str, Tuple[Set[str], Tuple[str, ...]]] = {}
    
    def _parse_rule_type(self, rule: str) -> Tuple[str, str]:
        """Parse rule and return (type, value)"""
        if rule.startswith("geosite:"):
            return ("geosite", rule[8:])
        elif rule.startswith("geoip:"):
            return ("geoip", rule[6:])
        elif rule.startswith("regex:"):
            return ("regex", rule[6:])
        else:
            return ("exact", rule)
    
    def _geosite_to_rules(self, tag: str) -> Tuple[Set[str], Tuple[str, ...]]:
        """Convert geosite tag to (exact_domains, suffixes)"""
        if tag in self._geosite_cache:
            return self._geosite_cache[tag]
        
        exact = set()
        suffixes = set()
        
        if self.geosite_manager:
            domains = self.geosite_manager.extract_domains_by_geosite(tag, silent=True)
            
            for domain in domains:
                domain = domain.lower().rstrip('.')
                if domain.startswith('.'):
                    suffixes.add(domain[1:])
                else:
                    exact.add(domain)
        
        result = (exact, tuple(suffixes))
        self._geosite_cache[tag] = result
        return result
    
    def _match_geosite(self, host: str, tag: str) -> bool:
        """Check if host matches a geosite tag"""
        exact, suffixes = self._geosite_to_rules(tag)
        normalized = host.lower().rstrip('.')
        
        if normalized in exact:
            return True
        
        for suffix in suffixes:
            if normalized == suffix or normalized.endswith('.' + suffix):
                return True
        
        return False
    
    def _match_regex(self, host: str, pattern: str) -> bool:
        """Check if host matches regex pattern"""
        try:
            return bool(re.search(pattern, host, re.IGNORECASE))
        except re.error:
            return False
    
    def match_host_with_rules(self, host: str, rules: tuple[set[str], tuple[str, ...]]) -> bool:
        """Match host with rules in order: exact -> regex -> geosite -> geoip"""
        
        normalized = host.lower().rstrip('.')
        
        # چک کردن legacy rules اول
        exact_legacy, suffixes_legacy = rules
        if normalized in exact_legacy:
            return True
        if any(normalized.endswith(suffix) for suffix in suffixes_legacy):
            return True
        
        # جدا کردن رول‌ها از exact_legacy
        exact_rules = []
        regex_rules = []
        geosite_rules = []
        geoip_rules = []
        
        for rule in exact_legacy:
            rule_type, value = self._parse_rule_type(rule)
            if rule_type == "exact":
                exact_rules.append(value)
            elif rule_type == "regex":
                regex_rules.append(value)
            elif rule_type == "geosite":
                geosite_rules.append(value)
            elif rule_type == "geoip":
                geoip_rules.append(value)
        
        # مرحله 1: exact
        for value in exact_rules:
            if normalized == value.lower().rstrip('.'):
                return True
        
        # مرحله 2: regex
        for pattern in regex_rules:
            if self._match_regex(host, pattern):
                return True
        
        # مرحله 3: geosite
        for tag in geosite_rules:
            if self.geosite_manager and self._match_geosite(host, tag):
                return True
        
        # مرحله 4: geoip
        for country in geoip_rules:
            if self.geoip_checker and self.geoip_checker.check(host, country):
                return True
        
        return False


# Enhanced version with geosite/geoip/regex support
def match_host_with_rules(host: str, rules: tuple[set[str], tuple[str, ...]]) -> bool:
    try:
        _GEOSITE_MANAGER._ensure_parser(silent=False)       
        _GEOIP_MANAGER.load()
    except:
        pass
    engine = RuleEngine(_GEOSITE_MANAGER, _GEOIP_MANAGER)
    return engine.match_host_with_rules(host, rules)


if __name__ == "__main__":
    print("Rule Engine Test")
    print("="*50)
    
    exact = {'google.com', 'youtube.com', 'geosite:github', 'geoip:ir'}
    suffixes = ('.google.com', '.youtube.com')
    rules = (exact, suffixes)
    
    test_hosts = ["google.com", "github.com", "8.8.8.8", "tabnak.ir"]
    
    for host in test_hosts:
        result = match_host_with_rules(host, rules)
        print(f"{host}: {result}")