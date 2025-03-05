#!/usr/bin/env python3

import sys
import os
import time
import threading
import argparse
from scapy.all import *
from colorama import init, Fore, Style
from datetime import datetime
from tqdm import tqdm
import json
import csv
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from утилиты.баннер import print_banner, print_tool_info, print_status

init()

class WiFiScanner:
    def __init__(self, interface, output_format="terminal", output_file=None):
        self.interface = interface
        self.networks = {}
        self.hidden_networks = []
        self.output_format = output_format
        self.output_file = output_file
        self.start_time = None
        self.channel_hopper = None
        self.is_running = False
        
        # Vendor MAC prefixes
        self.vendors = self.load_vendors()
    
    def load_vendors(self):
        vendors = {}
        try:
            with open(os.path.join(os.path.dirname(__file__), 'vendors.txt'), 'r') as f:
                for line in f:
                    mac_prefix, vendor = line.strip().split('\t')
                    vendors[mac_prefix] = vendor
        except:
            print_status("Не удалось загрузить базу производителей", "warning")
        return vendors
    
    def get_vendor(self, mac):
        mac = mac.replace(':', '').upper()[:6]
        return self.vendors.get(mac, "Неизвестный производитель")
    
    def analyze_packet(self, packet):
        if packet.haslayer(Dot11Beacon):
            bssid = packet[Dot11].addr2
            if bssid not in self.networks:
                ssid = packet[Dot11Elt].info.decode() if packet[Dot11Elt].info else "Hidden SSID"
                try:
                    dbm_signal = packet.dBm_AntSignal
                except:
                    dbm_signal = "N/A"
                
                # Enhanced network information
                stats = {
                    "ssid": ssid,
                    "channel": int(ord(packet[Dot11Elt:3].info)),
                    "encryption": self.get_encryption(packet),
                    "cipher": self.get_cipher(packet),
                    "auth": self.get_auth(packet),
                    "signal": dbm_signal,
                    "first_seen": datetime.now(),
                    "last_seen": datetime.now(),
                    "beacons": 1,
                    "data_packets": 0,
                    "vendor": self.get_vendor(bssid),
                    "wps": self.check_wps(packet),
                    "clients": set()
                }
                
                self.networks[bssid] = stats
                
                if ssid == "Hidden SSID" and bssid not in self.hidden_networks:
                    self.hidden_networks.append(bssid)
                    print_status(f"Скрытая сеть обнаружена: {bssid} ({stats['vendor']})", "warning")
            else:
                self.networks[bssid]["beacons"] += 1
                self.networks[bssid]["last_seen"] = datetime.now()
        
        elif packet.haslayer(Dot11):
            # Client detection
            if packet.haslayer(Dot11) and packet.type == 2:  # Data frames
                bssid = packet[Dot11].addr2
                client = packet[Dot11].addr1
                if bssid in self.networks and client not in self.networks[bssid]["clients"]:
                    self.networks[bssid]["clients"].add(client)
    
    def get_encryption(self, packet):
        crypto = set()
        
        while Dot11Elt in packet:
            try:
                if packet[Dot11Elt].ID == 48:  # RSN
                    crypto.add("WPA2")
                elif packet[Dot11Elt].ID == 221 and packet[Dot11Elt].info.startswith(b'\x00P\xf2\x01\x01\x00'):
                    crypto.add("WPA")
            except:
                pass
            packet = packet[Dot11Elt].payload
        
        if not crypto:
            if packet.haslayer(Dot11WEP):
                return "WEP"
            return "Open"
        
        return '/'.join(crypto)
    
    def get_cipher(self, packet):
        ciphers = set()
        
        while Dot11Elt in packet:
            try:
                if packet[Dot11Elt].ID == 48:
                    rsninfo = packet[Dot11Elt].info
                    if len(rsninfo) >= 8:
                        if rsninfo[7] == 4:  # CCMP
                            ciphers.add("CCMP")
                        elif rsninfo[7] == 2:  # TKIP
                            ciphers.add("TKIP")
            except:
                pass
            packet = packet[Dot11Elt].payload
        
        return '/'.join(ciphers) if ciphers else "Unknown"
    
    def get_auth(self, packet):
        auth = set()
        
        while Dot11Elt in packet:
            try:
                if packet[Dot11Elt].ID == 48:
                    rsninfo = packet[Dot11Elt].info
                    if len(rsninfo) >= 12:
                        if rsninfo[11] == 2:  # PSK
                            auth.add("PSK")
                        elif rsninfo[11] == 1:  # 802.1X
                            auth.add("802.1X")
            except:
                pass
            packet = packet[Dot11Elt].payload
        
        return '/'.join(auth) if auth else "Unknown"
    
    def check_wps(self, packet):
        while Dot11Elt in packet:
            try:
                if packet[Dot11Elt].ID == 221 and packet[Dot11Elt].info.startswith(b'\x00P\xf2\x04'):
                    return True
            except:
                pass
            packet = packet[Dot11Elt].payload
        return False
    
    def channel_hopper(self):
        while self.is_running:
            for channel in range(1, 14):
                try:
                    os.system(f"iwconfig {self.interface} channel {channel}")
                    time.sleep(0.5)
                except:
                    continue
    
    def save_results(self):
        if not self.output_file:
            return
            
        if self.output_format == "json":
            data = {
                "scan_info": {
                    "interface": self.interface,
                    "start_time": self.start_time.isoformat(),
                    "end_time": datetime.now().isoformat(),
                    "total_networks": len(self.networks),
                    "hidden_networks": len(self.hidden_networks)
                },
                "networks": {}
            }
            
            for bssid, net in self.networks.items():
                net_copy = net.copy()
                net_copy["first_seen"] = net_copy["first_seen"].isoformat()
                net_copy["last_seen"] = net_copy["last_seen"].isoformat()
                net_copy["clients"] = list(net_copy["clients"])
                data["networks"][bssid] = net_copy
            
            with open(self.output_file, 'w') as f:
                json.dump(data, f, indent=4)
                
        elif self.output_format == "csv":
            with open(self.output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["BSSID", "SSID", "Channel", "Encryption", "Cipher", "Auth", 
                               "Signal", "WPS", "Vendor", "Clients", "First Seen", "Last Seen"])
                
                for bssid, net in self.networks.items():
                    writer.writerow([
                        bssid, net["ssid"], net["channel"], net["encryption"],
                        net["cipher"], net["auth"], net["signal"], net["wps"],
                        net["vendor"], len(net["clients"]), net["first_seen"], net["last_seen"]
                    ])
    
    def print_networks(self):
        os.system('clear')
        print_banner("WiFi Scanner")
        
        print(f"\n{Fore.CYAN}=== Обнаруженные сети ==={Style.RESET_ALL}")
        headers = ["BSSID", "SSID", "Channel", "Signal", "Encryption", "Cipher", "Auth", "WPS", "Clients", "Vendor"]
        widths = [18, 25, 8, 8, 12, 10, 8, 5, 8, 30]
        
        # Print headers
        header_line = ""
        for header, width in zip(headers, widths):
            header_line += f"{Fore.BLUE}{header:<{width}}{Style.RESET_ALL}"
        print(f"\n{header_line}")
        print(f"{Fore.CYAN}{'-' * sum(widths)}{Style.RESET_ALL}")
        
        # Sort networks by signal strength
        sorted_networks = sorted(
            self.networks.items(),
            key=lambda x: x[1]['signal'] if x[1]['signal'] != "N/A" else -100,
            reverse=True
        )
        
        for bssid, data in sorted_networks:
            signal_str = str(data['signal']) if data['signal'] != "N/A" else "N/A"
            if signal_str != "N/A":
                if int(signal_str) > -50:
                    signal_color = Fore.GREEN
                elif int(signal_str) > -65:
                    signal_color = Fore.YELLOW
                else:
                    signal_color = Fore.RED
            else:
                signal_color = Fore.WHITE
            
            ssid_color = Fore.RED if data['ssid'] == "Hidden SSID" else Fore.GREEN
            wps_status = "Да" if data['wps'] else "Нет"
            
            print(
                f"{Fore.BLUE}{bssid:18}{Style.RESET_ALL}"
                f"{ssid_color}{data['ssid']:25}{Style.RESET_ALL}"
                f"{Fore.YELLOW}{data['channel']:<8}{Style.RESET_ALL}"
                f"{signal_color}{signal_str:8}{Style.RESET_ALL}"
                f"{Fore.CYAN}{data['encryption']:12}{Style.RESET_ALL}"
                f"{Fore.CYAN}{data['cipher']:10}{Style.RESET_ALL}"
                f"{Fore.CYAN}{data['auth']:8}{Style.RESET_ALL}"
                f"{Fore.RED if data['wps'] else Fore.GREEN}{wps_status:5}{Style.RESET_ALL}"
                f"{Fore.YELLOW}{len(data['clients']):8}{Style.RESET_ALL}"
                f"{Fore.WHITE}{data['vendor']:30}{Style.RESET_ALL}"
            )
        
        print(f"\n{Fore.YELLOW}[*] Всего сетей: {len(self.networks)}{Style.RESET_ALL}")
        print(f"{Fore.RED}[!] Скрытых сетей: {len(self.hidden_networks)}{Style.RESET_ALL}")
    
    def start(self):
        self.is_running = True
        self.start_time = datetime.now()
        
        # Start channel hopper
        self.channel_hopper = threading.Thread(target=self.channel_hopper)
        self.channel_hopper.daemon = True
        self.channel_hopper.start()
        
        try:
            sniff(iface=self.interface, prn=self.analyze_packet, store=0)
        except Exception as e:
            print_status(f"Ошибка: {str(e)}", "error")
            self.stop()
    
    def stop(self):
        self.is_running = False
        if self.channel_hopper:
            self.channel_hopper.join()
        self.save_results()

def main():
    parser = argparse.ArgumentParser(description="Продвинутый WiFi сканер")
    parser.add_argument("interface", help="Беспроводной интерфейс для сканирования")
    parser.add_argument("-o", "--output", help="Файл для сохранения результатов")
    parser.add_argument("-f", "--format", choices=["json", "csv"], default="json",
                      help="Формат выходного файла (json или csv)")
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print_status("Требуются права root", "error")
        sys.exit(1)
    
    interface = args.interface
    
    tool_desc = "Продвинутый WiFi сканер"
    tool_features = [
        "Обнаружение WiFi сетей в реальном времени",
        "Анализ сигнала и качества соединения",
        "Определение типов шифрования и аутентификации",
        "Обнаружение WPS",
        "Определение производителей устройств",
        "Обнаружение клиентов сети",
        "Мониторинг активности сетей",
        "Экспорт результатов в JSON/CSV"
    ]
    
    print_banner("WiFi Scanner")
    print_tool_info(tool_desc, tool_features)
    
    try:
        # Setup wireless interface
        os.system(f"ifconfig {interface} down")
        os.system(f"iwconfig {interface} mode monitor")
        os.system(f"ifconfig {interface} up")
        
        scanner = WiFiScanner(interface, args.format, args.output)
        print_status(f"Интерфейс: {interface}", "info")
        print_status("Начало сканирования...", "info")
        print_status("Нажмите Ctrl+C для остановки", "info")
        
        scanner.start()
        
    except KeyboardInterrupt:
        scanner.stop()
        scanner.print_networks()
        
        # Restore wireless interface
        os.system(f"ifconfig {interface} down")
        os.system(f"iwconfig {interface} mode managed")
        os.system(f"ifconfig {interface} up")
        
        sys.exit(0)
    except Exception as e:
        print_status(f"Критическая ошибка: {str(e)}", "error")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_status("\nПрограмма остановлена пользователем", "warning")
        sys.exit(0) 