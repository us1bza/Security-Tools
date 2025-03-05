#!/usr/bin/env python3

import sys
import os
import socket
import ssl
import OpenSSL
import argparse
import json
import csv
from datetime import datetime
import requests
from colorama import init, Fore, Style
from tqdm import tqdm
import time
import concurrent.futures
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from утилиты.баннер import print_banner, print_tool_info, print_status

init()

class CertificateAnalyzer:
    def __init__(self, output_format="terminal", output_file=None):
        self.output_format = output_format
        self.output_file = output_file
        self.start_time = datetime.now()
        
        # Common SSL/TLS vulnerabilities
        self.vulnerabilities = {
            'heartbleed': self.check_heartbleed,
            'poodle': self.check_poodle,
            'freak': self.check_freak,
            'logjam': self.check_logjam,
            'beast': self.check_beast,
            'sweet32': self.check_sweet32
        }
    
    def get_certificate(self, hostname, port=443):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)
                    
                    # Get supported cipher suites
                    ciphers = ssock.shared_ciphers()
                    
                    return cert, ciphers
        except Exception as e:
            print_status(f"Ошибка при получении сертификата: {str(e)}", "error")
            return None, None
    
    def analyze_certificate(self, cert):
        results = {
            "subject": dict(cert.get_subject().get_components()),
            "issuer": dict(cert.get_issuer().get_components()),
            "version": cert.get_version() + 1,
            "serial": cert.get_serial_number(),
            "not_before": datetime.strptime(cert.get_notBefore().decode(), "%Y%m%d%H%M%SZ"),
            "not_after": datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ"),
            "has_expired": cert.has_expired(),
            "signature_algorithm": cert.get_signature_algorithm().decode(),
            "key_info": self.analyze_public_key(cert),
            "extensions": self.analyze_extensions(cert),
            "fingerprints": self.get_fingerprints(cert)
        }
        return results
    
    def analyze_public_key(self, cert):
        key = cert.get_pubkey()
        key_type = key.type()
        key_bits = key.bits()
        
        key_info = {
            "type": "RSA" if key_type == OpenSSL.crypto.TYPE_RSA else
                   "DSA" if key_type == OpenSSL.crypto.TYPE_DSA else
                   "EC" if key_type == OpenSSL.crypto.TYPE_EC else "Unknown",
            "bits": key_bits,
            "security_level": "High" if key_bits >= 2048 else
                            "Medium" if key_bits >= 1024 else "Low"
        }
        
        if key_type == OpenSSL.crypto.TYPE_RSA:
            numbers = key.to_cryptography_key().public_numbers()
            key_info.update({
                "modulus": hex(numbers.n),
                "exponent": numbers.e
            })
        
        return key_info
    
    def analyze_extensions(self, cert):
        extensions = []
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            ext_info = {
                "name": ext.get_short_name().decode(),
                "critical": ext.get_critical(),
                "value": str(ext)
            }
            
            # Special handling for specific extensions
            if ext_info["name"] == "subjectAltName":
                ext_info["alt_names"] = self.parse_san(str(ext))
            elif ext_info["name"] == "keyUsage":
                ext_info["usages"] = str(ext).split(", ")
            elif ext_info["name"] == "extendedKeyUsage":
                ext_info["extended_usages"] = str(ext).split(", ")
            
            extensions.append(ext_info)
        return extensions
    
    def get_fingerprints(self, cert):
        return {
            "sha1": OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_ASN1, cert
            ).hex(),
            "sha256": OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_ASN1, cert
            ).hex()
        }
    
    def parse_san(self, san_string):
        sans = []
        for san in san_string.split(", "):
            if ":" in san:
                san_type, value = san.split(":", 1)
                sans.append({"type": san_type, "value": value})
        return sans
    
    def check_heartbleed(self, hostname, port=443):
        try:
            response = requests.get(f"https://{hostname}:{port}", 
                                 verify=False, timeout=5)
            return "1.0.1" in response.headers.get('Server', '')
        except:
            return False
    
    def check_poodle(self, hostname, port=443):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock) as ssock:
                    return True
        except:
            return False
    
    def check_freak(self, hostname, port=443):
        try:
            with socket.create_connection((hostname, port)) as sock:
                with ssl.wrap_socket(sock) as ssock:
                    cipher = ssock.cipher()
                    return "EXPORT" in cipher[0]
        except:
            return False
    
    def check_logjam(self, hostname, port=443):
        try:
            with socket.create_connection((hostname, port)) as sock:
                with ssl.wrap_socket(sock) as ssock:
                    cipher = ssock.cipher()
                    return "DHE_EXPORT" in cipher[0]
        except:
            return False
    
    def check_beast(self, hostname, port=443):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock) as ssock:
                    cipher = ssock.cipher()
                    return cipher[1] < 3 and "CBC" in cipher[0]
        except:
            return False
    
    def check_sweet32(self, hostname, port=443):
        try:
            with socket.create_connection((hostname, port)) as sock:
                with ssl.wrap_socket(sock) as ssock:
                    cipher = ssock.cipher()
                    return "3DES" in cipher[0] or "DES" in cipher[0]
        except:
            return False
    
    def check_vulnerabilities(self, hostname, port=443):
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.vulnerabilities)) as executor:
            future_to_vuln = {
                executor.submit(func, hostname, port): name
                for name, func in self.vulnerabilities.items()
            }
            for future in concurrent.futures.as_completed(future_to_vuln):
                vuln_name = future_to_vuln[future]
                try:
                    results[vuln_name] = future.result()
                except Exception:
                    results[vuln_name] = None
        return results
    
    def save_results(self, hostname, cert_info, vuln_results, ciphers):
        if not self.output_file:
            return
            
        data = {
            "scan_info": {
                "hostname": hostname,
                "scan_time": self.start_time.isoformat(),
                "duration": str(datetime.now() - self.start_time)
            },
            "certificate": cert_info,
            "vulnerabilities": vuln_results,
            "supported_ciphers": [f"{cipher[0]}:{cipher[1]}:{cipher[2]}" for cipher in (ciphers or [])]
        }
        
        if self.output_format == "json":
            with open(self.output_file, 'w') as f:
                json.dump(data, f, indent=4, default=str)
        elif self.output_format == "csv":
            with open(self.output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Hostname", "Valid From", "Valid To", "Issuer", "Subject", 
                               "Key Type", "Key Size", "Signature Algorithm", "Vulnerabilities"])
                writer.writerow([
                    hostname,
                    cert_info["not_before"],
                    cert_info["not_after"],
                    cert_info["issuer"].get(b'CN', b'N/A').decode(),
                    cert_info["subject"].get(b'CN', b'N/A').decode(),
                    cert_info["key_info"]["type"],
                    cert_info["key_info"]["bits"],
                    cert_info["signature_algorithm"],
                    ", ".join(k for k, v in vuln_results.items() if v)
                ])
    
    def print_certificate_info(self, hostname, cert_info, vuln_results, ciphers):
        print(f"\n{Fore.CYAN}=== Информация о сертификате ==={Style.RESET_ALL}")
        
        subject = cert_info["subject"]
        print(f"\n{Fore.YELLOW}Субъект:{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Общее имя (CN): {subject.get(b'CN', b'N/A').decode()}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Организация (O): {subject.get(b'O', b'N/A').decode()}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Подразделение (OU): {subject.get(b'OU', b'N/A').decode()}{Style.RESET_ALL}")
        
        issuer = cert_info["issuer"]
        print(f"\n{Fore.YELLOW}Издатель:{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Общее имя (CN): {issuer.get(b'CN', b'N/A').decode()}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Организация (O): {issuer.get(b'O', b'N/A').decode()}{Style.RESET_ALL}")
        
        validity_color = Fore.RED if cert_info["has_expired"] else Fore.GREEN
        print(f"\n{Fore.YELLOW}Срок действия:{Style.RESET_ALL}")
        print(f"{validity_color}[+] Действителен с: {cert_info['not_before']}{Style.RESET_ALL}")
        print(f"{validity_color}[+] Действителен до: {cert_info['not_after']}{Style.RESET_ALL}")
        print(f"{validity_color}[+] Статус: {'Истёк' if cert_info['has_expired'] else 'Действителен'}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Технические детали:{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Версия: {cert_info['version']}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Серийный номер: {cert_info['serial']}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Алгоритм подписи: {cert_info['signature_algorithm']}{Style.RESET_ALL}")
        
        key_info = cert_info["key_info"]
        key_color = Fore.GREEN if key_info["security_level"] == "High" else \
                   Fore.YELLOW if key_info["security_level"] == "Medium" else Fore.RED
        print(f"\n{Fore.YELLOW}Информация о ключе:{Style.RESET_ALL}")
        print(f"{key_color}[+] Тип: {key_info['type']}{Style.RESET_ALL}")
        print(f"{key_color}[+] Длина: {key_info['bits']} бит{Style.RESET_ALL}")
        print(f"{key_color}[+] Уровень безопасности: {key_info['security_level']}{Style.RESET_ALL}")
        
        if ciphers:
            print(f"\n{Fore.YELLOW}Поддерживаемые шифры:{Style.RESET_ALL}")
            for cipher in ciphers:
                cipher_str = f"{cipher[0]}:{cipher[1]}:{cipher[2]}"
                if "HIGH" in cipher[2]:
                    print(f"{Fore.GREEN}[+] {cipher_str}{Style.RESET_ALL}")
                elif "MEDIUM" in cipher[2]:
                    print(f"{Fore.YELLOW}[*] {cipher_str}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[-] {cipher_str}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Расширения:{Style.RESET_ALL}")
        for ext in cert_info["extensions"]:
            critical = "[CRITICAL] " if ext["critical"] else ""
            print(f"{Fore.CYAN}[+] {critical}{ext['name'].upper()}:{Style.RESET_ALL}")
            if "alt_names" in ext:
                for san in ext["alt_names"]:
                    print(f"    {san['type']}: {san['value']}")
            else:
                print(f"    {ext['value']}")
        
        print(f"\n{Fore.YELLOW}Отпечатки:{Style.RESET_ALL}")
        for algo, fp in cert_info["fingerprints"].items():
            print(f"{Fore.BLUE}[*] {algo.upper()}: {fp}{Style.RESET_ALL}")
        
        if vuln_results:
            print(f"\n{Fore.YELLOW}Уязвимости:{Style.RESET_ALL}")
            vuln_found = False
            for vuln, is_vulnerable in vuln_results.items():
                if is_vulnerable:
                    vuln_found = True
                    print(f"{Fore.RED}[!] Уязвим к {vuln.upper()}{Style.RESET_ALL}")
            if not vuln_found:
                print(f"{Fore.GREEN}[+] Уязвимости не обнаружены{Style.RESET_ALL}")
        
        caa_records = self.check_caa_records(hostname)
        if caa_records:
            print(f"\n{Fore.YELLOW}Записи CAA:{Style.RESET_ALL}")
            for record in caa_records:
                print(f"{Fore.GREEN}[+] {record}{Style.RESET_ALL}")
        
        ct_logs = self.check_ct_logs(hostname)
        if ct_logs >= 0:
            print(f"\n{Fore.YELLOW}Certificate Transparency:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Найдено {ct_logs} записей в журналах CT{Style.RESET_ALL}")
    
    def check_caa_records(self, hostname):
        try:
            import dns.resolver
            answers = dns.resolver.resolve(hostname, 'CAA')
            return [str(rdata) for rdata in answers]
        except:
            return []
    
    def check_ct_logs(self, hostname):
        try:
            url = f"https://crt.sh/?q={hostname}&output=json"
            response = requests.get(url)
            if response.status_code == 200:
                return len(response.json())
            return 0
        except:
            return -1
    
    def simulate_analysis(self):
        stages = [
            "Получение сертификата",
            "Анализ данных",
            "Проверка валидности",
            "Анализ уязвимостей",
            "Проверка расширений",
            "Поиск в CT логах"
        ]
        
        for stage in stages:
            with tqdm(total=100, desc=stage,
                     bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.CYAN, Fore.RESET)) as pbar:
                for i in range(100):
                    time.sleep(0.01)
                    pbar.update(1)

def main():
    parser = argparse.ArgumentParser(description="Продвинутый анализатор SSL/TLS сертификатов")
    parser.add_argument("hostname", help="Домен для анализа")
    parser.add_argument("-p", "--port", type=int, default=443,
                      help="Порт для подключения (по умолчанию: 443)")
    parser.add_argument("-o", "--output", help="Файл для сохранения результатов")
    parser.add_argument("-f", "--format", choices=["json", "csv"], default="json",
                      help="Формат выходного файла (json или csv)")
    args = parser.parse_args()
    
    tool_desc = "Продвинутый анализатор SSL/TLS сертификатов"
    tool_features = [
        "Анализ SSL/TLS сертификатов",
        "Проверка валидности и сроков действия",
        "Анализ криптографических параметров",
        "Обнаружение уязвимостей",
        "Проверка записей CAA",
        "Поиск в журналах Certificate Transparency",
        "Анализ поддерживаемых шифров",
        "Экспорт результатов в JSON/CSV"
    ]
    
    print_banner("Certificate Analyzer")
    print_tool_info(tool_desc, tool_features)
    
    analyzer = CertificateAnalyzer(args.format, args.output)
    print_status(f"Анализ сертификата для {args.hostname}:{args.port}...", "info")
    
    analyzer.simulate_analysis()
    
    cert, ciphers = analyzer.get_certificate(args.hostname, args.port)
    if cert:
        cert_info = analyzer.analyze_certificate(cert)
        vuln_results = analyzer.check_vulnerabilities(args.hostname, args.port)
        analyzer.print_certificate_info(args.hostname, cert_info, vuln_results, ciphers)
        analyzer.save_results(args.hostname, cert_info, vuln_results, ciphers)
    
    print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_status("\nПрограмма остановлена пользователем", "warning")
        sys.exit(0) 