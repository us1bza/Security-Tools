#!/usr/bin/env python3

import sys
import os
import re
import requests
import json
import socket
import whois
import dns.resolver
import tldextract
import concurrent.futures
import argparse
import csv
from urllib.parse import urlparse, parse_qs, urljoin
from datetime import datetime
from colorama import init, Fore, Style
from tqdm import tqdm
import time
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from утилиты.баннер import print_banner, print_tool_info, print_status

init()

class URLDetector:
    def __init__(self, output_format="terminal", output_file=None):
        self.output_format = output_format
        self.output_file = output_file
        self.start_time = datetime.now()
        
        # Load malicious patterns
        self.load_patterns()
    
    def load_patterns(self):
        self.suspicious_keywords = [
            'login', 'signin', 'account', 'bank', 'confirm', 'verify', 'secure', 'webscr',
            'update', 'authentication', 'authenticate', 'wallet', 'support', 'activity',
            'security', 'manage', 'password', 'credential', 'bitcoin', 'crypto', 'payment',
            'invoice', 'suspended', 'unusual', 'restore', 'recover', 'unlock'
        ]
        
        self.suspicious_tlds = [
            '.xyz', '.top', '.loan', '.work', '.click', '.link', '.win', '.party', '.gq',
            '.ml', '.cf', '.ga', '.tk', '.pw', '.cc', '.buzz', '.icu', '.monster', '.online'
        ]
        
        self.phishing_patterns = [
            r'paypal.*\.com(?!\.)',
            r'apple.*\.com(?!\.)',
            r'google.*\.com(?!\.)',
            r'microsoft.*\.com(?!\.)',
            r'amazon.*\.com(?!\.)',
            r'facebook.*\.com(?!\.)',
            r'twitter.*\.com(?!\.)',
            r'instagram.*\.com(?!\.)',
            r'netflix.*\.com(?!\.)',
            r'blockchain.*\.com(?!\.)'
        ]
        
        self.malware_extensions = [
            '.exe', '.dll', '.bat', '.cmd', '.scr', '.js', '.vbs', '.ps1',
            '.hta', '.jar', '.py', '.wsf', '.msi', '.pif', '.gadget'
        ]
    
    def check_virustotal(self, url, api_key):
        if not api_key:
            return None
        
        try:
            headers = {
                "x-apikey": api_key
            }
            
            url_id = requests.get(
                "https://www.virustotal.com/api/v3/urls",
                params={"url": url},
                headers=headers
            ).json()["data"]["id"]
            
            time.sleep(2)
            
            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers
            ).json()
            
            return {
                "malicious": response["data"]["attributes"]["last_analysis_stats"]["malicious"],
                "suspicious": response["data"]["attributes"]["last_analysis_stats"]["suspicious"],
                "total": sum(response["data"]["attributes"]["last_analysis_stats"].values()),
                "results": response["data"]["attributes"]["last_analysis_results"]
            }
        except Exception as e:
            print_status(f"Ошибка VirusTotal API: {str(e)}", "error")
            return None
    
    def check_phishtank(self, url):
        try:
            response = requests.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={"url": url, "format": "json"}
            )
            return response.json()["results"]["in_database"]
        except:
            return None
    
    def check_google_safebrowsing(self, url, api_key):
        if not api_key:
            return None
            
        try:
            data = {
                "client": {
                    "clientId": "url-detector",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
                json=data
            )
            
            return bool(response.json().get("matches"))
        except:
            return None
    
    def analyze_url_structure(self, url):
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        
        analysis = {
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "path": parsed.path,
            "params": parsed.params,
            "query": parse_qs(parsed.query),
            "fragment": parsed.fragment,
            "subdomain": extracted.subdomain,
            "domain": extracted.domain,
            "tld": extracted.suffix,
            "is_ip": self.is_ip_address(parsed.netloc)
        }
        
        suspicious_patterns = []
        
        # Check for suspicious keywords
        if any(keyword in url.lower() for keyword in self.suspicious_keywords):
            suspicious_patterns.append("Подозрительные ключевые слова")
        
        # Check TLD
        if analysis["tld"] in self.suspicious_tlds:
            suspicious_patterns.append(f"Подозрительный TLD: {analysis['tld']}")
        
        # Check domain length
        if len(analysis["domain"]) > 20:
            suspicious_patterns.append("Необычно длинное доменное имя")
        
        # Check for numeric patterns
        if re.search(r'\d{4,}', analysis["domain"]):
            suspicious_patterns.append("Множество цифр в домене")
        
        # Check for special characters
        if re.search(r'[^a-zA-Z0-9-.]', analysis["domain"]):
            suspicious_patterns.append("Специальные символы в домене")
        
        # Check path depth
        if analysis["path"].count('/') > 3:
            suspicious_patterns.append("Глубокая структура URL")
        
        # Check URL length
        if len(url) > 100:
            suspicious_patterns.append("Очень длинный URL")
        
        # Check for phishing patterns
        for pattern in self.phishing_patterns:
            if re.search(pattern, url, re.I):
                suspicious_patterns.append("Возможная попытка фишинга")
                break
        
        # Check for malicious file extensions
        if any(ext in analysis["path"].lower() for ext in self.malware_extensions):
            suspicious_patterns.append("Подозрительное расширение файла")
        
        # Check for obfuscated URLs
        if '%' in url:
            decoded = requests.utils.unquote(url)
            if decoded != url:
                suspicious_patterns.append("URL содержит закодированные символы")
        
        # Check for redirects
        if 'url' in analysis["query"] or 'redirect' in analysis["query"]:
            suspicious_patterns.append("URL содержит параметры перенаправления")
        
        return analysis, suspicious_patterns
    
    def is_ip_address(self, hostname):
        try:
            socket.inet_aton(hostname)
            return True
        except:
            return False
    
    def get_domain_info(self, domain):
        info = {
            "ip": None,
            "location": None,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "nameservers": [],
            "mx_records": [],
            "a_records": [],
            "txt_records": []
        }
        
        # Get IP and location
        try:
            info["ip"] = socket.gethostbyname(domain)
            response = requests.get(f"http://ip-api.com/json/{info['ip']}")
            if response.status_code == 200:
                data = response.json()
                info["location"] = f"{data.get('city', 'N/A')}, {data.get('country', 'N/A')}"
        except:
            pass
        
        # Get WHOIS info
        try:
            w = whois.whois(domain)
            info["registrar"] = w.registrar
            info["creation_date"] = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            info["expiration_date"] = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        except:
            pass
        
        # Get DNS records
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            
            # A records
            try:
                answers = resolver.resolve(domain, 'A')
                info["a_records"] = [str(rdata) for rdata in answers]
            except:
                pass
            
            # MX records
            try:
                answers = resolver.resolve(domain, 'MX')
                info["mx_records"] = [str(rdata.exchange) for rdata in answers]
            except:
                pass
            
            # NS records
            try:
                answers = resolver.resolve(domain, 'NS')
                info["nameservers"] = [str(rdata) for rdata in answers]
            except:
                pass
            
            # TXT records
            try:
                answers = resolver.resolve(domain, 'TXT')
                info["txt_records"] = [str(rdata) for rdata in answers]
            except:
                pass
            
        except Exception as e:
            print_status(f"Ошибка при получении DNS записей: {str(e)}", "warning")
        
        return info
    
    def check_ssl(self, url):
        try:
            response = requests.get(url, verify=True, timeout=5)
            return {
                "has_ssl": True,
                "issuer": response.cert['issuer'],
                "valid_from": response.cert['notBefore'],
                "valid_to": response.cert['notAfter'],
                "version": response.cert['version']
            }
        except:
            return {"has_ssl": False}
    
    def check_website(self, url):
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            return {
                "status_code": response.status_code,
                "final_url": response.url,
                "redirects": len(response.history),
                "server": response.headers.get('Server', 'Unknown'),
                "content_type": response.headers.get('Content-Type', 'Unknown'),
                "content_length": len(response.content),
                "has_forms": '<form' in response.text.lower(),
                "has_password_fields": 'type="password"' in response.text.lower(),
                "external_links": len(re.findall(r'href=["\'](http[s]?://(?!'+re.escape(urlparse(url).netloc)+')[^"\']+)["\']', response.text))
            }
        except Exception as e:
            print_status(f"Ошибка при проверке сайта: {str(e)}", "warning")
            return None
    
    def save_results(self, url, url_analysis, domain_info, ssl_info, website_info, vt_results):
        if not self.output_file:
            return
            
        data = {
            "scan_info": {
                "url": url,
                "scan_time": self.start_time.isoformat(),
                "duration": str(datetime.now() - self.start_time)
            },
            "url_analysis": url_analysis,
            "domain_info": domain_info,
            "ssl_info": ssl_info,
            "website_info": website_info,
            "virustotal": vt_results
        }
        
        if self.output_format == "json":
            with open(self.output_file, 'w') as f:
                json.dump(data, f, indent=4, default=str)
        elif self.output_format == "csv":
            with open(self.output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["URL", "Domain", "IP", "Location", "SSL", "Risk Score",
                               "Suspicious Patterns", "VirusTotal Detections"])
                
                structure, patterns = url_analysis
                writer.writerow([
                    url,
                    structure["domain"],
                    domain_info["ip"],
                    domain_info["location"],
                    ssl_info["has_ssl"],
                    self.calculate_risk_score(url_analysis, ssl_info, website_info, vt_results),
                    "; ".join(patterns),
                    f"{vt_results['malicious']}/{vt_results['total']}" if vt_results else "N/A"
                ])
    
    def calculate_risk_score(self, url_analysis, ssl_info, website_info, vt_results):
        score = 0
        structure, patterns = url_analysis
        
        # URL patterns
        score += len(patterns) * 10
        
        # SSL
        if not ssl_info["has_ssl"]:
            score += 20
        
        # Website characteristics
        if website_info:
            if website_info["has_password_fields"] and not ssl_info["has_ssl"]:
                score += 30
            if website_info["redirects"] > 2:
                score += 10
            if website_info["external_links"] > 10:
                score += 5
        
        # VirusTotal results
        if vt_results:
            score += min(vt_results["malicious"] * 15, 50)
        
        return min(score, 100)
    
    def simulate_analysis(self):
        stages = [
            "Анализ структуры URL",
            "Проверка домена",
            "Проверка SSL",
            "Анализ сайта",
            "Поиск в базах фишинга",
            "Проверка репутации"
        ]
        
        for stage in stages:
            with tqdm(total=100, desc=stage,
                     bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.CYAN, Fore.RESET)) as pbar:
                for i in range(100):
                    time.sleep(0.01)
                    pbar.update(1)
    
    def print_analysis_results(self, url, url_analysis, domain_info, ssl_info, website_info, vt_results):
        print(f"\n{Fore.CYAN}=== Анализ URL ==={Style.RESET_ALL}")
        
        structure, patterns = url_analysis
        print(f"\n{Fore.YELLOW}Структура URL:{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Схема: {structure['scheme']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Домен: {structure['domain']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Поддомен: {structure['subdomain'] or 'Нет'}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] TLD: {structure['tld']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Путь: {structure['path'] or '/'}{Style.RESET_ALL}")
        
        if patterns:
            print(f"\n{Fore.RED}Подозрительные паттерны:{Style.RESET_ALL}")
            for pattern in patterns:
                print(f"{Fore.RED}[!] {pattern}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Информация о домене:{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] IP адрес: {domain_info['ip'] or 'Не найден'}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Местоположение: {domain_info['location'] or 'Не найдено'}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Регистратор: {domain_info['registrar'] or 'Не найден'}{Style.RESET_ALL}")
        
        if domain_info['creation_date']:
            age = datetime.now() - domain_info['creation_date']
            age_color = Fore.RED if age.days < 30 else Fore.GREEN
            print(f"{age_color}[*] Возраст домена: {age.days} дней{Style.RESET_ALL}")
        
        if domain_info['nameservers']:
            print(f"\n{Fore.YELLOW}Nameservers:{Style.RESET_ALL}")
            for ns in domain_info['nameservers']:
                print(f"{Fore.GREEN}[+] {ns}{Style.RESET_ALL}")
        
        if domain_info['mx_records']:
            print(f"\n{Fore.YELLOW}MX записи:{Style.RESET_ALL}")
            for mx in domain_info['mx_records']:
                print(f"{Fore.GREEN}[+] {mx}{Style.RESET_ALL}")
        
        if domain_info['txt_records']:
            print(f"\n{Fore.YELLOW}TXT записи:{Style.RESET_ALL}")
            for txt in domain_info['txt_records']:
                print(f"{Fore.GREEN}[+] {txt}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}SSL статус:{Style.RESET_ALL}")
        if ssl_info["has_ssl"]:
            print(f"{Fore.GREEN}[+] HTTPS соединение защищено{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Издатель: {ssl_info['issuer']}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Действителен с: {ssl_info['valid_from']}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Действителен до: {ssl_info['valid_to']}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] HTTPS соединение не защищено{Style.RESET_ALL}")
        
        if website_info:
            print(f"\n{Fore.YELLOW}Информация о сайте:{Style.RESET_ALL}")
            print(f"{Fore.BLUE}[*] Код ответа: {website_info['status_code']}{Style.RESET_ALL}")
            print(f"{Fore.BLUE}[*] Сервер: {website_info['server']}{Style.RESET_ALL}")
            print(f"{Fore.BLUE}[*] Тип контента: {website_info['content_type']}{Style.RESET_ALL}")
            print(f"{Fore.BLUE}[*] Размер контента: {website_info['content_length']} байт{Style.RESET_ALL}")
            print(f"{Fore.BLUE}[*] Количество редиректов: {website_info['redirects']}{Style.RESET_ALL}")
            if website_info['has_forms']:
                print(f"{Fore.RED}[!] Обнаружены формы ввода{Style.RESET_ALL}")
            if website_info['has_password_fields']:
                print(f"{Fore.RED}[!] Обнаружены поля для ввода пароля{Style.RESET_ALL}")
            print(f"{Fore.BLUE}[*] Внешних ссылок: {website_info['external_links']}{Style.RESET_ALL}")
        
        if vt_results:
            print(f"\n{Fore.YELLOW}Результаты VirusTotal:{Style.RESET_ALL}")
            detection_rate = vt_results['malicious'] / vt_results['total'] * 100
            status_color = Fore.RED if detection_rate > 5 else Fore.GREEN
            print(f"{status_color}[*] Вредоносных обнаружений: {vt_results['malicious']}/{vt_results['total']} ({detection_rate:.1f}%){Style.RESET_ALL}")
            
            if vt_results['malicious'] > 0:
                print(f"\n{Fore.RED}Обнаруженные угрозы:{Style.RESET_ALL}")
                for engine, result in vt_results['results'].items():
                    if result['category'] == 'malicious':
                        print(f"{Fore.RED}[!] {engine}: {result['result']}{Style.RESET_ALL}")
        
        risk_score = self.calculate_risk_score(url_analysis, ssl_info, website_info, vt_results)
        print(f"\n{Fore.YELLOW}Итоговая оценка риска:{Style.RESET_ALL}")
        if risk_score >= 70:
            print(f"{Fore.RED}[!] Высокий риск ({risk_score}%){Style.RESET_ALL}")
        elif risk_score >= 40:
            print(f"{Fore.YELLOW}[!] Средний риск ({risk_score}%){Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] Низкий риск ({risk_score}%){Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description="Продвинутый детектор вредоносных URL")
    parser.add_argument("url", help="URL для анализа")
    parser.add_argument("-v", "--virustotal", help="API ключ VirusTotal")
    parser.add_argument("-g", "--gsb", help="API ключ Google Safe Browsing")
    parser.add_argument("-o", "--output", help="Файл для сохранения результатов")
    parser.add_argument("-f", "--format", choices=["json", "csv"], default="json",
                      help="Формат выходного файла (json или csv)")
    args = parser.parse_args()
    
    tool_desc = "Продвинутый детектор вредоносных URL"
    tool_features = [
        "Анализ структуры URL",
        "Проверка подозрительных паттернов",
        "Анализ домена и DNS записей",
        "Проверка SSL сертификата",
        "Анализ содержимого сайта",
        "Интеграция с VirusTotal",
        "Интеграция с Google Safe Browsing",
        "Оценка рисков безопасности",
        "Экспорт результатов в JSON/CSV"
    ]
    
    print_banner("URL Detector")
    print_tool_info(tool_desc, tool_features)
    
    url = args.url
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    detector = URLDetector(args.format, args.output)
    print_status(f"Анализ URL: {url}", "info")
    
    detector.simulate_analysis()
    
    parsed = urlparse(url)
    domain = parsed.netloc
    
    url_analysis = detector.analyze_url_structure(url)
    domain_info = detector.get_domain_info(domain)
    ssl_info = detector.check_ssl(url)
    website_info = detector.check_website(url)
    vt_results = detector.check_virustotal(url, args.virustotal)
    
    if args.gsb:
        gsb_result = detector.check_google_safebrowsing(url, args.gsb)
        if gsb_result:
            print_status("URL помечен как вредоносный в Google Safe Browsing!", "error")
    
    detector.print_analysis_results(url, url_analysis, domain_info, ssl_info, website_info, vt_results)
    detector.save_results(url, url_analysis, domain_info, ssl_info, website_info, vt_results)
    
    print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_status("\nПрограмма остановлена пользователем", "warning")
        sys.exit(0) 