#!/usr/bin/env python3

import sys
import os
import psutil
import platform
import socket
import json
import csv
import pwd
import grp
import stat
import subprocess
import argparse
from datetime import datetime
from colorama import init, Fore, Style
from tqdm import tqdm
import time
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from утилиты.баннер import print_banner, print_tool_info, print_status

init()

class SystemAuditor:
    def __init__(self, output_format="terminal", output_file=None):
        self.output_format = output_format
        self.output_file = output_file
        self.start_time = datetime.now()
        self.results = {
            "system_info": {},
            "security_config": {},
            "network_config": {},
            "user_audit": {},
            "service_audit": {},
            "file_audit": {},
            "process_audit": {},
            "vulnerability_check": {}
        }
    
    def get_system_info(self):
        print_status("Сбор информации о системе...", "info")
        
        try:
            uname = platform.uname()
            self.results["system_info"] = {
                "os": uname.system,
                "hostname": uname.node,
                "release": uname.release,
                "version": uname.version,
                "machine": uname.machine,
                "processor": uname.processor,
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
                "python_version": sys.version.split()[0],
                "total_memory": psutil.virtual_memory().total,
                "available_memory": psutil.virtual_memory().available,
                "cpu_count": psutil.cpu_count(),
                "cpu_usage": psutil.cpu_percent(interval=1)
            }
        except Exception as e:
            print_status(f"Ошибка при сборе системной информации: {str(e)}", "error")
    
    def check_security_config(self):
        print_status("Проверка конфигурации безопасности...", "info")
        
        try:
            # Check firewall status
            firewall_status = "Включен" if os.system("command -v ufw && ufw status | grep -q active") == 0 else "Отключен"
            
            # Check SSH configuration
            ssh_config = {}
            if os.path.exists("/etc/ssh/sshd_config"):
                with open("/etc/ssh/sshd_config", "r") as f:
                    for line in f:
                        if line.strip() and not line.startswith("#"):
                            try:
                                key, value = line.strip().split()
                                ssh_config[key] = value
                            except:
                                continue
            
            # Check password policies
            password_policies = {}
            if os.path.exists("/etc/login.defs"):
                with open("/etc/login.defs", "r") as f:
                    for line in f:
                        if line.strip() and not line.startswith("#"):
                            try:
                                key, value = line.strip().split()
                                password_policies[key] = value
                            except:
                                continue
            
            self.results["security_config"] = {
                "firewall_status": firewall_status,
                "selinux_status": self.check_selinux_status(),
                "ssh_config": ssh_config,
                "password_policies": password_policies,
                "sudo_users": self.get_sudo_users(),
                "world_writable_files": self.find_world_writable_files(),
                "suid_files": self.find_suid_files()
            }
        except Exception as e:
            print_status(f"Ошибка при проверке конфигурации безопасности: {str(e)}", "error")
    
    def check_network_config(self):
        print_status("Анализ сетевой конфигурации...", "info")
        
        try:
            network_info = {}
            
            # Get network interfaces
            interfaces = {}
            for iface, addrs in psutil.net_if_addrs().items():
                interfaces[iface] = []
                for addr in addrs:
                    interfaces[iface].append({
                        "address": addr.address,
                        "netmask": addr.netmask,
                        "family": str(addr.family)
                    })
            
            # Get open ports
            open_ports = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    open_ports.append({
                        "port": conn.laddr.port,
                        "ip": conn.laddr.ip,
                        "pid": conn.pid,
                        "program": psutil.Process(conn.pid).name() if conn.pid else "Unknown"
                    })
            
            # Get routing table
            routing_table = []
            try:
                output = subprocess.check_output(["netstat", "-rn"]).decode()
                routing_table = [line.split() for line in output.split("\n")[2:] if line]
            except:
                pass
            
            self.results["network_config"] = {
                "interfaces": interfaces,
                "open_ports": open_ports,
                "routing_table": routing_table,
                "hostname": socket.gethostname(),
                "fqdn": socket.getfqdn(),
                "dns_servers": self.get_dns_servers()
            }
        except Exception as e:
            print_status(f"Ошибка при анализе сетевой конфигурации: {str(e)}", "error")
    
    def audit_users(self):
        print_status("Аудит пользователей и групп...", "info")
        
        try:
            users = []
            for user in pwd.getpwall():
                users.append({
                    "username": user.pw_name,
                    "uid": user.pw_uid,
                    "gid": user.pw_gid,
                    "home": user.pw_dir,
                    "shell": user.pw_shell,
                    "groups": [g.gr_name for g in grp.getgrall() if user.pw_name in g.gr_mem]
                })
            
            groups = []
            for group in grp.getgrall():
                groups.append({
                    "groupname": group.gr_name,
                    "gid": group.gr_gid,
                    "members": group.gr_mem
                })
            
            self.results["user_audit"] = {
                "users": users,
                "groups": groups,
                "last_logins": self.get_last_logins(),
                "failed_logins": self.get_failed_logins()
            }
        except Exception as e:
            print_status(f"Ошибка при аудите пользователей: {str(e)}", "error")
    
    def audit_services(self):
        print_status("Аудит системных сервисов...", "info")
        
        try:
            services = []
            try:
                output = subprocess.check_output(["systemctl", "list-units", "--type=service"]).decode()
                for line in output.split("\n")[1:]:
                    if line and not line.startswith("LOAD"):
                        parts = line.split()
                        if len(parts) >= 4:
                            services.append({
                                "name": parts[0],
                                "load": parts[1],
                                "active": parts[2],
                                "sub": parts[3]
                            })
            except:
                pass
            
            self.results["service_audit"] = {
                "services": services,
                "total_services": len(services),
                "active_services": len([s for s in services if s["active"] == "active"]),
                "failed_services": len([s for s in services if s["active"] == "failed"])
            }
        except Exception as e:
            print_status(f"Ошибка при аудите сервисов: {str(e)}", "error")
    
    def audit_files(self):
        print_status("Аудит файловой системы...", "info")
        
        try:
            self.results["file_audit"] = {
                "world_writable": self.find_world_writable_files(),
                "suid_files": self.find_suid_files(),
                "unowned_files": self.find_unowned_files(),
                "large_files": self.find_large_files(),
                "hidden_files": self.find_hidden_files()
            }
        except Exception as e:
            print_status(f"Ошибка при аудите файлов: {str(e)}", "error")
    
    def audit_processes(self):
        print_status("Аудит процессов...", "info")
        
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
                try:
                    pinfo = proc.info
                    processes.append({
                        "pid": pinfo["pid"],
                        "name": pinfo["name"],
                        "user": pinfo["username"],
                        "cpu_usage": pinfo["cpu_percent"],
                        "memory_usage": pinfo["memory_percent"]
                    })
                except:
                    continue
            
            self.results["process_audit"] = {
                "processes": processes,
                "total_processes": len(processes),
                "users_processes": self.group_processes_by_user(processes),
                "high_cpu_processes": [p for p in processes if p["cpu_usage"] > 50],
                "high_memory_processes": [p for p in processes if p["memory_usage"] > 50]
            }
        except Exception as e:
            print_status(f"Ошибка при аудите процессов: {str(e)}", "error")
    
    def check_vulnerabilities(self):
        print_status("Проверка уязвимостей...", "info")
        
        try:
            self.results["vulnerability_check"] = {
                "kernel_version": platform.release(),
                "outdated_packages": self.check_outdated_packages(),
                "open_ports": self.results["network_config"]["open_ports"],
                "weak_permissions": self.check_weak_permissions(),
                "suspicious_processes": self.check_suspicious_processes(),
                "security_issues": self.check_security_issues()
            }
        except Exception as e:
            print_status(f"Ошибка при проверке уязвимостей: {str(e)}", "error")
    
    def check_selinux_status(self):
        try:
            if os.path.exists("/etc/selinux/config"):
                with open("/etc/selinux/config", "r") as f:
                    for line in f:
                        if line.startswith("SELINUX="):
                            return line.strip().split("=")[1]
            return "Not installed"
        except:
            return "Error checking"
    
    def get_sudo_users(self):
        sudo_users = []
        try:
            with open("/etc/sudoers", "r") as f:
                for line in f:
                    if line.strip() and not line.startswith("#"):
                        if "ALL=(ALL" in line:
                            user = line.split()[0]
                            sudo_users.append(user)
        except:
            pass
        return sudo_users
    
    def find_world_writable_files(self):
        world_writable = []
        for root, dirs, files in os.walk("/"):
            for name in files:
                try:
                    path = os.path.join(root, name)
                    if os.path.exists(path):
                        st = os.stat(path)
                        if st.st_mode & stat.S_IWOTH:
                            world_writable.append(path)
                except:
                    continue
        return world_writable
    
    def find_suid_files(self):
        suid_files = []
        try:
            output = subprocess.check_output(["find", "/", "-type", "f", "-perm", "-4000"]).decode()
            suid_files = output.strip().split("\n")
        except:
            pass
        return suid_files
    
    def get_dns_servers(self):
        dns_servers = []
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        dns_servers.append(line.split()[1])
        except:
            pass
        return dns_servers
    
    def get_last_logins(self):
        last_logins = []
        try:
            output = subprocess.check_output(["last", "-n", "10"]).decode()
            last_logins = [line for line in output.split("\n") if line.strip()]
        except:
            pass
        return last_logins
    
    def get_failed_logins(self):
        failed_logins = []
        try:
            output = subprocess.check_output(["faillog", "-a"]).decode()
            failed_logins = [line for line in output.split("\n") if line.strip()]
        except:
            pass
        return failed_logins
    
    def find_unowned_files(self):
        unowned = []
        try:
            output = subprocess.check_output(["find", "/", "-nouser", "-o", "-nogroup"]).decode()
            unowned = output.strip().split("\n")
        except:
            pass
        return unowned
    
    def find_large_files(self, size_limit=100*1024*1024):  # 100MB
        large_files = []
        try:
            output = subprocess.check_output(["find", "/", "-type", "f", "-size", f"+{size_limit}c"]).decode()
            large_files = output.strip().split("\n")
        except:
            pass
        return large_files
    
    def find_hidden_files(self):
        hidden_files = []
        try:
            output = subprocess.check_output(["find", "/", "-name", ".*", "-type", "f"]).decode()
            hidden_files = output.strip().split("\n")
        except:
            pass
        return hidden_files
    
    def group_processes_by_user(self, processes):
        user_processes = {}
        for proc in processes:
            user = proc["user"]
            if user not in user_processes:
                user_processes[user] = []
            user_processes[user].append(proc)
        return user_processes
    
    def check_outdated_packages(self):
        outdated = []
        try:
            if os.path.exists("/usr/bin/apt"):
                output = subprocess.check_output(["apt", "list", "--upgradable"]).decode()
                outdated = [line for line in output.split("\n") if line.strip()]
            elif os.path.exists("/usr/bin/yum"):
                output = subprocess.check_output(["yum", "check-update"]).decode()
                outdated = [line for line in output.split("\n") if line.strip()]
        except:
            pass
        return outdated
    
    def check_weak_permissions(self):
        weak_permissions = []
        critical_files = [
            "/etc/shadow",
            "/etc/passwd",
            "/etc/sudoers",
            "/etc/ssh/sshd_config"
        ]
        
        for file in critical_files:
            try:
                if os.path.exists(file):
                    st = os.stat(file)
                    mode = st.st_mode
                    if mode & (stat.S_IRWXO | stat.S_IRWXG):
                        weak_permissions.append({
                            "file": file,
                            "mode": oct(mode)[-3:],
                            "owner": pwd.getpwuid(st.st_uid).pw_name,
                            "group": grp.getgrgid(st.st_gid).gr_name
                        })
            except:
                continue
        
        return weak_permissions
    
    def check_suspicious_processes(self):
        suspicious = []
        known_suspicious = [
            "nc", "netcat", "ncat",  # Network tools that could be used maliciously
            "nmap", "wireshark", "tcpdump",  # Network scanning tools
            "john", "hashcat",  # Password cracking tools
            "msfconsole", "metasploit"  # Penetration testing frameworks
        ]
        
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                if proc.info['name'] in known_suspicious:
                    suspicious.append({
                        "name": proc.info['name'],
                        "pid": proc.pid,
                        "user": proc.username(),
                        "cmdline": proc.cmdline()
                    })
            except:
                continue
        
        return suspicious
    
    def check_security_issues(self):
        issues = []
        
        # Check for common security issues
        if self.results["security_config"]["firewall_status"] == "Отключен":
            issues.append("Firewall отключен")
        
        ssh_config = self.results["security_config"]["ssh_config"]
        if ssh_config.get("PermitRootLogin") == "yes":
            issues.append("Разрешен root SSH доступ")
        if ssh_config.get("PasswordAuthentication") == "yes":
            issues.append("Разрешена аутентификация по паролю SSH")
        
        if len(self.results["security_config"]["world_writable_files"]) > 0:
            issues.append(f"Найдено {len(self.results['security_config']['world_writable_files'])} файлов с правами на запись для всех")
        
        if self.results["security_config"]["selinux_status"] == "disabled":
            issues.append("SELinux отключен")
        
        return issues
    
    def save_results(self):
        if not self.output_file:
            return
            
        if self.output_format == "json":
            with open(self.output_file, 'w') as f:
                json.dump(self.results, f, indent=4, default=str)
        elif self.output_format == "csv":
            with open(self.output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Category", "Item", "Status", "Details"])
                
                for category, data in self.results.items():
                    for item, value in data.items():
                        if isinstance(value, (list, dict)):
                            writer.writerow([category, item, "See details", str(value)])
                        else:
                            writer.writerow([category, item, str(value), ""])
    
    def print_results(self):
        print(f"\n{Fore.CYAN}=== Результаты аудита системы ==={Style.RESET_ALL}")
        
        # System Information
        print(f"\n{Fore.YELLOW}Информация о системе:{Style.RESET_ALL}")
        sys_info = self.results["system_info"]
        print(f"{Fore.GREEN}[+] ОС: {sys_info['os']} {sys_info['release']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Хост: {sys_info['hostname']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Версия ядра: {sys_info['version']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Процессор: {sys_info['processor']} ({sys_info['cpu_count']} ядер){Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Загрузка CPU: {sys_info['cpu_usage']}%{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Память: {sys_info['available_memory']/1024/1024/1024:.1f}GB свободно из {sys_info['total_memory']/1024/1024/1024:.1f}GB{Style.RESET_ALL}")
        
        # Security Configuration
        print(f"\n{Fore.YELLOW}Конфигурация безопасности:{Style.RESET_ALL}")
        sec_config = self.results["security_config"]
        print(f"{Fore.GREEN}[+] Firewall: {sec_config['firewall_status']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] SELinux: {sec_config['selinux_status']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Пользователей с sudo: {len(sec_config['sudo_users'])}{Style.RESET_ALL}")
        
        # Network Configuration
        print(f"\n{Fore.YELLOW}Сетевая конфигурация:{Style.RESET_ALL}")
        net_config = self.results["network_config"]
        print(f"{Fore.GREEN}[+] Hostname: {net_config['hostname']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] FQDN: {net_config['fqdn']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] DNS серверы: {', '.join(net_config['dns_servers'])}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Открытые порты: {len(net_config['open_ports'])}{Style.RESET_ALL}")
        
        # User Audit
        print(f"\n{Fore.YELLOW}Аудит пользователей:{Style.RESET_ALL}")
        user_audit = self.results["user_audit"]
        print(f"{Fore.GREEN}[+] Всего пользователей: {len(user_audit['users'])}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Всего групп: {len(user_audit['groups'])}{Style.RESET_ALL}")
        
        # Service Audit
        print(f"\n{Fore.YELLOW}Аудит сервисов:{Style.RESET_ALL}")
        service_audit = self.results["service_audit"]
        print(f"{Fore.GREEN}[+] Всего сервисов: {service_audit['total_services']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Активных сервисов: {service_audit['active_services']}{Style.RESET_ALL}")
        print(f"{Fore.RED}[-] Сбойных сервисов: {service_audit['failed_services']}{Style.RESET_ALL}")
        
        # Process Audit
        print(f"\n{Fore.YELLOW}Аудит процессов:{Style.RESET_ALL}")
        proc_audit = self.results["process_audit"]
        print(f"{Fore.GREEN}[+] Всего процессов: {proc_audit['total_processes']}{Style.RESET_ALL}")
        print(f"{Fore.RED}[-] Процессов с высоким CPU: {len(proc_audit['high_cpu_processes'])}{Style.RESET_ALL}")
        print(f"{Fore.RED}[-] Процессов с высокой памятью: {len(proc_audit['high_memory_processes'])}{Style.RESET_ALL}")
        
        # Vulnerability Check
        print(f"\n{Fore.YELLOW}Проверка уязвимостей:{Style.RESET_ALL}")
        vuln_check = self.results["vulnerability_check"]
        if vuln_check["security_issues"]:
            print(f"{Fore.RED}[!] Обнаружены проблемы безопасности:{Style.RESET_ALL}")
            for issue in vuln_check["security_issues"]:
                print(f"{Fore.RED}[-] {issue}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] Критических уязвимостей не обнаружено{Style.RESET_ALL}")
        
        if vuln_check["suspicious_processes"]:
            print(f"\n{Fore.RED}[!] Подозрительные процессы:{Style.RESET_ALL}")
            for proc in vuln_check["suspicious_processes"]:
                print(f"{Fore.RED}[-] {proc['name']} (PID: {proc['pid']}, User: {proc['user']}){Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
    
    def simulate_analysis(self):
        stages = [
            "Сбор информации о системе",
            "Проверка конфигурации безопасности",
            "Анализ сетевой конфигурации",
            "Аудит пользователей",
            "Проверка сервисов",
            "Анализ файловой системы",
            "Мониторинг процессов",
            "Поиск уязвимостей"
        ]
        
        for stage in stages:
            with tqdm(total=100, desc=stage,
                     bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.CYAN, Fore.RESET)) as pbar:
                for i in range(100):
                    time.sleep(0.01)
                    pbar.update(1)
    
    def run_audit(self):
        self.simulate_analysis()
        
        self.get_system_info()
        self.check_security_config()
        self.check_network_config()
        self.audit_users()
        self.audit_services()
        self.audit_files()
        self.audit_processes()
        self.check_vulnerabilities()
        
        self.print_results()
        self.save_results()

def main():
    parser = argparse.ArgumentParser(description="Продвинутый аудитор безопасности системы")
    parser.add_argument("-o", "--output", help="Файл для сохранения результатов")
    parser.add_argument("-f", "--format", choices=["json", "csv"], default="json",
                      help="Формат выходного файла (json или csv)")
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print_status("Требуются права root", "error")
        sys.exit(1)
    
    tool_desc = "Продвинутый аудитор безопасности системы"
    tool_features = [
        "Анализ системной информации",
        "Проверка конфигурации безопасности",
        "Аудит сетевых настроек",
        "Анализ пользователей и групп",
        "Проверка системных сервисов",
        "Аудит файловой системы",
        "Мониторинг процессов",
        "Поиск уязвимостей",
        "Экспорт результатов в JSON/CSV"
    ]
    
    print_banner("System Auditor")
    print_tool_info(tool_desc, tool_features)
    
    auditor = SystemAuditor(args.format, args.output)
    auditor.run_audit()
    
    print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_status("\nПрограмма остановлена пользователем", "warning")
        sys.exit(0) 