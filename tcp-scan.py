import scapy.all
import argparse
import signal
import sys
import socket
from urllib.parse import urlparse
from scapy.all import IP, TCP, ICMP, sr1, send

def print_ascii():
    tcp_scan = """
  _______    _____   _____              _____    _____              _   _ 
 |__   __|  / ____| |  __ \            / ____|  / ____|     /\     | \ | |
    | |    | |      | |__) |  ______  | (___   | |         /  \    |  \| |
    | |    | |      |  ___/  |______|  \___ \  | |        / /\ \   | . ` |
    | |    | |____  | |                ____) | | |____   / ____ \  | |\  |
    |_|     \_____| |_|               |_____/   \_____| /_/    \_\ |_| \_|

    """
    print(tcp_scan)


def check_ip(target):
    try:
        parsed_url = urlparse(target)
        if parsed_url.scheme:  # 如果有 scheme（如 http、https），则认为是 URL
            host = parsed_url.netloc
            if ':' in host:
                host = host.split(':')[0]
            target_ip = socket.gethostbyname(host)
            return target_ip
        else:
            target_ip = socket.gethostbyname(target)
            return target_ip
    except socket.gaierror:
        print(f"错误: 无法解析 {target} 为有效的 IP 地址。")
        return None

def Icmp_scan_host(ip):
    packet = (scapy.all.IP(dst=ip) / scapy.all.ICMP(type=8, code=0))
    response = scapy.all.sr1(packet, timeout=5, verbose=0)
    if response:
        return "[+] Host is open"
    else:
        return "[-] Host is closed"

#半开放范围性端口扫描
def tcp_scan_port(ip, start_port, end_port):
    try:
        for i in range(start_port, end_port + 1):
            # 构造 SYN 包
            pkt = IP(dst=ip) / TCP(sport=i,dport=i, flags="S")

            # 发送并接收响应
            result = sr1(pkt, timeout=1, verbose=0)

            # 分析响应
            if result and result.haslayer(TCP):
                if result[TCP].flags == 0x12:  # SYN - ACK
                    # 发送 RST 终止连接，设置 verbose=0 关闭输出信息
                    send(IP(dst=ip) / TCP(dport=i, sport=result[TCP].sport, flags="R"), verbose=0)
                    print("[+] Port {} is open".format(i))
    except Exception as e:
        print(f"扫描出现错误：{e}")

#半开放性单端口扫描
def tcp_scan_port1(ip, ports):
    try:
        for i in ports:
            # 构造 SYN 包
            pkt = IP(dst=ip) / TCP(sport=i,dport=i, flags="S")
            result = sr1(pkt, timeout=6, verbose=0)  # 增加超时时间
            if result and result.haslayer(TCP):
                if result[TCP].flags == 0x12:  # SYN - ACK
                    # 发送 RST 终止连接，设置 verbose=0 关闭输出信息
                    send(IP(dst=ip) / TCP(dport=i, sport=result[TCP].sport, flags="R"), verbose=0)
                    print("[+] Port {} is open".format(i))
                elif result[TCP].flags == 0x14:  # RST - ACK
                    print(f"[-] Port {i} is closed")
            else:
                print(f"[-] Port {i} did not respond")  # 增加对未响应情况的处理
    except Exception as e:
        print(f"扫描出现错误：{e}")


def signal_handler(sig, frame):
    print('你按下了 Ctrl+C！程序即将退出...')
    sys.exit(0)


def main():
    signal.signal(signal.SIGINT, signal_handler)

    parse = argparse.ArgumentParser(description="Those are the description of all the parameters")
    parse.add_argument("-i", "--target", help="Target IP or Domain")
    parse.add_argument("-f", "--target_port", nargs=2, type=int, help="Range of target ports, e.g., -f 80 100")
    parse.add_argument("-C", "--Icmp_scan", action="store_true", help="Icmp scan")
    parse.add_argument("-p", "--port_scan", nargs='+', type=int, help="List of target ports, e.g., -p 80 90 100")
    args = parse.parse_args()

    print_ascii()
    if args.target is None:
        print("错误: 请提供目标 IP 地址或域名。")
        return

    target_ip = check_ip(args.target)
    if target_ip is None:
        return

    if args.Icmp_scan:
        print("[+] Icmp scan")
        host_status = Icmp_scan_host(target_ip)
        if host_status == "[+] Host is open":
            print(f"[+] host {target_ip} is living")
            if args.target_port:
                start_port, end_port = args.target_port
                tcp_scan_port(target_ip, start_port, end_port)
            elif args.port_scan:
                tcp_scan_port1(target_ip, args.port_scan)
        else:
            print(f"[-] host {args.target} is closed")


if __name__ == "__main__":
    main()