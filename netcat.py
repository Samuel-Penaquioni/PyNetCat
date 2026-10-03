import argparse
from concurrent.futures import ThreadPoolExecutor
import socket
import shlex
import ssl
import subprocess
import sys
import textwrap
import threading


def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        return None
    output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)

    return output.decode()


def scan_port(host, port):
    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(1)

        result = sock.connect_ex(
            (host, port)
        )

        sock.close()

        if result == 0:
            return port

        return None

    except Exception:
        return None


def get_banner(host, port):

    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(3)

        sock.connect((host, port))

        #
        # Alguns serviços enviam banner automaticamente
        #
        try:
            banner = sock.recv(1024)

            if banner:
                sock.close()

                return banner.decode(
                    errors='ignore'
                ).strip()

        except:
            pass

        #
        # Outros precisam receber algo
        #
        try:

            if port in (80, 8080):
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            elif port == 443:
                context = ssl.create_default_context()
                ssl_sock = context.wrap_socket(sock, server_hostname=host)
                ssl_sock.send(b'HEAD / HTTP/1.1\r\n\r\n')
                banner = ssl_sock.recv(4096)
                ssl_sock.close()
                return banner.decode(errors='ignore').strip()
            else:
                sock.send(b'\r\n')

            banner = sock.recv(1024)

            sock.close()

            if banner:
                return banner.decode(
                    errors='ignore'
                ).strip()

        except:
            pass

        sock.close()

        return 'Banner não disponível'

    except Exception:
        return 'Banner não disponível'


class PyNetCat:

    COMMON_PORTS = {
        1: "TCPMUX",
        7: "Echo",
        9: "Discard / Wake-on-LAN",
        13: "Daytime",
        17: "QOTD",
        19: "Character Generator",
        20: "FTP Data",
        21: "FTP",
        22: "SSH / SFTP / SCP",
        23: "Telnet",
        25: "SMTP",
        26: "SMTP",
        37: "Time",
        42: "WINS / Nameserver",
        43: "WHOIS",
        49: "TACACS",
        53: "DNS",
        70: "Gopher",
        79: "Finger",
        80: "HTTP",
        88: "Kerberos",
        109: "POP2",
        110: "POP3",
        111: "ONC RPC",
        113: "Ident",
        119: "NNTP",
        123: "NTP",
        135: "Microsoft RPC",
        137: "NetBIOS Session Service",
        138: "NetBIOS Session Service",
        139: "NetBIOS Session Service",
        143: "IMAP",
        161: "SNMP",
        162: "SNMP",
        179: "BGP",
        194: "IRC",
        199: "SMUX",
        264: "BGMP",
        366: "ODMR",
        389: "LDAP",
        427: "SLP",
        443: "HTTPS",
        444: "SNPP",
        445: "Microsoft SMB",
        464: "Kerberos Password",
        465: "SMTPS",
        475: "tcpnethaspsrv",
        497: "Retrospect",
        500: "IPsec IKE",
        512: "rexec",
        513: "rlogin",
        514: "Syslog / rsh",
        515: "LPD",
        524: "NCP",
        543: "klogin",
        544: "kshell",
        548: "AFP",
        554: "RTSP",
        563: "NNTPS",
        587: "SMTP Submission",
        593: "Microsoft RPC over HTTP",
        631: "IPP / CUPS",
        636: "LDAPS",
        646: "LDP",
        648: "RRP",
        666: "Doom",
        691: "MS Exchange Routing",
        700: "EPP",
        711: "Cisco TDP",
        749: "Kerberos Administration",
        783: "SpamAssassin",
        800: "mdbs-daemon",
        808: "Microsoft Net.TCP",
        843: "Adobe Flash Policy",
        873: "rsync",
        888: "CDDB",
        902: "VMware",
        981: "SofaWare",
        987: "Microsoft RPC",
        990: "FTPS",
        992: "Telnet TLS",
        993: "IMAPS",
        995: "POP3S",
        1080: "SOCKS Proxy",
        1194: "OpenVPN",
        1234: "VLC / Infoseek",
        1433: "Microsoft SQL Server",
        1434: "Microsoft SQL Monitor",
        1521: "Oracle Database",
        1723: "PPTP",
        1812: "RADIUS Authentication",
        1900: "SSDP",
        1935: "RTMP",
        2049: "NFS",
        2525: "SMTP",
        3000: "HBCI / Grafana",
        3128: "Squid Proxy",
        3268: "Active Directory Global Catalog",
        3269: "Active Directory Global Catalog SSL",
        3306: "MySQL / MariaDB",
        3389: "Remote Desktop Protocol",
        3690: "Subversion",
        5000: "Aplicações web / UPnP",
        5060: "SIP",
        5061: "SIP TLS",
        5222: "XMPP Client",
        5269: "XMPP Server",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        6667: "IRC",
        6881: "BitTorrentClient",
        8000: "IRDMI",
        8080: "HTTP alternativo / Proxy",
        8443: "HTTPS alternativo",
        8888: "Aplicações web / Jupyter",
        9200: "Elasticsearch",
        9418: "Git",
        27017: "MongoDB"

    }

    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        if self.args.scan:
            self.scan_common_ports()
        elif self.args.listen:
            self.listen()
        else:
            self.send()

    def scan_common_ports(self):
        host = self.args.target

        print(f'\nScanning {host}...\n')

        with ThreadPoolExecutor(
                max_workers=100
        ) as executor:

            futures = [
                executor.submit(
                    scan_port,
                    host,
                    port
                )
                for port in self.COMMON_PORTS
            ]

            for future in futures:

                port = future.result()

                if port:

                    banner = get_banner(host, port)

                    for line in banner.splitlines():
                        if line.lower().startswith('server:'):
                            banner_server = line
                        else:
                            banner_server = banner

                    service = self.COMMON_PORTS.get(
                        port,
                        "UNKNOWN"
                    )

                    print(
                        f'[OPEN] {port:<5} {service} - {banner_server}'
                    )

    def send(self):
        self.socket.connect((self.args.target, self.args.port))
        if self.buffer:
            self.socket.send(self.buffer)

        try:
            while True:
                recv_len = 1
                response = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()
                    if recv_len < 4096:
                        break
                if response:
                    print(response)
                    buffer = input('> ')
                    buffer += '\n'
                    self.socket.send(buffer.encode())
        except KeyboardInterrupt:
            print('User terminated.')
            self.socket.close()
            sys.exit()

    def listen(self):
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        while True:
            client_socket, _ = self.socket.accept()
            client_thread = threading.Thread(
                target=self.handle, args=(client_socket,)
            )
            client_thread.start()

    def handle(self, client_socket):
        if self.args.execute:
            output = execute(self.args.execute)
            client_socket.send(output.encode())

        elif self.args.upload:
            file_buffer = b''
            while True:
                data = client_socket.recv(4096)
                if data:
                    file_buffer += data
                else:
                    break

            with open(self.args.upload, 'wb') as f:
                f.write(file_buffer)
            message = f'Save file {self.args.upload}'
            client_socket.send(message.encode())

        elif self.args.command:
            cmd_buffer = b''
            while True:
                try:
                    client_socket.send(b'BHP: #> ')
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.send(response.encode())
                    cmd_buffer = b''
                except Exception as e:
                    print(f'Server Killed {e}')
                    self.socket.close()
                    sys.exit()
        

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='BHP Net Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Example:
            netcat.py -t 192.168.1.108 -p 5555 -l -c # command shell
            netcat.py -t 192.168.1.108 -p 5555 -l -u=mytest.txt # upload to file
            netcat.py -t 192.168.1.108 -p 5555 -l -e=\"cat /etc/passwd\" # execute command
            echo 'ABC' | ./netcat.py -t 192.168.1.108 -p 135 # echo text to server port 135
            netcat.py -t 192.168.1.108 -p 5555 # connect to server
        '''))
    parser.add_argument('-c', '--command', action='store_true', help='command shell')
    parser.add_argument('-e', '--execute', help='execute specified command')
    parser.add_argument('-l', '--listen', action='store_true', help='listen')
    parser.add_argument('-p', '--port', type=int, default=5555, help='specifed port')
    parser.add_argument('-t', '--target', default='192.168.1.203', help='specified IP')
    parser.add_argument('-u', '--upload', help='upload file')
    parser.add_argument('-s', '--scan', action='store_true', help='scan common ports')
    args = parser.parse_args()
    if args.listen or args.scan:
        buffer = ''
    else:
        buffer = sys.stdin.read()

    nc = PyNetCat(args, buffer.encode())
    nc.run()
