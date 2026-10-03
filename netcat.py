import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading
from concurrent.futures import ThreadPoolExecutor

def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        return
    output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)

    return output.decode()

class PyNetCat:

    COMMON_PORTS = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        111: "RPC",
        135: "MSRPC",
        139: "NETBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "ORACLE",
        3306: "MYSQL",
        3389: "RDP",
        5432: "POSTGRESQL",
        5900: "VNC",
        6379: "REDIS",
        8080: "HTTP-ALT",
        8443: "HTTPS-ALT"
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

    def scan_port(self, host, port):
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

    def scan_common_ports(self):
        host = self.args.target

        print(f'\nScanning {host}...\n')

        with ThreadPoolExecutor(
                max_workers=100
        ) as executor:

            futures = [
                executor.submit(
                    self.scan_port,
                    host,
                    port
                )
                for port in self.COMMON_PORTS
            ]

            for future in futures:

                port = future.result()

                if port:

                    service = self.COMMON_PORTS.get(
                        port,
                        "UNKNOWN"
                    )

                    print(
                        f'[OPEN] {port:<5} {service}'
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
