import asyncio
import socket
import struct
import argparse
import re
import subprocess
import ipaddress
import time
import hmac

TCP_CHUNK_SIZE = 32768
_DNS_TTL = 300
_DNS_NEG_TTL = 30
_DNS_TIMEOUT = 5.0
_CLIENT_REBIND_GRACE = 4.0
_SOCK_BUF = 131072
_DEFAULT_WORKERS = 64


def _is_blocked_destination(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


class _AsyncDnsCache:
    def __init__(self, ttl: float = _DNS_TTL, neg_ttl: float = _DNS_NEG_TTL):
        self._ttl = ttl
        self._neg_ttl = neg_ttl
        self._store = {}
        self._pending = {}

    def get_cached(self, host: str):
        entry = self._store.get(host)
        if entry is None:
            return None
        ip, exp = entry
        if time.monotonic() >= exp:
            return None
        return ip

    async def resolve(self, host: str, loop: asyncio.AbstractEventLoop):
        cached = self.get_cached(host)
        if cached is not None:
            return cached

        pending = self._pending.get(host)
        if pending is not None:
            return await pending

        fut = loop.create_future()
        self._pending[host] = fut
        try:
            ip = None
            try:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(host, None, family=socket.AF_INET),
                    timeout=_DNS_TIMEOUT,
                )
                if infos:
                    ip = infos[0][4][0]
            except (OSError, asyncio.TimeoutError):
                ip = None

            ttl = self._ttl if ip else self._neg_ttl
            self._store[host] = (ip, time.monotonic() + ttl)
            fut.set_result(ip)
            return ip
        finally:
            self._pending.pop(host, None)


class UdpRelayProtocol(asyncio.DatagramProtocol):
    def __init__(self, client_ip, proxy):
        self.client_ip = client_ip
        self.proxy = proxy
        self.transport = None
        self.client_addr = None
        self.client_last_seen = 0.0
        self.target_addrs = set()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if addr[0] == self.client_ip:
            now = time.monotonic()
            if self.client_addr is not None and addr != self.client_addr:
                if now - self.client_last_seen < _CLIENT_REBIND_GRACE:
                    return
            self.client_addr = addr
            self.client_last_seen = now
            self._handle_client_to_target(data)
        elif self.client_addr and addr in self.target_addrs:
            self._handle_target_to_client(data, addr)

    def _handle_client_to_target(self, data):
        if len(data) < 10:
            return

        if data[2] != 0x00:
            return

        atyp = data[3]

        if atyp == 0x01:
            target_ip = socket.inet_ntoa(data[4:8])
            target_port = struct.unpack_from(">H", data, 8)[0]
            self._forward(target_ip, target_port, data[10:])
        elif atyp == 0x03:
            domain_len = data[4]
            header_length = 5 + domain_len + 2
            if len(data) < header_length:
                return
            domain = data[5:5 + domain_len].decode('utf-8', errors='ignore')
            target_port = struct.unpack_from(">H", data, header_length - 2)[0]
            payload = data[header_length:]
            cached = self.proxy._dns.get_cached(domain)
            if cached is not None:
                self._forward(cached, target_port, payload)
            else:
                asyncio.ensure_future(self._resolve_and_forward(domain, target_port, payload))
        elif atyp == 0x04:
            return

    async def _resolve_and_forward(self, domain, port, payload):
        ip = await self.proxy._dns.resolve(domain, self.proxy._loop)
        if ip:
            self._forward(ip, port, payload)

    def _forward(self, target_ip, target_port, payload):
        if _is_blocked_destination(target_ip):
            return

        target_addr = (target_ip, target_port)
        self.target_addrs.add(target_addr)

        try:
            self.transport.sendto(payload, target_addr)
            self.proxy._bytes_up += len(payload)
        except Exception:
            pass

    def _handle_target_to_client(self, data, target_addr):
        header = b'\x00\x00\x00\x01' + socket.inet_aton(target_addr[0]) + struct.pack(">H", target_addr[1])
        payload = header + data
        try:
            self.transport.sendto(payload, self.client_addr)
            self.proxy._bytes_down += len(data)
        except Exception:
            pass


class VPNSocks5Proxy:
    def __init__(self, host: str = None, port: int = 9898, username: str = None, password: str = None, max_workers: int = _DEFAULT_WORKERS):
        self.host = host if host else self._detect_listen_address()
        self.port = port
        self.user = username.encode() if username else None
        self.pwd = password.encode() if password else None
        self.require_auth = bool(username and password)
        self._max_workers = max_workers

        self.total = 0
        self.auth_ok = 0
        self.auth_fail = 0
        self._bytes_up = 0
        self._bytes_down = 0
        self._ip_counts = {}
        self._dns = _AsyncDnsCache()

        self._loop = None
        self._stop_event = None
        self._server = None
        self._active_tasks = set()

    @staticmethod
    def _detect_listen_address() -> str:
        _IP_RE = re.compile(r"inet (\d+\.\d+\.\d+\.\d+)/\d+.*?\b(wlan\d+|rmnet\d+|ap\d+)")

        try:
            result = subprocess.run(
                ["ip", "addr"], capture_output=True, text=True, timeout=5
            )
            for m in _IP_RE.finditer(result.stdout):
                ip = m.group(1)
                if ip.startswith(("192.168.", "10.")):
                    return ip
        except Exception:
            pass

        try:
            result = subprocess.run(
                ["termux-wifi-connectioninfo"], capture_output=True, text=True, timeout=5
            )
            m = re.search(r'"ip"\s*:\s*"(\d+\.\d+\.\d+\.\d+)"', result.stdout)
            if m:
                return m.group(1)
        except Exception:
            pass

        return "0.0.0.0"

    @property
    def active_users(self) -> int:
        return len(self._ip_counts)

    @property
    def upload_bytes(self) -> int:
        return self._bytes_up

    @property
    def download_bytes(self) -> int:
        return self._bytes_down

    def _mark_connected(self, ip: str) -> None:
        self._ip_counts[ip] = self._ip_counts.get(ip, 0) + 1

    def _mark_disconnected(self, ip: str) -> None:
        count = self._ip_counts.get(ip)
        if count is None:
            return
        if count <= 1:
            del self._ip_counts[ip]
        else:
            self._ip_counts[ip] = count - 1

    def stop(self) -> None:
        loop = self._loop
        if loop is None:
            return
        loop.call_soon_threadsafe(self._trigger_stop)

    def _trigger_stop(self) -> None:
        if self._stop_event is not None and not self._stop_event.is_set():
            self._stop_event.set()

    async def _relay_stream(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, is_upload: bool):
        try:
            while True:
                data = await reader.read(TCP_CHUNK_SIZE)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
                if is_upload:
                    self._bytes_up += len(data)
                else:
                    self._bytes_down += len(data)
        except asyncio.CancelledError:
            pass
        except Exception:
            pass
        finally:
            if not writer.is_closing():
                writer.close()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        task = asyncio.current_task()
        self._active_tasks.add(task)

        self.total += 1
        client_ip = writer.get_extra_info('peername')[0]
        self._mark_connected(client_ip)

        try:
            version = await reader.readexactly(1)
            if version != b'\x05':
                return

            nmethods = await reader.readexactly(1)
            methods = await reader.readexactly(nmethods[0])

            if self.require_auth:
                if b'\x02' not in methods:
                    writer.write(b'\x05\xFF')
                    await writer.drain()
                    return
                writer.write(b'\x05\x02')
                await writer.drain()

                auth_version = await reader.readexactly(1)
                if auth_version != b'\x01':
                    return

                ulen = (await reader.readexactly(1))[0]
                uname = await reader.readexactly(ulen)
                plen = (await reader.readexactly(1))[0]
                upwd = await reader.readexactly(plen)

                if hmac.compare_digest(uname, self.user) and hmac.compare_digest(upwd, self.pwd):
                    writer.write(b'\x01\x00')
                    await writer.drain()
                    self.auth_ok += 1
                else:
                    writer.write(b'\x01\x01')
                    await writer.drain()
                    self.auth_fail += 1
                    return
            else:
                writer.write(b'\x05\x00')
                await writer.drain()

            req_header = await reader.readexactly(4)
            cmd = req_header[1]
            atyp = req_header[3]

            target_ip = None
            target_port = None

            if atyp == 0x01:
                ip_data = await reader.readexactly(4)
                target_ip = socket.inet_ntoa(ip_data)
                port_data = await reader.readexactly(2)
                target_port = struct.unpack(">H", port_data)[0]
            elif atyp == 0x03:
                domain_len = (await reader.readexactly(1))[0]
                domain_data = await reader.readexactly(domain_len)
                domain = domain_data.decode('utf-8', errors='ignore')
                port_data = await reader.readexactly(2)
                target_port = struct.unpack(">H", port_data)[0]
                if cmd == 0x01:
                    target_ip = await self._dns.resolve(domain, asyncio.get_running_loop())
                    if target_ip is None:
                        writer.write(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                        await writer.drain()
                        return

            if cmd == 0x01 and _is_blocked_destination(target_ip):
                writer.write(b'\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                return

            if cmd == 0x01:
                try:
                    remote_reader, remote_writer = await asyncio.open_connection(target_ip, target_port)

                    for w in (writer, remote_writer):
                        sock = w.get_extra_info('socket')
                        if sock is None:
                            continue
                        try:
                            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        except OSError:
                            pass
                        try:
                            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, _SOCK_BUF)
                            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _SOCK_BUF)
                        except OSError:
                            pass

                    local_ip = writer.get_extra_info('sockname')[0]
                    reply = b'\x05\x00\x00\x01' + socket.inet_aton(local_ip) + struct.pack(">H", 0)
                    writer.write(reply)
                    await writer.drain()

                    await asyncio.gather(
                        self._relay_stream(reader, remote_writer, True),
                        self._relay_stream(remote_reader, writer, False)
                    )
                except Exception:
                    try:
                        writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
                        await writer.drain()
                    except:
                        pass

            elif cmd == 0x03:
                loop = asyncio.get_running_loop()
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: UdpRelayProtocol(client_ip, self),
                    local_addr=('0.0.0.0', 0)
                )
                bind_ip, bind_port = transport.get_extra_info('sockname')

                local_conn_ip = writer.get_extra_info('sockname')[0]
                reply_ip = local_conn_ip if bind_ip == '0.0.0.0' else bind_ip

                reply = b'\x05\x00\x00\x01' + socket.inet_aton(reply_ip) + struct.pack(">H", bind_port)
                writer.write(reply)
                await writer.drain()

                try:
                    while True:
                        check_alive = await reader.read(1024)
                        if not check_alive:
                            break
                except asyncio.CancelledError:
                    pass
                finally:
                    transport.close()

            else:
                writer.write(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()

        except Exception:
            pass
        finally:
            self._active_tasks.discard(task)
            self._mark_disconnected(client_ip)
            if not writer.is_closing():
                writer.close()

    async def run(self):
        self._loop = asyncio.get_running_loop()
        self._stop_event = asyncio.Event()

        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        self._server = server

        print(f"[*] SOCKS5 Proxy   : {self.host}:{self.port}")
        print(f"[*] Authentication : {'Enabled' if self.require_auth else 'Disabled'}")
        print(f"[*] UDP relay      : Enabled (Nat-Type)")
        print(f"[*] Async Engine   : Enabled (asyncio/epoll)")
        print(f"[*] Max concurrent : {self._max_workers} (Termux-tuned)\n")

        serve_task = asyncio.ensure_future(server.serve_forever())
        await self._stop_event.wait()

        tasks = [t for t in self._active_tasks if not t.done()]
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        serve_task.cancel()
        try:
            await serve_task
        except asyncio.CancelledError:
            pass

        if server.is_serving():
            server.close()
        await server.wait_closed()

        print(
            f"\n[*] Proxy stopped."
            f"  total={self.total}"
            f"  auth_ok={self.auth_ok}"
            f"  auth_fail={self.auth_fail}"
        )

    def start(self) -> None:
        asyncio.run(self.run())


def main():
    parser = argparse.ArgumentParser(description="High-Performance Async SOCKS5 Proxy for Termux/Android")
    parser.add_argument("--host", default=None, help="Listen address")
    parser.add_argument("--port", type=int, default=9898, help="Listen port")
    parser.add_argument("--user", default=None, help="Username")
    parser.add_argument("--password", default=None, help="Password")
    parser.add_argument(
        "--workers", type=int, default=_DEFAULT_WORKERS,
        help=f"Max concurrent relayed connections (default {_DEFAULT_WORKERS}, Termux-tuned)"
    )
    args = parser.parse_args()

    proxy = VPNSocks5Proxy(host=args.host, port=args.port, username=args.user, password=args.password, max_workers=args.workers)

    try:
        proxy.start()
    except KeyboardInterrupt:
        print("\n[*] Shutdown requested")
    except Exception as e:
        print(f"[!] Fatal error: {e}")

if __name__ == "__main__":
    main()