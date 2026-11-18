#!/usr/local/bin/python3.13
"""Bounded localhost DNS matcher for exact, keyword, and regex routing rules."""

import argparse
import json
import re
import socket
import socketserver
import subprocess
import syslog
import threading
import time
from collections import OrderedDict
from pathlib import Path

MAX_PACKET = 4096
MAX_WORKERS = 64
QUERY_TIMEOUT = 2.0
TABLE_RE = re.compile(r"^(?:bvs|bvb)_[a-f0-9]{24}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)


def dns_name(data, offset):
    labels = []
    cursor = offset
    end = None
    seen = set()
    for _ in range(128):
        if cursor >= len(data):
            raise ValueError("truncated DNS name")
        size = data[cursor]
        if size == 0:
            end = cursor + 1 if end is None else end
            name = ".".join(labels).lower()
            return name, end
        if size & 0xC0 == 0xC0:
            if cursor + 1 >= len(data):
                raise ValueError("truncated DNS pointer")
            pointer = ((size & 0x3F) << 8) | data[cursor + 1]
            if pointer >= len(data) or pointer in seen:
                raise ValueError("invalid DNS pointer")
            seen.add(pointer)
            if end is None:
                end = cursor + 2
            cursor = pointer
            continue
        if size & 0xC0 or size > 63 or cursor + size + 1 > len(data):
            raise ValueError("invalid DNS label")
        labels.append(data[cursor + 1:cursor + 1 + size].decode("ascii", "strict"))
        cursor += size + 1
        if sum(map(len, labels)) + len(labels) > 253:
            raise ValueError("DNS name too long")
    raise ValueError("DNS compression depth exceeded")


def question(packet):
    if len(packet) < 17:
        raise ValueError("short DNS query")
    flags, questions = int.from_bytes(packet[2:4], "big"), int.from_bytes(packet[4:6], "big")
    if flags & 0x8000 or flags & 0x7800 or questions != 1:
        raise ValueError("unsupported DNS query")
    name, end = dns_name(packet, 12)
    if end + 4 > len(packet):
        raise ValueError("invalid DNS question")
    return name, int.from_bytes(packet[end:end + 2], "big"), end + 4


def answer_data(packet):
    if len(packet) < 12:
        return [], []
    answers = int.from_bytes(packet[6:8], "big")
    offset = 12
    questions = int.from_bytes(packet[4:6], "big")
    try:
        for _ in range(questions):
            _, offset = dns_name(packet, offset)
            offset += 4
        result, aliases = [], []
        for _ in range(min(answers, 256)):
            _, offset = dns_name(packet, offset)
            if offset + 10 > len(packet):
                return [], []
            record_type = int.from_bytes(packet[offset:offset + 2], "big")
            record_class = int.from_bytes(packet[offset + 2:offset + 4], "big")
            ttl = int.from_bytes(packet[offset + 4:offset + 8], "big")
            size = int.from_bytes(packet[offset + 8:offset + 10], "big")
            offset += 10
            if offset + size > len(packet):
                return [], []
            if record_type == 1 and record_class == 1 and size == 4:
                result.append(socket.inet_ntop(socket.AF_INET, packet[offset:offset + size]))
            elif record_type == 28 and record_class == 1 and size == 16:
                result.append(socket.inet_ntop(socket.AF_INET6, packet[offset:offset + size]))
            elif record_type == 5 and record_class == 1:
                target, end = dns_name(packet, offset)
                if target and end <= offset + size:
                    aliases.append((target, min(max(ttl, 60), 86400)))
            offset += size
        return list(dict.fromkeys(result[:64])), aliases[:64]
    except (ValueError, UnicodeError):
        return [], []


def empty_reply(packet, rcode=2):
    try:
        _, _, end = question(packet)
    except (ValueError, UnicodeError):
        return b""
    flags = int.from_bytes(packet[2:4], "big")
    response_flags = (flags & 0x0100) | 0x8080 | (rcode & 0x0F)
    header = packet[:2] + response_flags.to_bytes(2, "big") + b"\0\1\0\0\0\0\0\0"
    return header + packet[12:end]


def servfail(packet):
    return empty_reply(packet, 2)


def matches(rule, hostname):
    kind, pattern = rule["type"], rule["pattern"]
    if kind == "full":
        return hostname == pattern
    if kind == "keyword":
        return pattern in hostname
    if kind == "regex":
        return re.search(pattern, hostname, re.IGNORECASE) is not None
    return False


def forward(packet, port):
    if not isinstance(port, int) or port < 1 or port > 65535:
        return servfail(packet)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
            upstream.settimeout(QUERY_TIMEOUT)
            upstream.sendto(packet, ("127.0.0.1", port))
            response, _ = upstream.recvfrom(MAX_PACKET)
        if len(response) >= 4 and int.from_bytes(response[2:4], "big") & 0x0200:
            with socket.create_connection(("127.0.0.1", port), timeout=QUERY_TIMEOUT) as stream:
                stream.settimeout(QUERY_TIMEOUT)
                stream.sendall(len(packet).to_bytes(2, "big") + packet)
                size = int.from_bytes(read_exact(stream, 2), "big")
                if size > MAX_PACKET:
                    return servfail(packet)
                response = read_exact(stream, size)
        return response
    except (OSError, ValueError, TimeoutError):
        return servfail(packet)


def read_exact(stream, size):
    chunks = bytearray()
    while len(chunks) < size:
        chunk = stream.recv(size - len(chunks))
        if not chunk:
            raise OSError("truncated DNS stream")
        chunks.extend(chunk)
    return bytes(chunks)


class Matcher:
    def __init__(self, config):
        if config.get("version") != 1 or config.get("mode") not in ("shadow", "route"):
            raise ValueError("unsupported matcher configuration")
        self.mode = config["mode"]
        self.listeners = {}
        self.counts = {}
        self.aliases = OrderedDict()
        self.alias_lock = threading.Lock()
        self.addresses = OrderedDict()
        self.address_lock = threading.Lock()
        self.address_pruned = time.monotonic()
        for row in config.get("listeners", []):
            port = row.get("port")
            default_port = row.get("defaultPort")
            if not isinstance(port, int) or not 49100 <= port <= 49299:
                raise ValueError("invalid matcher listener")
            if not isinstance(default_port, int) or not 1 <= default_port <= 65535:
                raise ValueError("invalid default DNS listener")
            rules = []
            for rule in row.get("rules", []):
                if rule.get("type") not in ("full", "keyword", "regex"):
                    raise ValueError("invalid DNS matcher rule")
                pattern = rule.get("pattern")
                if not isinstance(pattern, str) or not pattern or len(pattern) > 512:
                    raise ValueError("invalid DNS matcher pattern")
                if rule["type"] == "regex":
                    re.compile(pattern, re.IGNORECASE)
                upstream = rule.get("upstreamPort")
                table = rule.get("table", "")
                if upstream is not None and (not isinstance(upstream, int) or not 1 <= upstream <= 65535):
                    raise ValueError("invalid route DNS listener")
                if table and not TABLE_RE.fullmatch(table):
                    raise ValueError("invalid route table")
                rules.append({"type": rule["type"], "pattern": pattern.lower(),
                              "upstreamPort": upstream, "table": table})
            self.listeners[port] = {"defaultPort": default_port, "rules": rules}

    def resolve(self, port, packet):
        entry = self.listeners.get(port)
        if entry is None:
            return servfail(packet)
        try:
            hostname, record_type, _ = question(packet)
        except (ValueError, UnicodeError):
            return servfail(packet)
        now = time.monotonic()
        alias_key = (port, hostname)
        with self.alias_lock:
            while self.aliases and next(iter(self.aliases.values()))[0] <= now:
                self.aliases.popitem(last=False)
            alias = self.aliases.get(alias_key)
            if alias is not None:
                self.aliases.move_to_end(alias_key)
        selected = next((rule for rule in entry["rules"] if matches(rule, hostname)), None)
        selected = selected or (alias[1] if alias is not None else None)
        if selected is None:
            return forward(packet, entry["defaultPort"])
        key = selected["type"] + ":" + selected["pattern"]
        with self.alias_lock:
            self.counts[key] = min(2**31 - 1, self.counts.get(key, 0) + 1)
        if self.mode == "shadow":
            return forward(packet, entry["defaultPort"])
        if selected["upstreamPort"] is None:
            return servfail(packet)
        if record_type in (64, 65):
            return empty_reply(packet, 0)
        response = forward(packet, selected["upstreamPort"])
        if selected["table"] and len(response) >= 4 and (int.from_bytes(response[2:4], "big") & 0x000F) == 0:
            addresses, cname_aliases = answer_data(response)
            if addresses and not self.add_addresses(selected["table"], addresses):
                return servfail(packet)
            for name, ttl in cname_aliases:
                if name != hostname:
                    alias_key = (port, name)
                    with self.alias_lock:
                        self.aliases[alias_key] = (time.monotonic() + ttl, selected)
                        self.aliases.move_to_end(alias_key)
                        while len(self.aliases) > 8192:
                            self.aliases.popitem(last=False)
        return response

    def add_addresses(self, table, addresses):
        now = time.monotonic()
        with self.address_lock:
            if now - self.address_pruned >= 300:
                for key, expires in list(self.addresses.items()):
                    if expires <= now:
                        self.addresses.pop(key, None)
                self.address_pruned = now
            fresh = []
            for address in addresses:
                key = (table, address)
                if key not in self.addresses:
                    fresh.append(address)
        if not fresh:
            return True
        try:
            check = subprocess.run(["/sbin/pfctl", "-v", "-t", table, "-T", "test", *fresh],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, text=True, timeout=1.0, check=False)
            present = set(re.findall(r"^M\s+([0-9a-fA-F:.]+)\s*$", check.stdout, re.M))
            missing = [address for address in fresh if address not in present]
            if missing:
                added = subprocess.run(["/sbin/pfctl", "-t", table, "-T", "add", *missing],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, timeout=1.0, check=False)
                if added.returncode != 0:
                    verify = subprocess.run(["/sbin/pfctl", "-v", "-t", table, "-T", "test", *missing],
                                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                            stderr=subprocess.DEVNULL, text=True, timeout=1.0, check=False)
                    verified = set(re.findall(r"^M\s+([0-9a-fA-F:.]+)\s*$", verify.stdout, re.M))
                    if not set(missing).issubset(verified):
                        raise RuntimeError("PF rejected DNS learned addresses")
            with self.address_lock:
                for address in fresh:
                    lifetime = 86400 - 300 if address in missing else 5
                    self.addresses[(table, address)] = now + lifetime
                    self.addresses.move_to_end((table, address))
                while len(self.addresses) > 100000:
                    self.addresses.popitem(last=False)
            return True
        except (OSError, subprocess.TimeoutExpired):
            pass
        except RuntimeError:
            pass
        with self.address_lock:
            for address in fresh:
                self.addresses.pop((table, address), None)
        syslog.syslog(syslog.LOG_ERR, "Blank VPN DNS matcher could not update a destination table.")
        return False


class LimitedMixIn:
    semaphore = threading.BoundedSemaphore(MAX_WORKERS)

    def process_request(self, request, client_address):
        if self.semaphore.acquire(blocking=False):
            try:
                super().process_request(request, client_address)
            except Exception:
                self.semaphore.release()
                raise
        else:
            self.busy_reply(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.semaphore.release()

    def busy_reply(self, request, client_address):
        raise NotImplementedError


class UDPServer(LimitedMixIn, socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(self, address, matcher):
        self.matcher = matcher
        super().__init__(address, UDPHandler)

    def busy_reply(self, request, client_address):
        packet = servfail(request[0])
        if packet:
            self.socket.sendto(packet, client_address)


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        response = self.server.matcher.resolve(self.server.server_address[1], packet[:MAX_PACKET])
        if response:
            sock.sendto(response[:MAX_PACKET], self.client_address)


class TCPServer(LimitedMixIn, socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(self, address, matcher):
        self.matcher = matcher
        super().__init__(address, TCPHandler)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(QUERY_TIMEOUT + 1)
        return request, address

    def busy_reply(self, request, client_address):
        try:
            length = int.from_bytes(read_exact(request, 2), "big")
            packet = read_exact(request, min(length, MAX_PACKET))
            response = servfail(packet)
            request.sendall(len(response).to_bytes(2, "big") + response)
        except OSError:
            pass


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            length = int.from_bytes(read_exact(self.request, 2), "big")
            if length < 12 or length > MAX_PACKET:
                return
            packet = read_exact(self.request, length)
            response = self.server.matcher.resolve(self.server.server_address[1], packet)
            self.request.sendall(len(response).to_bytes(2, "big") + response)
        except (OSError, ValueError):
            return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    path = Path(args.config)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("DNS matcher configuration is unavailable")
    config = json.loads(path.read_text())
    matcher = Matcher(config)
    servers = []
    try:
        for port in matcher.listeners:
            servers.extend([UDPServer(("127.0.0.1", port), matcher), TCPServer(("127.0.0.1", port), matcher)])
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        threading.Event().wait()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        syslog.syslog(syslog.LOG_ERR, "Blank VPN DNS matcher stopped: " + str(error)[:240])
        raise
