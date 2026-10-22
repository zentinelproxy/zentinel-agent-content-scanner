#!/usr/bin/env python3
"""Stand-in for clamd, for the smoke test where no real ClamAV is running.

Listens on a Unix socket and speaks the part of the clamd protocol the agent
uses: `nINSTREAM\\n`, then chunks of <4-byte big-endian length><data>, ended
by a zero length. Answers `stream: Eicar-Signature FOUND` when the stream
contains the EICAR test signature and `stream: OK` otherwise. It recognises
nothing else, so it only proves that the agent sends the body to clamd and
acts on the verdict.

    fake-clamd.py <socket-path>
"""

import os
import socket
import struct
import sys
import threading

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def read_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        part = conn.recv(n - len(buf))
        if not part:
            raise ConnectionError("client closed the stream")
        buf += part
    return buf


def handle(conn: socket.socket) -> None:
    with conn:
        try:
            cmd = b""
            while not cmd.endswith(b"\n") and not cmd.endswith(b"\0"):
                part = conn.recv(1)
                if not part:
                    return
                cmd += part
            if cmd.strip(b"\n\0") not in (b"nINSTREAM", b"zINSTREAM"):
                conn.sendall(b"UNKNOWN COMMAND\n")
                return
            data = b""
            while True:
                (length,) = struct.unpack(">I", read_exact(conn, 4))
                if length == 0:
                    break
                data += read_exact(conn, length)
            verdict = b"stream: Eicar-Signature FOUND\n" if EICAR in data else b"stream: OK\n"
            conn.sendall(verdict)
        except (ConnectionError, OSError):
            pass


def main() -> None:
    path = sys.argv[1]
    if os.path.exists(path):
        os.unlink(path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(16)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
