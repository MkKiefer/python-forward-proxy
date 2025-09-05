import asyncio
from datetime import UTC, datetime
import ssl
import os
import base64


class ProxyConnection:

    MAXHEADERS = 100

    def __init__(self, authorized_domains: list[str], authorized_users: dict[str, str]):
        self.authorized_domains = authorized_domains
        self.authorized_users = authorized_users

    async def handle(
        self, src_reader: asyncio.StreamReader, src_writer: asyncio.StreamWriter
    ):

        try:

            self.header = await self.read_headers(src_reader)

            print(f"Received request: {self.header}")

            if self.header["method"] != "CONNECT":
                await self.send_response(src_writer, 405, "Method Not Allowed")
                raise ValueError(f"Method Not Allowed: {self.header['method']} ❌")

            try:
                host, port = self.header["path"].split(":", 1)
            except ValueError:
                await self.send_response(src_writer, 400, "Bad Request")
                raise ValueError(f"Malformed host path: {self.header['path']} ❌")
            if not port.isdigit() or port != "443":
                await self.send_response(src_writer, 400, "Bad Request")
                raise ValueError(f"Port is not numeric or 443: {port} ❌")

            if host not in self.authorized_domains:
                await self.send_response(src_writer, 403, "Forbidden")
                raise ValueError(f"Unauthorized domain: {host} ❌")

            if "proxy-authorization" not in self.header:
                await self.send_response(
                    src_writer, 407, "Proxy Authentication Required"
                )
                raise ValueError("No Proxy-Authorization header ❌")

            if "Basic" not in self.header["proxy-authorization"]:
                await self.send_response(
                    src_writer, 407, "Proxy Authentication Required"
                )
                raise ValueError("Not of type Basic Auth ❌")

            auth_header = self.header["proxy-authorization"].lstrip("Basic ").strip()
            user_password = base64.b64decode(auth_header).decode("utf-8")
            username, password = user_password.split(":", 1)

            if username not in self.authorized_users:
                await self.send_response(src_writer, 403, "Forbidden")
                raise ValueError(f"Unauthorized user: {username} ❌")

            if self.authorized_users[username] != password:
                await self.send_response(src_writer, 403, "Forbidden")
                raise ValueError(f"Invalid password for user: {username} ❌")

            dst_reader, dst_writer = await asyncio.open_connection(host, int(port))

            await self.send_response(src_writer, 200, "Connection Established")

            print(f"Proxying to {host}:{port}... ✅")

            _, pending = await asyncio.wait(
                [
                    asyncio.create_task(
                        self.pipe_with_sni_check(src_reader, dst_writer, host)
                    ),
                    asyncio.create_task(self.pipe(dst_reader, src_writer)),
                ],
                return_when=asyncio.FIRST_COMPLETED,
            )

            # Finish the pending tasks and wait for their completion
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

        except Exception as e:
            print("Connection closed: ", e)
        finally:
            try:
                src_writer.close()
                await src_writer.wait_closed()
                dst_writer.close()
                await dst_writer.wait_closed()
            except (UnboundLocalError, ConnectionResetError, ssl.SSLError):
                pass
            print("Connection closed normally. 🎉")

    async def send_response(
        self,
        src_writer: asyncio.StreamWriter,
        status_code: int,
        reason: str,
        headers=None,
        body=b"",
    ):
        if headers is None:
            headers = {}
        status_line = f"HTTP/1.1 {status_code} {reason}\r\n"
        default_headers = {
            "Mime-Version": "1.0",
            "Date": datetime.now(tz=UTC).strftime("%a, %d %b %Y %H:%M:%S GMT"),
            "Content-Type": "text/html;charset=utf-8",
            "Content-Length": str(len(body)),
            "Proxy-Authenticate": "Basic",
            "Connection": "keep-alive",
        }
        # Merge/override with custom headers
        default_headers.update(headers)
        header_lines = "".join(f"{k}: {v}\r\n" for k, v in default_headers.items())
        payload = (status_line + header_lines + "\r\n").encode() + body
        src_writer.write(payload)
        await src_writer.drain()

    async def read_headers(self, src_reader: asyncio.StreamReader) -> dict[str, str]:
        lines: list[bytes] = []
        while True:
            line = await src_reader.readline()
            lines.append(line)
            if len(lines) > self.MAXHEADERS:
                raise ValueError("got more than %d headers" % self.MAXHEADERS)
            if line in (b"\r\n", b"\n", b""):
                break
        if not lines:
            raise ValueError("Empty request line")

        header: dict[str, str] = {}
        data = b"".join(lines).decode()
        request_text, header_text = data.split("\r\n", 1)
        # Parse the first line
        header["method"], header["path"], header["http-version"] = request_text.split(
            " ", 2
        )
        # Parse the additional headers
        for header_line in header_text.split("\r\n"):
            if ": " in header_line:
                key, value = header_line.split(": ", 1)
                header[key.strip().lower()] = value.strip()
            elif header_line != "":
                print(f"Skipping malformed header line: {header_line} ⚠️")

        return header

    @staticmethod
    def parse_sni(data: bytes) -> str | None:
        """
        Parse SNI from TLS ClientHello.
        Returns the server name or None if not found.
        """
        if len(data) < 6 or data[0] != 0x16:  # 0x16 = Client Hello Package
            return None
        idx = 5  # Skip record header
        idx += 1 + 3 + 2 + 32  # Skip handshake header, version, random
        if idx >= len(data):
            return None
        session_id_len = data[idx]  # Session ID length
        idx += 1 + session_id_len  # Skip session ID
        if idx + 2 > len(data):
            return None
        cs_len = int.from_bytes(data[idx : idx + 2], "big")  # Cipher Suites length
        idx += 2 + cs_len  # Skip cipher suites
        if idx >= len(data):
            return None
        comp_len = data[idx]  # Compression Methods length
        idx += 1 + comp_len  # Skip compression methods
        if idx + 2 > len(data):
            return None
        ext_len = int.from_bytes(data[idx : idx + 2], "big")  # Extensions length
        idx += 2  # Move to the start of extensions
        end = idx + ext_len
        while idx + 4 <= end and idx + 4 <= len(data):  # Each ext header is 4 bytes
            ext_type = int.from_bytes(data[idx : idx + 2], "big")
            ext_size = int.from_bytes(data[idx + 2 : idx + 4], "big")
            if ext_type == 0:  # Find SNI Extension
                sni_data = data[idx + 4 : idx + 4 + ext_size]
                if len(sni_data) >= 5 and sni_data[2] == 0:
                    name_len = int.from_bytes(sni_data[3:5], "big")  # Name length
                    return sni_data[5 : 5 + name_len].decode()  # Return SNI
            idx += 4 + ext_size  # Move to the next extension
        return None

    @classmethod
    async def pipe(cls, src: asyncio.StreamReader, dst: asyncio.StreamWriter):
        try:
            while True:
                chunk = await src.read(4096)
                if not chunk:
                    break
                dst.write(chunk)
                await dst.drain()
        except asyncio.CancelledError:
            pass

    @classmethod
    async def pipe_with_sni_check(
        cls, src: asyncio.StreamReader, dst: asyncio.StreamWriter, expected_host
    ):
        # Peek at the first bytes for TLS ClientHello
        first_chunk = await src.read(4096)
        sni = cls.parse_sni(first_chunk)
        if not sni or sni != expected_host:
            raise ValueError(
                f"SNI does not match expected: {expected_host} actual {sni} ❌"
            )
        # Forward the first chunk
        dst.write(first_chunk)
        await dst.drain()
        # Create new pipe task
        await cls.pipe(src, dst)


async def main():
    # SSL context for incoming connections
    base_dir = os.path.dirname(os.path.abspath(__file__))
    cert_path = os.path.join(base_dir, "cert", "certificate.crt")
    key_path = os.path.join(base_dir, "cert", "private.key")
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

    proxy = ProxyConnection(
        authorized_domains=["httpbin.org", "google.com"],
        authorized_users={"admin": "secret"},
    )

    server = await asyncio.start_server(proxy.handle, "0.0.0.0", 8081, ssl=ssl_ctx)
    print("HTTPS forward proxy listening on port 8081...")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
