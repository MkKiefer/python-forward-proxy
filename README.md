# ⚠️ NOT FOR PRODUCTION USE! ⚠️

**This code is for learning purposes only. It is NOT production ready. Do not use in any real-world or security-critical environment.**

---

# Python HTTPS Forward Proxy (Learning Project)

This project is a simple HTTPS forward proxy written in Python using `asyncio`. It demonstrates basic concepts of proxying, authentication, and TLS SNI inspection.

## Features

- Handles HTTPS `CONNECT` requests
- Domain and user authentication (basic auth)
- SNI (Server Name Indication) validation for TLS connections
- Customizable list of allowed domains and users

## Usage

1. **Clone the repository**
2. **Add SSL certificates**: Place your certificate and key in the `cert/` directory as `certificate.crt` and `private.key`.
3. **Run with Python**:
   ```sh
   python main.py
   ```
   Or use Docker:
   ```sh
   docker build -t python-forward-proxy .
   docker run -p 8081:8081 python-forward-proxy
   ```

## Configuration

- Allowed domains and users are set in `main.py`.
- Listens on port `8081` by default.

## Limitations & Warnings

- **No security hardening**
- **No logging, monitoring, or error handling for production**
- **No support for HTTP requests (only HTTPS CONNECT)**
- **Single-threaded, not optimized for performance**

## License

MIT License

---

**For educational use only.**
