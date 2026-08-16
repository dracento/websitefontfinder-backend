import os
import ipaddress
import re
import socket

import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urljoin, urlparse


app = Flask(__name__)


# In development, for example:
# FRONTEND_ORIGIN=http://127.0.0.1:5500
#
# On Render:
# FRONTEND_ORIGIN=https://dracento.github.io
frontend_origin = os.getenv(
    "FRONTEND_ORIGIN",
    "http://127.0.0.1:5500"
)

CORS(
    app,
    resources={
        r"/analyze": {
            "origins": frontend_origin
        }
    }
)


ignored_fonts = {
    "inherit",
    "initial",
    "unset",
    "revert",
    "sans-serif",
    "serif",
    "monospace",
    "ui-sans-serif",
    "ui-monospace",
}


MAX_RESPONSE_SIZE = 5 * 1024 * 1024  # 5 MB
REQUEST_TIMEOUT = 10
MAX_REDIRECTS = 3


def is_safe_url(url):
    """
    Check whether a URL is safe to use for an external HTTP request.
    """

    try:
        parsed = urlparse(url)

        # Only allow HTTP and HTTPS
        if parsed.scheme not in ("http", "https"):
            return False

        # A hostname is required
        if not parsed.hostname:
            return False

        # Reject URLs containing embedded credentials
        if parsed.username is not None or parsed.password is not None:
            return False

        # Only allow standard HTTP/HTTPS ports
        if parsed.port not in (None, 80, 443):
            return False

        hostname = parsed.hostname.rstrip(".")

        # Reject empty hostnames
        if not hostname:
            return False

        # Check IP addresses directly
        try:
            ip = ipaddress.ip_address(hostname)

            if not ip.is_global:
                return False

            return True

        except ValueError:
            # Not a literal IP address, so resolve the hostname
            pass

        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM
        )

        if not addresses:
            return False

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])

            # Only allow globally routable IP addresses
            if not ip.is_global:
                return False

        return True

    except (ValueError, socket.gaierror, socket.herror):
        return False


def get_url(url):
    """
    Fetch a URL after checking it for SSRF risks.

    Redirects are not followed automatically.
    """

    if not is_safe_url(url):
        raise ValueError("This URL is not allowed.")

    response = requests.get(
        url,
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
        stream=True,
        headers={
            "User-Agent": "FontFinder/1.0"
        }
    )

    # Limit the response size
    content_length = response.headers.get("Content-Length")

    if content_length:
        try:
            if int(content_length) > MAX_RESPONSE_SIZE:
                response.close()
                raise ValueError("The response is too large.")
        except ValueError:
            response.close()
            raise ValueError("Invalid Content-Length header.")

    # Read the response body with a size limit
    content = bytearray()

    for chunk in response.iter_content(chunk_size=8192):
        content.extend(chunk)

        if len(content) > MAX_RESPONSE_SIZE:
            response.close()
            raise ValueError("The response is too large.")

    response.close()

    # Store the downloaded content in the response object
    response._content = bytes(content)

    return response


def get_url_with_redirects(url):
    """
    Follow redirects manually and validate every redirect target.
    """

    current_url = url

    for _ in range(MAX_REDIRECTS + 1):
        response = get_url(current_url)

        if response.status_code not in (301, 302, 303, 307, 308):
            return response

        location = response.headers.get("Location")

        if not location:
            return response

        next_url = urljoin(current_url, location)

        if not is_safe_url(next_url):
            raise ValueError(
                "The redirect leads to a URL that is not allowed."
            )

        current_url = next_url

    raise ValueError("Too many redirects.")


def find_fonts(css, found_fonts):
    """
    Find font-family declarations in CSS.
    """

    matches = re.findall(
        r"font-family\s*:\s*([^;}]+)",
        css,
        flags=re.IGNORECASE
    )

    for match in matches:
        fonts = match.split(",")

        for font in fonts:
            font = font.strip(' "\'()')

            if font and font.lower() not in ignored_fonts:
                found_fonts.add(font)


@app.route("/analyze", methods=["GET"])
def analyze():
    url = request.args.get("url", "").strip()

    if not url:
        return jsonify({
            "error": "Please enter a URL."
        }), 400

    if len(url) > 2048:
        return jsonify({
            "error": "The URL is too long."
        }), 400

    try:
        found_fonts = set()

        # Fetch the target website
        response = get_url_with_redirects(url)

        # Raise an exception for HTTP error responses
        response.raise_for_status()

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        # --------------------------------------------------
        # Inline CSS
        # --------------------------------------------------

        styles = soup.find_all("style")

        for style in styles:
            css = style.get_text()
            find_fonts(css, found_fonts)

        # --------------------------------------------------
        # External CSS files
        # --------------------------------------------------

        links = soup.find_all(
            "link",
            rel=lambda value: (
                value
                and "stylesheet" in value
            )
        )

        for link in links:
            href = link.get("href")

            if not href:
                continue

            css_url = urljoin(
                response.url or url,
                href
            )

            try:
                css_response = get_url_with_redirects(css_url)
                css_response.raise_for_status()

                find_fonts(
                    css_response.text,
                    found_fonts
                )

            except (
                ValueError,
                requests.RequestException
            ):
                # Ignore individual CSS files that cannot be fetched
                continue

        return jsonify({
            "fonts": sorted(found_fonts)
        })

    except ValueError as error:
        return jsonify({
            "error": str(error)
        }), 400

    except requests.Timeout:
        return jsonify({
            "error": "The target website took too long to respond."
        }), 504

    except requests.RequestException:
        return jsonify({
            "error": "The website could not be reached."
        }), 502


if __name__ == "__main__":
    app.run(debug=True)