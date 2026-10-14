#!/usr/bin/env python3
"""SMTP client for the compose demo.

Uses the stdlib `smtplib`. The password is the decoy from SMTP_URL or
SMTPS_URL. A reply that contains the real password fails the process.
"""

import os
import smtplib
import socket
import ssl
import sys
from urllib.parse import unquote, urlparse

REAL = "arkham_real_smtp_pass"
CA = "/certs/ca.crt"


def fail(message: str) -> None:
    print(message)
    sys.exit(1)


def check(text: str) -> str:
    if REAL in text:
        fail(f"reply leaked the real password: {text}")
    return text


def auth_via(smtp: smtplib.SMTP, mechanism: str, user: str, password: str) -> tuple[int, str]:
    smtp.user = user
    smtp.password = password
    method = smtp.auth_plain if mechanism == "PLAIN" else smtp.auth_login
    code, resp = smtp.auth(mechanism, method)
    text = resp.decode("utf-8", "replace") if isinstance(resp, bytes) else str(resp)
    return code, check(text)


def context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=CA)
    ctx.check_hostname = True
    return ctx


def credentials(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    if not parsed.username or not parsed.password:
        fail("SMTP url is missing the user or the password")
    return unquote(parsed.username), unquote(parsed.password)


# Capture skips sockets that already carry the backend's bypass mark.
# tproxy's egress mark is 0x89; tun's fib bypass mark is 0x88.
BYPASS_MARK = {"tproxy": 0x89, "tun": 0x88}


def connect_marked(host: str, port: int, timeout: float) -> socket.socket:
    backend = os.environ.get("ARKHAM_BACKEND", "tproxy")
    mark = BYPASS_MARK.get(backend)
    if mark is None:
        fail(f"direct dial has no bypass mark for backend {backend}")
    last = "no address"
    for family, _kind, _proto, _canon, sockaddr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            return sock
        except OSError as err:
            last = str(err)
            sock.close()
    fail(f"direct dial to {host}:{port} failed: {last}")
    raise AssertionError("unreachable")


class MarkedSMTP(smtplib.SMTP):
    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        return connect_marked(host, port, timeout)


class MarkedSMTP_SSL(smtplib.SMTP_SSL):
    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        raw = connect_marked(host, port, timeout)
        return self.context.wrap_socket(raw, server_hostname=self._host)


def prove_direct(url: str) -> None:
    user, password = credentials(url)
    submission = MarkedSMTP("mail", 587, timeout=15)
    try:
        submission.ehlo()
        submission.starttls(context=context())
        submission.ehlo()
        try:
            submission.login(user, password)
        except smtplib.SMTPException as err:
            print(f"decoy refused 587 {check(str(err))}")
        else:
            fail("decoy authenticated on 587 without the proxy")
    finally:
        try:
            submission.quit()
        except smtplib.SMTPException:
            submission.close()

    implicit = MarkedSMTP_SSL("mail", 465, context=context(), timeout=15)
    try:
        implicit.ehlo()
        try:
            implicit.login(user, password)
        except smtplib.SMTPException as err:
            print(f"decoy refused 465 {check(str(err))}")
        else:
            fail("decoy authenticated on 465 without the proxy")
    finally:
        try:
            implicit.quit()
        except smtplib.SMTPException:
            implicit.close()


def prove_submission(url: str) -> None:
    user, password = credentials(url)
    # AUTH on a cleartext submission session is refused. A fresh session
    # then upgrades and authenticates with the decoy, which the proxy swaps.
    early = smtplib.SMTP("mail", 587, timeout=15)
    try:
        early.ehlo()
        try:
            code, text = auth_via(early, "PLAIN", user, password)
        except smtplib.SMTPException as err:
            text = check(str(err))
            code = 0
        if code == 235:
            fail(f"AUTH before STARTTLS succeeded: {code} {text}")
        print(f"before-starttls refused {code} {text}")
    finally:
        try:
            early.quit()
        except smtplib.SMTPException:
            early.close()

    plain = smtplib.SMTP("mail", 587, timeout=15)
    try:
        plain.ehlo()
        plain.starttls(context=context())
        plain.ehlo()
        code, text = auth_via(plain, "PLAIN", user, password)
        if code != 235:
            fail(f"AUTH PLAIN after STARTTLS failed: {code} {text}")
        print(f"plain ok {code}")
    finally:
        try:
            plain.quit()
        except smtplib.SMTPException:
            plain.close()

    login = smtplib.SMTP("mail", 587, timeout=15)
    try:
        login.ehlo()
        login.starttls(context=context())
        login.ehlo()
        try:
            login.login(user, password)
        except smtplib.SMTPException as err:
            fail(f"SMTP.login after STARTTLS failed: {check(str(err))}")
        print("login ok 235")
    finally:
        try:
            login.quit()
        except smtplib.SMTPException:
            login.close()

    mechanism = smtplib.SMTP("mail", 587, timeout=15)
    try:
        mechanism.ehlo()
        mechanism.starttls(context=context())
        mechanism.ehlo()
        code, text = auth_via(mechanism, "LOGIN", user, password)
        if code != 235:
            fail(f"AUTH LOGIN after STARTTLS failed: {code} {text}")
        print(f"login mechanism ok {code}")
    finally:
        try:
            mechanism.quit()
        except smtplib.SMTPException:
            mechanism.close()

    wrong = smtplib.SMTP("mail", 587, timeout=15)
    try:
        wrong.ehlo()
        wrong.starttls(context=context())
        wrong.ehlo()
        try:
            code, text = auth_via(wrong, "PLAIN", user, "not-the-password")
        except smtplib.SMTPException as err:
            print(f"wrong refused {check(str(err))}")
        else:
            if code == 235:
                fail(f"wrong password authenticated: {text}")
            print(f"wrong refused {code} {text}")
    finally:
        try:
            wrong.quit()
        except smtplib.SMTPException:
            wrong.close()
    print("smtp ok")


def prove_smtps(url: str) -> None:
    user, password = credentials(url)
    smtp = smtplib.SMTP_SSL("mail", 465, context=context(), timeout=15)
    try:
        smtp.ehlo()
        code, text = auth_via(smtp, "PLAIN", user, password)
        if code != 235:
            fail(f"AUTH PLAIN on SMTPS failed: {code} {text}")
        print(f"plain ok {code}")
    finally:
        try:
            smtp.quit()
        except smtplib.SMTPException:
            smtp.close()

    wrong = smtplib.SMTP_SSL("mail", 465, context=context(), timeout=15)
    try:
        wrong.ehlo()
        try:
            code, text = auth_via(wrong, "PLAIN", user, "not-the-password")
        except smtplib.SMTPException as err:
            print(f"wrong refused {check(str(err))}")
        else:
            if code == 235:
                fail(f"wrong password authenticated: {text}")
            print(f"wrong refused {code} {text}")
    finally:
        try:
            wrong.quit()
        except smtplib.SMTPException:
            wrong.close()
    print("smtps ok")


def main() -> None:
    if len(sys.argv) < 2:
        fail("usage: smtp.py direct | smtp.py smtp|smtps <url>")
    mode = sys.argv[1]
    if mode == "direct":
        url = os.environ.get("SMTP_URL", "")
        if not url:
            fail("SMTP_URL is required")
        prove_direct(url)
        return
    if len(sys.argv) != 3:
        fail("usage: smtp.py direct | smtp.py smtp|smtps <url>")
    url = sys.argv[2]
    if mode == "smtp":
        prove_submission(url)
    elif mode == "smtps":
        prove_smtps(url)
    else:
        fail(f"unknown mode {mode}")


if __name__ == "__main__":
    main()
