#!/usr/bin/env python3
"""SMTP client for the compose demo.

Uses the stdlib `smtplib`. The password is the decoy from SMTP_URL or
SMTPS_URL. A reply that contains the real password fails the process.
"""

import base64
import os
import smtplib
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


def auth_plain(smtp: smtplib.SMTP, user: str, password: str) -> tuple[int, str]:
    token = base64.b64encode(f"\0{user}\0{password}".encode()).decode()
    code, resp = smtp.docmd("AUTH", f"PLAIN {token}")
    return code, check(resp.decode("utf-8", "replace"))


def auth_login(smtp: smtplib.SMTP, user: str, password: str) -> tuple[int, str]:
    code, resp = smtp.docmd("AUTH", "LOGIN")
    text = check(resp.decode("utf-8", "replace"))
    if code != 334:
        return code, text
    code, resp = smtp.docmd(base64.b64encode(user.encode()).decode())
    text = check(resp.decode("utf-8", "replace"))
    if code != 334:
        return code, text
    code, resp = smtp.docmd(base64.b64encode(password.encode()).decode())
    return code, check(resp.decode("utf-8", "replace"))


def context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=CA)
    ctx.check_hostname = True
    return ctx


def credentials(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    if not parsed.username or not parsed.password:
        fail("SMTP url is missing the user or the password")
    return unquote(parsed.username), unquote(parsed.password)


def prove_submission(url: str) -> None:
    user, password = credentials(url)
    # AUTH on a cleartext submission session is refused. A fresh session
    # then upgrades and authenticates with the decoy, which the proxy swaps.
    early = smtplib.SMTP("mail", 587, timeout=15)
    try:
        early.ehlo()
        try:
            code, text = auth_plain(early, user, password)
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
        code, text = auth_plain(plain, user, password)
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
        code, text = auth_login(login, user, password)
        if code != 235:
            fail(f"AUTH LOGIN after STARTTLS failed: {code} {text}")
        print(f"login ok {code}")
    finally:
        try:
            login.quit()
        except smtplib.SMTPException:
            login.close()

    wrong = smtplib.SMTP("mail", 587, timeout=15)
    try:
        wrong.ehlo()
        wrong.starttls(context=context())
        wrong.ehlo()
        code, text = auth_plain(wrong, user, "not-the-password")
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
        code, text = auth_plain(smtp, user, password)
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
        code, text = auth_plain(wrong, user, "not-the-password")
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
    if len(sys.argv) != 3:
        fail("usage: smtp.py smtp|smtps <url>")
    mode, url = sys.argv[1], sys.argv[2]
    if mode == "smtp":
        prove_submission(url)
    elif mode == "smtps":
        prove_smtps(url)
    else:
        fail(f"unknown mode {mode}")


if __name__ == "__main__":
    main()
