#!/usr/bin/env python
"""One-off migration: move insecure password storage to bcrypt(>=12).

There are two kinds of legacy data, handled differently:

  * PLAINTEXT (the stored value IS the password) -> the plaintext is known, so we
    can re-hash it to bcrypt immediately and irreversibly with `--apply`.

  * WEAK/UNRECOVERABLE HASH (unsalted MD5/SHA-1/SHA-256, werkzeug pbkdf2/scrypt,
    or a bcrypt hash below the current cost) -> the plaintext canNOT be recovered,
    so it is impossible to re-hash offline. These are upgraded transparently on
    the user's NEXT successful login by `User.check_password` in backend_app.py.
    This script only counts and reports them.

Classification reuses backend_app's own helpers, so it always matches runtime.

Usage:
    python migrate_passwords.py            # dry run: classify and report only
    python migrate_passwords.py --apply    # additionally re-hash plaintext rows
"""
import sys

import backend_app as a


def classify(stored):
    """Return a short label describing how a password_hash value is stored."""
    if not stored:
        return 'empty'
    m = a._BCRYPT_RE.match(stored)
    if m:
        return 'bcrypt-ok' if int(m.group(1)) >= a.BCRYPT_ROUNDS else 'bcrypt-weak'
    if stored.startswith(('pbkdf2:', 'scrypt:')):
        return 'werkzeug'
    low = stored.strip().lower()
    if a._HEX_MD5.match(low):
        return 'md5'
    if a._HEX_SHA1.match(low):
        return 'sha1'
    if a._HEX_SHA256.match(low):
        return 'sha256'
    return 'plaintext'


# Hash schemes whose plaintext we cannot recover -> upgraded on next login.
_ON_LOGIN = ('md5', 'sha1', 'sha256', 'werkzeug', 'bcrypt-weak')


def main():
    apply = '--apply' in sys.argv[1:]
    buckets = {}
    rehashed = 0

    with a.app.app_context():
        for u in a.User.query.all():
            kind = classify(u.password_hash)
            buckets[kind] = buckets.get(kind, 0) + 1
            if kind == 'plaintext' and apply:
                # The stored value is the plaintext itself (captured before the
                # attribute is reassigned) -> re-hash with bcrypt(>=12).
                u.set_password(u.password_hash)
                rehashed += 1
        if apply and rehashed:
            a.db.session.commit()

    print("=== Password storage audit ===")
    print(f"Database     : {a.app.config['SQLALCHEMY_DATABASE_URI']}")
    print(f"bcrypt cost  : {a.BCRYPT_ROUNDS}")
    print(f"Users scanned: {sum(buckets.values())}")
    for k in sorted(buckets):
        print(f"  {k:12s}: {buckets[k]}")
    print()

    if apply:
        print(f"Re-hashed {rehashed} plaintext password(s) to bcrypt(cost={a.BCRYPT_ROUNDS}).")
    elif buckets.get('plaintext'):
        print(f"{buckets['plaintext']} plaintext password(s) can be re-hashed now -> "
              f"re-run with: python migrate_passwords.py --apply")

    on_login = sum(buckets.get(k, 0) for k in _ON_LOGIN)
    if on_login:
        print(f"{on_login} weak/low-cost hash(es) cannot be re-hashed offline "
              f"(plaintext unknown); they upgrade automatically on next login.")
    print("Done.")


if __name__ == '__main__':
    main()
