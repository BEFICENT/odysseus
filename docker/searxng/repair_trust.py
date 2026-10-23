"""Remove known incident certificates without downloading packages or roots.

Inventory provenance: https://emudhra.we-have-a-problem.com/roots.json and
https://emudhra.we-have-a-problem.com/impacted-intermediates.json; the additional
cross-signed issuer is from the incident's public chains.zip.
"""

import hashlib
import json
from pathlib import Path
import re
import ssl
import subprocess


BLOCKED = json.loads(Path(__file__).with_name("blocked-certificates.json").read_text())
PEM = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


def certificates(text):
    blocks = PEM.findall(text)
    if not blocks or "-----BEGIN" in PEM.sub("", text):
        raise ValueError("empty or malformed certificate input")
    for block in blocks:
        # Validate the X.509 object as well as its base64 encoding.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=block)
        yield block, hashlib.sha256(ssl.PEM_cert_to_DER_cert(block)).hexdigest()


def filter_bundle(path, *, allow_empty=False):
    original = list(certificates(path.read_text()))
    retained = [block for block, digest in original if digest not in BLOCKED]
    removed = len(original) - len(retained)
    if not retained and not allow_empty:
        raise ValueError(f"refusing to empty trust bundle: {path}")
    if removed:
        if retained:
            path.write_text("\n".join(retained) + "\n")
        else:
            path.unlink()
    return removed


def check_bundle(path):
    blocks = list(certificates(path.read_text()))
    if any(digest in BLOCKED for _, digest in blocks):
        raise ValueError(f"incident certificate remains: {path}")
    return len(blocks)


def main():
    import certifi

    sources = list(Path("/usr/share/ca-certificates").rglob("*.crt"))
    sources += list(Path("/usr/local/share/ca-certificates").rglob("*.crt"))
    if not sources:
        raise ValueError("no system CA sources found")
    removed = sum(filter_bundle(path, allow_empty=True) for path in sources)
    removed += filter_bundle(Path(certifi.where()))
    # The upstream entrypoint also regenerates trust at root startup. Removing
    # source certificates ensures that it cannot restore the incident roots.
    subprocess.run(["update-ca-certificates", "--fresh"], check=True)
    paths = [Path("/etc/ssl/certs/ca-certificates.crt"), Path(certifi.where())]
    paths += [p for p in Path("/etc/ssl/certs").iterdir()
              if re.fullmatch(r"[0-9a-fA-F]{8}\.[0-9]+", p.name)]
    if len(paths) <= 2:
        raise ValueError("no hashed system CA entries generated")
    for path in paths:
        check_bundle(path)
    print(f"Removed {removed} incident certificates; checked {len(paths)} trust files")


if __name__ == "__main__":
    main()
