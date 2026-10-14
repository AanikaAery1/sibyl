#!/bin/sh
# Gateway launcher (compose). Runs as uid 10001 on a read-only root; /tmp is a tmpfs.
#
# When the sim profile runs, trust the sibyl-sim dev CA for upstream TLS to the doubles:
# fetch its certificate from SIBYL_SIM_CA_URL, check it is a CA that cannot issue sub-CAs,
# and append it to the upstream bundle: the operator's SIBYL_UPSTREAM_CA_FILE when set (an
# egress proxy CA), else the system bundle (real providers keep their normal trust). The sim discards
# the CA private key after signing its single leaf (SANs: sim, localhost, 127.0.0.1, ::1), so the
# extra anchor can vouch for those dev hosts only. Without the sim, nothing changes.
set -eu

bundle=/tmp/sibyl-upstream-ca.pem
base="${SIBYL_UPSTREAM_CA_FILE:-/etc/ssl/certs/ca-certificates.crt}"
if [ -n "${SIBYL_SIM_CA_URL:-}" ]; then
  if python - "$SIBYL_SIM_CA_URL" "$bundle" "$base" <<'EOF'
import sys
import time
import urllib.request

from cryptography import x509

url, out, base = sys.argv[1], sys.argv[2], sys.argv[3]
pem = b""
for attempt in range(3):
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:  # noqa: S310 (in-network http)
            pem = resp.read(65536)
        break
    except OSError:
        time.sleep(1)
if not pem:
    print("gateway start: sibyl-sim CA not reachable; upstream trust unchanged", file=sys.stderr)
    sys.exit(1)
cert = x509.load_pem_x509_certificate(pem)
constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
if not constraints.ca or constraints.path_length != 0:
    print("gateway start: sim certificate is not a leaf-only CA; refusing it", file=sys.stderr)
    sys.exit(2)
with open(base, "rb") as trusted:
    combined = trusted.read().rstrip(b"\n") + b"\n" + pem
with open(out, "wb") as fh:
    fh.write(combined)
print(f"gateway start: trusting sibyl-sim dev CA {cert.subject.rfc4514_string()}", file=sys.stderr)
EOF
  then
    export SIBYL_UPSTREAM_CA_FILE="$bundle"
  fi
fi

exec python -m sibyl_gateway
