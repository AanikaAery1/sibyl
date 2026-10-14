#!/usr/bin/env bash
# Codespace (real deployment) one-time setup: tools real.sh and the SDK walkthrough need.
set -euo pipefail
sudo apt-get update -qq
sudo apt-get install -y -qq --no-install-recommends apache2-utils jq uuid-runtime >/dev/null
python -m pip install --quiet --user "uv>=0.13"
export PATH="$HOME/.local/bin:$PATH"
uv sync --all-packages --quiet
echo "post-create: uv $(uv --version | cut -d' ' -f2), jq, htpasswd ready"
