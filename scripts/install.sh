#!/usr/bin/env bash

set -euo pipefail

uv sync --group dev --group demo
uv pip install -e .