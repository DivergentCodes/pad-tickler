#!/usr/bin/env bash

set -euo pipefail

uv sync
uv pip install -e .