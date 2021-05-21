#!/bin/bash -e
source /build/venv/bin/activate
set -x
pip install '.[dev]'
mkdir -p /build/artifacts
pytest \
  --cov-report xml:/build/artifacts/coverage.xml \
  --cov-report term \
  --cov=purepy_remctl \
  --junitxml=/build/artifacts/testreport.xml \
  tests/
