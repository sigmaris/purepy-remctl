#!/bin/bash -eux
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get -y install \
    gcc \
    krb5-{user,kdc,admin-server,multidev} \
    libkrb5-dev \
    python3-{virtualenv,dev} \
    remctl-server \
    virtualenv

mkdir /build
virtualenv --system-site-packages -p $(which python3) /build/venv
