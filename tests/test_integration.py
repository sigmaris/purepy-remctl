from contextlib import closing
import os
import socket
import subprocess
import tempfile
import time
from typing import NamedTuple

import pytest
import k5test

import purepy_remctl as pkg


class RemctlDaemon(NamedTuple):
    port: int
    proc: subprocess.Popen


def _find_free_port():
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(('localhost', 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def realm():
    realm = k5test.realm.K5Realm()
    yield realm
    realm.stop()


@pytest.fixture
def k5env(realm, monkeypatch):
    for k, v in realm.env.items():
        monkeypatch.setenv(k, v)


@pytest.fixture(scope="session")
def remctld(realm):
    with tempfile.NamedTemporaryFile(mode="w+") as conffile:
        conffile.write("testshell ALL /bin/sh ANYUSER\n")
        conffile.write("denied ALL /bin/sh deny\n")
        conffile.flush()
        port = _find_free_port()
        args = (
            "remctld",
            "-d",  # Debug logging
            "-f", conffile.name,
            "-F",  # Run in foreground instead of daemonizing
            "-m",  # standalone mode, not inetd
            "-p", str(port),
            "-s", realm.host_princ,  # service principal
            "-S",  # Log to stdout/stderr
        )
        proc = subprocess.Popen(args, env=dict(PATH=os.environ['PATH'], **realm.env))

        start = time.time()
        while True:
            try:
                socket.create_connection((realm.hostname, port), 1)
            except ConnectionRefusedError:
                if time.time() - start > 5:
                    raise
                else:
                    time.sleep(0.1)
            else:
                break

        yield RemctlDaemon(port, proc)
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture(scope="session")
def user_kinit(realm):
    password = realm.password("user")
    realm.kinit(realm.user_princ, password=password)


def test_cmd_success(realm, remctld, k5env, user_kinit):
    result = pkg.remctl(host=realm.hostname, port=remctld.port, command=["testshell", "-c", "echo -n foobar"])
    assert result.stdout == b"foobar"
    assert result.status == 0


def test_cmd_exiterror(realm, remctld, k5env, user_kinit):
    result = pkg.remctl(host=realm.hostname, port=remctld.port, command=["testshell", "-c", "echo -n someerror; exit 1"])
    assert result.stdout == b"someerror"
    assert result.status == 1


def test_cmd_stderr(realm, remctld, k5env, user_kinit):
    result = pkg.remctl(host=realm.hostname, port=remctld.port, command=["testshell", "-c", "echo -n foobar 1>&2"])
    assert result.stderr == b"foobar"
    assert result.status == 0


def test_denied(realm, remctld, k5env, user_kinit):
    with pytest.raises(pkg.RemctlProtocolError):
        pkg.remctl(host=realm.hostname, port=remctld.port, command=["denied"])
