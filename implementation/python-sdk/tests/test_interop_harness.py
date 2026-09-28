"""Regression checks for bounded local test-peer lifecycle."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock
import pytest

path=Path(__file__).resolve().parents[2]/'tests/test_interop.py'
spec=importlib.util.spec_from_file_location('interop_runner',path)
runner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def test_partial_line_has_total_deadline():
    proc=subprocess.Popen([sys.executable,'-c',
        "import sys,time;sys.stdout.write('123');sys.stdout.flush();time.sleep(10)"],stdout=subprocess.PIPE,bufsize=0)
    os.set_blocking(proc.stdout.fileno(),False)
    try:
        with pytest.raises(TimeoutError): runner.readline(proc,timeout=0.2)
    finally:
        proc.kill();proc.wait(timeout=2);proc.stdout.close()


def test_broken_stop_pipe_still_waits_and_closes(monkeypatch):
    proc=Mock();proc.poll.return_value=None
    proc.stdin.write.side_effect=BrokenPipeError()
    monkeypatch.setattr(runner.subprocess,'Popen',lambda *args,**kwargs:proc)
    monkeypatch.setattr(runner.os,'set_blocking',lambda *args:None)
    monkeypatch.setattr(runner,'readline',lambda proc:'12345')
    with runner.rust_server() as (port,_): assert port==12345
    proc.wait.assert_called_once_with(timeout=5)
    for pipe in (proc.stdin,proc.stdout,proc.stderr):pipe.close.assert_called_once()


@pytest.mark.parametrize('mode',['deadline','bytes'])
def test_raw_response_is_bounded(monkeypatch,mode):
    sock=Mock()
    sock.__enter__=Mock(return_value=sock);sock.__exit__=Mock(return_value=False)
    sock.recv.return_value=b'x'*4096 if mode=='bytes' else b'x'
    monkeypatch.setattr(runner.socket,'create_connection',lambda *a,**k:sock)
    tick=iter([0,1,2,3,4,5])
    monkeypatch.setattr(runner.time,'monotonic',lambda:next(tick) if mode=='deadline' else 0)
    with pytest.raises(TimeoutError if mode=='deadline' else ValueError):runner.raw(1,b'{}')
    assert sock.recv.call_count<=19
