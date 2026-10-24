"""TEST ONLY fixed bounded .control pause, never a tenant or execution fallback."""
import os
from pathlib import Path
import time
from systemd_delegate_probe import guard

def entry():
    guard()
    if Path('/etc/xandbox-systemd-readiness-fixture').read_text()!='Xandbox owned systemd readiness fixture v1\n':raise RuntimeError('owned readiness marker required')
    if os.geteuid()!=0:raise RuntimeError('owned root required')
    fd=os.open('/run/xandbox-ready-gate-entered',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);os.close(fd)
    end=time.monotonic()+15
    while not Path('/run/xandbox-ready-gate-release').exists():
        if time.monotonic()>=end:raise RuntimeError('fixed readiness gate expired')
        time.sleep(.02)
if __name__=='__main__':entry()
