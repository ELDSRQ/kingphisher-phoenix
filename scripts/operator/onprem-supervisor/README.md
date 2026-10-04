# On-prem supervisor as a boot-persistent systemd unit (.105)

The `.105` WSL2 worker runs the app under `scripts/supervisor.py` (operator-api,
tracking-api, and the workers). The `kp-ai-gateway` is a root-owned **system**
unit and already comes back after a reboot; the app supervisor used to be a
plain detached process, so a WSL restart left the stack **down** until someone
relaunched it by hand. It also exited (taking the whole stack with it) if any
single child crashed, with nothing to restart it.

`kp-supervisor.service` is a systemd **user** unit (owned by `builder`, no sudo
needed to install) that fixes both:

- `WantedBy=default.target` + **linger** → starts on WSL boot.
- `Restart=on-failure` + `StartLimitIntervalSec=0` → if a child crashes (the
  supervisor exits non-zero), systemd restarts the whole stack, and it keeps
  retrying while Docker (postgres/redis/mailpit) is still coming up at boot.

## Install

As `builder` on `.105` (`ssh -p 2222 builder@192.168.1.105`):

```
bash scripts/operator/onprem-supervisor/install.sh
```

This installs + enables the unit unprivileged. Because a `--user` unit only
starts at boot when the account is **lingering**, and enabling linger needs root
(builder has no sudo), the script prints the single privileged command to run
once:

```
sudo loginctl enable-linger builder            # inside WSL, as a sudoer
# or, from Windows (erikd):
wsl -u root -- loginctl enable-linger builder
```

Then cut the running stack over to the unit (no privilege):

```
pkill -f 'python scripts/supervisor.py' || true   # stop the old detached process
systemctl --user start kp-supervisor.service
systemctl --user status kp-supervisor.service --no-pager
```

## Operate

```
systemctl --user status  kp-supervisor.service
systemctl --user restart kp-supervisor.service     # full stack restart
journalctl --user -u kp-supervisor.service -f      # supervisor stdout
```

Deploying code still works the same way: `git pull` → (`alembic upgrade head`
only if a migration was added) → `touch data/run/restart` (the supervisor's
in-process restart marker — no systemd action needed). Use
`systemctl --user restart` only when you want to recycle the supervisor process
itself (e.g. after editing the unit). A **new worker role** still needs the
supervisor process restarted — now `systemctl --user restart kp-supervisor`
instead of the old manual relaunch.
