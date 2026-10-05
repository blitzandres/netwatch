# NetWatch

Local network monitoring dashboard: a Python Flask backend with a live globe,
connection/packet investigation, network tools and a data console, all served
on your own machine.

- **Project page:** https://andresblitz.com/projects/netwatch/

## Run

```bash
./launch.sh
# dashboard: http://localhost:5001
```

`launch.sh` installs the minimal dependencies (`flask`, `psutil`) if missing
and starts `app.py`. Run it with `sudo` to enable tcpdump-backed live packet
capture; without it NetWatch runs in safe local mode.

Or run it directly:

```bash
pip install flask psutil
python3 app.py
```

Environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `NETWATCH_BIND` | `127.0.0.1` | Address to bind |
| `NETWATCH_PORT` | `5001` | Port to listen on |

Logs and history live under `~/netwatch_logs/`.

## Docs

- [CHANGES.md](CHANGES.md): change log and environment requirements
- [PHASE1_FOUNDATION.md](PHASE1_FOUNDATION.md), [PHASE3_REPO_DATA.md](PHASE3_REPO_DATA.md): design phases

NetWatch also feeds the TOPOLOGY realm in [SIGSPACE](https://github.com/blitzandres/sigspace).
