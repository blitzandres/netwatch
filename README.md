# NetWatch

Local network monitoring dashboard — Python **Flask** backend with a live globe, connection/packet investigation, network tools and a data console, all on your own machine.

- **Project page:** [andresblitz.com/projects/netwatch](https://andresblitz.com/projects/netwatch/)
- **Author:** [Andrés Blitz](https://andresblitz.com/) · [@andresblitz](https://x.com/andresblitz)

## Features

- Live bandwidth and connection views
- Device / packet investigation panels
- Local-first: data stays on your machine
- Optional tcpdump-backed capture (sudo)

## Tech stack

Python · Flask · psutil · HTML/CSS/JS dashboard

## Run

```bash
./launch.sh
# dashboard: http://localhost:5001
```

Or:

```bash
pip install flask psutil
python3 app.py
```

Run with `sudo` only if you need live packet capture; otherwise NetWatch runs in safe local mode.

## Related

[SIGSPACE](https://github.com/blitzandres/sigspace) · [SIGNET thesis](https://github.com/blitzandres/signet-thesis) · [andresblitz.com](https://andresblitz.com/)
