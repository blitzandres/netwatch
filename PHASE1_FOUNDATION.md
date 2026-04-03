NetWatch Next - Phase 1 Foundation

Principles
- Preserve every existing tool unless a replacement is proven feature-complete.
- Prefer shared actions over deleting UI entry points.
- Keep the original `netwatch10` untouched; all migration work happens in `netwatch_next`.

Phase 1 goals
- Harden the riskiest API paths without breaking the local app workflow.
- Introduce a shared action-dispatch foundation for engine and node actions.
- Keep the current tool tabs available during migration.

Feature preservation policy
- `keep`: existing tool remains visible and callable.
- `merge later`: duplicate actions can be routed through a shared registry, but old buttons stay alive until verified.
- `replace later`: only after parity is confirmed.

Current tool inventory status
- Terminal: keep
- Port Scan: keep
- Processes / Memory: keep
- WiFi Devices: keep
- WiFi Channels: keep
- World Map: keep
- Speed Test: keep
- Report: keep
- IP Info: keep
- DNS Benchmark: keep
- HTTP Headers: keep
- Subnet Calculator: keep
- MAC Lookup: keep
- Ping Watchdog: keep
- Interfaces: keep
- Routes: keep
- TCP States: keep
- Open Sockets / LSOF: keep
- WiFi Signal: keep
- Host Discovery: keep
- MTU Test: keep
- Cert Watch: keep
- Packet Stats: keep
- Bandwidth Alerts: keep
- Bandwidth Chart: keep
- IP Book: keep

Phase 1 completed
- Local-only protection added for mutating API requests.
- Safer command validation for the in-app terminal.
- Safer folder opening path checks.
- PF firewall actions moved behind a dedicated NetWatch anchor/table flow.
- Shared frontend action registry added.
- Visual Intelligence and Connection Manager started using the shared action model.

Next phase candidates
- Add per-entity notes storage.
- Start backend split into modules.
- Move more engine/node buttons to `data-action`.
- Add parity checklist per tool before removing duplicate handlers.
