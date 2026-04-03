# Phase 3A + 3B

This phase adds lightweight repo intelligence and data analytics without storing raw source snapshots or creating large new local datasets.

What is live in the app:
- Repo scans stored in DuckDB as summaries only
- Folder/package edge extraction rendered as Graphviz DOT
- Context Engine data summary cards backed by Polars/Pandera-friendly pipelines
- Lightweight repo pulse cards in the main engines

What is added to the repo:
- `.github/workflows/repo-visualizer.yml` for GitHub Repo Visualizer artifacts
- `.cgcignore` to keep CodeGraphContext focused on the useful code paths
- `repo_intel/emerge-netwatch.yaml` as a starter lightweight Emerge profile

Storage approach:
- Keep at most 5 repo scan snapshots in DuckDB
- Do not store raw file contents
- Reuse the existing SQLite traffic/threat/DNS history instead of duplicating it
