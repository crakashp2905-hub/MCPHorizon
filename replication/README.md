# Replication package (P11-16) — minimal, UNVERIFIED by any independent reader

Anonymous. Needs: Linux, Python ≥ 3.11, Node 22 (for Code Mode scenarios), `git`.
```
cd codemode && npm ci && cd ..
python3 bench/secbench/freeze.py verify
python3 -W ignore bench/p9/study.py --out /tmp/p9.json      # ~1-2 min; compare with results/v2/p9_comparative.json
python3 paper/build.py --check                                # tables/figures/manuscript match committed artifacts
sh scripts/repro_p9.sh                                        # full pipeline incl. integrity manifest
```
Minimal demo: `python3 -m unittest tests.p9.test_study`. The Dockerfile in this directory is provided but **has not been built or run here** and its base image is referenced by tag, not digest (so not pinned). Nobody other than the author has followed these steps (P11-17/18 open).
