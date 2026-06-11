# TODO

- [ ] Inspect existing `log_attack()` and `/api/attack-logs` implementations in `main.py`.
- [ ] Add PostgreSQL helper module for attack log persistence (connection handling, table creation, insert + fetch APIs).
- [ ] Update `requirements.txt` to include a PostgreSQL driver.
- [ ] Update `main.py` to:
  - [ ] Insert every detected attack into PostgreSQL (keep file write as fallback).
  - [ ] Update `/api/attack-logs` to read from PostgreSQL (fallback to file if DB not available).
- [ ] Ensure DB table schema matches required fields.
- [ ] Run a quick smoke test: trigger an attack and verify `/api/attack-logs` returns new entries.
