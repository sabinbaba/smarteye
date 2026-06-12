# TODO - Blocked IPs on Attacks Page

- [ ] Step 1: Extend SQLite auth database (`database.py`) with `blocked_ips` table + helper methods.
- [ ] Step 2: Add API endpoints in `main.py`:
  - [ ] POST `/api/blocked-ips` (block an IP)
  - [ ] GET `/api/blocked-ips` (list blocked IPs)
  - [ ] GET `/api/blocked-ip-count` (optional count)
- [ ] Step 3: Update `templates/attacks.html`:
  - [ ] Make the “Blocked” card open a modal
  - [ ] Replace simulated blocked count with real count
  - [ ] Implement list rendering for blocked IPs
  - [ ] Wire `blockSource(ip)` and “Block Source IP” in modal to backend
- [ ] Step 4: Basic verification:
  - [ ] Start server and open `/attacks`
  - [ ] Block an IP and confirm it appears in the blocked list
  - [ ] Confirm blocked card count matches list length
- [ ] Step 5: Keep block state stable across restarts (ensure SQLite init runs)
