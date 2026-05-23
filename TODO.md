# TODO - React dashboard template port

## Completed

- [x] Added `frontend/src/App.css` and imported it from `frontend/src/App.tsx`.
- [x] Implemented `frontend/src/pages/AnalysisPage.tsx` (it was empty, breaking build).
- [x] Verified `npx vite build` succeeds.

## Next

- [ ] Port `templates/attacks.html` -> `frontend/src/pages/AttacksPage.tsx`
  - [ ] Implement filters + table + pagination + modal
  - [ ] Hook data from `/api/attacks`
  - [ ] Implement charts (Plotly) if/when backend provides chart data
- [ ] Port `templates/notifications.html` -> `frontend/src/pages/NotificationsPage.tsx`
  - [ ] Implement tabs + filters + selection + bulk actions + pagination
  - [ ] Hook data from `/api/notifications`
  - [ ] Implement charts (Plotly) if/when backend provides chart data
- [ ] Port `templates/settings.html` -> `frontend/src/pages/SettingsPage.tsx`
  - [ ] Implement multi-tab settings UI
  - [ ] Persist to `localStorage` using key `ids-settings`
  - [ ] Save/Reset/Export actions
- [ ] Upgrade `frontend/src/pages/NetworkTrafficPage.tsx` to match `templates/network_traffic.html`
  - [ ] Implement attack alert + pause/resume UI
  - [ ] Implement background monitoring UI
  - [ ] Implement charts (Plotly) if/when backend provides chart data
- [ ] Move/merge any remaining page CSS into `frontend/src/App.css`

## Verification

- [ ] Run `cd frontend && npx vite build`
- [ ] Run `cd frontend && npx vite` and verify all routes render
