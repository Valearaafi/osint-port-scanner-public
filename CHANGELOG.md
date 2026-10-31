# Changelog

The project was developed without a version control system; this log
summarizes the build stages based on development records.

## 0.3.0 - 2026-10-26

- Dark UI redesign: custom palette on the `clam` theme, colored status
  rows in result tables, redesigned settings and detail dialogs.
- Fix: DNS and WHOIS sessions are now saved in history with their target;
  previously the target field was empty.
- Windows executable rebuilt (PyInstaller onedir) and validated end to end
  on a Windows 10 machine.
- Test suite: 104 tests passing.

## 0.2.0 - 2026-10-26

- First functional GUI release: shared target field, five tabs
  (IP / DNS / WHOIS / Port / History), background task worker with
  cancellation, JSON/CSV export, settings dialog, automatic scan history.
- Test suite: 83 tests passing.

## 0.1.0 - 2026-10-26

- Initial working version: IP/DNS/WHOIS/TCP-connect scanning core, SQLite
  storage, `config.json` handling, rate limiter and cancellation token.
- Test suite: 52 tests passing.
