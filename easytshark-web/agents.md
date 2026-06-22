# EasyTshark Web Agent Notes

This directory contains the pure React web frontend for EasyTshark. Electron has been removed; do not add Electron-specific APIs or scripts back unless explicitly requested.

## Role

The frontend runs in the browser at `http://localhost:3000` and talks to the local C++ backend at `http://127.0.0.1:8080`.

## Run

```powershell
cd D:\Organized_Files\Projects\EasyTshark\easytshark-web
npm.cmd start
```

Open:

```text
http://localhost:3000
```

The backend must be started separately.

## Build

```powershell
npm.cmd run build
```

Current build may show existing ESLint warnings in unrelated files, but should compile.

## Project Pointers

- `src/Api.ts`: axios wrappers. Backend base URL is `http://127.0.0.1:8080`.
- `src/App.tsx`: route registration.
- `src/Page/HomePage.tsx`: landing workflow for live capture and pcap upload.
- `src/Page/PageLayout.tsx`: application layout shell.
- `src/components/Navbar.tsx`: top actions for home, live capture, and stop capture. Do not add a duplicate file-analysis entry here.
- `src/components/Capture.tsx`: adapter selection and live capture controls.
- `src/components/DataPacketPage.tsx`: packet list and packet detail navigation.
- `src/components/SessionPage.tsx`: session list.
- `src/components/SessionDetail/*`: session detail tabs.
- `src/components/StatsPage.tsx`: statistics views.

## Important Behavior

- Browser mode uses native file input and drag/drop upload for pcap files.
- Do not use `window.electronAPI`, `ipcRenderer`, preload scripts, or Electron dialogs.
- Browser security does not allow choosing arbitrary local save paths; keep save-to-path features out of the pure web UI.
- File analysis lives on `src/Page/HomePage.tsx` only. It should upload to `/api/analysisTasks`, poll task status, activate after `DONE`, and then navigate to the packet list.
- Avoid `/api/uploadAnalysisFile` for new UI flows; it is a legacy compatibility endpoint and does not by itself switch the displayed dataset.
- The backend CORS allows `http://localhost:3000` and `http://127.0.0.1:3000`.

## Package Scripts

Only these scripts are expected:

```text
npm.cmd start
npm.cmd run build
npm.cmd test
npm.cmd run eject
```

There should be no `electron`, `electron-dev`, or `electron-build` scripts.
