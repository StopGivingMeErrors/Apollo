---
title: Sentinel SOC API
emoji: 🛡️
colorFrom: slate
colorTo: blue
sdk: docker
app_port: 8000
pinned: false
license: mit
short_description: Honeypot SOC API — FastAPI + SQLite + live simulator
---

# Sentinel SOC API

Backend for the [Sentinel SOC](https://sentinel-soc-sand.vercel.app) dashboard.

This Space is a **free, sleeping** host: after idle time Hugging Face pauses
the container and the SQLite file is gone. On the next request the process
boots, seeds seven days of demo history, and starts the attack simulator so
the dashboard is never empty.

Public sensors (SSH/FTP/Telnet) are not exposed here — only HTTP. That is a
limitation of Spaces, not of the application.

Dashboard: https://sentinel-soc-sand.vercel.app
