# LinuxLink: Mobile Terminal Overlord

A next-generation mobile remote control panel for your Linux machine. Secure, real-time, and feature-rich — combining terminal, file explorer, system monitor, voice commands, and GUI access in one app.

## Repo Structure

```
/linuxlink
├── /android-client/      # Kotlin Jetpack Compose Android app
├── /backend-api/         # FastAPI backend (secure command exec, stats, JWT)
├── /docs/                # Architecture, API, and setup docs
├── README.md             # Project overview
├── LICENSE               # MIT License
└── docker-compose.yml    # One-command deployment
```

## Getting Started

1. **Clone the repo:**
   ```sh
   git clone https://github.com/sreevarshan-xenoz/Linux-Link.git
   cd  Linux-Link
   ```
2. **Backend:**
   - See `/backend-api/README.md` for setup and running instructions.
3. **Android App:**
   - See `/android-client/README.md` for build and install steps.
4. **Docs:**
   - See `/docs/` for architecture, API, and security details.

---

**MIT Licensed.**

---

> LinuxLink is in active development. See `/docs/` for the full vision and roadmap.
