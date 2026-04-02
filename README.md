<div align="center">

# 🛡️ SentinelAI

### AI-Powered Endpoint Detection & Response Platform

**Autonomous Threat Detection · LLM-Powered Analysis · Cross-Platform Agents**

<br/>

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)
![Next.js](https://img.shields.io/badge/Next.js-000000?style=for-the-badge&logo=nextdotjs&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Tauri](https://img.shields.io/badge/Tauri-24C8D8?style=for-the-badge&logo=tauri&logoColor=white)

![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-DC382D?style=for-the-badge&logo=redis&logoColor=white)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-005571?style=for-the-badge&logo=elasticsearch&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Protobuf](https://img.shields.io/badge/Protobuf-4285F4?style=for-the-badge&logo=google&logoColor=white)

<br/>

![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen?style=flat-square)

</div>

<br/>

<div align="center">

<a href="https://www.youtube.com/watch?v=1D6CrU3YAnI">
  <img src="https://img.youtube.com/vi/1D6CrU3YAnI/maxresdefault.jpg" alt="Watch SentinelAI Demo on YouTube" width="700" />
</a>

<br/>

[![▶ Watch Full Demo on YouTube](https://img.shields.io/badge/▶%20Watch%20Full%20Demo-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=1D6CrU3YAnI)

</div>

<br/>

![SentinelAI Platform](https://raw.githubusercontent.com/Forever506-Dev/SentinelAI_V3/main/assets/demo/SentinelAI-Demo.png)

<br/>

## 📖 Overview

SentinelAI is an **open-source, AI-augmented EDR platform** that combines traditional endpoint telemetry with Large Language Model (LLM) intelligence to detect, analyze, and respond to cybersecurity threats in real time.

<br/>

### ✨ Key Capabilities

| Feature | Description |
|:--------|:------------|
| 🖥️ **Cross-Platform Agent** | Lightweight Rust-based agent for Windows, Linux, and macOS |
| 🤖 **AI Threat Analysis** | LLM-powered threat correlation, anomaly detection, and natural language investigation |
| 🎯 **MITRE ATT&CK Mapping** | Automatic technique/tactic classification for every alert |
| 🔍 **Vulnerability Enrichment** | Real-time CVE/NVD database integration |
| 📊 **Live Telemetry Dashboard** | Real-time process, network, and filesystem monitoring via WebSocket |
| ⚡ **Autonomous Response** | Automated containment — process kill, network isolation, quarantine |
| 🏢 **Multi-Tenant** | Manage thousands of endpoints from a single panel |
| 🖱️ **Desktop & Web** | Tauri-powered desktop app + Next.js web panel |
| 🔥 **Firewall Management** | Cross-platform firewall control — Windows `netsh` and Linux `ufw` |

<br/>

---

<br/>

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        SentinelAI Platform                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────────┐    ┌────────────────┐  │
│  │  Web Panel   │    │   Desktop App    │    │  Mobile App    │  │
│  │  (Next.js)   │    │   (Tauri 2.0)    │    │  (Future)      │  │
│  └──────┬───────┘    └───────┬──────────┘    └───────┬────────┘  │
│         │                    │                       │           │
│         └────────────┬───────┘───────────────────────┘           │
│                      ▼                                           │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │              Backend API (FastAPI + Python)               │   │
│  │  ┌──────────┐ ┌───────────┐ ┌──────────┐ ┌───────────┐    │   │
│  │  │ REST API │ │ WebSocket │ │ Auth/JWT │ │ gRPC Svc  │    │   │
│  │  └──────────┘ └───────────┘ └──────────┘ └───────────┘    │   │
│  │  ┌──────────────────────────────────────────────────┐     │   │
│  │  │            Intelligence Services                 │     │   │
│  │  │  ┌─────────┐ ┌──────────┐ ┌───────────────────┐  │     │   │
│  │  │  │ LLM     │ │ Threat   │ │ MITRE ATT&CK      │  │     │   │
│  │  │  │ Engine  │ │ Analyzer │ │ Correlation Engine│  │     │   │
│  │  │  └─────────┘ └──────────┘ └───────────────────┘  │     │   │
│  │  │  ┌─────────┐ ┌──────────┐ ┌───────────────────┐  │     │   │
│  │  │  │ NVD/CVE │ │ YARA     │ │ Behavioral        │  │     │   │
│  │  │  │ Lookup  │ │ Rules    │ │ Analytics         │  │     │   │
│  │  │  └─────────┘ └──────────┘ └───────────────────┘  │     │   │
│  │  └──────────────────────────────────────────────────┘     │   │
│  └──────────────────────────┬────────────────────────────────┘   │
│                             │                                    │
│  ┌──────────────────────────┼───────────────────────────────┐    │
│  │         Data Layer       │                               │    │
│  │  ┌──────────┐ ┌──────────┴─┐ ┌─────────────────────┐     |    │
│  │  │PostgreSQL│ │   Redis    │ │   Elasticsearch     │     │    │
│  │  │(Metadata)│ │(Cache/PubS)│ │   (Log Search)      │     │    │
│  │  └──────────┘ └────────────┘ └─────────────────────┘     │    │
│  └──────────────────────────────────────────────────────────┘    │
│                             ▲                                    │
│                             │  TLS / mTLS                        │
│         ┌───────────────────┼────────────────────┐               │
│         ▼                   ▼                    ▼               │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────┐         │
│  │ Agent       │   │ Agent       │   │ Agent           │         │
│  │ (Windows)   │   │ (Linux)     │   │ (macOS/Android) │         │
│  │ Rust Binary │   │ Rust Binary │   │ Rust Binary     │         │
│  └─────────────┘   └─────────────┘   └─────────────────┘         │
└──────────────────────────────────────────────────────────────────┘
```

<br/>

---

<br/>

## 📁 Project Structure

```
sentinelai/
│
├── 🦀 agent/                   Rust cross-platform endpoint agent
│   ├── src/
│   │   ├── collector/          Telemetry collectors (process, fs, net)
│   │   ├── detection.rs        Local detection engine
│   │   ├── executor.rs         Remote command execution
│   │   ├── firewall.rs         Cross-platform firewall (netsh + ufw)
│   │   ├── transport.rs        Backend communication (REST + WS)
│   │   └── main.rs             Entry point + Windows Service support
│   └── Cargo.toml
│
├── 🐍 backend/                 Python FastAPI backend
│   ├── app/
│   │   ├── api/routes/         REST API endpoints
│   │   ├── core/               Config, security, database
│   │   ├── models/             SQLAlchemy ORM models
│   │   ├── schemas/            Pydantic validation schemas
│   │   └── services/           Business logic & AI services
│   └── pyproject.toml
│
├── 🌐 panel/                   Next.js web dashboard
│   ├── src/
│   │   ├── app/                App Router pages
│   │   ├── components/         React UI components
│   │   └── lib/                Utilities & API client
│   └── package.json
│
├── 🖥️ desktop/                 Tauri desktop application
│   └── src-tauri/
│
├── 📦 shared/                  Shared protocol definitions
│   └── proto/                  Protobuf schemas
│
├── 🚀 deploy/                  Deployment scripts & templates
│   ├── install_agent.sh        Linux auto-installer
│   └── windows/                Windows installer + configs
│
├── 🐳 docker/                  Dockerfiles per service
├── 📚 docs/                    Architecture & design docs
└── docker-compose.yml          Full infrastructure stack
```

<br/>

---

<br/>

## 🚀 Quick Start

### Prerequisites

| Tool | Version | Used For |
|:-----|:--------|:---------|
| **Rust** | 1.75+ | Agent compilation |
| **Python** | 3.11+ | Backend API |
| **Node.js** | 20+ | Web panel |
| **Docker** | Latest | Infrastructure services |

<br/>

### 1️⃣ Start Infrastructure

```bash
docker-compose up -d
```

> This launches PostgreSQL, Redis, Elasticsearch, and NATS.

<br/>

### 2️⃣ Start Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate         # Windows

pip install -e ".[dev]"
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

<br/>

### 3️⃣ Start Web Panel

```bash
cd panel
npm install
npm run dev
```

> Panel runs on [http://localhost:3000](http://localhost:3000)

<br/>

### 4️⃣ Build & Run Agent

```bash
cd agent
cargo build --release

# Linux / macOS
./target/release/sentinel-agent

# Windows
.\target\release\sentinel-agent.exe
```

<br/>

---

<br/>

## ⚙️ Tech Stack

<table>
  <thead>
    <tr>
      <th>Layer</th>
      <th>Technology</th>
      <th>Purpose</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>🦀 Agent</strong></td>
      <td>Rust · Tokio · sysinfo · notify</td>
      <td>Cross-platform endpoint telemetry & response</td>
    </tr>
    <tr>
      <td><strong>🐍 Backend</strong></td>
      <td>Python · FastAPI · SQLAlchemy · Alembic</td>
      <td>REST API, WebSocket, business logic</td>
    </tr>
    <tr>
      <td><strong>🤖 AI / ML</strong></td>
      <td>LangChain · OpenAI / Anthropic</td>
      <td>Threat analysis, NL investigation</td>
    </tr>
    <tr>
      <td><strong>🌐 Web Panel</strong></td>
      <td>Next.js 14 · TypeScript · Tailwind CSS</td>
      <td>Real-time security dashboard</td>
    </tr>
    <tr>
      <td><strong>🖥️ Desktop</strong></td>
      <td>Tauri 2.0 · Rust · WebView</td>
      <td>Native desktop app (Win / Mac / Linux)</td>
    </tr>
    <tr>
      <td><strong>🗄️ Database</strong></td>
      <td>PostgreSQL</td>
      <td>Relational data, agent metadata</td>
    </tr>
    <tr>
      <td><strong>⚡ Cache</strong></td>
      <td>Redis</td>
      <td>Real-time pub/sub, session cache</td>
    </tr>
    <tr>
      <td><strong>🔎 Search</strong></td>
      <td>Elasticsearch</td>
      <td>Log search, full-text telemetry queries</td>
    </tr>
    <tr>
      <td><strong>📡 Protocol</strong></td>
      <td>Protocol Buffers (gRPC)</td>
      <td>Agent ↔ Backend communication</td>
    </tr>
    <tr>
      <td><strong>🐳 Infra</strong></td>
      <td>Docker · Docker Compose</td>
      <td>Container orchestration</td>
    </tr>
  </tbody>
</table>

<br/>

---

<br/>

## 🔥 Firewall Management

SentinelAI includes a **cross-platform firewall engine** built into the agent:

| Platform | Backend Tool | Capabilities |
|:---------|:-------------|:-------------|
| **Windows** | `netsh advfirewall` | List, add, edit, delete, toggle, quarantine |
| **Linux** | `ufw` (Uncomplicated Firewall) | List, add, edit, delete, toggle, quarantine |

All firewall commands are **signed with HMAC-SHA256** to prevent unauthorized execution. The panel can manage rules remotely, block IPs/ports with one click, and apply network quarantine (partial or full isolation).

<br/>

---

<br/>

## 📚 Documentation

| Document | Description |
|:---------|:------------|
| [docs/architecture.md](docs/architecture.md) | High-level architecture overview |
| [docs/architecture/](docs/architecture/) | Detailed design documents |
| [deploy/README.md](deploy/README.md) | Remote agent deployment guide |
| [deploy/windows/README.md](deploy/windows/README.md) | Windows-specific deployment |

<br/>

---

<br/>

## 📝 License

<br/>

<div align="center">

**Built with ❤️ for the cybersecurity community**

</div>
