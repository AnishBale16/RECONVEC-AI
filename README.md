# RECONVEC-AI
RECONVEC -Real-time Exploit Orchestration &amp; Vulnerability Expression Correlator is a local, privacy-first Incident Response triage tool designed to eliminate alert fatigue.
## 🎯 Project Goal
Traditional SIEMs inundate analysts with hundreds of isolated alerts. This project demonstrates how to use Python, SQLite, and local AI to parse multi-source logs, track adversarial session states, map actions to the MITRE ATT&CK framework, and visually present the reconstructed timeline in a web dashboard for fast triage.

## 🏗️ Architecture Diagram
+------------------+      +-----------------+| Windows Sysmon   |      | Zeek Network    || (Endpoint Logs)  |      | (Network Logs)  |+--------+---------+      +--------+--------+|                         |+------------+------------+| (Raw JSON/CSV)v+-------------------+|   Python Parser   |+---------+---------+| (Normalized)v+-------------------+|  SQLite Database  |+---------+---------+| (Event Batches)v+-------------------+|    Ollama LLM     | <--> [MITRE ATT&CK Mapping]+---------+---------+| (Enriched Timeline)v+-------------------+|  Flask Dashboard  |+-------------------+
## ⚙️ Installation & Setup

### Prerequisites
- Python 3.12+
- [Ollama](https://ollama.com) installed and running locally

### 1. Clone & Set Up Environment
```bash
git clone https://github.com
cd ai-attack-chain-reconstructor
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure the AI Model
Pull the preferred security-focused or general instruction model via Ollama:
```bash
ollama pull llama3
```

### 3. Initialize the Database & Parse Sample Logs
```bash
# Initialize SQLite tables
sqlite3 database/siem.db < database/schema.sql

# Ingest test logs into the database
python -m parsers.sysmon_parser --file tests/mock_attack.json
```

### 4. Run the Reconstruction & Web Server
```bash
# Process events through Ollama to generate the chain
python src/engine.py

# Launch the Flask dashboard
python app.py
```
Navigate to `http://127.0.0.1:5000` in your web browser.

## 🚀 Future Roadmap
- [ ] **Graph Database Integration:** Migrate from SQLite to Neo4j for deep relationship visualization between processes and IPs.
- [ ] **Real-Time Streaming:** Add Kafka or RabbitMQ support to process live log streams instead of batch files.
- [ ] **Vector Embeddings:** Use an internal vector database (e.g., ChromaDB) to search past incidents and identify identical adversary playbooks.
- [ ] **Automated Playbook Generation:** Allow Ollama to generate specific remediation commands (e.g., specific PowerShell commands to isolate an endpoint) based on the attack chain.
