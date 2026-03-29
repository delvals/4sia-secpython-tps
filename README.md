# 4sia-secpython-tps

## TPs

### TP1 — IDS/IPS maison (analyse réseau)

Capture et analyse du trafic réseau avec Scapy. Génère un rapport PDF contenant les statistiques protocolaires et les tentatives d'attaque détectées.

**Détections implémentées :**
- ARP Spoofing
- Injection SQL (payloads HTTP/TCP)
- Port Scan

### TP2 — Analyse de shellcode

Analyse statique et dynamique de shellcodes via plusieurs outils, avec explication par un LLM.

**Fonctions implémentées :**
| Fonction | Description |
|---|---|
| `get_shellcode_strings` | Extraction des chaînes ASCII lisibles |
| `get_pylibemu_analysis` | Émulation du shellcode via pylibemu |
| `get_capstone_analysis` | Désassemblage x86 32-bit via Capstone |
| `get_llm_analysis` | Explication par GPT-4o (OpenAI) |

---

## Prérequis

- Python 3.11+
- Poetry
- Linux (les TPs utilisent des sockets raw — Windows non supporté)

## Installation de Poetry

```bash
curl -sSL https://install.python-poetry.org | python3 -
export PATH="$HOME/.local/bin:$PATH"
```

> Relancer le terminal après installation pour appliquer le PATH.

## Installation des dépendances

```bash
git clone git@github.com:<VotreNom>/4sia-secpython-tps.git
cd 4sia-secpython-tps
poetry install
```

---

## TP1 — Utilisation

La capture réseau nécessite les droits root pour ouvrir un socket raw.

```bash
sudo $(poetry env info --path)/bin/python -m tp1.main
```

Le programme liste les interfaces disponibles, capture le trafic pendant 30 secondes, analyse les paquets et génère un fichier `report.pdf` dans le répertoire courant.

### Dépendances système

Scapy nécessite libpcap :

```bash
sudo apt install libpcap-dev
```

---

## TP2 — Utilisation

```bash
sudo $(poetry env info --path)/bin/python -m tp2.main -f shellcode_easy.txt
sudo $(poetry env info --path)/bin/python -m tp2.main -f shellcode_medium.txt
sudo $(poetry env info --path)/bin/python -m tp2.main -f shellcode_hard.txt
```

### Format des fichiers shellcode

Deux formats sont acceptés :

**Séquences d'échappement :**
```
\xEB\x54\x8B\x75...
```

**Binaire brut** (fichier `.bin`)

### Configuration de la clé OpenAI

L'analyse LLM nécessite une clé API OpenAI. Créer un fichier `.env` à la racine du projet :

```
OPENAI_KEY=sk-...
```
