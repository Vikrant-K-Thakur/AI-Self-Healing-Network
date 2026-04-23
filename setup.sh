#!/bin/bash
# setup.sh — One-time setup for AI Self-Healing Network IDS
# Run this once on Ubuntu 22.04 before starting the system.
# Usage: bash setup.sh

set -e

echo ""
echo "=============================================="
echo "  AI Self-Healing Network — Setup Script"
echo "=============================================="
echo ""

# ── Step 1: System packages ───────────────────────────────────────────────────
echo "[1/4] Installing system packages..."
sudo apt update -qq
sudo apt install -y mininet python3-pip
echo "  Done."

# ── Step 2: Python packages ───────────────────────────────────────────────────
echo ""
echo "[2/4] Installing Python packages..."
pip3 install -r requirements.txt
echo "  Done."

# ── Step 3: Verify Mininet ────────────────────────────────────────────────────
echo ""
echo "[3/4] Verifying Mininet..."
sudo mn --version
echo "  Mininet OK."

# ── Step 4: Train ML models ───────────────────────────────────────────────────
echo ""
echo "[4/4] Training ML models (downloads NSL-KDD dataset ~5 min)..."
python3 model.py
echo "  Models saved to models/ folder."

echo ""
echo "=============================================="
echo "  Setup complete! Now run the system:"
echo ""
echo "  Terminal 1:  ryu-manager ryu_controller.py --observe-links"
echo "  Terminal 2:  sudo mn --custom topo.py --topo mytopo \\"
echo "                   --controller=remote,ip=127.0.0.1,port=6653"
echo "  Terminal 3:  sudo python3 main.py"
echo "  Browser:     http://127.0.0.1:8050"
echo "  Attack test: (inside Mininet) h3 python3 attacker.py --attack mixed"
echo "=============================================="
