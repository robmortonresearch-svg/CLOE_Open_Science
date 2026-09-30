#!/bin/bash

# CLOE Open Science Artifact - Quick Start Script
# For IEEE SaTML Double-Blind Peer Review

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  🐉 CLOE: Causal Learning in Offline and Online Environments  ║"
echo "║                   Open Science Artifact                        ║"
echo "║            IEEE SaTML - Double-Blind Peer Review              ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check Docker installation
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}⚠️  Docker not installed. Install from: https://docker.com${NC}"
    echo ""
    echo "Falling back to local Python mode..."
    echo ""
    python3 evaluate.py
    exit 0
fi

# Check Docker daemon
if ! docker ps &> /dev/null; then
    echo -e "${YELLOW}⚠️  Docker daemon not running. Starting Docker...${NC}"
    if command -v open &> /dev/null; then
        open -a Docker
        sleep 5
    else
        echo "Please start Docker and run this script again."
        exit 1
    fi
fi

echo -e "${GREEN}✓${NC} Docker is running"
echo ""

# Menu
echo "Select how you want to run CLOE:"
echo ""
echo "  1) Run full evaluation (Stages 1-3)"
echo "  2) Run evaluation + view web dashboard"
echo "  3) View web results (already evaluated)"
echo "  4) Run local Python (no Docker)"
echo ""
read -p "Enter your choice (1-4): " choice

case $choice in
    1)
        echo ""
        echo -e "${BLUE}Building Docker image...${NC}"
        docker-compose build --no-cache
        echo ""
        echo -e "${BLUE}Running three-stage CLOE evaluation...${NC}"
        echo ""
        docker-compose run --rm cloe-evaluator
        ;;
    2)
        echo ""
        echo -e "${BLUE}Building Docker image...${NC}"
        docker-compose build --no-cache
        echo ""
        echo -e "${BLUE}Starting services...${NC}"
        docker-compose up -d
        echo ""
        echo -e "${GREEN}✓${NC} Services started:"
        echo "   • Backend: http://localhost:8080"
        echo "   • Web UI:  http://localhost:7000"
        echo ""
        echo -e "${BLUE}Running three-stage evaluation...${NC}"
        echo ""
        docker-compose run --rm cloe-evaluator
        echo ""
        echo -e "${GREEN}✓${NC} Evaluation complete!"
        echo ""
        echo -e "${YELLOW}Keep containers running?${NC} (Press Enter to keep, Ctrl+C to stop)"
        read -p ""
        ;;
    3)
        echo ""
        echo -e "${BLUE}Starting web server...${NC}"
        docker run -p 7000:7000 -v "$(pwd):/app" -it --rm python:3.11-slim python3 -m http.server 7000
        ;;
    4)
        echo ""
        echo -e "${BLUE}Running local Python evaluation...${NC}"
        echo ""
        python3 evaluate.py
        ;;
    *)
        echo -e "${YELLOW}Invalid choice. Exiting.${NC}"
        exit 1
        ;;
esac

# Cleanup instructions
echo ""
echo -e "${GREEN}✓${NC} CLOE Open Science evaluation complete!"
echo ""
echo "Next steps:"
echo "  • View results at: http://localhost:7000"
echo "  • Check evaluation_results.json for detailed metrics"
echo "  • Review results.json for raw experimental data"
echo ""
echo "To stop services:"
echo "  docker-compose down"
echo ""
