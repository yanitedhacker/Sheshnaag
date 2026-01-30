#!/bin/bash
# ===========================================
# CVE Threat Radar - Run Script
# ===========================================

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Virtual environment not found. Running setup first...${NC}"
    ./setup.sh
fi

# Activate virtual environment
source venv/bin/activate

echo -e "${GREEN}🚀 Starting CVE Threat Radar...${NC}"
echo ""
echo "📍 API:       http://127.0.0.1:8000"
echo "📖 API Docs:  http://127.0.0.1:8000/docs"
echo "🎨 Dashboard: Open frontend/index.html in browser"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Run the server
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
