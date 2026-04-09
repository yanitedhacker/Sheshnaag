#!/bin/bash
# ===========================================
# Project Sheshnaag - Run Script
# ===========================================

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}Virtual environment not found. Running setup first...${NC}"
    ./setup.sh
fi

# Activate virtual environment
source .venv/bin/activate

echo -e "${GREEN}🚀 Starting Project Sheshnaag...${NC}"
echo ""
echo "📍 API:       http://127.0.0.1:8000"
echo "📖 API Docs:  http://127.0.0.1:8000/docs"
echo "🎛️  Operator UI: http://127.0.0.1:5173 (run npm --prefix frontend run dev)"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Run the server
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
