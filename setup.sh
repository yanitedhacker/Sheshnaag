#!/bin/bash
# ===========================================
# Project Sheshnaag - Setup Script
# ===========================================

set -e

echo "🚀 Project Sheshnaag - Setup"
echo "============================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
PYTHON_CMD=""
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    echo -e "${RED}Error: Python is not installed${NC}"
    exit 1
fi

PYTHON_VERSION=$($PYTHON_CMD -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "${GREEN}✓ Found Python $PYTHON_VERSION${NC}"

# Create virtual environment
echo ""
echo "📦 Creating virtual environment..."
if [ -d ".venv" ]; then
    echo -e "${YELLOW}  Virtual environment already exists. Recreating...${NC}"
    rm -rf .venv
fi

$PYTHON_CMD -m venv .venv
echo -e "${GREEN}✓ Virtual environment created${NC}"

# Activate virtual environment
echo ""
echo "🔌 Activating virtual environment..."
source .venv/bin/activate
echo -e "${GREEN}✓ Virtual environment activated${NC}"

# Upgrade pip
echo ""
echo "⬆️  Upgrading pip..."
pip install --upgrade pip --quiet

# Install requirements
echo ""
echo "📥 Installing requirements (this may take a few minutes)..."
pip install -r requirements.txt

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ All requirements installed successfully${NC}"
else
    echo -e "${RED}✗ Some requirements failed to install${NC}"
    echo -e "${YELLOW}  Trying with pre-built wheels only...${NC}"
    pip install --only-binary :all: -r requirements.txt || true
fi

# Create .env file if it doesn't exist
echo ""
echo "⚙️  Setting up environment..."
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo -e "${GREEN}✓ Created .env file from .env.example${NC}"
else
    echo -e "${YELLOW}  .env file already exists, skipping${NC}"
fi

# Create necessary directories
mkdir -p models data logs

# Initialize database
echo ""
echo "🗄️  Initializing database..."
$PYTHON_CMD scripts/init_db.py

echo ""
echo "==========================================="
echo -e "${GREEN}✅ Setup complete!${NC}"
echo "==========================================="
echo ""
echo "To run the application:"
echo ""
echo "  1. Activate the virtual environment:"
echo "     source .venv/bin/activate"
echo ""
echo "  2. Start the server:"
echo "     python -m uvicorn app.main:app --host 127.0.0.1 --port 8000"
echo ""
echo "  3. Open in browser:"
echo "     - API Docs: http://127.0.0.1:8000/docs"
echo "     - Operator UI: run npm --prefix frontend run dev"
echo ""
echo "Or use the run script:"
echo "     ./run.sh"
echo ""
