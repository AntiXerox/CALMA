

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo ""
echo -e "${CYAN}==========================================${NC}"
echo -e "${CYAN}   CALMA - Instalador Universal${NC}"
echo -e "${CYAN}==========================================${NC}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PYTHON_CMD=""
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    if python --version 2>&1 | grep -q "Python 3"; then
        PYTHON_CMD="python"
    fi
fi

if [ -z "$PYTHON_CMD" ]; then
    echo -e "${RED}[ERRO] Python 3 não encontrado!${NC}"
    echo ""
    echo "Por favor, instale Python 3.8 ou superior:"
    echo ""
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "  macOS:"
        echo "    brew install python@3.10"
        echo "    ou: https://www.python.org/downloads/"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/debian_version ]; then
            echo "  Ubuntu/Debian:"
            echo "    sudo apt update && sudo apt install python3.10 python3-pip python3-venv"
        elif [ -f /etc/fedora-release ]; then
            echo "  Fedora:"
            echo "    sudo dnf install python3.10 python3-pip"
        elif [ -f /etc/arch-release ]; then
            echo "  Arch Linux:"
            echo "    sudo pacman -S python python-pip"
        else
            echo "  Linux genérico:"
            echo "    Use o gerenciador de pacotes da sua distribuição"
        fi
    fi
    echo ""
    exit 1
fi

PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
echo -e "${GREEN} Python encontrado: $PYTHON_VERSION${NC}"
echo ""

echo "Iniciando instalador universal..."
echo ""
$PYTHON_CMD "$SCRIPT_DIR/install_universal.py"

exit_code=$?

if [ $exit_code -ne 0 ]; then
    echo ""
    echo -e "${RED}[ERRO] A instalação falhou!${NC}"
    echo "Tente executar diretamente: $PYTHON_CMD install_universal.py"
    exit 1
fi

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}   Instalação concluída!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""

exit 0
