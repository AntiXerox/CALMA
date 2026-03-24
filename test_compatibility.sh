

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "${CYAN}=========================================${NC}"
echo -e "${CYAN}   CALMA - Teste de Compatibilidade${NC}"
echo -e "${CYAN}=========================================${NC}"
echo ""

ERRORS=0
WARNINGS=0

detect_os() {
    case "$(uname -s)" in
        Linux*)     echo "Linux" ;;
        Darwin*)    echo "macOS" ;;
        CYGWIN*|MINGW*|MSYS*) echo "Windows" ;;
        *)          echo "Unknown" ;;
    esac
}

OS_TYPE=$(detect_os)
echo -e "${CYAN}Sistema Operacional:${NC} $OS_TYPE"

if [ -f /etc/os-release ]; then
    DISTRO=$(grep "^PRETTY_NAME" /etc/os-release | cut -d'"' -f2)
    echo -e "${CYAN}Distribuição:${NC} $DISTRO"
fi

echo ""
echo -e "${CYAN}=== Verificações ===${NC}"
echo ""

echo -n "1. Bash Shell... "
if [ -n "$BASH_VERSION" ]; then
    echo -e "${GREEN}${NC} (versão $BASH_VERSION)"
else
    echo -e "${RED}${NC} Bash não detectado!"
    ((ERRORS++))
fi

echo -n "2. Python 3... "
PYTHON_CMD=""
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    if python --version 2>&1 | grep -q "Python 3"; then
        PYTHON_CMD="python"
    fi
fi

if [ -n "$PYTHON_CMD" ]; then
    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    
    if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 8 ]; then
        echo -e "${GREEN}${NC} (versão $PYTHON_VERSION)"
    else
        echo -e "${YELLOW}${NC} (versão $PYTHON_VERSION - recomendado 3.8+)"
        ((WARNINGS++))
    fi
else
    echo -e "${RED}${NC} Python 3 não encontrado!"
    ((ERRORS++))
fi

echo -n "3. jq (JSON parser)... "
if command -v jq &> /dev/null; then
    JQ_VERSION=$(jq --version 2>&1)
    echo -e "${GREEN}${NC} ($JQ_VERSION)"
else
    echo -e "${RED}${NC} jq não instalado (necessário para calma.sh)"
    echo "   Instale: "
    case "$OS_TYPE" in
        Linux)
            if [ -f /etc/debian_version ]; then
                echo "   sudo apt install jq"
            elif [ -f /etc/fedora-release ]; then
                echo "   sudo dnf install jq"
            elif [ -f /etc/arch-release ]; then
                echo "   sudo pacman -S jq"
            fi
            ;;
        macOS)
            echo "   brew install jq"
            ;;
        Windows)
            echo "   Via Git Bash: https://stedolan.github.io/jq/download/"
            ;;
    esac
    ((ERRORS++))
fi

echo -n "4. curl... "
if command -v curl &> /dev/null; then
    CURL_VERSION=$(curl --version | head -1 | awk '{print $2}')
    echo -e "${GREEN}${NC} (versão $CURL_VERSION)"
else
    echo -e "${YELLOW}${NC} curl não instalado (opcional)"
    ((WARNINGS++))
fi

echo -n "5. Ambiente Virtual Python... "
if [ -d "venv" ]; then
    echo -e "${GREEN}${NC} (venv/ existe)"
else
    echo -e "${YELLOW}${NC} venv/ não encontrado (execute install_universal.sh)"
    ((WARNINGS++))
fi

echo -n "6. Configuração... "
if [ -f "config/calma_config.json" ]; then
    if grep -q "seu_email@gmail.com" config/calma_config.json 2>/dev/null; then
        echo -e "${YELLOW}${NC} Configuração padrão (edite config/calma_config.json)"
        ((WARNINGS++))
    else
        echo -e "${GREEN}${NC} (config/calma_config.json configurado)"
    fi
else
    echo -e "${YELLOW}${NC} config/calma_config.json não encontrado"
    ((WARNINGS++))
fi

echo -n "7. Estrutura de diretórios... "
REQUIRED_DIRS=("scripts/detection" "scripts/ml" "scripts/utils" "dados" "logs" "config")
MISSING_DIRS=0

for dir in "${REQUIRED_DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        ((MISSING_DIRS++))
    fi
done

if [ $MISSING_DIRS -eq 0 ]; then
    echo -e "${GREEN}${NC} (todos os diretórios existem)"
else
    echo -e "${YELLOW}${NC} Faltam $MISSING_DIRS diretórios"
    ((WARNINGS++))
fi

echo -n "8. Modelos ML... "
if [ -f "scripts/ml/modelo_logistica.pkl" ]; then
    echo -e "${GREEN}${NC} (modelos treinados encontrados)"
else
    echo -e "${YELLOW}${NC} Modelos não encontrados (serão treinados na primeira execução)"
    ((WARNINGS++))
fi

if [ -d "venv" ] && [ -n "$PYTHON_CMD" ]; then
    echo -n "9. Pacotes Python... "
    
    if [ "$OS_TYPE" = "Windows" ]; then
        VENV_PYTHON="venv/Scripts/python"
    else
        VENV_PYTHON="venv/bin/python"
    fi
    
    if [ -f "$VENV_PYTHON" ]; then
        CHECK_RESULT=$($VENV_PYTHON -c "import numpy, pandas, sklearn, flask, pefile; print('OK')" 2>&1 || echo "FAIL")
        
        if [ "$CHECK_RESULT" = "OK" ]; then
            echo -e "${GREEN}${NC} (numpy, pandas, sklearn, flask, pefile)"
        else
            echo -e "${YELLOW}${NC} Alguns pacotes podem estar faltando"
            ((WARNINGS++))
        fi
    else
        echo -e "${YELLOW}${NC} Python do venv não encontrado"
        ((WARNINGS++))
    fi
fi

if [ "$OS_TYPE" != "Windows" ]; then
    echo -n "10. Permissões de execução... "
    if [ -x "calma.sh" ] && [ -x "install_universal.sh" ]; then
        echo -e "${GREEN}${NC} (scripts executáveis)"
    else
        echo -e "${YELLOW}${NC} Alguns scripts não são executáveis"
        echo "    Execute: chmod +x calma.sh install_universal.sh scripts/utils/*.sh"
        ((WARNINGS++))
    fi
fi

echo ""
echo -e "${CYAN}=== Resumo ===${NC}"
echo ""

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN} Sistema totalmente compatível!${NC}"
    echo ""
    echo "Pronto para executar:"
    echo "  ./calma.sh"
    EXIT_CODE=0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW} Sistema compatível com avisos (${WARNINGS})${NC}"
    echo ""
    echo "O sistema deve funcionar, mas recomenda-se resolver os avisos acima."
    EXIT_CODE=0
else
    echo -e "${RED} Sistema não compatível (${ERRORS} erros, ${WARNINGS} avisos)${NC}"
    echo ""
    echo "Resolva os erros acima antes de executar o CALMA."
    echo "Execute: ./install_universal.sh"
    EXIT_CODE=1
fi

echo ""
exit $EXIT_CODE
