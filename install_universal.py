                      
"""
CALMA - Instalador Universal Cross-Platform
Suporta: Windows 10/11, macOS, Linux (todas distribuições)
"""

import subprocess
import sys
import os
import platform
import shutil
import json
from pathlib import Path

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def supports_color():
    """Verifica se o terminal suporta cores"""
    if platform.system() == 'Windows':
        return os.environ.get('TERM') or os.environ.get('WT_SESSION')
    return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()

def print_color(text, color):
    """Imprime texto colorido se suportado"""
    if supports_color():
        print(f"{color}{text}{Colors.ENDC}")
    else:
        print(text)

def print_header():
    """Exibe o cabeçalho do instalador"""
    system = platform.system()
    print()
    print_color("=" * 70, Colors.CYAN)
    print_color("   ██████╗ █████╗ ██╗     ███╗   ███╗ █████╗ ", Colors.CYAN)
    print_color("  ██╔════╝██╔══██╗██║     ████╗ ████║██╔══██╗", Colors.CYAN)
    print_color("  ██║     ███████║██║     ██╔████╔██║███████║", Colors.CYAN)
    print_color("  ██║     ██╔══██║██║     ██║╚██╔╝██║██╔══██║", Colors.CYAN)
    print_color("  ╚██████╗██║  ██║███████╗██║ ╚═╝ ██║██║  ██║", Colors.CYAN)
    print_color("   ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝", Colors.CYAN)
    print_color("", Colors.CYAN)
    print_color("   Instalador Universal - Cross-Platform", Colors.BOLD)
    print_color(f"   Sistema: {system} {platform.release()}", Colors.BLUE)
    print_color(f"   Python: {sys.version.split()[0]}", Colors.BLUE)
    print_color("=" * 70, Colors.CYAN)
    print()

def detect_os():
    """Detecta o sistema operacional"""
    system = platform.system().lower()
    if system == 'linux':
                                     
        try:
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release') as f:
                    lines = f.readlines()
                    for line in lines:
                        if line.startswith('ID='):
                            distro = line.split('=')[1].strip().strip('"')
                            return f"linux-{distro}"
        except:
            pass
        return "linux-generic"
    elif system == 'darwin':
        return "macos"
    elif system == 'windows':
        return "windows"
    else:
        return "unknown"

def check_python_version():
    """Verifica se a versão do Python é compatível"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print_color(" ERRO: Python 3.8 ou superior é necessário!", Colors.FAIL)
        print_color(f"   Versão atual: {version.major}.{version.minor}.{version.micro}", Colors.WARNING)
        print()
        print_color("Instale Python 3.8+:", Colors.BOLD)
        
        os_type = detect_os()
        if 'linux' in os_type:
            print("  Ubuntu/Debian: sudo apt update && sudo apt install python3.10")
            print("  Fedora/RHEL:   sudo dnf install python3.10")
            print("  Arch:          sudo pacman -S python")
        elif os_type == 'macos':
            print("  brew install python@3.10")
            print("  ou: https://www.python.org/downloads/")
        elif os_type == 'windows':
            print("  https://www.python.org/downloads/windows/")
            print("  ou: winget install Python.Python.3.10")
        
        return False
    return True

def install_system_dependencies(os_type):
    """Instala dependências do sistema operacional"""
    print_color(" Verificando dependências do sistema...", Colors.CYAN)
    
    dependencies = {
        'linux': ['jq', 'curl'],
        'macos': ['jq', 'curl'],
        'windows': []
    }
    
    missing = []
    
                                             
    if 'linux' in os_type or os_type == 'macos':
        if not shutil.which('jq'):
            missing.append('jq')
        if not shutil.which('curl'):
            missing.append('curl')
    
    if missing:
        print_color(f"️  Faltam dependências: {', '.join(missing)}", Colors.WARNING)
        print()
        print_color("Comandos para instalar:", Colors.BOLD)
        
        if 'linux-ubuntu' in os_type or 'linux-debian' in os_type:
            print(f"  sudo apt update && sudo apt install -y {' '.join(missing)}")
        elif 'linux-fedora' in os_type or 'linux-rhel' in os_type or 'linux-centos' in os_type:
            print(f"  sudo dnf install -y {' '.join(missing)}")
        elif 'linux-arch' in os_type:
            print(f"  sudo pacman -S {' '.join(missing)}")
        elif 'linux-opensuse' in os_type:
            print(f"  sudo zypper install {' '.join(missing)}")
        elif os_type == 'macos':
            print(f"  brew install {' '.join(missing)}")
        elif os_type == 'linux-generic':
            print(f"  Use o gerenciador de pacotes da sua distribuição para instalar: {' '.join(missing)}")
        
        print()
        response = input("Deseja que o instalador tente instalar automaticamente? (s/N): ").strip().lower()
        
        if response == 's' or response == 'sim':
            try:
                if 'linux-ubuntu' in os_type or 'linux-debian' in os_type:
                    subprocess.run(['sudo', 'apt', 'update'], check=True)
                    subprocess.run(['sudo', 'apt', 'install', '-y'] + missing, check=True)
                elif 'linux-fedora' in os_type or 'linux-rhel' in os_type:
                    subprocess.run(['sudo', 'dnf', 'install', '-y'] + missing, check=True)
                elif 'linux-arch' in os_type:
                    subprocess.run(['sudo', 'pacman', '-S', '--noconfirm'] + missing, check=True)
                elif os_type == 'macos':
                    subprocess.run(['brew', 'install'] + missing, check=True)
                
                print_color(" Dependências instaladas com sucesso!", Colors.GREEN)
            except Exception as e:
                print_color(f" Erro ao instalar dependências: {e}", Colors.FAIL)
                print_color("   Instale manualmente e execute novamente.", Colors.WARNING)
                return False
        else:
            print_color("️  Instale as dependências manualmente e execute novamente.", Colors.WARNING)
            return False
    else:
        print_color(" Todas as dependências do sistema estão instaladas!", Colors.GREEN)
    
    print()
    return True

def create_venv(venv_path):
    """Cria ambiente virtual Python"""
    print_color(" Criando ambiente virtual...", Colors.CYAN)
    
    if venv_path.exists():
        print_color("   Ambiente virtual já existe, recriando...", Colors.WARNING)
        shutil.rmtree(venv_path)
    
    try:
        import venv
        venv.create(venv_path, with_pip=True)
        print_color(" Ambiente virtual criado!", Colors.GREEN)
        return True
    except Exception as e:
        print_color(f" Erro ao criar ambiente virtual: {e}", Colors.FAIL)
        return False

def get_pip_executable(venv_path):
    """Retorna o caminho do pip no venv"""
    if platform.system() == 'Windows':
        return venv_path / 'Scripts' / 'pip.exe'
    else:
        return venv_path / 'bin' / 'pip'

def get_python_executable(venv_path):
    """Retorna o caminho do python no venv"""
    if platform.system() == 'Windows':
        return venv_path / 'Scripts' / 'python.exe'
    else:
        return venv_path / 'bin' / 'python'

def install_python_packages(venv_path, requirements_file):
    """Instala pacotes Python via pip"""
    print_color(" Instalando pacotes Python...", Colors.CYAN)
    
    pip_executable = get_pip_executable(venv_path)
    
    if not pip_executable.exists():
        print_color(f" Pip não encontrado em: {pip_executable}", Colors.FAIL)
        return False
    
    try:
                       
        print("   Atualizando pip...")
        subprocess.run([str(pip_executable), 'install', '--upgrade', 'pip'], 
                      check=True, capture_output=True)
        
                               
        print(f"   Instalando pacotes de {requirements_file}...")
        result = subprocess.run(
            [str(pip_executable), 'install', '-r', str(requirements_file)],
            check=True,
            capture_output=True,
            text=True
        )
        
        print_color(" Pacotes Python instalados com sucesso!", Colors.GREEN)
        return True
        
    except subprocess.CalledProcessError as e:
        print_color(f" Erro ao instalar pacotes Python:", Colors.FAIL)
        print(e.stderr)
        return False

def create_directory_structure(base_dir):
    """Cria estrutura de diretórios necessária"""
    print_color(" Criando estrutura de diretórios...", Colors.CYAN)
    
    directories = [
        'config',
        'scripts/detection',
        'scripts/ml',
        'scripts/utils',
        'docs',
        'logs',
        'dados/anexos_processados/a_analisar',
        'dados/anexos_processados/limpos',
        'dados/anexos_processados/infetados',
        'dados/anexos_processados/suspeitos',
        'dados/quarentena'
    ]
    
    for directory in directories:
        dir_path = base_dir / directory
        dir_path.mkdir(parents=True, exist_ok=True)
    
    print_color(" Estrutura de diretórios criada!", Colors.GREEN)

def create_config_file(base_dir):
    """Cria arquivo de configuração padrão se não existir"""
    config_file = base_dir / 'config' / 'calma_config.json'
    
    if config_file.exists():
        print_color("ℹ️  Arquivo de configuração já existe, mantendo...", Colors.BLUE)
        return True
    
    print_color("️  Criando arquivo de configuração padrão...", Colors.CYAN)
    
    default_config = {
        "email_user": "seu_email@gmail.com",
        "email_pass": "sua_senha_app",
        "email_server": "imap.gmail.com",
        "email_port": 993,
        "max_file_size": 10485760,
        "scan_timeout": 300,
        "keep_logs_days": 7,
        "hash_algorithm": "sha256",
        "enable_metadata": True,
        "threshold_limpo": 50,
        "threshold_suspeito": 75
    }
    
    try:
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        print_color(" Arquivo de configuração criado!", Colors.GREEN)
        print_color(f"   Edite: {config_file}", Colors.WARNING)
        return True
    except Exception as e:
        print_color(f" Erro ao criar configuração: {e}", Colors.FAIL)
        return False

def create_activation_scripts(base_dir, venv_path):
    """Cria scripts de ativação do ambiente"""
    print_color(" Criando scripts de ativação...", Colors.CYAN)
    
                             
    if platform.system() != 'Windows':
        activate_sh = base_dir / 'activate_calma.sh'
        with open(activate_sh, 'w') as f:
            f.write(f"""#!/bin/bash
# CALMA - Ativar Ambiente Virtual

source "{venv_path}/bin/activate"
echo " Ambiente CALMA ativado!"
echo ""
echo "Comandos disponíveis:"
echo "  ./calma.sh                           - Executar sistema"
echo "  ./scripts/utils/enviar_emails_teste.sh - Enviar emails teste"
echo "  python3 scripts/utils/app.py         - Interface web"
echo ""
""")
        os.chmod(activate_sh, 0o755)
    
                         
    if platform.system() == 'Windows':
        activate_bat = base_dir / 'activate_calma.bat'
        with open(activate_bat, 'w') as f:
            f.write(f"""@echo off
REM CALMA - Ativar Ambiente Virtual

call "{venv_path}\\Scripts\\activate.bat"
echo  Ambiente CALMA ativado!
echo.
echo Comandos disponíveis:
echo   bash calma.sh                          - Executar sistema
echo   bash scripts/utils/enviar_emails_teste.sh - Enviar emails teste
echo   python scripts/utils/app.py            - Interface web
echo.
""")
    
    print_color(" Scripts de ativação criados!", Colors.GREEN)

def verify_installation(venv_path):
    """Verifica se a instalação foi bem-sucedida"""
    print_color(" Verificando instalação...", Colors.CYAN)
    
    python_executable = get_python_executable(venv_path)
    
    try:
                                      
        result = subprocess.run(
            [str(python_executable), '-c', 
             'import numpy, pandas, sklearn, flask, pefile; print("OK")'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0 and 'OK' in result.stdout:
            print_color(" Todos os pacotes verificados!", Colors.GREEN)
            return True
        else:
            print_color("️  Alguns pacotes podem estar faltando", Colors.WARNING)
            return False
            
    except Exception as e:
        print_color(f"️  Não foi possível verificar completamente: {e}", Colors.WARNING)
        return False

def print_next_steps(os_type):
    """Imprime próximos passos após instalação"""
    print()
    print_color("=" * 70, Colors.GREEN)
    print_color("    INSTALAÇÃO CONCLUÍDA COM SUCESSO!", Colors.GREEN)
    print_color("=" * 70, Colors.GREEN)
    print()
    print_color(" Próximos passos:", Colors.BOLD)
    print()
    
    if platform.system() == 'Windows':
        print_color("1. Ativar ambiente virtual:", Colors.CYAN)
        print("   activate_calma.bat")
        print()
        print_color("2. Configurar credenciais:", Colors.CYAN)
        print("   notepad config\\calma_config.json")
        print()
        print_color("3. Executar o sistema (Git Bash ou WSL):", Colors.CYAN)
        print("   bash calma.sh")
        print()
        print_color(" Nota: No Windows use Git Bash ou WSL para scripts .sh", Colors.WARNING)
    else:
        print_color("1. Ativar ambiente virtual:", Colors.CYAN)
        print("   source venv/bin/activate")
        print("   ou: source activate_calma.sh")
        print()
        print_color("2. Configurar credenciais:", Colors.CYAN)
        print("   nano config/calma_config.json")
        print()
        print_color("3. Enviar emails de teste:", Colors.CYAN)
        print("   ./scripts/utils/enviar_emails_teste.sh")
        print()
        print_color("4. Executar o sistema:", Colors.CYAN)
        print("   ./calma.sh")
    
    print()
    print_color(" Documentação completa:", Colors.CYAN)
    print("   docs/QUICKSTART_ESTRUTURADO.md")
    print()

def main():
    """Função principal do instalador"""
    print_header()
    
                 
    os_type = detect_os()
    print_color(f"️  Sistema detectado: {os_type}", Colors.BLUE)
    print()
    
                      
    if not check_python_version():
        return 1
    print_color(f" Python {sys.version.split()[0]} - OK!", Colors.GREEN)
    print()
    
                                       
    if not install_system_dependencies(os_type):
        print()
        print_color("️  Continue a instalação Python, mas lembre-se de instalar as dependências do sistema.", Colors.WARNING)
        print()
    
                      
    base_dir = Path(__file__).parent.resolve()
    venv_path = base_dir / 'venv'
    requirements_file = base_dir / 'requirements.txt'
    
                                   
    create_directory_structure(base_dir)
    print()
    
                               
    create_config_file(base_dir)
    print()
    
                
    if not create_venv(venv_path):
        return 1
    print()
    
                             
    if not install_python_packages(venv_path, requirements_file):
        return 1
    print()
    
                               
    create_activation_scripts(base_dir, venv_path)
    print()
    
                          
    verify_installation(venv_path)
    print()
    
                     
    print_next_steps(os_type)
    
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        print_color("\n️  Instalação cancelada pelo usuário.", Colors.WARNING)
        sys.exit(1)
    except Exception as e:
        print()
        print_color(f"\n Erro inesperado: {e}", Colors.FAIL)
        import traceback
        traceback.print_exc()
        sys.exit(1)
