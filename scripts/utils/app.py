from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
from datetime import datetime, timedelta
import json
import os
import subprocess
import shutil
import glob
import re
from pathlib import Path
from functools import wraps
import logging

BASE_DIR = Path(__file__).resolve().parents[2]
TEMPLATES_DIR = BASE_DIR / 'templates'
STATIC_DIR = BASE_DIR / 'assets'

app = Flask(__name__, template_folder=str(TEMPLATES_DIR), static_folder=str(STATIC_DIR))
app.secret_key = 'calma-secure-key-2025'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

LOGS_DIR = str(BASE_DIR / 'logs')
DATA_DIR = str(BASE_DIR / 'dados')
LOGO_DIR = str(BASE_DIR / 'assets')
CONFIG_FILE = str(BASE_DIR / 'config' / 'calma_config.json')

EMAIL_ATTACHMENTS_DIR = os.path.join(DATA_DIR, 'anexos_processados')
pending_dir = os.path.join(EMAIL_ATTACHMENTS_DIR, 'a_analisar')
clean_dir = os.path.join(EMAIL_ATTACHMENTS_DIR, 'limpos')
infected_dir = os.path.join(EMAIL_ATTACHMENTS_DIR, 'infetados')
suspicious_dir = os.path.join(EMAIL_ATTACHMENTS_DIR, 'suspeitos')
quarantine_dir = os.path.join(DATA_DIR, 'quarentena')

os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
DEFAULT_CONFIG = {
    'email_user': '',
    'email_pass': '',
    'email_server': 'imap.gmail.com',
    'email_port': 993,
    'max_file_size': 10485760,
    'scan_timeout': 300,
    'hash_algorithm': 'sha256',
    'enable_metadata': True,
    'keep_logs_days': 7,
    'cron_enabled': False,
    'cron_interval': 5,
    'cron_interval_unit': 'minutes',
    'require_vm': True,
    'vm_warning_only': False,
    'labels': {
        'clean': 'Clean',
        'infected': 'Infected',
        'suspicious': 'Suspicious'
    }
}


def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
                return {**DEFAULT_CONFIG, **config}
        except Exception as e:
            logger.error(f"Erro ao carregar config: {e}")
    return DEFAULT_CONFIG.copy()


def save_config(config):
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
        return True, "Configuração guardada com sucesso"
    except Exception as e:
        return False, f"Erro ao guardar configuração: {e}"


def get_cron_status():
    try:
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
        if 'calma.sh' in result.stdout:
            return True, "Ativo"
        return False, "Inativo"
    except Exception as e:
        logger.error(f"Erro ao verificar cron: {e}")
        return False, "Erro ao verificar"


def get_service_status():
    config = load_config()
    cron_enabled, cron_status = get_cron_status()
    
    return {
        'cron_enabled': cron_enabled,
        'cron_status': cron_status,
        'config_loaded': bool(config.get('email_user')),
        'labels_configured': bool(config.get('labels'))
    }


def get_statistics():
    stats = {
        'clean': 0,
        'infected': 0,
        'suspicious': 0,
        'pending': 0,
        'quarantine': 0,
        'total': 0
    }
    
    try:
        for dir_path, key in [(clean_dir, 'clean'), 
                               (infected_dir, 'infected'),
                               (suspicious_dir, 'suspicious'),
                               (pending_dir, 'pending')]:
            if os.path.exists(dir_path):
                stats[key] = len([f for f in os.listdir(dir_path) 
                                 if os.path.isfile(os.path.join(dir_path, f)) 
                                 and not f.endswith('.meta')])
        
        if os.path.exists(quarantine_dir):
            quarantine_files = [f for f in os.listdir(quarantine_dir) 
                               if os.path.isfile(os.path.join(quarantine_dir, f)) 
                               and not f.endswith('.meta')]
            stats['quarantine'] = len(quarantine_files)
        
        stats['total'] = sum(v for k, v in stats.items() if k != 'total')
    except Exception as e:
        logger.error(f"Erro ao obter estatísticas: {e}")
    
    return stats


def get_recent_logs(limit=200):
    all_logs = []
    try:
        log_files = sorted(glob.glob(os.path.join(LOGS_DIR, 'execucao_*.log')), 
                          key=os.path.getmtime, reverse=True)
        
        if not log_files:
            log_files = sorted(glob.glob(os.path.join(LOGS_DIR, '*.log')), 
                              key=os.path.getmtime, reverse=True)
            log_files = [f for f in log_files if not f.endswith('web_') and 'web_' not in f]
        
        for log_file in log_files:
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    all_logs.extend(lines)
            except Exception as e:
                logger.error(f"Erro ao ler {log_file}: {e}")
        
        logs = list(dict.fromkeys(all_logs))
        
        logs = logs[-limit:] if len(logs) > limit else logs
        
        logs = [log.strip() for log in logs if log.strip()]
    except Exception as e:
        logger.error(f"Erro ao obter logs: {e}")
        logs = []
    
    return logs


def get_recent_analyses(limit=50):
    analyses = []
    try:
        logs = get_recent_logs(500)
        
        for log in logs:
            if 'Classificado:' in log:
                try:
                    timestamp_match = re.search(r'\[(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\]', log)
                    filename_match = re.search(r'Classificado:\s*([^\s]+)', log)
                    status_match = re.search(r'Classificado:.*->\s*(\w+)\s*\(', log)
                    score_match = re.search(r'Score:\s*(\d+)', log)
                    
                    if filename_match:
                        timestamp = timestamp_match.group(1) if timestamp_match else 'N/A'
                        filename = filename_match.group(1)
                        status = status_match.group(1) if status_match else 'UNKNOWN'
                        score = int(score_match.group(1)) if score_match else 0
                        
                        if score >= 70:
                            verdict = 'Malicious'
                        elif score >= 30:
                            verdict = 'Suspicious'
                        else:
                            verdict = 'Clean'
                        
                        analyses.append({
                            'timestamp': timestamp,
                            'filename': filename,
                            'status': status,
                            'score': score,
                            'verdict': verdict
                        })
                except Exception as e:
                    logger.debug(f"Erro ao parsear log: {e}")
                    
    except Exception as e:
        logger.error(f"Erro ao obter análises: {e}")
    
    return analyses[-limit:] if len(analyses) > limit else analyses


def get_clean_emails(limit=50):
    clean_emails = []
    try:
        if not os.path.exists(clean_dir):
            return []
        
        # Obter todos os ficheiros .meta
        meta_files = sorted(glob.glob(os.path.join(clean_dir, '*.meta')), 
                           key=os.path.getmtime, reverse=True)
        
        for meta_file in meta_files[:limit]:
            try:
                with open(meta_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Extrair informações do metadata
                filename_match = re.search(r'Nome original:\s*([^\n]+)', content)
                email_origin = re.search(r'Email de origem:\s*([^\n]+)', content)
                extraction_date = re.search(r'Data de extração:\s*([^\n]+)', content)
                score_match = re.search(r'Score:\s*(\d+)/(\d+)', content)
                subject_match = re.search(r'Assunto:\s*([^\n]+)', content)
                sender_match = re.search(r'Remetente:\s*([^\n]+)', content)
                email_id = re.search(r'Email ID original:\s*(\d+)', content)
                
                if filename_match:
                    filename = filename_match.group(1).strip()
                    score = int(score_match.group(1)) if score_match else 0
                    max_score = int(score_match.group(2)) if score_match else 100
                    
                    clean_emails.append({
                        'filename': filename,
                        'score': score,
                        'max_score': max_score,
                        'timestamp': extraction_date.group(1).strip() if extraction_date else 'N/A',
                        'email_origin': email_origin.group(1).strip() if email_origin else 'Unknown',
                        'subject': subject_match.group(1).strip() if subject_match else 'No subject',
                        'sender': sender_match.group(1).strip() if sender_match else 'Unknown',
                        'email_id': email_id.group(1).strip() if email_id else 'N/A'
                    })
            except Exception as e:
                logger.debug(f"Erro ao processar meta file {meta_file}: {e}")
        
        return clean_emails
    except Exception as e:
        logger.error(f"Erro ao obter emails limpos: {e}")
        return []


@app.route('/assets/<filename>')
def serve_logo(filename):
    try:
        return send_from_directory(LOGO_DIR, filename)
    except Exception as e:
        logger.error(f"Erro ao servir logo: {e}")
        return jsonify({'error': 'Logo not found'}), 404

@app.route('/')
def index():
    config = load_config()
    stats = get_statistics()
    service_status = get_service_status()
    
    return render_template('index.html',
                         config=config,
                         stats=stats,
                         service_status=service_status)



@app.route('/api/config', methods=['GET', 'POST'])
def api_config():
    if request.method == 'GET':
        config = load_config()
        config['email_pass'] = '••••••••' if config.get('email_pass') else ''
        return jsonify(config)
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            config = load_config()
            
            for key in data:
                if key != 'email_pass' or data[key] != '••••••••':
                    config[key] = data[key]
                else:
                    if not data[key].startswith('•'):
                        config[key] = data[key]
            
            success, message = save_config(config)
            
            if success:
                update_calma_script(config)
            
            return jsonify({'success': success, 'message': message}), 200 if success else 400
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 400


@app.route('/api/stats', methods=['GET'])
def api_stats():
    stats = get_statistics()
    return jsonify(stats)


@app.route('/api/status', methods=['GET'])
def api_status():
    status = get_service_status()
    status['stats'] = get_statistics()
    return jsonify(status)


@app.route('/api/clean-emails', methods=['GET'])
def api_clean_emails():
    limit = request.args.get('limit', 50, type=int)
    clean_emails = get_clean_emails(limit)
    return jsonify({'clean_emails': clean_emails, 'total': len(clean_emails)})


def check_virtual_machine():
    is_vm = False
    vm_type = None
    allowed_vm_types = {
        'virtualbox', 'vmware', 'kvm', 'qemu', 'xen', 'hyper-v', 'hyperv', 'parallels', 'bhyve'
    }
    
    try:
        if os.path.exists('/sys/class/dmi/id/product_name'):
            with open('/sys/class/dmi/id/product_name', 'r') as f:
                product_name = f.read().strip()
                if any(x.lower() in product_name.lower() for x in allowed_vm_types):
                    is_vm = True
                    vm_type = product_name
        
        if not is_vm and os.path.exists('/sys/class/dmi/id/sys_vendor'):
            with open('/sys/class/dmi/id/sys_vendor', 'r') as f:
                sys_vendor = f.read().strip()
                if any(x.lower() in sys_vendor.lower() for x in allowed_vm_types):
                    is_vm = True
                    vm_type = sys_vendor
        
        if not is_vm:
            try:
                result = subprocess.run(['systemd-detect-virt', '--quiet'], 
                                      capture_output=True, timeout=2)
                if result.returncode == 0:
                    vm_result = subprocess.run(['systemd-detect-virt'], 
                                             capture_output=True, text=True, timeout=2)
                    detected = vm_result.stdout.strip() if vm_result.returncode == 0 else "unknown"
                    vm_type = detected or "unknown"
                    if vm_type.lower() in allowed_vm_types:
                        is_vm = True
            except:
                pass
        
        if not is_vm:
            try:
                result = subprocess.run(['lscpu'], capture_output=True, text=True, timeout=2)
                if 'Hypervisor vendor' in result.stdout:
                    for line in result.stdout.split('\n'):
                        if 'Hypervisor vendor' in line:
                            vm_type = line.split(':')[1].strip()
                            if vm_type.lower() in allowed_vm_types:
                                is_vm = True
                            break
            except:
                pass
                
    except Exception as e:
        logger.error(f"Erro ao verificar VM: {e}")
    
    if is_vm:
        message = f"Ambiente Virtual: {vm_type}"
    elif vm_type:
        message = f"Ambiente não seguro detectado: {vm_type}"
    else:
        message = "Sistema Físico - RISCO ELEVADO!"

    return {
        'is_vm': is_vm,
        'vm_type': vm_type if is_vm else None,
        'safe': is_vm,
        'message': message
    }


@app.route('/api/vm-check', methods=['GET'])
def api_vm_check():
    return jsonify(check_virtual_machine())


@app.route('/api/logs', methods=['GET'])
def api_logs():
    limit = request.args.get('lines', request.args.get('limit', 200, type=int), type=int)
    logs = get_recent_logs(limit)
    return jsonify({'logs': logs})


@app.route('/api/analyses', methods=['GET'])
def api_analyses():
    limit = request.args.get('limit', 50, type=int)
    analyses = get_recent_analyses(limit)
    return jsonify({'analyses': analyses})


@app.route('/api/cron/enable', methods=['POST'])
def api_cron_enable():
    try:
        config = load_config()
        vm_status = check_virtual_machine()
        if config.get('require_vm', True) and not vm_status.get('safe', False):
            if not config.get('vm_warning_only', True):
                return jsonify({'success': False, 'message': 'Execução bloqueada: VM obrigatória não detectada'}), 400
        data = request.get_json()
        interval = data.get('interval', 5)
        interval_unit = data.get('interval_unit', 'minutes')
        
        script_path = os.path.join(BASE_DIR, 'calma.sh')
        cron_log = os.path.join(LOGS_DIR, 'cron.log')
        
                                                          
        if interval_unit == 'seconds':
            if interval <= 0 or interval >= 60:
                return jsonify({'success': False, 'message': 'Intervalo em segundos deve ser entre 1 e 59'}), 400
            if 60 % interval != 0:
                return jsonify({'success': False, 'message': 'Intervalo em segundos deve dividir 60 (ex: 1, 2, 3, 4, 5, 6, 10, 12, 15, 20, 30)'}), 400

            cron_entries = []
            for offset in range(0, 60, interval):
                if offset == 0:
                    cron_entries.append(f"* * * * * cd {BASE_DIR} && ./calma.sh >> {cron_log} 2>&1")
                else:
                    cron_entries.append(f"* * * * * sleep {offset}; cd {BASE_DIR} && ./calma.sh >> {cron_log} 2>&1")
        elif interval_unit == 'hours':
                                                                  
            cron_entries = [f"0 */{interval} * * * cd {BASE_DIR} && ./calma.sh >> {cron_log} 2>&1"]
        else:                    
                                       
            cron_entries = [f"*/{interval} * * * * cd {BASE_DIR} && ./calma.sh >> {cron_log} 2>&1"]
        
                                           
        try:
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            crontab_content = result.stdout
        except:
            crontab_content = ""
        
                                
        lines = [line for line in crontab_content.split('\n') if 'calma.sh' not in line]
        lines.extend(cron_entries)
        
                               
        new_crontab = '\n'.join(lines) + '\n'
        process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, 
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(input=new_crontab)
        
        if process.returncode == 0:
            config['cron_enabled'] = True
            config['cron_interval'] = interval
            config['cron_interval_unit'] = interval_unit
            save_config(config)
            response = {'success': True, 'message': f'Cron job ativado a cada {interval} {interval_unit}'}
            if config.get('require_vm', True) and not vm_status.get('safe', False):
                response['warning'] = vm_status.get('message', 'VM não detectada')
            return jsonify(response)
        else:
            return jsonify({'success': False, 'message': f'Erro: {stderr}'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400


@app.route('/api/cron/disable', methods=['POST'])
def api_cron_disable():
    try:
        config = load_config()
        
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
        crontab_content = result.stdout
        
        lines = [line for line in crontab_content.split('\n') if 'calma.sh' not in line]
        new_crontab = '\n'.join(lines) + '\n'
        
        process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(input=new_crontab)
        
        if process.returncode == 0:
            config['cron_enabled'] = False
            save_config(config)
            return jsonify({'success': True, 'message': 'Cron job desativado'})
        else:
            return jsonify({'success': False, 'message': f'Erro: {stderr}'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400


@app.route('/api/run', methods=['POST'])
def api_run():
    try:
        config = load_config()
        vm_status = check_virtual_machine()
        if config.get('require_vm', True) and not vm_status.get('safe', False):
            if not config.get('vm_warning_only', True):
                return jsonify({'success': False, 'message': 'Execução bloqueada: VM obrigatória não detectada'}), 400
        script_path = os.path.join(BASE_DIR, 'calma.sh')
        if not os.path.exists(script_path):
            return jsonify({'success': False, 'message': 'Script calma.sh não encontrado'}), 400
        
        os.chmod(script_path, 0o755)
        
        log_file = os.path.join(LOGS_DIR, f'manual_run_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
        with open(log_file, 'w') as f:
            subprocess.Popen([script_path], stdout=f, stderr=subprocess.STDOUT, cwd=BASE_DIR)
        
        response = {'success': True, 'message': 'Script iniciado em background', 'log': log_file}
        if config.get('require_vm', True) and not vm_status.get('safe', False):
            response['warning'] = vm_status.get('message', 'VM não detectada')
        return jsonify(response)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400


@app.route('/api/logs/clear', methods=['POST'])
def api_logs_clear():
    try:
        days = request.get_json().get('days', 7)
        
        now = datetime.now()
        cutoff_time = (now - timedelta(days=days)).timestamp()
        
        count = 0
        for log_file in glob.glob(os.path.join(LOGS_DIR, '*')):
            if os.path.getmtime(log_file) < cutoff_time:
                try:
                    if os.path.isfile(log_file):
                        os.remove(log_file)
                        count += 1
                except:
                    pass
        
        return jsonify({'success': True, 'message': f'{count} ficheiros eliminados'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400


@app.route('/api/test-connection', methods=['POST'])
def api_test_connection():
    try:
        import imaplib
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password or password.startswith('•'):
            return jsonify({'success': False, 'message': 'Email e password obrigatórios'}), 400
        
        mail = imaplib.IMAP4_SSL('imap.gmail.com', 993)
        mail.login(email, password)
        mail.logout()
        
        return jsonify({'success': True, 'message': 'Conexão estabelecida com sucesso!'})
    except imaplib.IMAP4.error as e:
        return jsonify({'success': False, 'message': f'Erro de autenticação: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erro na conexão: {str(e)}'}), 400


def update_calma_script(config):
    try:
        script_path = os.path.join(BASE_DIR, 'calma.sh')
        with open(script_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        replacements = {
            'EMAIL_USER="[^"]*"': f'EMAIL_USER="{config.get("email_user", "")}"',
            'EMAIL_PASS="[^"]*"': f'EMAIL_PASS="{config.get("email_pass", "")}"',
            'EMAIL_SERVER="[^"]*"': f'EMAIL_SERVER="{config.get("email_server", "imap.gmail.com")}"',
            'EMAIL_PORT="[^"]*"': f'EMAIL_PORT="{config.get("email_port", "993")}"',
            'MAX_FILE_SIZE="[^"]*"': f'MAX_FILE_SIZE="{config.get("max_file_size", "10485760")}"',
            'SCAN_TIMEOUT="[^"]*"': f'SCAN_TIMEOUT="{config.get("scan_timeout", "300")}"',
            'KEEP_LOGS_DAYS="[^"]*"': f'KEEP_LOGS_DAYS="{config.get("keep_logs_days", "7")}"',
            'HASH_ALGORITHM="[^"]*"': f'HASH_ALGORITHM="{config.get("hash_algorithm", "sha256")}"',
            'ENABLE_METADATA="[^"]*"': f'ENABLE_METADATA="{str(config.get("enable_metadata", True)).lower()}"',
        }
        
        for pattern, replacement in replacements.items():
            content = re.sub(pattern, replacement, content)
        
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return True
    except Exception as e:
        logger.error(f"Erro ao atualizar calma.sh: {e}")
        return False


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
