"""
Módulo de Notificações para CALMA
Envia notificações por email sobre ficheiros suspeitos/maliciosos
"""

import json
import smtplib
import logging
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional, List
from dataclasses import dataclass

# Imports locais
import sys
sys.path.insert(0, str(Path(__file__).parent))


@dataclass
class NotificationConfig:
    """Configuração de notificações"""
    enabled: bool = True
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 587
    sender_email: str = ""
    sender_password: str = ""
    recipient_emails: List[str] = None
    notify_on_clean: bool = False
    notify_on_suspicious: bool = True
    notify_on_malware: bool = True


class NotificationService:
    """Serviço de notificações por email"""
    
    def __init__(self, config_file: str = None):
        """
        Inicializa serviço de notificações
        
        Args:
            config_file: Caminho do ficheiro de config
        """
        if config_file is None:
            config_file = Path(__file__).parent.parent.parent / "config" / "calma_config.json"
        
        self.config_file = Path(config_file)
        self.logger = self._setup_logger()
        self.config = self._load_config()
    
    def _setup_logger(self) -> logging.Logger:
        """Setup de logging"""
        logger = logging.getLogger('CALMA-Notifications')
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger
    
    def _load_config(self) -> NotificationConfig:
        """Carrega configuração de notificações"""
        try:
            if not self.config_file.exists():
                self.logger.warning(f"Ficheiro de config não encontrado: {self.config_file}")
                return NotificationConfig()
            
            with open(self.config_file) as f:
                config_data = json.load(f)
            
            return NotificationConfig(
                enabled=config_data.get('notifications_enabled', True),
                smtp_server=config_data.get('notifications_smtp', "smtp.gmail.com"),
                smtp_port=config_data.get('notifications_smtp_port', 587),
                sender_email=config_data.get('email_user', ''),
                sender_password=config_data.get('email_pass', ''),
                recipient_emails=config_data.get('notifications_recipients', [config_data.get('email_user', '')]),
                notify_on_clean=config_data.get('notifications_on_clean', False),
                notify_on_suspicious=config_data.get('notifications_on_suspicious', True),
                notify_on_malware=config_data.get('notifications_on_malware', True)
            )
        except Exception as e:
            self.logger.error(f"Erro ao carregar config: {e}")
            return NotificationConfig()
    
    def send_detection_notification(self, detection_result, filename: str = None, 
                                    sender_email: str = None, subject: str = None) -> bool:
        """
        Envia notificação sobre detecção de ficheiro
        
        Args:
            detection_result: DetectionResult object
            filename: Nome do ficheiro (para logs)
            sender_email: Email do remetente (pode substituir config)
            subject: Assunto customizado
            
        Returns:
            True se enviado com sucesso
        """
        if not self.config.enabled:
            return False
        
        # Verifica se deve notificar baseado na classificação
        should_notify = False
        
        if detection_result.prediction == "LIMPO" and self.config.notify_on_clean:
            should_notify = True
        elif detection_result.prediction == "SUSPEITO" and self.config.notify_on_suspicious:
            should_notify = True
        elif detection_result.prediction == "MALWARE" and self.config.notify_on_malware:
            should_notify = True
        
        if not should_notify:
            return False
        
        try:
            html_body = self._build_html_email(detection_result, filename)
            
            # Usa email do sender customizado ou da config
            from_email = sender_email or self.config.sender_email
            if not from_email:
                self.logger.warning("Email de sender não configurado")
                return False
            
            # Assunto
            if not subject:
                emoji = "🟢" if detection_result.prediction == "LIMPO" else \
                        "🟡" if detection_result.prediction == "SUSPEITO" else "🔴"
                subject = f"[CALMA] {emoji} Detecção: {detection_result.prediction} - {filename or 'Ficheiro'}"
            
            # Envia email
            return self._send_email(
                from_email=from_email,
                to_emails=self.config.recipient_emails,
                subject=subject,
                html_body=html_body
            )
        
        except Exception as e:
            self.logger.error(f"Erro ao enviar notificação: {e}")
            return False
    
    def _build_html_email(self, detection_result, filename: str = None) -> str:
        """Constrói corpo HTML do email"""
        
        file_name = filename or Path(detection_result.file_path).name
        
        # Cores baseadas na classificação
        if detection_result.prediction == "LIMPO":
            color = "#4CAF50"
            bg_color = "#E8F5E9"
            icon = "✅"
        elif detection_result.prediction == "SUSPEITO":
            color = "#FF9800"
            bg_color = "#FFF3E0"
            icon = "⚠️"
        else:  # MALWARE
            color = "#F44336"
            bg_color = "#FFEBEE"
            icon = "🚨"
        
        # Informações do VirusTotal
        vt_info = ""
        if detection_result.virustotal_result:
            vt = detection_result.virustotal_result
            if not vt.error:
                vt_info = f"""
                <tr style="background-color: #f5f5f5;">
                    <td colspan="2" style="padding: 15px; border-left: 4px solid #2196F3;">
                        <strong style="color: #2196F3;">📊 Análise VirusTotal (Sandbox)</strong>
                        <p style="margin: 10px 0; font-size: 14px;">
                            <strong>Detecções:</strong> {vt.malicious_count}/{vt.total_vendors} antivírus<br>
                            <strong>Hash SHA256:</strong> <code style="background: #f0f0f0; padding: 2px 5px;">{vt.file_hash[:32]}...</code><br>
                            <strong>Data:</strong> {vt.analysis_date or 'N/A'}
                        </p>
                        {"<strong>Ameaça:</strong> " + vt.threat_name + "<br>" if vt.threat_name else ""}
                    </td>
                </tr>
                """
        
        # Template HTML
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; }}
                .header {{ background-color: {color}; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }}
                .content {{ border: 1px solid #ddd; border-top: none; border-radius: 0 0 5px 5px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                td {{ padding: 10px; border-bottom: 1px solid #eee; }}
                tr:last-child td {{ border-bottom: none; }}
                .status-badge {{ 
                    background-color: {bg_color}; 
                    color: {color}; 
                    padding: 10px 15px; 
                    border-radius: 5px; 
                    font-weight: bold; 
                    font-size: 16px;
                    display: inline-block;
                }}
                .score-bar {{
                    width: 100%;
                    height: 25px;
                    background: linear-gradient(to right, #4CAF50 0%, #FFC107 50%, #F44336 100%);
                    border-radius: 5px;
                    overflow: hidden;
                    position: relative;
                }}
                .score-indicator {{
                    position: absolute;
                    height: 100%;
                    background: white;
                    width: 3px;
                    left: {detection_result.score}%;
                }}
                .label {{ font-weight: bold; color: #666; width: 40%; }}
                .footer {{ 
                    background: #f5f5f5; 
                    padding: 10px; 
                    text-align: center; 
                    font-size: 12px; 
                    color: #999; 
                    border-radius: 0 0 5px 5px;
                }}
                code {{ background: #f0f0f0; padding: 2px 5px; border-radius: 3px; font-family: monospace; }}
                .vendor-list {{ 
                    max-height: 200px; 
                    overflow-y: auto; 
                    font-size: 13px;
                    background: #f9f9f9;
                    padding: 10px;
                    border-radius: 3px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1 style="margin: 0;">{icon} {detection_result.prediction}</h1>
                    <p style="margin: 10px 0 0 0; font-size: 14px;">Resultado da detecção de malware</p>
                </div>
                <div class="content">
                    <table>
                        <tr>
                            <td class="label">Ficheiro:</td>
                            <td><strong>{file_name}</strong></td>
                        </tr>
                        <tr>
                            <td class="label">Tipo:</td>
                            <td>{detection_result.file_type}</td>
                        </tr>
                        <tr>
                            <td class="label">Método:</td>
                            <td>{detection_result.method}</td>
                        </tr>
                        <tr>
                            <td class="label">Data/Hora:</td>
                            <td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td>
                        </tr>
                        <tr>
                            <td colspan="2" style="padding: 15px; text-align: center;">
                                <div class="status-badge">{detection_result.prediction}</div>
                            </td>
                        </tr>
                        <tr>
                            <td class="label">Score de Risco:</td>
                            <td>
                                <strong>{detection_result.score}/100</strong>
                                <div class="score-bar">
                                    <div class="score-indicator"></div>
                                </div>
                                <p style="margin: 5px 0 0 0; font-size: 12px;">Nível: <strong>{detection_result.risk_level}</strong></p>
                            </td>
                        </tr>
                        <tr>
                            <td class="label">Confiança:</td>
                            <td>{detection_result.confidence:.1%}</td>
                        </tr>
                        <tr>
                            <td class="label">Detalhes:</td>
                            <td><code>{detection_result.details}</code></td>
                        </tr>
                        {vt_info}
                    </table>
                </div>
                <div class="footer">
                    <p>CALMA - Sistema Inteligente de Detecção de Malware<br>
                    Gerado em {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _send_email(self, from_email: str, to_emails: List[str], subject: str, html_body: str) -> bool:
        """Envia email via SMTP"""
        
        if not to_emails or not to_emails[0]:
            self.logger.warning("Lista de destinatários vazia")
            return False
        
        try:
            # Cria mensagem
            message = MIMEMultipart('alternative')
            message['Subject'] = subject
            message['From'] = from_email
            message['To'] = ', '.join(to_emails)
            
            # Adiciona corpo HTML
            html_part = MIMEText(html_body, 'html')
            message.attach(html_part)
            
            # Envia via SMTP
            with smtplib.SMTP(self.config.smtp_server, self.config.smtp_port) as server:
                server.starttls()
                server.login(from_email, self.config.sender_password)
                server.send_message(message)
            
            self.logger.info(f"✅ Notificação enviada para {', '.join(to_emails)}")
            return True
        
        except smtplib.SMTPAuthenticationError:
            self.logger.error("Erro de autenticação SMTP. Verifique email e senha.")
            return False
        except smtplib.SMTPException as e:
            self.logger.error(f"Erro SMTP: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Erro ao enviar email: {e}")
            return False


if __name__ == '__main__':
    print("Módulo de notificações CALMA")
    print("Use em conjunto com detect_malware_universal.py")
