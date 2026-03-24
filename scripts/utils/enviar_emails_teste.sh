

EMAIL_USER="calma.sndbox.willback@gmail.com"
EMAIL_PASS="habv aijj szwo cbek"

echo "Enviando emails de teste para o CALMA..."
echo "=================================================="

echo "Este é um ficheiro seguro para teste." > documento_seguro.txt
echo "Conteúdo suspeito simulado." > suspeito.exe.txt
echo "PDF de teste limpo." > relatorio.pdf
echo "MALWARE TROJAN VIRUS RANSOMWARE - Ficheiro perigoso!" > virus_malware_trojan.exe
echo "Este é um ficheiro Word limpo para documentação." > documento.docx
echo "Planilha Excel com dados normais." > planilha.xlsx
echo "BACKDOOR ROOTKIT SPYWARE CRYPTOLOCKER EMOTET - ALTAMENTE INFECTADO!" > malware_critico.exe
echo "Arquivo potencialmente suspeito para análise de segurança." > arquivo_suspeito.txt
echo "#!/bin/bash\necho 'Script legítimo de teste'" > script_legitimo.sh
echo "Conteúdo PDF suspeito com payload potencial." > documento_suspeito.pdf

python3 << END
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import os
import time

def send_test_emails():
    try:
        smtp_server = "smtp.gmail.com"
        smtp_port = 587

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login("$EMAIL_USER", "$EMAIL_PASS")

        test_emails = [
            {
                "to": "$EMAIL_USER",
                "subject": "Relatório mensal - Seguro",
                "body": "Segue em anexo o relatório mensal do departamento. Documento totalmente seguro.",
                "attachment": "relatorio.pdf"
            },
            {
                "to": "$EMAIL_USER",
                "subject": "Documento importante - Sem problemas",
                "body": "Este email contém um documento seguro para documentação.",
                "attachment": "documento_seguro.txt"
            },
            {
                "to": "$EMAIL_USER",
                "subject": "Planilha de dados - Segura",
                "body": "Segue em anexo a planilha com dados normais para análise.",
                "attachment": "planilha.xlsx"
            },
            {
                "to": "$EMAIL_USER",
                "subject": "Script de teste - Legítimo",
                "body": "Aqui está o script de teste para operações do sistema.",
                "attachment": "script_legitimo.sh"
            },
            
            {
                "to": "$EMAIL_USER",
                "subject": "ALERTA: Ficheiro suspeito anexado",
                "body": "Cuidado! Este ficheiro pode ser malicioso. Requires further analysis.",
                "attachment": "suspeito.exe.txt"
            },
            {
                "to": "$EMAIL_USER",
                "subject": "Documento Word - Verificar",
                "body": "Este ficheiro Word precisa de verificação de segurança.",
                "attachment": "documento.docx"
            },
            {
                "to": "$EMAIL_USER",
                "subject": "Arquivo compactado suspeito",
                "body": "Arquivo suspeito recebido. Requer análise e verificação.",
                "attachment": "arquivo_suspeito.txt"
            },
            {
                "to": "$EMAIL_USER",
                "subject": "PDF com conteúdo questionável",
                "body": "Este PDF contém conteúdo potencialmente suspeito.",
                "attachment": "documento_suspeito.pdf"
            },
            
            {
                "to": "$EMAIL_USER",
                "subject": "URGENTE: Vírus detectado - QUARENTENA IMEDIATA",
                "body": "PERIGO! Este anexo contém malware, trojan e vírus detectados. NÃO ABRIR!",
                "attachment": "virus_malware_trojan.exe"
            },
            {
                "to": "$EMAIL_USER",
                "subject": "ALERTA CRÍTICO: Ficheiro altamente infectado",
                "body": "Este ficheiro é altamente perigoso. Contém backdoor, rootkit e spyware. ISOLADO IMEDIATAMENTE!",
                "attachment": "malware_critico.exe"
            }
        ]

        print(f"Total de {len(test_emails)} emails de teste a enviar...")
        print("-" * 50)

        for i, test_email in enumerate(test_emails, 1):
            msg = MIMEMultipart()
            msg['From'] = "$EMAIL_USER"
            msg['To'] = test_email["to"]
            msg['Subject'] = test_email["subject"]

            msg.attach(MIMEText(test_email["body"], 'plain'))

            if os.path.exists(test_email["attachment"]):
                with open(test_email["attachment"], 'rb') as attachment:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment.read())
                    encoders.encode_base64(part)
                    part.add_header('Content-Disposition',
                                  f'attachment; filename="{test_email["attachment"]}"')
                    msg.attach(part)

            server.send_message(msg)
            print(f"[{i}/{len(test_emails)}] Email enviado: {test_email['subject']}")

            time.sleep(2)
        print("-" * 50)
        print(f"\nSucesso! {len(test_emails)} emails de teste foram enviados!")
        print("\nProximos passos:")
        print("1. Aguarde 2-3 minutos para os emails chegarem")
        print("2. Execute: ./calma.sh")
        print("3. O sistema vai processar os emails e classificar os anexos")
        print("4. Verifique os resultados em:")
        print("   - limpos/       (ficheiros seguros)")
        print("   - suspeitos/    (ficheiros com risco médio)")
        print("   - infetados/    (ficheiros perigosos)")
        print("   - quarentena/   (ficheiros neutralizados)")

    except Exception as e:
        print(f"ERRO: {e}")

send_test_emails()
END

echo ""
echo "Limpando ficheiros de teste temporários..."
rm -f documento_seguro.txt suspeito.exe.txt relatorio.pdf virus_malware_trojan.exe
rm -f documento.docx planilha.xlsx malware_critico.exe arquivo_suspeito.txt
rm -f script_legitimo.sh documento_suspeito.pdf

echo ""
echo "=================================================="
echo "Script concluído!"
echo ""
echo "Proximos passos:"
echo "1. Aguarde 2-3 minutos para os emails chegarem à caixa de entrada"
echo "2. Execute: ./calma.sh"
echo "3. O sistema vai processar os emails e classificar os anexos"
