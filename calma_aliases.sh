alias calma='cd /home/samu/calma && ./calma.sh'

alias calma-web='cd /home/samu/calma && python3 scripts/utils/app.py'

alias calma-logs='cd /home/samu/calma && tail -f logs/execucao_*.log | tail -1'

alias calma-train='cd /home/samu/calma && source venv/bin/activate && python3 scripts/ml/modelo_logistica.py train --balanced'

echo " Atalhos CALMA carregados!"
echo ""
echo "Comandos disponíveis:"
echo "  calma         - Executar sistema principal"
echo "  calma-web     - Abrir interface web"
echo "  calma-logs    - Ver logs em tempo real"
echo "  calma-train   - Retreinar modelos ML"
