import os
import sys
import hashlib
import struct
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass


                                                                               
                                
                                                                               

@dataclass
class Signal:
    id: str
    name: str
    weight: float                          
    max_points: int                                        
    description: str


SIGNALS = {
    "S1_EXTENSION": Signal(
        id="S1",
        name="Extensão Crítica",
        weight=12.0,                    
        max_points=3,
        description="Extensão executável ou de script crítica"
    ),
    "S2_MIME_MISMATCH": Signal(
        id="S2",
        name="MIME Mismatch",
        weight=15.0,                                               
        max_points=3,
        description="Assinatura real (magic bytes) não corresponde extensão"
    ),
    "S3_ENTROPY": Signal(
        id="S3",
        name="Entropia Alta",
        weight=5.0,                                                 
        max_points=3,
        description="Dados comprimidos/criptografados/ofuscados"
    ),
    "S4_STRINGS": Signal(
        id="S4",
        name="Strings Suspeitas",
        weight=12.0,                     
        max_points=3,
        description="APIs maliciosas ou padrões conhecidos de malware"
    ),
    "S5_SIZE": Signal(
        id="S5",
        name="Tamanho Anómalo",
        weight=3.0,                   
        max_points=2,
        description="Ficheiro muito grande/pequeno para seu tipo"
    ),
    "S6_DOUBLE_EXT": Signal(
        id="S6",
        name="Duplicação de Extensão",
        weight=8.0,                                     
        max_points=2,
        description="Múltiplas extensões (ex: arquivo.txt.exe)"
    ),
    "S7_ARCHIVE": Signal(
        id="S7",
        name="Arquivo Suspeito",
        weight=7.0,                   
        max_points=2,
        description="Arquivo comprimido contendo executáveis ou estrutura suspeita"
    ),
    "S8_DECEPTIVE_NAME": Signal(
        id="S8",
        name="Nome Enganador",
        weight=2.0,
        max_points=1,
        description="Nome sugere tipo diferente do conteúdo"
    ),
}

                          
TOTAL_MAX_SCORE = sum(s.weight * s.max_points for s in SIGNALS.values())


                                                                               
                                  
                                                                               

CRITICAL_EXTENSIONS = {
    'exe', 'bat', 'cmd', 'ps1', 'dll', 'scr', 'vbs', 'com', 'pif', 'msi',
    'wsf', 'vbe', 'jse', 'lnk'
}

HIGH_RISK_EXTENSIONS = {
    'js', 'jar', 'hta', 'jse', 'wsh', 'app', 'apk', 'dex', 'sh', 'bash'
}

ARCHIVE_EXTENSIONS = {'zip', 'rar', '7z', 'iso', 'img', 'tar', 'gz', 'bz2'}

COMMON_EXTENSIONS = {
    'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'mp3', 'mp4', 'avi', 'mkv'
}


                                                       
MAGIC_SIGNATURES = {
    b'MZ': ('application/x-msdownload', {'exe', 'dll', 'scr', 'sys', 'com'}),
    b'PK\x03\x04': ('application/zip', {'zip'}),
    b'Rar': ('application/x-rar', {'rar'}),
    b'7z\xBC\xAF\x27\x1C': ('application/x-7z-compressed', {'7z'}),
    b'%PDF': ('application/pdf', {'pdf'}),
    b'\xff\xd8\xff': ('image/jpeg', {'jpg', 'jpeg'}),
    b'\x89PNG': ('image/png', {'png'}),
    b'GIF8': ('image/gif', {'gif'}),
    b'BM': ('image/bmp', {'bmp'}),
    b'ID3': ('audio/mpeg', {'mp3'}),
    b'\xff\xfb': ('audio/mpeg', {'mp3'}),
    b'\xff\xf3': ('audio/mpeg', {'mp3'}),
    b'\x1a\x45\xdf\xa3': ('video/x-matroska', {'mkv'}),
}


                                                                               
                   
                                                                               

def get_file_extension(filepath: str) -> str:
    return Path(filepath).suffix.lstrip('.').lower()


def get_all_extensions(filepath: str) -> List[str]:
    name = Path(filepath).name
    parts = name.split('.')
    return [p.lower() for p in parts[1:] if p]


def detect_magic_bytes(filepath: str) -> Tuple[str, str]:
    try:
        with open(filepath, 'rb') as f:
            header = f.read(512)
        
        for magic, (mime, _) in MAGIC_SIGNATURES.items():
            if header.startswith(magic):
                return mime, magic.hex()
        
        return 'application/octet-stream', 'unknown'
    except Exception as e:
        return 'error', str(e)


def calculate_entropy(filepath: str, max_bytes: int = 8192) -> float:
    try:
        with open(filepath, 'rb') as f:
            data = f.read(max_bytes)
        
        if not data:
            return 0.0
        
                                        
        byte_freqs = [0] * 256
        for byte in data:
            byte_freqs[byte] += 1
        
                           
        entropy = 0.0
        for freq in byte_freqs:
            if freq > 0:
                p = freq / len(data)
                entropy -= p * (p.bit_length() - 1)                         
        
                               
        import math
        entropy = 0.0
        for freq in byte_freqs:
            if freq > 0:
                p = freq / len(data)
                entropy -= p * math.log2(p)
        
        return min(entropy, 8.0)
    except Exception:
        return 0.0


def extract_strings(filepath: str, min_length: int = 4, max_bytes: int = 1024 * 1024) -> List[str]:
    strings = []
    try:
        with open(filepath, 'rb') as f:
            data = f.read(max_bytes)
        
        current_string = bytearray()
        for byte in data:
            if 32 <= byte <= 126:                    
                current_string.append(byte)
            else:
                if len(current_string) >= min_length:
                    try:
                        strings.append(current_string.decode('ascii'))
                    except UnicodeDecodeError:
                        pass
                current_string = bytearray()
        
        if len(current_string) >= min_length:
            strings.append(current_string.decode('ascii'))
    except Exception:
        pass
    
    return strings


MALWARE_PATTERNS = {
    'critical': [
        'WinExec', 'ShellExecute', 'CreateProcessA', 'CreateProcessW',
        'GetProcAddress', 'LoadLibraryA', 'LoadLibraryW', 'VirtualAlloc',
        'SetWindowsHookEx', 'SetWinEventHook', 'InternetOpenA', 'HttpSendRequest',
        'cmd.exe', 'powershell.exe', 'bash', '/bin/sh',
    ],
    'suspicious': [
        'CreateRemoteThread', 'WriteProcessMemory', 'ReadProcessMemory',
        'VirtualProtect', 'SetFilePointer', 'CreateNamedPipe',
        'registry', 'HKLM', 'HKCU', 'System32', 'Sysnative',
        'mutex', 'ZwCreateKey', 'RegOpenKey',
    ]
}


def signal_1_extension(filepath: str) -> int:
    ext = get_file_extension(filepath)
    
                                                             
                                             
    
                                                                          
                                              
    safe_text_formats = {'txt', 'log', 'csv', 'md', 'json', 'xml', 'html', 'css'}
    
    if ext in safe_text_formats:
        return 0                                 
    elif ext in CRITICAL_EXTENSIONS:
        return 3
    elif ext in HIGH_RISK_EXTENSIONS:
        return 2
    elif ext in ARCHIVE_EXTENSIONS:
        return 1
    else:
        return 0


def signal_2_mime_mismatch(filepath: str) -> int:
    mime, _ = detect_magic_bytes(filepath)
    ext = get_file_extension(filepath)
    
                               
    if mime == 'application/x-msdownload' and ext not in {'exe', 'dll', 'scr', 'com', 'sys'}:
        return 3                         
    
    if mime == 'application/x-rar' and ext != 'rar':
        return 2
    
    if mime == 'application/zip' and ext != 'zip':
        return 2
    
    if mime == 'application/pdf' and ext != 'pdf':
        return 2
    
    if mime in ['image/jpeg', 'image/png', 'image/gif'] and ext not in ['jpg', 'jpeg', 'png', 'gif']:
        return 1
    
    return 0


def signal_3_entropy(filepath: str) -> int:
    entropy = calculate_entropy(filepath)
    ext = get_file_extension(filepath)
    
                                                                        
                                                     
    exempt_formats = {'pdf', 'docx', 'xlsx', 'pptx', 'zip', 'rar', '7z', 'png', 'jpg', 'jpeg'}
    
    if ext in exempt_formats:
                                                                              
        if entropy > 7.8:
            return 2                                               
        elif entropy > 7.2:
            return 1
        else:
            return 0
    else:
                                                 
        if entropy > 7.5:
            return 3                                      
        elif entropy > 6.8:
            return 2                            
        elif entropy > 6.0:
            return 1                     
        else:
            return 0


def signal_4_strings(filepath: str) -> int:
    ext = get_file_extension(filepath)
    
                                                                          
                                                
    safe_text_formats = {'txt', 'log', 'csv', 'md', 'json', 'xml', 'html', 'css'}
    if ext in safe_text_formats:
        return 0                                                             
    
    strings = extract_strings(filepath)
    strings_lower = [s.lower() for s in strings]
    
    critical_count = sum(
        1 for s in strings_lower 
        if any(pattern.lower() in s for pattern in MALWARE_PATTERNS['critical'])
    )
    
    suspicious_count = sum(
        1 for s in strings_lower 
        if any(pattern.lower() in s for pattern in MALWARE_PATTERNS['suspicious'])
    )
    
    score = min(3, critical_count * 2 + suspicious_count // 2)
    return score


def signal_5_size_anomaly(filepath: str) -> int:
    try:
        size = os.path.getsize(filepath)
        ext = get_file_extension(filepath)
        
        if size == 0:
            return 2                             
        
        if size > 500 * 1024 * 1024:           
            return 1
        
                                                           
        if ext in {'txt', 'log', 'csv', 'xml', 'json'} and size > 100 * 1024 * 1024:
            return 2
        
                                                
        if ext in {'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'} and size > 50 * 1024 * 1024:
            return 2
        
        return 0
    except Exception:
        return 0


def signal_6_double_extension(filepath: str) -> int:
    extensions = get_all_extensions(filepath)
    
    if len(extensions) < 2:
        return 0
    
                                             
    last_ext = extensions[-1]
    if last_ext in CRITICAL_EXTENSIONS:
        return 2                                
    elif last_ext in HIGH_RISK_EXTENSIONS:
        return 2
    elif len(extensions) > 2:
        return 1                                           
    
    return 0


def signal_7_archive_content(filepath: str) -> int:
    ext = get_file_extension(filepath)
    
    if ext not in ARCHIVE_EXTENSIONS:
        return 0
    
    try:
                                                    
        if ext == 'zip':
            import zipfile
            try:
                with zipfile.ZipFile(filepath, 'r') as zf:
                    for name in zf.namelist():
                        file_ext = Path(name).suffix.lstrip('.').lower()
                        if file_ext in CRITICAL_EXTENSIONS or file_ext in HIGH_RISK_EXTENSIONS:
                            return 3
                        if name.count('/') > 2:                        
                            return 2
                    return 0
            except zipfile.BadZipFile:
                return 2                                 
        
        elif ext == 'rar':
                                               
            return 1
        
        return 0
    except Exception:
        return 2                               


def signal_8_deceptive_name(filepath: str) -> int:
    mime, _ = detect_magic_bytes(filepath)
    ext = get_file_extension(filepath)
    name = Path(filepath).name.lower()
    
                                                     
    if mime == 'application/x-msdownload':
        if any(word in name for word in ['document', 'relatório', 'report', 'spreadsheet', 'planilha']):
            return 1
    
    return 0


                                                                               
                        
                                                                               

@dataclass
class RiskAssessment:
    filepath: str
    filename: str
    score: int
    classification: str
    signals: Dict[str, Tuple[int, float, str]]                                              
    explanation: str
    raw_score: float


def assess_risk(filepath: str) -> RiskAssessment:
    
    if not os.path.exists(filepath):
        return RiskAssessment(
            filepath=filepath,
            filename=Path(filepath).name,
            score=0,
            classification="ERROR",
            signals={},
            explanation="Ficheiro não encontrado",
            raw_score=0.0
        )
    
                              
    signal_values = {
        'S1': signal_1_extension(filepath),
        'S2': signal_2_mime_mismatch(filepath),
        'S3': signal_3_entropy(filepath),
        'S4': signal_4_strings(filepath),
        'S5': signal_5_size_anomaly(filepath),
        'S6': signal_6_double_extension(filepath),
        'S7': signal_7_archive_content(filepath),
        'S8': signal_8_deceptive_name(filepath),
    }
    
                              
    raw_score = 0.0
    signals_detail = {}
    
    for signal_key, signal_obj in SIGNALS.items():
        signal_id = signal_obj.id
        points = signal_values[signal_id]
        weighted = signal_obj.weight * points
        raw_score += weighted
        
        signals_detail[signal_id] = (
            points,
            signal_obj.weight,
            f"{signal_obj.name}: {points}/{signal_obj.max_points} → +{weighted:.1f} pts"
        )
    
                           
    normalized_score = min(100, int(raw_score * 100 / TOTAL_MAX_SCORE))
    
                 
    if normalized_score < 10:
        classification = "LIMPO"
    elif normalized_score < 25:
        classification = "BAIXO_RISCO"
    elif normalized_score < 50:
        classification = "MÉDIO"
    elif normalized_score < 70:
        classification = "SUSPEITO"
    else:
        classification = "INFECTADO"
    
                      
    active_signals = [v[2] for v in signals_detail.values() if v[0] > 0]
    explanation = "Sinais ativados:\n  " + "\n  ".join(active_signals) if active_signals else "Nenhum sinal suspeito"
    
    return RiskAssessment(
        filepath=filepath,
        filename=Path(filepath).name,
        score=normalized_score,
        classification=classification,
        signals=signals_detail,
        explanation=explanation,
        raw_score=raw_score
    )


def format_report(assessment: RiskAssessment) -> str:
    report = f"""
╔════════════════════════════════════════════════════════════════╗
║          ANÁLISE DE RISCO - CALMA v2.0                         ║
╚════════════════════════════════════════════════════════════════╝

Ficheiro:        {assessment.filename}
Caminho:         {assessment.filepath}

Score Final:     {assessment.score}/100
Classificação:   {assessment.classification}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Detalhamento dos Sinais:
"""
    
    for signal_id, (points, weight, desc) in sorted(assessment.signals.items()):
        marker = "" if points > 0 else "·"
        report += f"  {marker} S{signal_id[-1]}: {desc}\n"
    
    report += f"\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    report += f"\nExplicação:\n{assessment.explanation}\n"
    report += f"\nScore bruto: {assessment.raw_score:.1f}\nNormalizado: {assessment.score}\n"
    
    return report


                                                                               
               
                                                                               

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Uso: score_risco.py <caminho_ficheiro>")
        print("      score_risco.py <caminho_ficheiro> --json")
        sys.exit(1)
    
    filepath = sys.argv[1]
    json_output = '--json' in sys.argv
    
    assessment = assess_risk(filepath)
    
    if json_output:
        import json
        result = {
            'filepath': assessment.filepath,
            'filename': assessment.filename,
            'score': assessment.score,
            'classification': assessment.classification,
            'signals': {
                k: {'points': v[0], 'weight': v[1]}
                for k, v in assessment.signals.items()
            }
        }
        print(json.dumps(result, indent=2))
    else:
        print(format_report(assessment))
    
                                         
    if assessment.classification == "INFECTADO":
        sys.exit(2)
    elif assessment.classification == "SUSPEITO":
        sys.exit(1)
    else:
        sys.exit(0)
