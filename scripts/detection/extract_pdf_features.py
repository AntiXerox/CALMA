import sys
import re
from pathlib import Path
from typing import Dict

try:
    import PyPDF2
except ImportError:
    print(" Erro: PyPDF2 não instalado")
    print("   Instale com: pip install PyPDF2")
    sys.exit(1)


def extract_pdf_features(file_path: str) -> Dict[str, any]:
    path = Path(file_path)
    
                      
    with open(file_path, 'rb') as f:
        raw_content = f.read()
    
    raw_text = raw_content.decode('latin-1', errors='ignore')
    
                    
    try:
        with open(file_path, 'rb') as f:
            pdf_reader = PyPDF2.PdfReader(f)
            num_pages = len(pdf_reader.pages)
            is_encrypted = pdf_reader.is_encrypted
            
                           
            contains_text = "No"
            for page in pdf_reader.pages:
                text = page.extract_text()
                if text and len(text.strip()) > 10:
                    contains_text = "Yes"
                    break
    except:
        num_pages = 0
        is_encrypted = False
        contains_text = "No"
    
                      
    features = {
        'name': path.stem,
        'pdf_size': len(raw_content) // 1024,      
        'metadata_size': len(raw_text[:500]),                       
        'pages': num_pages,
        'xref_length': raw_text.count('xref'),
        'title_characters': len(extract_title(raw_text)),
        'isEncrypted': 1.0 if is_encrypted else 0.0,
        'embedded_files': count_pattern(raw_text, r'/EmbeddedFile'),
        'images': count_images(raw_text),
        'contains_text': contains_text,
        'header': extract_header(raw_text),
    }
    
                               
    features['obj'] = count_pattern(raw_text, r'\bobj\b')
    features['endobj'] = count_pattern(raw_text, r'\bendobj\b')
    features['stream'] = count_pattern(raw_text, r'\bstream\b')
    features['endstream'] = count_pattern(raw_text, r'\bendstream\b')
    features['xref'] = count_pattern(raw_text, r'\bxref\b')
    features['trailer'] = count_pattern(raw_text, r'\btrailer\b')
    features['startxref'] = count_pattern(raw_text, r'\bstartxref\b')
    features['pageno'] = num_pages
    
                                 
    features['encrypt'] = count_pattern(raw_text, r'/Encrypt')
    features['ObjStm'] = count_pattern(raw_text, r'/ObjStm')
    features['JS'] = count_pattern(raw_text, r'/JS\b')
    features['Javascript'] = count_pattern(raw_text, r'/JavaScript')
    features['AA'] = count_pattern(raw_text, r'/AA\b')
    features['OpenAction'] = count_pattern(raw_text, r'/OpenAction')
    features['Acroform'] = count_pattern(raw_text, r'/AcroForm')
    features['JBIG2Decode'] = count_pattern(raw_text, r'/JBIG2Decode')
    features['RichMedia'] = count_pattern(raw_text, r'/RichMedia')
    features['launch'] = count_pattern(raw_text, r'/Launch')
    features['EmbeddedFile'] = count_pattern(raw_text, r'/EmbeddedFile')
    features['XFA'] = count_pattern(raw_text, r'/XFA')
    features['URI'] = count_pattern(raw_text, r'/URI')
    features['Colors'] = count_pattern(raw_text, r'/Colors')
    
                          
    features['class'] = 'Unknown'
    
    return features


def extract_header(text: str) -> str:
    match = re.search(r'%PDF-\d\.\d', text[:100])
    return match.group(0) if match else '%PDF-1.4'


def extract_title(text: str) -> str:

    match = re.search(r'/Title\s*\(([^)]+)\)', text[:2000])
    return match.group(1) if match else ''


def count_pattern(text: str, pattern: str) -> float:
    matches = re.findall(pattern, text, re.IGNORECASE)
    return float(len(matches))


def count_images(text: str) -> float:
    image_count = count_pattern(text, r'/Image')
    if image_count == 0:
        return -1.0                                        
    return image_count


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    file_path = sys.argv[1]
    output_json = '--json' in sys.argv
    
    if not Path(file_path).exists():
        print(f" Ficheiro não encontrado: {file_path}")
        sys.exit(1)
    
    try:
        features = extract_pdf_features(file_path)
        
        if output_json:
            import json
            print(json.dumps(features, indent=2))
        else:
            print(f"# Features extraídas de PDF: {len(features)}")
            print(f"Tipo: {features['header']}")
            print(f"Páginas: {features['pages']}")
            print(f"Tamanho: {features['pdf_size']} KB")
            print(f"Texto: {features['contains_text']}")
            print(f"\nSinais de malware:")
            print(f"  JavaScript: {features['Javascript']}")
            print(f"  JS: {features['JS']}")
            print(f"  OpenAction: {features['OpenAction']}")
            print(f"  URI: {features['URI']}")
            print(f"  EmbeddedFile: {features['EmbeddedFile']}")
            print(f"  AA: {features['AA']}")
            
    except Exception as e:
        print(f" Erro: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
