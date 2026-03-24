import sys
import json
import pickle
import warnings
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    precision_recall_curve, roc_curve, accuracy_score
)

warnings.filterwarnings('ignore')

                                                        
DATASET_PATH = Path(__file__).parent / "Data/dataset_malwares.csv"
DATASET_BALANCED_PATH = Path(__file__).parent / "Data/dataset_malwares_balanced.csv"
MODEL_PATH = Path(__file__).parent / "Data/modelo_malware.pkl"
SCALER_PATH = Path(__file__).parent / "Data/scaler_malware.pkl"
STATS_PATH = Path(__file__).parent / "Data/modelo_stats.json"

                                                     
RANDOM_STATE = 42
TEST_SIZE = 0.25
CV_FOLDS = 5

                                     
                                                                                             
                                                                  
                                         
                                                
LR_PARAMS = {
    'C': 0.5,
    'class_weight': None,                                  
    'solver': 'lbfgs',
    'max_iter': 1000,
    'random_state': RANDOM_STATE
}


                                                   
@dataclass
class ModelMetrics:
    accuracy: float
    precision_clean: float
    precision_malware: float
    recall_clean: float
    recall_malware: float
    f1_clean: float
    f1_malware: float
    roc_auc: float
    confusion_matrix: List[List[int]]
    cv_scores: List[float]
    cv_mean: float
    cv_std: float
    
    def __str__(self):
        return f"""
╔══════════════════════════════════════════════════════════╗
║           MÉTRICAS DO MODELO - REGRESSÃO LOGÍSTICA       ║
╠══════════════════════════════════════════════════════════╣
║ Dataset: 19612 amostras (26% limpo, 74% malware)         ║
║ Test Set: {int(len(self.confusion_matrix[0])*4/3)} amostras ({TEST_SIZE*100:.0f}% holdout)                       ║
╠══════════════════════════════════════════════════════════╣
║ ACCURACY GERAL:          {self.accuracy:6.2%}                          ║
║ ROC-AUC Score:           {self.roc_auc:6.2%}                          ║
╠══════════════════════════════════════════════════════════╣
║ CLASSE: LIMPO (0)                                        ║
║   Precision:             {self.precision_clean:6.2%}                          ║
║   Recall:                {self.recall_clean:6.2%}                          ║
║   F1-Score:              {self.f1_clean:6.2%}                          ║
╠══════════════════════════════════════════════════════════╣
║ CLASSE: MALWARE (1)                                      ║
║   Precision:             {self.precision_malware:6.2%}                          ║
║   Recall:                {self.recall_malware:6.2%}                          ║
║   F1-Score:              {self.f1_malware:6.2%}                          ║
╠══════════════════════════════════════════════════════════╣
║ CONFUSION MATRIX                                         ║
║                    Predicted                             ║
║              Limpo(0)   Malware(1)                       ║
║   Limpo(0)   {self.confusion_matrix[0][0]:5}      {self.confusion_matrix[0][1]:5}                            ║
║ Malware(1)   {self.confusion_matrix[1][0]:5}      {self.confusion_matrix[1][1]:5}                            ║
╠══════════════════════════════════════════════════════════╣
║ VALIDAÇÃO CRUZADA (5-Fold Stratified)                    ║
║   Mean Accuracy:         {self.cv_mean:6.2%} ± {self.cv_std:5.2%}                  ║
║   Scores: {' | '.join(f'{s:.2%}' for s in self.cv_scores)}     ║
╚══════════════════════════════════════════════════════════╝
"""


@dataclass
class PredictionResult:
    file_path: str
    prediction: int                      
    probability_clean: float
    probability_malware: float
    confidence: float                      
    risk_level: str                                      
    
    def __str__(self):
        emoji = "" if self.prediction == 0 else "️"
        label = "LIMPO" if self.prediction == 0 else "MALWARE"
        
        return f"""
{emoji} CLASSIFICAÇÃO: {label}
Ficheiro: {self.file_path}
Probabilidades:
  - Limpo:   {self.probability_clean:6.2%}
  - Malware: {self.probability_malware:6.2%}
Confiança: {self.confidence:6.2%}
Nível de Risco: {self.risk_level}
"""


                                                              
def load_dataset(csv_path: Path = None, use_balanced: bool = True) -> Tuple[pd.DataFrame, pd.Series]:
                               
    if csv_path is None:
        if use_balanced and DATASET_BALANCED_PATH.exists():
            csv_path = DATASET_BALANCED_PATH
            print(f"[1/7] Carregando dataset BALANCEADO: {csv_path}")
        else:
            csv_path = DATASET_PATH
            print(f"[1/7] Carregando dataset ORIGINAL: {csv_path}")
    else:
        print(f"[1/7] Carregando dataset: {csv_path}")
    
    df = pd.read_csv(csv_path)
    
    print(f"      → {len(df)} amostras, {len(df.columns)} colunas")
    print(f"      → Distribuição: {(df['Malware']==0).sum()} limpos ({(df['Malware']==0).sum()/len(df)*100:.1f}%), {(df['Malware']==1).sum()} malware ({(df['Malware']==1).sum()/len(df)*100:.1f}%)")
    
                                       
    X = df.drop(columns=['Name', 'Malware'])                                
    y = df['Malware']
    
                                      
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(X.median())
    
    print(f"      → Features selecionadas: {len(X.columns)}")
    return X, y


def train_model(X: pd.DataFrame, y: pd.Series) -> Tuple[LogisticRegression, StandardScaler, ModelMetrics]:
    print("\n[2/7] Dividindo dataset (75% treino, 25% teste)")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"      → Treino: {len(X_train)} | Teste: {len(X_test)}")
    
                                     
    print("\n[3/7] Normalizando features (StandardScaler)")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    print(f"      → Mean: {scaler.mean_[:3]} ... | Std: {scaler.scale_[:3]} ...")
    
            
    print("\n[4/7] Treinando Regressão Logística")
    print(f"      Params: C={LR_PARAMS['C']}, class_weight={LR_PARAMS['class_weight']}")
    model = LogisticRegression(**LR_PARAMS)
    model.fit(X_train_scaled, y_train)
    print(f"      → Convergência: {model.n_iter_[0]} iterações")
    
                       
    print("\n[5/7] Validação cruzada (5-Fold Stratified)")
    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=cv, scoring='accuracy')
    print(f"      → Scores: {' | '.join(f'{s:.2%}' for s in cv_scores)}")
    print(f"      → Mean: {cv_scores.mean():.2%} ± {cv_scores.std():.2%}")
    
                     
    print("\n[6/7] Avaliação no conjunto de teste")
    y_pred = model.predict(X_test_scaled)
    y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
    
              
    acc = accuracy_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_pred_proba)
    cm = confusion_matrix(y_test, y_pred).tolist()
    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    
    metrics = ModelMetrics(
        accuracy=acc,
        precision_clean=report['0']['precision'],
        precision_malware=report['1']['precision'],
        recall_clean=report['0']['recall'],
        recall_malware=report['1']['recall'],
        f1_clean=report['0']['f1-score'],
        f1_malware=report['1']['f1-score'],
        roc_auc=roc_auc,
        confusion_matrix=cm,
        cv_scores=cv_scores.tolist(),
        cv_mean=cv_scores.mean(),
        cv_std=cv_scores.std()
    )
    
    print(f"      → Accuracy: {acc:.2%}")
    print(f"      → ROC-AUC: {roc_auc:.2%}")
    
    return model, scaler, metrics


def save_model(model: LogisticRegression, scaler: StandardScaler, metrics: ModelMetrics):
    print("\n[7/7] Salvando modelo")
    
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    print(f"      → Modelo: {MODEL_PATH}")
    
    with open(SCALER_PATH, 'wb') as f:
        pickle.dump(scaler, f)
    print(f"      → Scaler: {SCALER_PATH}")
    
    with open(STATS_PATH, 'w') as f:
        json.dump(asdict(metrics), f, indent=2)
    print(f"      → Stats: {STATS_PATH}")


def load_model() -> Tuple[LogisticRegression, StandardScaler]:
    if not MODEL_PATH.exists() or not SCALER_PATH.exists():
        raise FileNotFoundError(
            "Modelo não encontrado! Execute primeiro:\n"
            "  python3 modelo_logistica.py train"
        )
    
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    
    with open(SCALER_PATH, 'rb') as f:
        scaler = pickle.load(f)
    
    return model, scaler


def predict_file(file_path: str) -> PredictionResult:
    model, scaler = load_model()
    
                                                           
                                                                       
    raise NotImplementedError(
        "Feature extraction não implementada.\n"
        "Use dataset_malwares.csv para demonstração ou integre com pefile/LIEF"
    )


def calculate_risk_level(prob_malware: float) -> str:
    if prob_malware < 0.10:
        return "LIMPO"
    elif prob_malware < 0.30:
        return "BAIXO"
    elif prob_malware < 0.60:
        return "MÉDIO"
    elif prob_malware < 0.85:
        return "ALTO"
    else:
        return "CRÍTICO"


def show_stats():
    if not STATS_PATH.exists():
        print(" Estatísticas não encontradas. Treine o modelo primeiro.")
        return
    
    with open(STATS_PATH) as f:
        data = json.load(f)
    
    metrics = ModelMetrics(**data)
    print(metrics)


def show_feature_importance(top_n: int = 20):
    model, scaler = load_model()
    
                                
    df = pd.read_csv(DATASET_PATH)
    feature_names = df.drop(columns=['Name', 'Malware']).columns
    
                                
    coefs = model.coef_[0]
    importance = pd.DataFrame({
        'Feature': feature_names,
        'Coeficiente': coefs,
        'Abs_Coef': np.abs(coefs)
    }).sort_values('Abs_Coef', ascending=False)
    
    print(f"\n{'='*70}")
    print(f"TOP {top_n} FEATURES MAIS IMPORTANTES (|coeficiente|)")
    print(f"{'='*70}")
    print(importance.head(top_n).to_string(index=False))
    print(f"{'='*70}\n")


                                               
def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    if command == 'train':
        print("╔══════════════════════════════════════════════════════════╗")
        print("║      TREINO: MODELO DE REGRESSÃO LOGÍSTICA               ║")
        print("╚══════════════════════════════════════════════════════════╝\n")
        
                                                   
        use_balanced = '--balanced' in sys.argv or DATASET_BALANCED_PATH.exists()
        
        X, y = load_dataset(use_balanced=use_balanced)
        model, scaler, metrics = train_model(X, y)
        save_model(model, scaler, metrics)
        
        print("\n" + "="*70)
        print(" TREINO COMPLETO!")
        print("="*70)
        print(metrics)
        
    elif command == 'stats':
        show_stats()
        
    elif command == 'importance':
        top_n = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        show_feature_importance(top_n)
        
    elif command == 'predict':
        if len(sys.argv) < 3:
            print(" Uso: python3 modelo_logistica.py predict <ficheiro>")
            sys.exit(1)
        
        result = predict_file(sys.argv[2])
        print(result)
        
    else:
        print(f" Comando desconhecido: {command}")
        print("\nComandos disponíveis:")
        print("  train          Treina modelo com dataset_malwares.csv")
        print("  stats          Mostra métricas do modelo")
        print("  importance [N] Mostra top N features importantes")
        print("  predict FILE   Classifica ficheiro (requer features PE)")
        sys.exit(1)


if __name__ == '__main__':
    main()
