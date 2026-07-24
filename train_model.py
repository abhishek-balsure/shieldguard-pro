"""
Train and compare phishing detection models.

Expected dataset format:
- Required columns: url, label
- Optional precomputed feature columns: any names returned by get_feature_names()

If precomputed columns exist, they override live feature extraction for those
specific features. That keeps training practical for expanded datasets that
already include external rank and page-content signals.
"""

import json
import os
import pickle
import time
from datetime import datetime

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.base import clone
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split, RandomizedSearchCV
from sklearn.ensemble import GradientBoostingClassifier

from feature_extraction import extract_features, features_to_array, get_feature_names

try:
    from imblearn.over_sampling import SMOTE
    SMOTE_AVAILABLE = True
except ImportError:
    SMOTE_AVAILABLE = False

try:
    from xgboost import XGBClassifier
except ImportError as exc:
    raise ImportError(
        "xgboost is required for model comparison. Install dependencies from requirements.txt."
    ) from exc

ENABLE_TUNING = os.environ.get('ENABLE_HYPERPARAM_TUNING', 'false').lower() in {'1', 'true', 'yes'}
DATASET_FILE = os.environ.get('PHISHING_DATASET', 'phishing_data.csv')
MODEL_OUTPUT = os.environ.get('PHISHING_MODEL_OUTPUT', 'phishing_model.pkl')


def prepare_data(csv_file=DATASET_FILE):
    if not os.path.exists(csv_file):
        raise FileNotFoundError(
            f"Training dataset not found: {csv_file}. "
            "Add a CSV with 'url' and 'label' columns before retraining."
        )

    print(f"Loading data from {csv_file}...")
    df = pd.read_csv(csv_file)
    required_columns = {'url', 'label'}
    missing = required_columns - set(df.columns)
    if missing:
        raise ValueError(f"Dataset is missing required columns: {sorted(missing)}")

    feature_names = get_feature_names()
    print(f"Total samples: {len(df)}")
    print("Label distribution:")
    print(df['label'].value_counts())
    print(f"\nExtracting {len(feature_names)} features...")

    features_list = []
    labels = []
    available_feature_columns = set(feature_names).intersection(df.columns)

    start_extraction_time = time.time()
    for index, row in df.iterrows():
        if index % 1000 == 0:
            percent = (index / len(df)) * 100
            print(f"  Processed {index}/{len(df)} URLs ({percent:.1f}%)...")

        url = row['url']
        if pd.isna(url) or not str(url).strip():
            continue
            
        url = str(url)
        label = str(row['label']).strip().lower()
        features_dict = extract_features(url)

        for feature_name in available_feature_columns:
            value = row.get(feature_name)
            if pd.notna(value):
                features_dict[feature_name] = value

        features_list.append(features_to_array(features_dict, feature_names))
        labels.append(1 if label == 'phishing' else 0)

    X = np.array(features_list, dtype=float)
    y = np.array(labels, dtype=int)

    extraction_time = time.time() - start_extraction_time
    print(f"\nFeature extraction completed in {extraction_time:.2f} seconds.")
    print(f"Final Class Distribution:\n  Class 0 (Legitimate): {sum(y == 0)}\n  Class 1 (Phishing): {sum(y == 1)}")
    print(f"Feature matrix shape: {X.shape}")
    return X, y, feature_names, csv_file


def get_model_specs():
    specs = {
        'RandomForest': RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            min_samples_split=3,
            min_samples_leaf=1,
            max_features='sqrt',
            random_state=42,
            n_jobs=-1,
            class_weight='balanced',
        ),
        'XGBoost': XGBClassifier(
            n_estimators=500,
            max_depth=8,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_alpha=0.1,
            reg_lambda=1.0,
            objective='binary:logistic',
            eval_metric='logloss',
            random_state=42,
            n_jobs=-1,
        ),
        'GradientBoosting': GradientBoostingClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.05,
            subsample=0.8,
            min_samples_split=4,
            min_samples_leaf=2,
            random_state=42,
        ),
    }
    
    try:
        from lightgbm import LGBMClassifier
        specs['LightGBM'] = LGBMClassifier(
            n_estimators=500,
            max_depth=8,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_alpha=0.1,
            reg_lambda=1.0,
            random_state=42,
            n_jobs=-1,
            verbose=-1,
        )
    except ImportError:
        print("LightGBM not available, skipping...")
        
    return specs


def evaluate_single_model(model_name, estimator, X_train, X_test, y_train, y_test, X_all, y_all):
    print("\n" + "=" * 80)
    print(f"Training {model_name}")
    print("=" * 80)

    start_time = time.time()
    estimator.fit(X_train, y_train)
    training_time = time.time() - start_time

    y_pred = estimator.predict(X_test)
    y_pred_proba = estimator.predict_proba(X_test)[:, 1]

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    auc = roc_auc_score(y_test, y_pred_proba)

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scoring = {
        'accuracy': 'accuracy',
        'precision': 'precision',
        'recall': 'recall',
        'f1': 'f1',
        'roc_auc': 'roc_auc',
    }
    cv_result = cross_validate(clone(estimator), X_all, y_all, cv=cv, scoring=scoring, n_jobs=1)

    metrics = {
        'accuracy': round(float(accuracy), 6),
        'precision': round(float(precision), 6),
        'recall': round(float(recall), 6),
        'f1_score': round(float(f1), 6),
        'roc_auc': round(float(auc), 6),
        'training_time_seconds': round(float(training_time), 4),
        'cv_accuracy_mean': round(float(np.mean(cv_result['test_accuracy'])), 6),
        'cv_accuracy_std': round(float(np.std(cv_result['test_accuracy'])), 6),
        'cv_precision_mean': round(float(np.mean(cv_result['test_precision'])), 6),
        'cv_recall_mean': round(float(np.mean(cv_result['test_recall'])), 6),
        'cv_f1_mean': round(float(np.mean(cv_result['test_f1'])), 6),
        'cv_roc_auc_mean': round(float(np.mean(cv_result['test_roc_auc'])), 6),
    }

    print(f"Accuracy:  {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall:    {metrics['recall']:.4f}")
    print(f"F1-Score:  {metrics['f1_score']:.4f}")
    print(f"AUC-ROC:   {metrics['roc_auc']:.4f}")
    print(f"5-fold CV Accuracy: {metrics['cv_accuracy_mean']:.4f} (+/- {metrics['cv_accuracy_std']:.4f})")

    return {
        'estimator': estimator,
        'metrics': metrics,
        'y_pred': y_pred,
        'y_pred_proba': y_pred_proba,
        'classification_report': classification_report(
            y_test, y_pred, target_names=['Legitimate', 'Phishing'], zero_division=0
        ),
        'confusion_matrix': confusion_matrix(y_test, y_pred),
    }


def train_and_compare_models(X, y, feature_names):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    if SMOTE_AVAILABLE:
        smote = SMOTE(random_state=42)
        X_train, y_train = smote.fit_resample(X_train, y_train)
        print(f"After SMOTE - Training samples: {len(X_train)}")
        print(f"  Class 0: {sum(y_train == 0)}, Class 1: {sum(y_train == 1)}")
    else:
        print("SMOTE not available (install imbalanced-learn). Proceeding without oversampling.")
        print(f"Training samples: {len(X_train)}")
        
    print(f"Testing samples: {len(X_test)}")

    results = {}
    for model_name, estimator in get_model_specs().items():
        results[model_name] = evaluate_single_model(
            model_name, estimator, X_train, X_test, y_train, y_test, X, y
        )

    best_model_name = max(
        results,
        key=lambda name: (
            results[name]['metrics']['cv_f1_mean'],
            results[name]['metrics']['cv_accuracy_mean'],
        ),
    )

    best_estimator = clone(get_model_specs()[best_model_name])
    
    if ENABLE_TUNING:
        print(f"\nRunning hyperparameter tuning for {best_model_name}...")
        param_grid = {}
        if 'RandomForest' in best_model_name:
            param_grid = {'n_estimators': [200, 300, 400], 'max_depth': [None, 10, 20]}
        elif 'XGBoost' in best_model_name:
            param_grid = {'n_estimators': [300, 500], 'max_depth': [6, 8], 'learning_rate': [0.01, 0.05]}
        elif 'GradientBoosting' in best_model_name:
            param_grid = {'n_estimators': [200, 300], 'learning_rate': [0.05, 0.1]}
        elif 'LightGBM' in best_model_name:
            param_grid = {'n_estimators': [300, 500], 'learning_rate': [0.01, 0.05]}
            
        if param_grid:
            search = RandomizedSearchCV(best_estimator, param_distributions=param_grid, n_iter=3, cv=3, scoring='f1', random_state=42, n_jobs=-1)
            search.fit(X_train, y_train)
            best_estimator = search.best_estimator_
            print(f"Best params: {search.best_params_}")

    print(f"\nRetraining best model ({best_model_name}) on ALL data (train+test) before saving...")
    best_estimator.fit(X, y)

    if hasattr(best_estimator, 'feature_importances_'):
        importances = best_estimator.feature_importances_
        indices = np.argsort(importances)[::-1]
    else:
        importances = np.zeros(len(feature_names))
        indices = np.arange(len(feature_names))

    save_artifacts(results, best_model_name, feature_names, importances, indices)

    metadata = {
        'trained_at': datetime.utcnow().isoformat() + 'Z',
        'feature_names': feature_names,
        'feature_count': len(feature_names),
        'best_model_name': best_model_name,
        'comparison': {name: result['metrics'] for name, result in results.items()},
    }

    return best_estimator, metadata


def save_artifacts(results, best_model_name, feature_names, importances, indices):
    best_result = results[best_model_name]
    cm = best_result['confusion_matrix']

    plt.figure(figsize=(8, 6))
    sns.heatmap(
        cm,
        annot=True,
        fmt='d',
        cmap='Blues',
        xticklabels=['Legitimate', 'Phishing'],
        yticklabels=['Legitimate', 'Phishing'],
        cbar_kws={'label': 'Count'},
    )
    plt.title(f'Confusion Matrix - {best_model_name}', fontsize=14, fontweight='bold')
    plt.xlabel('Predicted Label', fontsize=12)
    plt.ylabel('True Label', fontsize=12)
    plt.tight_layout()
    plt.savefig('confusion_matrix.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("Confusion matrix saved to: confusion_matrix.png")

    plt.figure(figsize=(10, 6))
    top_n = min(15, len(feature_names))
    top_indices = indices[:top_n]
    top_features = [feature_names[i] for i in top_indices]
    top_importances = importances[top_indices]
    
    sns.barplot(x=top_importances, y=top_features, palette='viridis')
    plt.title(f'Top {top_n} Feature Importances - {best_model_name}', fontsize=14, fontweight='bold')
    plt.xlabel('Importance', fontsize=12)
    plt.ylabel('Feature', fontsize=12)
    plt.tight_layout()
    plt.savefig('feature_importances.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("Feature importances chart saved to: feature_importances.png")

    metrics_payload = {
        'best_model_name': best_model_name,
        'comparison': {name: result['metrics'] for name, result in results.items()},
        'feature_ranking': [
            {
                'feature': feature_names[indices[i]],
                'importance': round(float(importances[indices[i]]), 6),
            }
            for i in range(min(15, len(feature_names)))
        ],
        'reports': {name: result['classification_report'] for name, result in results.items()},
    }

    with open('model_metrics.json', 'w', encoding='utf-8') as metrics_file:
        json.dump(metrics_payload, metrics_file, indent=2)
    print("Model metrics saved to: model_metrics.json")

    lines = [
        "ShieldGuard Pro Model Comparison",
        "=" * 80,
        f"Best model: {best_model_name}",
        "",
    ]
    for name, result in results.items():
        lines.append(name)
        lines.append("-" * len(name))
        for metric_name, metric_value in result['metrics'].items():
            lines.append(f"{metric_name}: {metric_value}")
        lines.append("")
        lines.append(result['classification_report'])
        lines.append("")

    with open('model_metrics.txt', 'w', encoding='utf-8') as metrics_text:
        metrics_text.write("\n".join(lines))
    print("Model metrics saved to: model_metrics.txt")


def save_model(model, metadata, filename=MODEL_OUTPUT):
    bundle = {
        'model': model,
        'scaler': None,
        'metadata': metadata,
        'feature_names': metadata['feature_names'],
    }
    with open(filename, 'wb') as model_file:
        pickle.dump(bundle, model_file)
    print(f"\nBest model saved to: {filename}")


def main():
    print("=" * 80)
    print("ShieldGuard Pro Model Training")
    print("=" * 80)

    X, y, feature_names, dataset_file = prepare_data()
    best_model, metadata = train_and_compare_models(X, y, feature_names)
    metadata['dataset'] = {
        'csv_file': dataset_file,
        'sample_count': int(len(y)),
    }
    save_model(best_model, metadata)

    print("\nTraining complete.")
    print(f"Selected best model: {metadata['best_model_name']}")
    print(f"Feature count: {metadata['feature_count']}")


if __name__ == "__main__":
    main()
