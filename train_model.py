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
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split

from feature_extraction import extract_features, features_to_array, get_feature_names

try:
    from xgboost import XGBClassifier
except ImportError as exc:
    raise ImportError(
        "xgboost is required for model comparison. Install dependencies from requirements.txt."
    ) from exc

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

    for index, row in df.iterrows():
        if index % 1000 == 0:
            print(f"  Processed {index}/{len(df)} URLs...")

        url = str(row['url'])
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

    print(f"\nFeature matrix shape: {X.shape}")
    return X, y, feature_names, csv_file


def get_model_specs():
    return {
        'RandomForest': RandomForestClassifier(
            n_estimators=200,
            max_depth=24,
            min_samples_split=4,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced',
        ),
        'XGBoost': XGBClassifier(
            n_estimators=250,
            max_depth=8,
            learning_rate=0.08,
            subsample=0.9,
            colsample_bytree=0.9,
            objective='binary:logistic',
            eval_metric='logloss',
            random_state=42,
            n_jobs=-1,
        ),
    }


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
