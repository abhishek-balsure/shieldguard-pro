"""
Train Random Forest Classifier for Phishing Detection
Loads phishing_data.csv, extracts features, trains model, and saves it.
"""

import pandas as pd
import numpy as np
import pickle
import time
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score, 
                            f1_score, classification_report, confusion_matrix,
                            roc_auc_score, roc_curve)
from feature_extraction import extract_features, get_feature_names, features_to_array
import warnings
warnings.filterwarnings('ignore')


def prepare_data(csv_file='phishing_data.csv'):
    """
    Load data and extract features.
    
    Args:
        csv_file (str): Path to the CSV file
        
    Returns:
        tuple: X (features), y (labels), feature_names
    """
    print(f"Loading data from {csv_file}...")
    df = pd.read_csv(csv_file)
    
    print(f"Total samples: {len(df)}")
    print(f"Label distribution:")
    print(df['label'].value_counts())
    
    print("\nExtracting features...")
    features_list = []
    labels = []
    
    for idx, row in df.iterrows():
        if idx % 1000 == 0:
            print(f"  Processed {idx}/{len(df)} URLs...")
        
        url = str(row['url'])
        label = row['label']
        
        # Extract features
        features_dict = extract_features(url)
        features_array = features_to_array(features_dict)
        
        features_list.append(features_array)
        labels.append(1 if label == 'phishing' else 0)
    
    X = np.array(features_list)
    y = np.array(labels)
    feature_names = get_feature_names()
    
    print(f"\nFeature matrix shape: {X.shape}")
    return X, y, feature_names


def train_model(X, y, feature_names):
    """
    Train Random Forest classifier.
    
    Args:
        X (np.array): Feature matrix
        y (np.array): Labels
        feature_names (list): List of feature names
        
    Returns:
        RandomForestClassifier: Trained model
    """
    print("\n" + "=" * 80)
    print("Training Model")
    print("=" * 80)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples: {len(X_test)}")
    
    # Create and train model
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )
    
    print("\nTraining Random Forest...")
    start_time = time.time()
    model.fit(X_train, y_train)
    training_time = time.time() - start_time
    
    print(f"Training completed in {training_time:.2f} seconds")
    
    # Make predictions
    print("\nEvaluating model...")
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_pred_proba)
    
    print("\n" + "=" * 80)
    print("Model Performance")
    print("=" * 80)
    print(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"F1-Score:  {f1:.4f} ({f1*100:.2f}%)")
    print(f"AUC-ROC:   {auc:.4f} ({auc*100:.2f}%)")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"                 Predicted")
    print(f"                 Legit  Phish")
    print(f"Actual Legit     {cm[0,0]:5d}  {cm[0,1]:5d}")
    print(f"       Phish     {cm[1,0]:5d}  {cm[1,1]:5d}")
    
    # Feature importance
    print("\n" + "=" * 80)
    print("Feature Importance")
    print("=" * 80)
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    for i in range(min(20, len(feature_names))):
        print(f"{i+1:2d}. {feature_names[indices[i]]:30s} {importances[indices[i]]:.4f}")
    
    # Cross-validation
    print("\n" + "=" * 80)
    print("Cross-Validation (5-fold)")
    print("=" * 80)
    cv_scores = cross_val_score(model, X, y, cv=5, scoring='accuracy')
    print(f"CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    # Save confusion matrix plot
    print("\n" + "=" * 80)
    print("Saving Evaluation Artifacts")
    print("=" * 80)
    
    # Create confusion matrix plot
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Legitimate', 'Phishing'],
                yticklabels=['Legitimate', 'Phishing'],
                cbar_kws={'label': 'Count'})
    plt.title('Confusion Matrix - Phishing Detection Model', fontsize=14, fontweight='bold')
    plt.xlabel('Predicted Label', fontsize=12)
    plt.ylabel('True Label', fontsize=12)
    plt.tight_layout()
    plt.savefig('confusion_matrix.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("Confusion matrix saved to: confusion_matrix.png")
    
    # Generate and save detailed metrics report
    report = classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing'])
    
    metrics_content = f"""
================================================================================
                    PHISHING DETECTION MODEL - EVALUATION REPORT
================================================================================

Dataset Information:
-------------------
Total Samples: {len(y)}
Training Samples: {len(X_train)} (80%)
Testing Samples: {len(X_test)} (20%)
Features Extracted: {X.shape[1]}

Model Configuration:
-------------------
Algorithm: Random Forest Classifier
Number of Trees: 100
Max Depth: 20
Min Samples Split: 5
Min Samples Leaf: 2
Class Weight: Balanced

================================================================================
                            PERFORMANCE METRICS
================================================================================

Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)
Precision: {precision:.4f} ({precision*100:.2f}%)
Recall:    {recall:.4f} ({recall*100:.2f}%)
F1-Score:  {f1:.4f} ({f1*100:.2f}%)
AUC-ROC:   {auc:.4f} ({auc*100:.2f}%)

Cross-Validation Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})

================================================================================
                        CLASSIFICATION REPORT
================================================================================

{report}

================================================================================
                        CONFUSION MATRIX
================================================================================

                 Predicted
                 Legit    Phish
Actual Legit     {cm[0,0]:5d}    {cm[0,1]:5d}
       Phish     {cm[1,0]:5d}    {cm[1,1]:5d}

Interpretation:
- True Negatives (Legitimate correctly identified): {cm[0,0]}
- False Positives (Legitimate marked as Phishing): {cm[0,1]}
- False Negatives (Phishing marked as Legitimate): {cm[1,0]}
- True Positives (Phishing correctly identified): {cm[1,1]}

================================================================================
                        TOP 10 FEATURE IMPORTANCE
================================================================================

"""
    
    for i in range(min(10, len(feature_names))):
        metrics_content += f"{i+1:2d}. {feature_names[indices[i]]:30s} {importances[indices[i]]:.4f}\n"
    
    metrics_content += """
================================================================================
Generated by: ShieldGuard Pro Model Training Script
================================================================================
"""
    
    with open('model_metrics.txt', 'w') as f:
        f.write(metrics_content)
    print("Model metrics saved to: model_metrics.txt")
    
    return model, accuracy, precision, recall, f1


def save_model(model, filename='phishing_model.pkl'):
    """Save trained model to file."""
    with open(filename, 'wb') as f:
        pickle.dump(model, f)
    print(f"\nModel saved to: {filename}")


def test_model(model):
    """Test model on sample URLs."""
    print("\n" + "=" * 80)
    print("Testing on Sample URLs")
    print("=" * 80)
    
    test_urls = [
        ("https://www.google.com", "legitimate"),
        ("https://www.youtube.com/watch?v=test", "legitimate"),
        ("http://192.168.1.1/login.php", "phishing"),
        ("https://bit.ly/abc123", "phishing"),
        ("http://verify-paypal-account.tk/login", "phishing"),
        ("https://www.bankofamerica.com/secure/login", "legitimate"),
        ("http://secure-update-apple.tk/verify", "phishing"),
        ("https://github.com/login", "legitimate"),
        ("http://login-microsoft-verify.ga/auth", "phishing"),
        ("https://www.amazon.com/gp/sign-in.html", "legitimate")
    ]
    
    print("\nSample Predictions:")
    print("-" * 80)
    print(f"{'URL':<50s} {'Actual':<12s} {'Predicted':<12s} {'Confidence':<10s}")
    print("-" * 80)
    
    correct = 0
    for url, actual in test_urls:
        features_dict = extract_features(url)
        features_array = features_to_array(features_dict)
        X_sample = np.array([features_array])
        
        prediction = model.predict(X_sample)[0]
        confidence = model.predict_proba(X_sample)[0]
        
        predicted_label = "phishing" if prediction == 1 else "legitimate"
        confidence_score = max(confidence) * 100
        
        if predicted_label == actual:
            correct += 1
            status = ""
        else:
            status = " [WRONG]"
        
        url_display = url[:47] + "..." if len(url) > 50 else url
        print(f"{url_display:<50s} {actual:<12s} {predicted_label:<12s} {confidence_score:>6.2f}%{status}")
    
    print("-" * 80)
    print(f"Accuracy on samples: {correct}/{len(test_urls)} ({correct/len(test_urls)*100:.1f}%)")


def main():
    """Main training pipeline."""
    print("=" * 80)
    print("Phishing Detection Model Training")
    print("=" * 80)
    
    # Load and prepare data
    X, y, feature_names = prepare_data()
    
    # Train model
    model, accuracy, precision, recall, f1 = train_model(X, y, feature_names)
    
    # Save model
    save_model(model)
    
    # Test on samples
    test_model(model)
    
    print("\n" + "=" * 80)
    print("Training Complete!")
    print("=" * 80)
    print(f"\nModel achieves {accuracy*100:.2f}% accuracy on test set")
    print("Ready for deployment!")


if __name__ == "__main__":
    main()
