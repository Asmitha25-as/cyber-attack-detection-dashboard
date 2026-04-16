"""
Model Training Script for Cyber Attack Detection
Trains a Random Forest classifier on NSL-KDD dataset
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import json
import os
from datetime import datetime
import joblib

def load_and_preprocess_data():
    """Load and preprocess the NSL-KDD dataset"""
    print("📊 Loading dataset...")
    
    # Check if dataset exists
    if not os.path.exists('dataset/nsl_kdd.csv'):
        print("❌ Dataset not found! Please place nsl_kdd.csv in the dataset folder.")
        return None, None, None
    
    # Define column names for NSL-KDD (the dataset has NO headers)
    column_names = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
        'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
        'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
        'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
        'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'attack_type', 'difficulty'
    ]
    
    # Load dataset with column names
    df = pd.read_csv('dataset/nsl_kdd.csv', names=column_names)
    
    print(f"✅ Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns")
    print(f"✅ Columns: {df.columns.tolist()[:10]}...")  # Show first 10 columns
    
    return df, column_names

def engineer_features(df, column_names):
    """Feature engineering and selection"""
    print("🔧 Engineering features...")
    
    # Select most important features (simplified for better performance)
    selected_features = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'same_srv_rate',
        'diff_srv_rate', 'dst_host_count', 'dst_host_srv_count'
    ]
    
    # Verify all selected features exist
    missing_features = [f for f in selected_features if f not in df.columns]
    if missing_features:
        print(f"⚠️ Warning: Missing features: {missing_features}")
        # Use only available features
        selected_features = [f for f in selected_features if f in df.columns]
    
    print(f"✅ Using features: {selected_features}")
    
    # Handle categorical variables
    categorical_features = ['protocol_type', 'service', 'flag']
    # Only use categorical features that exist in the dataframe
    categorical_features = [f for f in categorical_features if f in df.columns]
    
    X = pd.get_dummies(df[selected_features], columns=categorical_features)
    
    # Get attack labels
    y = df['attack_type']
    
    # Simplify attack categories
    def simplify_attack(attack):
        attack = str(attack).lower()
        if attack == 'normal':
            return 'normal'
        elif attack in ['neptune', 'back', 'land', 'pod', 'smurf', 'teardrop', 'apache2', 'udpstorm', 'processtable', 'worm']:
            return 'dos'
        elif attack in ['satan', 'ipsweep', 'nmap', 'portsweep', 'mscan', 'saint']:
            return 'probe'
        elif attack in ['guess_passwd', 'ftp_write', 'imap', 'phf', 'multihop', 'warezmaster', 'warezclient', 'spy', 'xlock', 'xsnoop', 'snmpguess', 'snmpgetattack', 'httptunnel', 'sendmail', 'named']:
            return 'r2l'
        elif attack in ['buffer_overflow', 'loadmodule', 'rootkit', 'perl', 'sqlattack', 'xterm', 'ps']:
            return 'u2r'
        else:
            return 'unknown'
    
    y_simplified = y.apply(simplify_attack)
    
    # Remove unknown attacks
    mask = y_simplified != 'unknown'
    X = X[mask]
    y_simplified = y_simplified[mask]
    
    print(f"✅ Features engineered: {X.shape[1]} features")
    print(f"✅ Attack distribution:\n{y_simplified.value_counts()}")
    
    return X, y_simplified

def train_model(X, y):
    """Train the Random Forest model"""
    print("🤖 Training Random Forest model...")
    
    # Encode labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )
    
    # Train model
    model = RandomForestClassifier(
        n_estimators=50,  # Reduced for faster training
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    
    # Make predictions
    y_pred = model.predict(X_test)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
    f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    
    print(f"✅ Model training complete!")
    print(f"   Accuracy: {accuracy:.4f}")
    print(f"   Precision: {precision:.4f}")
    print(f"   Recall: {recall:.4f}")
    print(f"   F1-Score: {f1:.4f}")
    
    return model, label_encoder, {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'timestamp': datetime.now().isoformat()
    }

def save_model_artifacts(model, label_encoder, metrics, feature_names):
    """Save model and related artifacts"""
    print("💾 Saving model artifacts...")
    
    # Create model directory if it doesn't exist
    os.makedirs('model', exist_ok=True)
    
    # Save the model using joblib
    joblib.dump(model, 'model/random_forest_model.joblib')
    print("✅ Model saved: model/random_forest_model.joblib")
    
    # Save label encoder classes
    attack_mapping = pd.DataFrame({
        'attack_id': range(len(label_encoder.classes_)),
        'attack_name': label_encoder.classes_
    })
    attack_mapping.to_csv('model/attack_mapping.csv', index=False)
    print("✅ Attack mapping saved: model/attack_mapping.csv")
    
    # Save feature names
    with open('model/feature_names.json', 'w') as f:
        json.dump(feature_names, f, indent=2)
    
    # Save model configuration
    config = {
        'model_type': 'RandomForestClassifier',
        'n_estimators': 50,
        'max_depth': 10,
        'feature_count': len(feature_names),
        'attack_types': label_encoder.classes_.tolist(),
        'accuracy': metrics['accuracy'],
        'f1_score': metrics['f1_score']
    }
    with open('model/model_config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    # Save training metrics
    pd.DataFrame([metrics]).to_csv('model/training_history.csv', index=False)
    print("✅ Training metrics saved: model/training_history.csv")

def main():
    """Main training pipeline"""
    print("="*50)
    print("🚀 CYBER ATTACK DETECTION - MODEL TRAINING")
    print("="*50)
    
    # Load data
    df, column_names = load_and_preprocess_data()
    if df is None:
        return
    
    # Engineer features
    X, y = engineer_features(df, column_names)
    
    # Train model
    model, label_encoder, metrics = train_model(X, y)
    
    # Save artifacts
    save_model_artifacts(model, label_encoder, metrics, X.columns.tolist())
    
    print("="*50)
    print("✅ TRAINING COMPLETE!")
    print("="*50)

if __name__ == "__main__":
    main()