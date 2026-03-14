"""
Prediction Module for Cyber Attack Detection
Handles loading model and making predictions
"""

import joblib
import pandas as pd
import numpy as np
import json
import os
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AttackPredictor:
    """Main predictor class for cyber attack detection"""
    
    def __init__(self):
        """Initialize the predictor and load model"""
        self.model = None
        self.feature_names = []
        self.attack_mapping = {}
        self.reverse_mapping = {}
        self.model_loaded = False
        self.load_model()
    
    def load_model(self):
        """Load trained model and artifacts from disk"""
        try:
            # Check if model exists
            if not os.path.exists('model/random_forest_model.joblib'):
                logger.warning("No trained model found. Please run train_model.py first")
                return False
            
            # Load model
            self.model = joblib.load('model/random_forest_model.joblib')
            logger.info("✅ Model loaded successfully")
            
            # Load feature names
            if os.path.exists('model/feature_names.json'):
                with open('model/feature_names.json', 'r') as f:
                    self.feature_names = json.load(f)
                logger.info(f"✅ Loaded {len(self.feature_names)} features")
            
            # Load attack mapping
            if os.path.exists('model/attack_mapping.csv'):
                mapping_df = pd.read_csv('model/attack_mapping.csv')
                self.attack_mapping = dict(zip(mapping_df['attack_id'], mapping_df['attack_name']))
                self.reverse_mapping = dict(zip(mapping_df['attack_name'], mapping_df['attack_id']))
                logger.info(f"✅ Loaded {len(self.attack_mapping)} attack types")
            
            self.model_loaded = True
            return True
            
        except Exception as e:
            logger.error(f"❌ Error loading model: {str(e)}")
            return False
    
    def preprocess_input(self, raw_data):
        """
        Preprocess raw input data to match training features
        
        Args:
            raw_data: Dictionary with raw input values
        
        Returns:
            DataFrame with all required features
        """
        # Start with empty DataFrame with all required columns
        input_df = pd.DataFrame(columns=self.feature_names)
        input_df.loc[0] = 0  # Initialize with zeros
        
        # Map raw input to features
        feature_mapping = {
            'duration': 'duration',
            'src_bytes': 'src_bytes',
            'dst_bytes': 'dst_bytes',
            'count': 'count',
            'srv_count': 'srv_count',
            'serror_rate': 'serror_rate',
            'srv_serror_rate': 'srv_serror_rate',
            'same_srv_rate': 'same_srv_rate',
            'diff_srv_rate': 'diff_srv_rate',
            'dst_host_count': 'dst_host_count',
            'dst_host_srv_count': 'dst_host_srv_count'
        }
        
        # Fill numeric features
        for raw_key, feature in feature_mapping.items():
            if raw_key in raw_data and feature in self.feature_names:
                input_df[feature] = float(raw_data[raw_key])
        
        # Handle categorical features (one-hot encoded)
        if 'protocol_type' in raw_data:
            protocol = raw_data['protocol_type'].lower()
            for col in self.feature_names:
                if col.startswith('protocol_type_'):
                    input_df[col] = 1 if col == f'protocol_type_{protocol}' else 0
        
        if 'service' in raw_data:
            service = raw_data['service'].lower()
            for col in self.feature_names:
                if col.startswith('service_'):
                    input_df[col] = 1 if col == f'service_{service}' else 0
        
        if 'flag' in raw_data:
            flag = raw_data['flag'].upper()
            for col in self.feature_names:
                if col.startswith('flag_'):
                    input_df[col] = 1 if col == f'flag_{flag}' else 0
        
        return input_df
    
    def predict(self, input_data):
        """
        Make prediction on input data
        
        Args:
            input_data: Dictionary with raw input features
        
        Returns:
            tuple: (attack_type, confidence, risk_level)
        """
        if not self.model_loaded:
            return "Model not loaded", 0.0, "UNKNOWN"
        
        try:
            # Preprocess input
            X = self.preprocess_input(input_data)
            
            # Ensure correct column order
            X = X[self.feature_names]
            
            # Make prediction
            prediction_id = self.model.predict(X)[0]
            probabilities = self.model.predict_proba(X)[0]
            confidence = float(max(probabilities))
            
            # Get attack type
            attack_type = self.attack_mapping.get(prediction_id, 'unknown')
            
            # Determine risk level
            if attack_type == 'normal':
                risk_level = 'LOW'
            elif confidence > 0.85:
                risk_level = 'CRITICAL' if attack_type in ['dos', 'u2r'] else 'HIGH'
            elif confidence > 0.60:
                risk_level = 'MEDIUM'
            else:
                risk_level = 'LOW'
            
            # Log prediction
            self.log_prediction(input_data, attack_type, confidence, risk_level)
            
            return attack_type, confidence, risk_level
            
        except Exception as e:
            logger.error(f"❌ Prediction error: {str(e)}")
            return "error", 0.0, "UNKNOWN"
    
    def log_prediction(self, input_data, attack_type, confidence, risk_level):
        """Save prediction to CSV log"""
        try:
            log_entry = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': input_data.get('src_ip', 'unknown'),
                'duration': input_data.get('duration', 0),
                'protocol': input_data.get('protocol_type', 'unknown'),
                'service': input_data.get('service', 'unknown'),
                'src_bytes': input_data.get('src_bytes', 0),
                'dst_bytes': input_data.get('dst_bytes', 0),
                'flag': input_data.get('flag', 'unknown'),
                'attack_type': attack_type,
                'confidence': round(confidence, 3),
                'risk_level': risk_level
            }
            
            # Create data directory if needed
            os.makedirs('data', exist_ok=True)
            
            # Append to log
            log_df = pd.DataFrame([log_entry])
            log_file = 'data/predictions_log.csv'
            
            if os.path.exists(log_file):
                existing = pd.read_csv(log_file)
                updated = pd.concat([existing, log_df], ignore_index=True)
                # Keep only last 1000 records
                if len(updated) > 1000:
                    updated = updated.tail(1000)
                updated.to_csv(log_file, index=False)
            else:
                log_df.to_csv(log_file, index=False)
                
        except Exception as e:
            logger.error(f"❌ Error logging prediction: {str(e)}")
    
    def get_stats(self):
        """Get prediction statistics"""
        try:
            if os.path.exists('data/predictions_log.csv'):
                df = pd.read_csv('data/predictions_log.csv')
                
                # Calculate stats
                total = len(df)
                attacks = len(df[df['attack_type'] != 'normal'])
                critical = len(df[df['risk_level'] == 'CRITICAL'])
                high = len(df[df['risk_level'] == 'HIGH'])
                
                return {
                    'total_predictions': total,
                    'total_attacks': attacks,
                    'critical_alerts': critical,
                    'high_risk_alerts': high,
                    'attack_rate': round(attacks/total*100, 1) if total > 0 else 0
                }
            else:
                return {
                    'total_predictions': 0,
                    'total_attacks': 0,
                    'critical_alerts': 0,
                    'high_risk_alerts': 0,
                    'attack_rate': 0
                }
        except Exception as e:
            logger.error(f"❌ Error getting stats: {str(e)}")
            return {}

# Create global predictor instance
predictor = AttackPredictor()