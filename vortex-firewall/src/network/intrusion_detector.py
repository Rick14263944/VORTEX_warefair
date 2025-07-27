
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, LSTM, RepeatVector, Attention, Dense
import requests
import shap

class IntrusionDetector:
    # Distributed support stub
    node_id = None
    cluster_nodes = []

    # Automated response stub
    def automated_response(self, anomaly_indices, action='alert'):
        """Automated response: alert, block, or quarantine."""
        for idx in anomaly_indices:
            print(f"Automated response: {action} triggered for anomaly at index {idx}")

    # Online learning stub
    def online_update(self, new_data):
        """Online/incremental learning stub."""
        # Example: partial fit for IsolationForest (not supported natively, but can retrain)
        self.train_baseline(new_data)
        self.train_deep_learning(new_data)

    # Feature engineering stub
    def feature_engineering(self, raw_data):
        """Extract features from raw network traffic."""
        # Example: extract mean, std, min, max, etc.
        features = np.column_stack([
            np.mean(raw_data, axis=1),
            np.std(raw_data, axis=1),
            np.min(raw_data, axis=1),
            np.max(raw_data, axis=1)
        ])
        return features

    # Adversarial robustness stub
    def adversarial_check(self, traffic_data):
        """Detect adversarial samples (simple stub)."""
        # Example: flag extreme values
        flagged = np.where(np.abs(traffic_data) > 100)
        return flagged

    # Visualization hook stub
    def visualization_hook(self, anomaly_scores):
        """Send anomaly scores to visualization dashboard (stub)."""
        print(f"Visualization update: {anomaly_scores}")

    # Multi-feed threat intelligence stub
    def enrich_with_multi_threat_intel(self, traffic_point):
        """Query multiple threat intelligence feeds."""
        feeds = [
            "https://api.threatintel.example.com/lookup",
            "https://api.anotherfeed.com/lookup"
        ]
        results = []
        for url in feeds:
            try:
                response = requests.get(url, params={"data": traffic_point.tolist()})
                if response.status_code == 200:
                    results.append(response.json())
            except Exception as e:
                results.append({"error": str(e)})
        return results

    # Advanced explainable AI stub
    def deep_explain_anomaly(self, traffic_data, idx):
        """Advanced explainability for neural networks (stub)."""
        # Placeholder for DeepSHAP or Integrated Gradients
        return {"explanation": "Advanced neural explanation not implemented."}
    """
    AI-Powered Intrusion Detection System (IDS):
    Monitors inbound/outbound traffic, detects known and unknown threats using ML,
    correlates anomalies with behavior-based baselines.
    """
    def __init__(self, baseline_data=None):
        self.scaler = StandardScaler()
        self.model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
        self.dl_model = None
        self.is_trained = False
        self.dl_trained = False
        if baseline_data is not None:
            self.train_baseline(baseline_data)
            self.train_deep_learning(baseline_data)
    def train_deep_learning(self, baseline_data, timesteps=10):
        """Train an LSTM autoencoder with attention for sequential anomaly detection."""
        X = self.scaler.fit_transform(baseline_data)
        n_samples, n_features = X.shape
        if n_samples < timesteps:
            raise ValueError("Not enough samples for the specified timesteps.")
        X_seq = np.array([X[i:i+timesteps] for i in range(n_samples - timesteps)])
        inputs = Input(shape=(timesteps, n_features))
        encoded = LSTM(64, activation='relu', return_sequences=True)(inputs)
        attention = Attention()([encoded, encoded])
        encoded_vec = LSTM(32, activation='relu')(attention)
        decoded = RepeatVector(timesteps)(encoded_vec)
        decoded = LSTM(n_features, activation='relu', return_sequences=True)(decoded)
        autoencoder = Model(inputs, decoded)
        autoencoder.compile(optimizer='adam', loss='mse')
        autoencoder.fit(X_seq, X_seq, epochs=15, batch_size=32, verbose=0)
        self.dl_model = autoencoder
        self.dl_trained = True
        self.timesteps = timesteps

    def deep_anomaly_score(self, traffic_data):
        """Return anomaly scores using LSTM autoencoder reconstruction error."""
        if not self.dl_trained:
            raise RuntimeError("Deep learning model not trained.")
        X = self.scaler.transform(traffic_data)
        n_samples = X.shape[0]
        timesteps = getattr(self, 'timesteps', 10)
        if n_samples < timesteps:
            raise ValueError("Not enough samples for the specified timesteps.")
        X_seq = np.array([X[i:i+timesteps] for i in range(n_samples - timesteps)])
        recon = self.dl_model.predict(X_seq)
        mse = np.mean(np.square(X_seq - recon), axis=(1,2))
        return mse

    def explain_anomaly(self, traffic_data, idx):
        """Use SHAP to explain why a traffic point is anomalous."""
        if not self.is_trained:
            raise RuntimeError("IDS model is not trained.")
        X = self.scaler.transform(traffic_data)
        explainer = shap.KernelExplainer(self.model.predict, X)
        shap_values = explainer.shap_values(X[idx])
        return shap_values

    def enrich_with_threat_intel(self, traffic_point):
        """Enrich anomaly with external threat intelligence (mock example)."""
        # Example: Query a threat intelligence API (replace with real endpoint)
        try:
            response = requests.get("https://api.threatintel.example.com/lookup", params={"data": traffic_point.tolist()})
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            return {"error": str(e)}
        return {"info": "No threat intel available."}

    def train_baseline(self, baseline_data):
        """Train IDS on baseline (normal) network behavior."""
        X = self.scaler.fit_transform(baseline_data)
        self.model.fit(X)
        self.is_trained = True

    def analyze_traffic(self, traffic_data):
        """Analyze new traffic data and detect anomalies/threats."""
        if not self.is_trained:
            raise RuntimeError("IDS model is not trained on baseline data.")
        X = self.scaler.transform(traffic_data)
        predictions = self.model.predict(X)
        # -1: anomaly/threat, 1: normal
        anomalies = np.where(predictions == -1)[0]
        return anomalies

    def correlate_with_behavior(self, traffic_data, user_behavior_profiles):
        """Correlate detected anomalies with user/device behavior baselines."""
        anomalies = self.analyze_traffic(traffic_data)
        correlated = []
        for idx in anomalies:
            traffic_point = traffic_data[idx]
            # Example: compare with user/device profiles (simple distance metric)
            for profile in user_behavior_profiles:
                distance = np.linalg.norm(traffic_point - profile)
                if distance > 2.5:  # threshold for abnormal behavior
                    correlated.append((idx, profile, distance))
        return correlated

# Example usage (to be replaced with real data integration)
if __name__ == "__main__":
    # Simulate baseline and traffic data
    baseline = np.random.normal(loc=0, scale=1, size=(1000, 5))
    traffic = np.random.normal(loc=0, scale=1, size=(100, 5))
    # Inject some anomalies
    traffic[10] = np.array([10, 10, 10, 10, 10])
    traffic[50] = np.array([-10, -10, -10, -10, -10])
    user_profiles = [np.zeros(5), np.ones(5)]

    ids = IntrusionDetector(baseline)
    anomalies = ids.analyze_traffic(traffic)
    print(f"IsolationForest anomalies detected at indices: {anomalies}")
    # LSTM autoencoder expects sequential data
    try:
        dl_scores = ids.deep_anomaly_score(traffic)
        print(f"LSTM Autoencoder anomaly scores: {dl_scores}")
        ids.visualization_hook(dl_scores)
    except Exception as e:
        print(f"Deep learning anomaly detection error: {e}")
    correlated = ids.correlate_with_behavior(traffic, user_profiles)
    print(f"Correlated anomalies: {correlated}")
    # Automated response example
    ids.automated_response(anomalies, action='alert')
    # Online learning example
    ids.online_update(baseline)
    # Feature engineering example
    features = ids.feature_engineering(traffic)
    print(f"Engineered features: {features}")
    # Adversarial robustness example
    flagged = ids.adversarial_check(traffic)
    print(f"Adversarial samples flagged: {flagged}")
    # Distributed support example
    ids.node_id = 'node-1'
    ids.cluster_nodes = ['node-1', 'node-2', 'node-3']
    print(f"Cluster nodes: {ids.cluster_nodes}")
    # Multi-feed threat intelligence example
    if len(anomalies) > 0:
        multi_intel = ids.enrich_with_multi_threat_intel(traffic[anomalies[0]])
        print(f"Multi-feed threat intelligence: {multi_intel}")
        # Advanced explainable AI example
        deep_expl = ids.deep_explain_anomaly(traffic, anomalies[0])
        print(f"Advanced neural explanation: {deep_expl}")
