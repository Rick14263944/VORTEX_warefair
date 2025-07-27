import numpy as np
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense, Dropout, Concatenate, LSTM, Attention
from sklearn.preprocessing import StandardScaler

class AdaptiveZeroTrustAI:
    """
    Adaptive Zero-Trust AI Engine:
    Evaluates every identity, device, and access attempt with contextual risk analysis.
    Dynamically adjusts access based on trust score using deep neural and hybrid models.
    """
    def __init__(self):
        self.scaler = StandardScaler()
        self.dnn_model = self._build_dnn_model()
        self.lstm_model = self._build_lstm_model()
        self.is_trained = False

    def _build_dnn_model(self):
        inputs = Input(shape=(10,))
        x = Dense(128, activation='relu')(inputs)
        x = Dropout(0.2)(x)
        x = Dense(64, activation='relu')(x)
        x = Dropout(0.2)(x)
        x = Dense(32, activation='relu')(x)
        outputs = Dense(1, activation='sigmoid')(x)
        model = Model(inputs, outputs)
        model.compile(optimizer='adam', loss='binary_crossentropy')
        return model

    def _build_lstm_model(self):
        inputs = Input(shape=(5, 10))  # 5 timesteps, 10 features
        x = LSTM(64, activation='relu', return_sequences=True)(inputs)
        attention = Attention()([x, x])
        x = LSTM(32, activation='relu')(attention)
        outputs = Dense(1, activation='sigmoid')(x)
        model = Model(inputs, outputs)
        model.compile(optimizer='adam', loss='binary_crossentropy')
        return model

    def train(self, identity_data, device_data, access_data, labels):
        """Train DNN and LSTM models on contextual risk data."""
        X_id = self.scaler.fit_transform(identity_data)
        X_dev = self.scaler.transform(device_data)
        X_acc = self.scaler.transform(access_data)
        # DNN: combine all features
        X_dnn = np.concatenate([X_id, X_dev, X_acc], axis=1)
        self.dnn_model.fit(X_dnn, labels, epochs=10, batch_size=32, verbose=0)
        # LSTM: sequence of access attempts
        X_lstm = X_dnn.reshape((-1, 5, 10))  # Example reshape
        self.lstm_model.fit(X_lstm, labels, epochs=10, batch_size=32, verbose=0)
        self.is_trained = True

    def evaluate_access(self, identity, device, access):
        """Evaluate access attempt and return trust score."""
        X_id = self.scaler.transform(identity.reshape(1, -1))
        X_dev = self.scaler.transform(device.reshape(1, -1))
        X_acc = self.scaler.transform(access.reshape(1, -1))
        X_dnn = np.concatenate([X_id, X_dev, X_acc], axis=1)
        trust_score_dnn = float(self.dnn_model.predict(X_dnn)[0][0])
        # LSTM expects sequence, so we simulate with repeated access
        X_lstm = np.tile(X_dnn, (5, 1)).reshape((1, 5, 10))
        trust_score_lstm = float(self.lstm_model.predict(X_lstm)[0][0])
        # Hybrid: average trust scores
        trust_score = (trust_score_dnn + trust_score_lstm) / 2
        return trust_score

    def dynamic_access_control(self, trust_score, threshold=0.7):
        """Dynamically adjust access based on trust score."""
        if trust_score >= threshold:
            return "Access Granted"
        elif trust_score >= threshold * 0.5:
            return "Access Limited"
        else:
            return "Access Denied"

# Example usage
if __name__ == "__main__":
    # Simulate training data
    identity_data = np.random.normal(loc=0, scale=1, size=(100, 10))
    device_data = np.random.normal(loc=0, scale=1, size=(100, 10))
    access_data = np.random.normal(loc=0, scale=1, size=(100, 10))
    labels = np.random.randint(0, 2, size=(100,))
    engine = AdaptiveZeroTrustAI()
    engine.train(identity_data, device_data, access_data, labels)
    # Simulate access attempt
    identity = np.random.normal(loc=0, scale=1, size=(10,))
    device = np.random.normal(loc=0, scale=1, size=(10,))
    access = np.random.normal(loc=0, scale=1, size=(10,))
    trust_score = engine.evaluate_access(identity, device, access)
    print(f"Trust score: {trust_score}")
    decision = engine.dynamic_access_control(trust_score)
    print(f"Access decision: {decision}")
