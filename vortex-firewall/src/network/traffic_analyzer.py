import numpy as np

class TrafficAnalyzer:
    """
    Processes packet data and interfaces with IDS for anomaly detection.
    """
    def __init__(self, ids):
        self.ids = ids

    def analyze(self, packet_data):
        """Analyze packet data using IDS and return anomalies."""
        anomalies = self.ids.analyze_traffic(packet_data)
        return anomalies

if __name__ == "__main__":
    from intrusion_detector import IntrusionDetector
    baseline = np.random.normal(loc=0, scale=1, size=(1000, 5))
    sniffer_data = np.random.normal(loc=0, scale=1, size=(100, 5))
    ids = IntrusionDetector(baseline)
    analyzer = TrafficAnalyzer(ids)
    anomalies = analyzer.analyze(sniffer_data)
    print(f"Detected anomalies: {anomalies}")
