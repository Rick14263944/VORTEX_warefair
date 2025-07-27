class AuditLogger:
    """
    Logs detected threats and defense actions for compliance.
    """
    def __init__(self):
        self.logs = []

    def log_threat(self, threat_info):
        self.logs.append(threat_info)
        print(f"Threat logged: {threat_info}")

    def log_action(self, action_info):
        self.logs.append(action_info)
        print(f"Action logged: {action_info}")

if __name__ == "__main__":
    logger = AuditLogger()
    logger.log_threat({"index": 10, "type": "anomaly"})
    logger.log_action({"action": "block", "index": 10})
