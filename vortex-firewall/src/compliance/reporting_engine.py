class ReportingEngine:
    """
    Generates reports on detected threats and system actions.
    """
    def __init__(self):
        self.reports = []

    def generate_report(self, data):
        report = f"Report: {data}"
        self.reports.append(report)
        print(report)

if __name__ == "__main__":
    engine = ReportingEngine()
    engine.generate_report({"threats": [10, 50], "actions": ["block", "alert"]})
