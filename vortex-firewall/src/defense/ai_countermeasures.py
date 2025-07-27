class AICountermeasures:
    """
    Triggers defense actions (block, quarantine, alert) based on IDS findings.
    """
    def __init__(self):
        pass

    def trigger(self, action, indices):
        for idx in indices:
            print(f"AI Countermeasure: {action} triggered for index {idx}")

if __name__ == "__main__":
    cm = AICountermeasures()
    cm.trigger('block', [10, 50])
