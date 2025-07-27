class LockdownMode:
    """
    Activates network lockdown in response to critical threats.
    """
    def __init__(self):
        self.active = False

    def activate(self):
        self.active = True
        print("Network lockdown activated!")

    def deactivate(self):
        self.active = False
        print("Network lockdown deactivated.")

if __name__ == "__main__":
    lockdown = LockdownMode()
    lockdown.activate()
    lockdown.deactivate()
