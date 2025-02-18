class action_t:
    """
    A placeholder action extension to be incorporated into mutilz context
    """

    def __init__(self):
        """
        Initialize the action.
        """
        pass

    def term(self):
        """
        Terminate the action & clean up.
        """
        pass


def get_action() -> action_t:
    """entry function to be defined by every additional plugin"""
