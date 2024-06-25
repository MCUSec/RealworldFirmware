from pyhidra.launcher import PyhidraLauncher #, GHIDRA_INSTALL_DIR

# define the headless logging pyhidra launcher 
class HeadlessLoggingPyhidraLauncher(PyhidraLauncher):
    """
    Headless pyhidra launcher
    Slightly Modified from Pyhidra to allow the Ghidra log path to be set
    """

    def __init__(self, verbose=False, log_path=None):
        super().__init__(verbose)
        self.log_path = log_path

    def _launch(self):
        from pyhidra.launcher import _silence_java_output
        from ghidra.framework import Application, HeadlessGhidraApplicationConfiguration
        from java.io import File
        with _silence_java_output(not self.verbose, not self.verbose):
            config = HeadlessGhidraApplicationConfiguration()
            if self.log_path:
                log = File(self.log_path)
                config.setApplicationLogFile(log)
            Application.initializeApplication(self._layout, config)