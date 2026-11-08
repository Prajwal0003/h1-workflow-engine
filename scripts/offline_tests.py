"""Run the local regression suite without live targets or external tools."""
import sys
import unittest
from pathlib import Path


def offline_only(event, args):
    if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto",
                 "subprocess.Popen", "os.system", "os.posix_spawn"}:
        raise RuntimeError(f"Offline test attempted {event}")


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    sys.addaudithook(offline_only)
    suite = unittest.defaultTestLoader.discover(str(root / "tests"))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if suite.countTestCases() and result.wasSuccessful() else 1)
