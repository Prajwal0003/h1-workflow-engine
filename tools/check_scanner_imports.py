import importlib
import pkgutil

import scanners

failed = []
for module in sorted(name for _, name, _ in pkgutil.iter_modules(scanners.__path__)):
    try:
        importlib.import_module(f"scanners.{module}")
    except Exception as exc:
        failed.append((module, type(exc).__name__, str(exc)))

if failed:
    for module, kind, message in failed:
        print(f"{module}: {kind}: {message}")
else:
    print("all_scanner_imports=ok")
