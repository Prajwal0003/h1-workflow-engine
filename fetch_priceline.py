import sys
import os
sys.path.insert(0, ".")
from modules import scope as scope_module

print("Fetching scope for priceline...")
scope_module.get_scope("priceline")
print("Done fetching scope.")
