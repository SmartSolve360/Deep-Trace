"""Find the Signer factory function in c2pa-python."""
import inspect

import c2pa

# Look for module-level functions
print("=== Module-level functions ===")
for name, obj in vars(c2pa).items():
    if callable(obj) and not isinstance(obj, type):
        sig = ""
        try:
            sig = str(inspect.signature(obj))
        except (ValueError, TypeError):
            pass
        doc = (obj.__doc__ or "").split("\n")[0]
        print(f"  {name}{sig}")
        if doc:
            print(f"     {doc[:140]}")
        print()

# Look at Settings and load_settings
print("=== Settings class ===")
for name, method in inspect.getmembers(c2pa.Settings, predicate=inspect.isfunction):
    if name.startswith("_") and name != "__init__":
        continue
    try:
        sig = str(inspect.signature(method))
    except (ValueError, TypeError):
        continue
    doc = (method.__doc__ or "").split("\n")[0]
    print(f"  {name}{sig}")
    if doc:
        print(f"     {doc[:140]}")
    print()
