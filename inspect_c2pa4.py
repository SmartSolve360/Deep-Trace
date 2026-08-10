"""Probe Signer construction paths in c2pa-python 0.37.5."""
import c2pa

# Look at all attributes of c2pa module
print("=== All c2pa attributes ===")
for name in sorted(dir(c2pa)):
    obj = getattr(c2pa, name)
    if hasattr(obj, "__module__") and obj.__module__ and "c2pa" in obj.__module__:
        kind = type(obj).__name__
        print(f"  {name:35s}  {kind}")

print()
print("=== c2pa.c2pa sub-module ===")
for name in sorted(dir(c2pa.c2pa)):
    if name.startswith("_"):
        continue
    obj = getattr(c2pa.c2pa, name)
    kind = type(obj).__name__
    print(f"  {name:35s}  {kind}")

# Check if there's a from_settings or from_files classmethod
print()
print("=== Signer classmethods ===")
for name in dir(c2pa.Signer):
    if name.startswith("_"):
        continue
    obj = getattr(c2pa.Signer, name)
    if isinstance(obj, classmethod) or callable(obj):
        print(f"  {name}  ({type(obj).__name__})")

# Check the Builder.sign signature more carefully
import inspect
print()
print("=== Builder.sign() full doc ===")
print(inspect.getdoc(c2pa.Builder.sign))
