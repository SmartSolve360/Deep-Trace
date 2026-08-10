"""Probe c2pa-python Builder + Signer APIs."""
import inspect

import c2pa

print("=== Builder class ===")
for name, method in inspect.getmembers(c2pa.Builder, predicate=inspect.isfunction):
    if name.startswith("_") and name != "__init__":
        continue
    sig = inspect.signature(method)
    doc = (method.__doc__ or "").split("\n")[0]
    print(f"  {name}{sig}")
    if doc:
        print(f"     {doc[:140]}")

print()
print("=== Signer class ===")
for name, method in inspect.getmembers(c2pa.Signer, predicate=inspect.isfunction):
    if name.startswith("_") and name != "__init__":
        continue
    sig = inspect.signature(method)
    doc = (method.__doc__ or "").split("\n")[0]
    print(f"  {name}{sig}")
    if doc:
        print(f"     {doc[:140]}")

print()
print("=== Builder() signature ===")
try:
    print(inspect.signature(c2pa.Builder.__init__))
except Exception as e:
    print(f"could not get signature: {e}")

print()
print("=== Signer() signature ===")
try:
    print(inspect.signature(c2pa.Signer.__init__))
except Exception as e:
    print(f"could not get signature: {e}")
