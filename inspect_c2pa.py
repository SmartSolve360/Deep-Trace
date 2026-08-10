"""Inspect the c2pa-python API to figure out the right way to sign."""
import c2pa

print("c2pa version:", getattr(c2pa, "__version__", "?"))
print()
print("Public API surface (top-level):")
for name in sorted(dir(c2pa)):
    if name.startswith("_"):
        continue
    obj = getattr(c2pa, name)
    kind = type(obj).__name__
    print(f"  {name:30s}  {kind}")

print()
print("Looking for signing-related functions…")
for name in sorted(dir(c2pa)):
    if any(kw in name.lower() for kw in ("sign", "read", "manifest", "builder", "verify")):
        obj = getattr(c2pa, name)
        print(f"  {name}: {type(obj).__name__}")
        if callable(obj) and not isinstance(obj, type):
            try:
                sig = obj.__doc__.split("\n")[0] if obj.__doc__ else ""
                print(f"     -> {sig[:120]}")
            except Exception:
                pass
