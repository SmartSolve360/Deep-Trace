"""Find the right Settings JSON format."""
import inspect
import c2pa

print("=== Settings.update doc ===")
print(inspect.getdoc(c2pa.Settings.update))
print()
print("=== Settings.set doc ===")
print(inspect.getdoc(c2pa.Settings.set))
print()
print("=== ContextBuilder ===")
for name, method in inspect.getmembers(c2pa.ContextBuilder, predicate=inspect.isfunction):
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
