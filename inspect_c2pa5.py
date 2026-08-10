"""Look at Signer.from_info signature."""
import inspect

import c2pa

print("Signer.from_info signature:")
print(" ", inspect.signature(c2pa.Signer.from_info))
print(" doc:", (c2pa.Signer.from_info.__doc__ or "").strip())
print()

print("Signer.from_callback signature:")
print(" ", inspect.signature(c2pa.Signer.from_callback))
print(" doc:", (c2pa.Signer.from_callback.__doc__ or "").strip())
print()

# Try c2pa.c2pa.create_signer
print("c2pa.c2pa.create_signer signature:")
print(" ", inspect.signature(c2pa.c2pa.create_signer))
print(" doc:", (c2pa.c2pa.create_signer.__doc__ or "").strip())
print()

print("c2pa.c2pa.create_signer_from_info signature:")
print(" ", inspect.signature(c2pa.c2pa.create_signer_from_info))
print(" doc:", (c2pa.c2pa.create_signer_from_info.__doc__ or "").strip())
