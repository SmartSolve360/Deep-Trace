"""List C2paSigningAlg enum values."""
import c2pa
for v in c2pa.C2paSigningAlg:
    print(f"  {v.name} = {v.value}")
