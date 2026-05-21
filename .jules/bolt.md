
## 2025-03-05 - Optimize ArrayList usage and Remove Manual GC in high-frequency loops
**Learning:** In PowerShell, `System.Collections.ArrayList` causes performance degradation due to boxing/unboxing overhead, and manual garbage collection (`[System.GC]::Collect()`) inside high-frequency loops (like file enumeration) causes "stop-the-world" pauses.
**Action:** Replace `System.Collections.ArrayList` with generic collections like `System.Collections.Generic.List[T]`, and remove manual GC inside tight loops to allow the runtime to optimize memory management effectively.
