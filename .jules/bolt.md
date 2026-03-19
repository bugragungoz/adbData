## 2024-05-20 - Replace ArrayList with Generic List[T]
**Learning:** System.Collections.ArrayList forces boxing/unboxing overhead for value types and requires a `[void]` cast when calling `.Add()` to suppress the return value (the index). Using `System.Collections.Generic.List[T]` provides better performance by eliminating boxing/unboxing overhead and automatically returning `void` on `.Add()`.
**Action:** Always prefer `System.Collections.Generic.List[T]` over `System.Collections.ArrayList` in high-frequency PowerShell collections to save memory overhead and streamline syntax.
