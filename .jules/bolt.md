## 2025-03-05 - Replace ArrayList with Generic.List[T]
**Learning:** In PowerShell 5.1+, `System.Collections.ArrayList` is slower and causes pipeline pollution that must be suppressed with `[void]`. `[System.Collections.Generic.List[T]]` is significantly faster for large collections and does not output added items.
**Action:** Use `[System.Collections.Generic.List[T]]` (e.g., `[System.Collections.Generic.List[object]]`) instead of `ArrayList` for batch processing in PowerShell to improve performance and code cleanliness.
