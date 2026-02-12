## 2025-02-19 - PowerShell Pipeline Overhead
**Learning:** PowerShell pipelines (`|`) involve significant overhead due to object wrapping and processing. In tight loops (like file transfer logic), replacing pipelines with direct .NET calls or native loops can yield massive performance gains (e.g., replacing `Get-Random` pipeline with `RNGCryptoServiceProvider`).
**Action:** Always inspect inner loops for pipeline usage and replace with .NET primitives where performance is critical.
