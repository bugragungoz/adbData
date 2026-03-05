## 2024-05-24 - Remove artificial delay in hash comparison
**Learning:** Applying constant-time string comparisons with artificial sleeps for local file verification is an anti-pattern that introduces unnecessary bottlenecks during bulk operations.
**Action:** Remove timing attack protection (`Start-Sleep` and constant-time loops) in local file hash verification, as standard equality checks (`-eq`) are sufficient and significantly faster.
