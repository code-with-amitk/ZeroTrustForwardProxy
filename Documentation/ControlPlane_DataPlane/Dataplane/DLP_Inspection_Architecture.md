
## DLP & Inspection Architecture

### File-type detection (first 4 KiB)

**Target:** read the first **512B – 4KiB** of body (and `Content-Type` / `Content-Disposition` headers) before choosing inspect depth.

| Detected type | Typical action |
|---------------|----------------|
| `text/json`, `text/plain` | Full regex DLP up to cap |
| `application/pdf`, `image/*`, `video/*` | Metadata-only or skip inline scan; optional async deep scan |
| `application/octet-stream` | Magic-byte table (PDF `%PDF`, ZIP `PK\x03\x04`, etc.) |
| Unknown / binary | Default shallow scan or allow-with-log per tenant policy |

**Why detect file type:** avoids wasting CPU and RAM running text regexes on compressed or binary blobs; routes large archives to async pipeline; lets policy say "block executables" without scanning entire file; reduces false positives on non-text data.

ztfp does **not** send the full file to DLP upfront. It peeks, classifies, then applies a **scan profile** (depth, patterns, async vs inline).
