# LHSec — Import Format Reference

LHSec accepts **CSV** and **JSON** files when bulk-importing institutions and their public IP addresses.

---

## CSV Format

### Required columns

| Column | Type | Description |
|---|---|---|
| `name` | string | Institution name (must be unique) |
| `ips` | string | Comma-separated list of IPs or CIDR ranges |

### Optional columns

| Column | Type | Description |
|---|---|---|
| `contact_email` | string | Security / IT contact email |
| `notes` | string | Free-text notes |

### Rules
- First row **must** be the header.
- The `ips` field supports both individual addresses (`1.2.3.4`) and CIDR ranges (`203.0.113.0/28`).
- Separate multiple IPs with a comma **inside the same cell** (quote the cell if needed).
- Importing the same institution name a second time **updates** it (upsert); it does not create a duplicate.
- UTF-8 encoding; BOM is accepted.

### Example

```csv
name,ips,contact_email,notes
"Acme Corp","1.2.3.4,5.6.7.8,203.0.113.0/28",security@acme.com,"Primary datacenter"
"Beta University","198.51.100.0/24",it@beta.edu,""
"City Council","192.0.2.10,192.0.2.11",,
```

---

## JSON Format

Root element must be an **array** of institution objects.

### Schema

```json
[
  {
    "name":          "string (required)",
    "ips":           ["string", "…"],
    "contact_email": "string (optional)",
    "notes":         "string (optional)"
  }
]
```

### Field details

| Field | Required | Notes |
|---|---|---|
| `name` | ✅ | Unique identifier for upsert matching |
| `ips` | ✅ | Array of IP strings or CIDR ranges. May also be a comma-separated string. |
| `contact_email` | ❌ | |
| `notes` | ❌ | |

### Example

```json
[
  {
    "name": "Acme Corp",
    "ips": ["1.2.3.4", "5.6.7.8", "203.0.113.0/28"],
    "contact_email": "security@acme.com",
    "notes": "Primary datacenter"
  },
  {
    "name": "Beta University",
    "ips": ["198.51.100.0/24"],
    "contact_email": "it@beta.edu"
  },
  {
    "name": "City Council",
    "ips": ["192.0.2.10", "192.0.2.11"]
  }
]
```

---

## Validation

The following checks are applied during import and reported in the response:

- Empty `name` → row skipped with a warning.
- Invalid IP or CIDR → that specific IP is skipped; the institution is still created.
- Duplicate IP range for the same institution → silently skipped (no duplicates).
- Duplicate institution name → institution record is **updated**, not duplicated.

## API Response

```json
{
  "created": 2,
  "updated": 1,
  "skipped": 0,
  "errors": [
    "[Acme Corp] Invalid IP/CIDR 'not-an-ip' — skipped."
  ]
}
```
