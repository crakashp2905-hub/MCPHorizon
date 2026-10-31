# P3 synthetic API examples (P3-19)

All values are synthetic: tokens (`ta`, `adm`, `rev`), the demo HMAC key and every URL are fake. No real credentials are used or needed.
Start the demo service: `python3 scripts/serve_p3_demo.py /tmp/demo` (prints the socket path), then run the commands below.

## ALLOWED: public artifact to the registry zone
```
curl --unix-socket /tmp/demo/h.sock -s -H 'Authorization: Bearer ta' -H 'Content-Type: application/json' http://x/v2/decisions -d @examples/p3/allow.json
```
Expected: `"verdict": "ALLOW"` with a request-bound `token`.

## DENIED: input artifact is unknown, so it is treated as SECRET with incomplete lineage
```
curl --unix-socket /tmp/demo/h.sock -s -H 'Authorization: Bearer ta' -H 'Content-Type: application/json' http://x/v2/decisions -d @examples/p3/deny_unknown_artifact.json
```
Expected: `"verdict": "DENY"`.

## DENIED: no credentials
```
curl --unix-socket /tmp/demo/h.sock -s -o /dev/null -w '%{http_code}\n' -X POST http://x/v2/decisions -d '{}'
```
Expected: `401`.
