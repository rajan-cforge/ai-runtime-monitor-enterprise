# Antfooding Probe Design Notes

Lessons captured from running probes against the Vigil dashboard.

## Browser-based probes inherit app credentials

Probes that drive a Chrome tab to test server-side authentication will
silently inherit any auth tokens the app has already acquired (via
localStorage, cookies, or in-memory state). The dashboard's
`dashboard.html` monkey-patches `window.fetch` to inject the auth token
on all `/api/*` calls. A probe running `fetch('/api/stats')` from inside
that tab cannot tell whether the server requires authentication or not.

### Required practice for auth probes

When testing server-side auth state, use at least one of these:

1. **Out-of-browser HTTP client** — `curl`, Python `requests`, `gh api`,
   etc. — for ground truth.
2. **Fresh tab on different origin** with `credentials: 'omit'` and
   explicit empty headers.
3. **Strip the monkey patch** before testing:
   ```js
   delete window.fetch;  // restores native
   // OR
   const nativeFetch = window.fetch.toString().includes('original')
     ? originalFetch
     : window.fetch;
   ```

### Required practice for all probes

- Cross-verify any "no auth required" finding with `curl` before
  flagging as a security issue.
- Cross-verify any "data exfiltrated" finding by reproducing without
  the app's session state.
- Cross-verify any "endpoint exists" finding from server logs, not just
  network response.

## Confidence reclassification in detectors

The Day 1 probe also found that the alert detection pipeline
reclassified the same fixture hash from `low/likely_fp:true` to
`critical/likely_fp:false` based on a different search context. This is
genuine (Lane D1 D1-FP-CONSISTENCY scope), distinct from the auth probe
issue.

## What the probe pattern is still good for

Browser-driven probes remain valuable for:
- UI rendering verification (XSS regression, console errors, layout
  correctness)
- Click-through behavior
- Real-session end-to-end flow
- Sensitive-data masking visual confirmation

They are NOT a substitute for server-side auth verification.
