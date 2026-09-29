# Playbook: logic (business logic and state)

**CWEs:** 840 business logic errors · 362/367 race condition / TOCTOU · 841 workflow bypass · 20 missing validation of business constraints · 770 missing rate limits on sensitive actions · 204/203 user enumeration

## What to look for
- **Money and quantities:** negative or zero amounts, integer or float rounding, currency mismatch, applying a discount twice, refunding more than was paid
- **Workflow skipping:** calling step 3 without steps 1–2 (checkout without payment confirmation, verifying email by calling the confirm endpoint with any token)
- **Races:** check-then-act on balances, coupons, invites or file existence without a transaction or lock (`if balance >= x: balance -= x` across requests)
- **Trusting client state:** prices, roles, totals or "verified" flags sent from the browser
- **Rate limits** on login, OTP, password reset and invite endpoints (brute force)
- **Enumeration:** different responses or timings for existing and non-existing users on login or reset

Only report issues with a concrete sequence of requests that produces a gain for the attacker.
Spell that sequence out in `attack_path`.
