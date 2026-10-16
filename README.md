# Swift POS v0.4.5 — Complete Cashier Demo Upgrade

Includes prior Excel upload, shift reconciliation, receipts and added role quick-login (local only), held carts, manager discounts, simulated split payment API, idempotent checkout request, and manager full-sale refunds.

## Local setup
1. Copy `server/.env.example` to `server/.env`, set a UNIQUE `SWIFT_ADMIN_PASSWORD` of 12+ characters.
2. Set `SWIFT_DEMO_QUICK_LOGIN=true` in `server/.env` **only locally**.
3. Run `npm install`, `npm --prefix client install`, `npm --prefix server install`, then `npm run dev`.
4. Never commit `.env` or deploy quick-login on Render. Existing saved demo data may contain outdated shift/account associations; close existing shifts with a manager account.

## Limitations
All M-Pesa/card/split payments are DEMONSTRATIONS. Cashier shift permissions are enforced by the API. Refund flow is FULL refund only, not a real payment reversal. Local JSON persistence is not production-safe. Browser-held carts disappear on refresh. Server-side transaction serialization and PostgreSQL are required before commercial use.
# swift-pos-demo
