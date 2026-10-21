# Cloudflare DNS Telegram Bot

A Telegram bot that manages DNS records in Cloudflare zones using a Cloudflare Worker.

## Features

- List Cloudflare zones and DNS records
- Add and edit DNS records
- Delete records with a confirmation step
- Telegram administrator allowlist
- Telegram webhook secret verification
- Runs on Cloudflare Workers; no VPS required

### Supported record types

`A`, `AAAA`, `CNAME`, `TXT`, `MX`, `NS`, `SRV`, `CAA`, `HTTPS`, `DS`, `TLSA`, `CERT`, `SMIMEA`, `URI`, `OPENPGPKEY`, `LOC`, `SSHFP`, `SVCB`, `PTR`, `NAPTR`

## Requirements

- Cloudflare account and a Worker
- Telegram bot created using [@BotFather](https://t.me/BotFather)
- Cloudflare API token with Zone Read and DNS Read/Edit permissions for the intended zones
- Telegram administrator user ID

## Deploy from the Cloudflare dashboard

1. Create a Worker in the Cloudflare dashboard.
2. Paste the contents of `src/worker.js` into the Worker editor.
3. In **Settings → Variables and Secrets**, add these as **secrets**:

   - `TELEGRAM_BOT_TOKEN`
   - `CLOUDFLARE_API_TOKEN`
   - `TELEGRAM_ADMIN_ID`
   - `TELEGRAM_WEBHOOK_SECRET`

4. Deploy the Worker.
5. Set the Telegram webhook URL to `https://YOUR-WORKER.YOUR-SUBDOMAIN.workers.dev/telegram`.
6. Use the same value for `TELEGRAM_WEBHOOK_SECRET` and Telegram's `secret_token` parameter when configuring the webhook.
7. Open your Telegram bot and send `/start`.

See the [Telegram Bot API setWebhook documentation](https://core.telegram.org/bots/api#setwebhook).

## DNS record input

When adding or editing a record, reply to the bot's prompt with a JSON object. For example:

```json
{
  "name": "www",
  "content": "192.0.2.10",
  "ttl": 1,
  "proxied": false
}
```

For record types using structured data, use the `data` object shown in the template. Replace all example and `REPLACE_WITH_...` values with real values before submitting. The examples are templates, not valid production DNS values.

`ttl: 1` means automatic TTL. Record types have different requirements; Cloudflare may reject data that does not meet its API schema.

## Security notes

- Never commit real bot tokens, Cloudflare API tokens, administrator IDs, or webhook secrets.
- Use least-privilege API permissions and limit the token to the intended zones when possible.
- Review the code before deploying it to an account containing production DNS records.
- Deleting or changing DNS records can disrupt websites, email, DNSSEC, and other services.
- This project is provided as-is and has not been independently audited.

## Project layout

```text
cloudflare-dns-telegram-bot/
├── src/
│   └── worker.js
├── .dev.vars.example
├── .gitignore
├── LICENSE
├── README.md
└── wrangler.toml
```

## License

MIT. See `LICENSE`.
