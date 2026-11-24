# Notification provider contracts

This note records the official API contracts used by the outgoing notification adapters. Provider credentials are stored inside the existing encrypted endpoint configuration; they are not included in API responses.

## Telegram Bot API

The API request URL is `https://api.telegram.org/bot<TOKEN>/METHOD_NAME`; the integration calls `sendMessage` with a JSON body containing `chat_id` and `text`. Telegram's response is a JSON object with a boolean `ok`, so a 2xx response with `ok: false` is not considered delivered. The bot token belongs in encrypted configuration, not in application logs or API responses.

Official sources: [Bot API request format and response](https://core.telegram.org/bots/api), [sendMessage fields](https://core.telegram.org/bots/api/methods/sendmessage).

## Slack incoming webhooks

Slack creates a secret incoming-webhook URL under `https://hooks.slack.com/services/...`. The adapter sends a JSON `text` payload. The documented normal success response is HTTP 200 with the plain-text body `ok`; both are checked before an outbox item is marked delivered.

Official source: [Sending messages using incoming webhooks](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks).

## Discord webhooks

The adapter executes a webhook by posting to the secret URL under `https://discord.com/api/webhooks/{id}/{token}` with a JSON `content` field. Discord allows `content` up to 2,000 characters and can return `204 No Content` when `wait` is not enabled. The payload sets `allowed_mentions.parse` to an empty list so alert text cannot trigger unintended mentions.

Official source: [Discord Webhook resource — Execute Webhook](https://docs.discord.com/developers/resources/webhook).

## Security and delivery notes

Slack and Discord URLs are restricted to their official webhook host and expected path shape. Telegram uses the fixed `api.telegram.org` host and a bot token validated before use. Every request still applies the existing HTTPS/public-DNS check, DNS address pinning, proxy disabling, redirect disabling, timeout, and outbox retry behavior. No live provider message was sent during tests; provider request payloads and response rules are checked locally.
