const API = "https://api.cloudflare.com/client/v4";

const TYPES = [
  "A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "CAA",
  "HTTPS", "DS", "TLSA", "CERT", "SMIMEA", "URI",
  "OPENPGPKEY", "LOC", "SSHFP", "SVCB", "PTR", "NAPTR"
];

const TEMPLATES = {
  A: { content: "192.0.2.10", proxied: false },
  AAAA: { content: "2001:db8::1", proxied: false },
  CNAME: { content: "target.example.net", proxied: false },
  TXT: { content: "example verification text" },
  MX: { content: "mail.example.net", priority: 10 },
  NS: { content: "ns1.example.net" },
  SRV: { data: { priority: 10, weight: 5, port: 5060, target: "server.example.net" } },
  CAA: { data: { flags: 0, tag: "issue", value: "letsencrypt.org" } },
  HTTPS: { data: { priority: 1, target: ".", value: "alpn=h2" } },
  SVCB: { data: { priority: 1, target: ".", value: "alpn=h2" } },
  DS: { data: { key_tag: 12345, algorithm: 13, digest_type: 2, digest: "REPLACE_WITH_REAL_DIGEST" } },
  TLSA: { data: { usage: 3, selector: 1, matching_type: 1, certificate: "REPLACE_WITH_REAL_HEX_DIGEST" } },
  CERT: { data: { type: 1, key_tag: 12345, algorithm: 8, certificate: "REPLACE_WITH_CERTIFICATE_DATA" } },
  SMIMEA: { data: { usage: 3, selector: 1, matching_type: 1, certificate: "REPLACE_WITH_REAL_HEX_DIGEST" } },
  URI: { data: { priority: 10, weight: 1, target: "https://example.net/" } },
  OPENPGPKEY: { content: "REPLACE_WITH_OPENPGPKEY_DATA" },
  LOC: {
    data: {
      lat_degrees: 37, lat_minutes: 46, lat_seconds: 29,
      lat_direction: "N",
      long_degrees: 122, long_minutes: 25, long_seconds: 9,
      long_direction: "W",
      altitude: 10, size: 1, precision_horz: 10000,
      precision_vert: 10
    }
  },
  SSHFP: { data: { algorithm: 4, type: 2, fingerprint: "REPLACE_WITH_REAL_FINGERPRINT" } },
  PTR: { content: "host.example.net" },
  NAPTR: {
    data: {
      order: 100, preference: 10, flags: "S",
      service: "SIP+D2U", regex: "", replacement: "_sip._udp.example.net"
    }
  }
};

const ALLOWED_FIELDS = new Set([
  "type", "name", "content", "data", "ttl", "proxied",
  "priority", "comment", "tags"
]);

const DATA_FIELDS = {
  SRV: ["priority", "weight", "port", "target"],
  CAA: ["flags", "tag", "value"],
  HTTPS: ["priority", "target", "value"],
  SVCB: ["priority", "target", "value"],
  DS: ["key_tag", "algorithm", "digest_type", "digest"],
  TLSA: ["usage", "selector", "matching_type", "certificate"],
  SMIMEA: ["usage", "selector", "matching_type", "certificate"],
  CERT: ["type", "key_tag", "algorithm", "certificate"],
  SSHFP: ["algorithm", "type", "fingerprint"],
  URI: ["priority", "weight", "target"],
  NAPTR: ["order", "preference", "flags", "service", "regex", "replacement"],
  LOC: [
    "lat_degrees", "lat_minutes", "lat_seconds", "lat_direction",
    "long_degrees", "long_minutes", "long_seconds", "long_direction",
    "altitude", "size", "precision_horz", "precision_vert"
  ]
};

const DATA_REQUIRED = {
  SRV: ["priority", "weight", "port", "target"],
  CAA: ["flags", "tag", "value"],
  HTTPS: ["priority", "target"],
  SVCB: ["priority", "target"],
  DS: ["key_tag", "algorithm", "digest_type", "digest"],
  TLSA: ["usage", "selector", "matching_type", "certificate"],
  SMIMEA: ["usage", "selector", "matching_type", "certificate"],
  CERT: ["type", "key_tag", "algorithm", "certificate"],
  SSHFP: ["algorithm", "type", "fingerprint"],
  URI: ["target", "weight"],
  NAPTR: ["order", "preference", "flags", "service", "replacement"],
  LOC: [
    "lat_degrees", "lat_minutes", "lat_seconds", "lat_direction",
    "long_degrees", "long_minutes", "long_seconds", "long_direction"
  ]
};

const CONTENT_REQUIRED = new Set([
  "A", "AAAA", "CNAME", "TXT", "MX", "NS",
  "PTR", "OPENPGPKEY"
]);

const SENSITIVE_TYPES = new Set(["NS", "DS", "CAA"]);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname !== "/telegram") {
      return new Response("Not found", { status: 404 });
    }

    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }

    const webhookSecret = request.headers.get(
      "X-Telegram-Bot-Api-Secret-Token"
    );

    if (
      !env.TELEGRAM_WEBHOOK_SECRET ||
      webhookSecret !== env.TELEGRAM_WEBHOOK_SECRET
    ) {
      return new Response("Unauthorized", { status: 401 });
    }

    let update;
    try {
      update = await request.json();
    } catch {
      return new Response("Bad JSON", { status: 400 });
    }

    const message = update.message;
    const callback = update.callback_query;
    const chatId = message?.chat?.id ?? callback?.message?.chat?.id;
    const userId = message?.from?.id ?? callback?.from?.id;

    if (!chatId || !userId) return new Response("OK");

    if (String(userId) !== String(env.TELEGRAM_ADMIN_ID)) {
      if (callback) {
        await answerCallback(env, callback.id, "دسترسی غیرمجاز");
      }
      return new Response("OK");
    }

    try {
      if (message?.text === "/start") {
        await mainMenu(env, chatId);
        return new Response("OK");
      }

      // Process only replies to prompts issued by this bot.
      if (message?.text && message.reply_to_message?.text) {
        const prompt = message.reply_to_message.text;
        const marker = prompt.match(
          /\[\[DNSBOT:(ADD|EDIT):([a-f0-9]{32}):([A-Z]+)(?::([a-f0-9]{32}))?\]\]/i
        );

        if (marker) {
          const [, action, zoneId, type, recordId] = marker;
          if (!TYPES.includes(type)) {
            await sendMessage(env, chatId, "نوع رکورد معتبر نیست.");
            return new Response("OK");
          }

          let submitted;
          try {
            submitted = JSON.parse(message.text);
          } catch {
            await sendMessage(
              env, chatId,
              "JSON معتبر نیست. به پیام قالب پاسخ بده و یک JSON معتبر بفرست."
            );
            return new Response("OK");
          }

          if (!isPlainObject(submitted)) {
            await sendMessage(env, chatId, "ورودی باید یک شیء JSON باشد.");
            return new Response("OK");
          }

          const zone = await getZone(env, zoneId);
          if (!zone) {
            await sendMessage(env, chatId, "دامنه معتبر نیست.");
            return new Response("OK");
          }

          if (action === "ADD") {
            const payload = buildPayload(type, zone.name, submitted);
            const result = await cfRequest(
              env, "POST", `/zones/${zoneId}/dns_records`, payload
            );
            await sendMessage(env, chatId, `✅ رکورد ایجاد شد.\n\n${formatRecord(result)}`);
          } else {
            if (!recordId) {
              await sendMessage(env, chatId, "شناسه رکورد موجود نیست.");
              return new Response("OK");
            }

            const existing = await getRecord(env, zoneId, recordId);
            if (!existing || existing.type !== type) {
              await sendMessage(env, chatId, "رکورد دیگر موجود نیست یا نوع آن تغییر کرده است.");
              return new Response("OK");
            }

            const patch = buildPatch(type, zone.name, submitted);
            const result = await cfRequest(
              env, "PATCH", `/zones/${zoneId}/dns_records/${recordId}`, patch
            );
            await sendMessage(env, chatId, `✅ رکورد ویرایش شد.\n\n${formatRecord(result)}`);
          }
          return new Response("OK");
        }
      }

      if (!callback) return new Response("OK");

      await answerCallback(env, callback.id);
      const data = callback.data || "";

      if (data === "menu") {
        await mainMenu(env, chatId);
      } else if (data === "zones") {
        await showZones(env, chatId);
      } else if (data.startsWith("zone:")) {
        const zoneId = data.slice(5);
        const zone = await getZone(env, zoneId);
        if (!zone) {
          await sendMessage(env, chatId, "دامنه معتبر نیست.");
        } else {
          await showZoneMenu(env, chatId, zone);
        }
      } else if (data.startsWith("records:")) {
        const [, zoneId, pageText] = data.split(":");
        await showRecords(env, chatId, zoneId, Number(pageText || 1));
      } else if (data.startsWith("add:")) {
        const zoneId = data.slice(4);
        const zone = await getZone(env, zoneId);
        if (!zone) {
          await sendMessage(env, chatId, "دامنه معتبر نیست.");
        } else {
          await showTypes(env, chatId, zoneId);
        }
      } else if (data.startsWith("type:")) {
        const [, zoneId, type] = data.split(":");
        const zone = await getZone(env, zoneId);
        if (!zone || !TYPES.includes(type)) {
          await sendMessage(env, chatId, "دامنه یا نوع رکورد معتبر نیست.");
        } else {
          await promptAdd(env, chatId, zone, type);
        }
      } else if (data.startsWith("record:")) {
        const recordId = data.slice(7);
        const found = await findRecord(env, recordId);
        if (!found) {
          await sendMessage(env, chatId, "رکورد پیدا نشد.");
        } else {
          await showRecordMenu(env, chatId, found.zone, found.record);
        }
      } else if (data.startsWith("edit:")) {
        const recordId = data.slice(5);
        const found = await findRecord(env, recordId);
        if (!found) {
          await sendMessage(env, chatId, "رکورد پیدا نشد.");
        } else {
          await promptEdit(env, chatId, found.zone, found.record);
        }
      } else if (data.startsWith("delete:")) {
        const recordId = data.slice(7);
        const found = await findRecord(env, recordId);
        if (!found) {
          await sendMessage(env, chatId, "رکورد پیدا نشد.");
        } else {
          await promptDelete(env, chatId, found.zone, found.record);
        }
      } else if (data.startsWith("D:")) {
        await confirmDelete(env, chatId, data);
      } else if (data === "cancel") {
        await sendMessage(env, chatId, "عملیات لغو شد.");
      }
    } catch (error) {
      console.error("Worker operation failed", { message: String(error?.message || error) });
      await sendMessage(env, chatId, "عملیات انجام نشد. لاگ Worker را بررسی کن.");
    }

    return new Response("OK");
  }
};

async function cfRequest(env, method, path, payload) {
  const options = {
    method,
    headers: {
      Authorization: `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
      "Content-Type": "application/json"
    }
  };
  if (payload !== undefined) options.body = JSON.stringify(payload);

  const response = await fetch(`${API}${path}`, options);
  const body = await response.json().catch(() => ({}));

  if (!response.ok || !body.success) {
    console.error("Cloudflare API error", {
      method, path, status: response.status, errors: body.errors
    });
    throw new Error("Cloudflare API request failed");
  }
  return body.result;
}

async function getZones(env) {
  const zones = [];
  let page = 1;
  while (page <= 20) {
    const result = await cfRequest(env, "GET", `/zones?per_page=50&page=${page}`);
    zones.push(...result);
    if (result.length < 50) break;
    page++;
  }
  return zones;
}

async function getZone(env, zoneId) {
  if (!/^[a-f0-9]{32}$/i.test(zoneId)) return null;
  return (await getZones(env)).find(z => z.id === zoneId) || null;
}

async function getRecords(env, zoneId, page = 1) {
  return cfRequest(env, "GET", `/zones/${zoneId}/dns_records?per_page=100&page=${page}`);
}

async function getRecord(env, zoneId, recordId) {
  if (!/^[a-f0-9]{32}$/i.test(recordId)) return null;
  try {
    return await cfRequest(env, "GET", `/zones/${zoneId}/dns_records/${recordId}`);
  } catch {
    return null;
  }
}

async function findRecord(env, recordId) {
  if (!/^[a-f0-9]{32}$/i.test(recordId)) return null;
  const zones = await getZones(env);
  for (const zone of zones) {
    const record = await getRecord(env, zone.id, recordId);
    if (record) return { zone, record };
  }
  return null;
}

function buildPayload(type, zoneName, input) {
  for (const key of Object.keys(input)) {
    if (!ALLOWED_FIELDS.has(key)) throw new Error(`Unsupported field: ${key}`);
  }

  const name = normalizeName(input.name, zoneName);

  if (CONTENT_REQUIRED.has(type) &&
      (typeof input.content !== "string" || !input.content.trim())) {
    throw new Error("content is required");
  }

  if (DATA_REQUIRED[type]) {
    if (!isPlainObject(input.data)) throw new Error("data object is required");
    for (const key of DATA_REQUIRED[type]) {
      if (input.data[key] === undefined || input.data[key] === "") {
        throw new Error(`Missing data.${key}`);
      }
    }
    const allowed = DATA_FIELDS[type] || [];
    for (const key of Object.keys(input.data)) {
      if (!allowed.includes(key)) throw new Error(`Unsupported data field: ${key}`);
    }
  }

  validateType(type, input);

  const payload = { type, name, ttl: validateTTL(input.ttl) };
  if (input.content !== undefined) payload.content = input.content;
  if (input.data !== undefined) payload.data = input.data;
  if (input.priority !== undefined) payload.priority = Number(input.priority);

  if (input.proxied !== undefined) {
    if (!["A", "AAAA", "CNAME"].includes(type)) {
      throw new Error("Proxy is only configurable here for A, AAAA and CNAME.");
    }
    if (typeof input.proxied !== "boolean") throw new Error("proxied must be true or false.");
    payload.proxied = input.proxied;
  }
  if (input.comment !== undefined) payload.comment = String(input.comment);
  if (input.tags !== undefined) {
    if (!Array.isArray(input.tags)) throw new Error("tags must be an array.");
    payload.tags = input.tags;
  }
  return payload;
}

function buildPatch(type, zoneName, input) {
  for (const key of Object.keys(input)) {
    if (!ALLOWED_FIELDS.has(key) || key === "type") {
      throw new Error(`Unsupported update field: ${key}`);
    }
  }

  const patch = {};
  if (input.name !== undefined) patch.name = normalizeName(input.name, zoneName);
  if (input.ttl !== undefined) patch.ttl = validateTTL(input.ttl);
  if (input.content !== undefined) patch.content = input.content;
  if (input.priority !== undefined) patch.priority = Number(input.priority);
  if (input.comment !== undefined) patch.comment = String(input.comment);
  if (input.tags !== undefined) {
    if (!Array.isArray(input.tags)) throw new Error("tags must be an array.");
    patch.tags = input.tags;
  }
  if (input.proxied !== undefined) {
    if (!["A", "AAAA", "CNAME"].includes(type)) {
      throw new Error("Proxy is not supported for this type in this bot.");
    }
    if (typeof input.proxied !== "boolean") throw new Error("proxied must be true or false.");
    patch.proxied = input.proxied;
  }
  if (input.data !== undefined) {
    if (!isPlainObject(input.data)) throw new Error("data must be an object.");
    const allowed = DATA_FIELDS[type] || [];
    for (const key of Object.keys(input.data)) {
      if (!allowed.includes(key)) throw new Error(`Unsupported data field: ${key}`);
    }
    patch.data = input.data;
  }

  if (input.content === undefined && input.data === undefined &&
      input.name === undefined && input.ttl === undefined &&
      input.priority === undefined && input.proxied === undefined &&
      input.comment === undefined && input.tags === undefined) {
    throw new Error("No fields to update.");
  }

  validateType(type, input);
  return patch;
}

function validateType(type, input) {
  if (input.priority !== undefined) validateInteger(input.priority, 0, 65535, "priority");

  if (input.data && DATA_FIELDS[type]) {
    for (const key of Object.keys(input.data)) {
      if (["priority", "weight", "port", "flags", "key_tag",
        "algorithm", "digest_type", "usage", "selector",
        "matching_type", "type", "order", "preference",
        "lat_degrees", "lat_minutes", "long_degrees", "long_minutes"].includes(key)) {
        validateInteger(input.data[key], 0, 65535, `data.${key}`);
      }
    }
  }

  if (type === "A" && input.content && !isIPv4(input.content)) {
    throw new Error("Invalid IPv4 address.");
  }
  if (type === "AAAA" && input.content && !isIPv6(input.content)) {
    throw new Error("Invalid IPv6 address.");
  }
}

function normalizeName(name, zoneName) {
  if (typeof name !== "string" || !name.trim()) throw new Error("name is required");
  name = name.trim().replace(/\.$/, "");
  if (name === "@") return zoneName;

  const lowerName = name.toLowerCase();
  const lowerZone = zoneName.toLowerCase();

  if (lowerName !== lowerZone && !lowerName.endsWith(`.${lowerZone}`)) {
    if (name.includes(".")) {
      throw new Error("Record name is outside this zone.");
    }
    name = `${name}.${zoneName}`;
  }

  if (name.length > 255 || /[\s/\\]/.test(name)) throw new Error("Invalid DNS name.");
  return name;
}

function validateTTL(ttl) {
  if (ttl === undefined || ttl === null || ttl === 1 || ttl === "1") return 1;
  const n = Number(ttl);
  if (!Number.isInteger(n) || n < 60 || n > 86400) {
    throw new Error("TTL must be 1 (automatic) or between 60 and 86400.");
  }
  return n;
}

function validateInteger(value, min, max, label) {
  if (!Number.isInteger(Number(value)) || Number(value) < min || Number(value) > max) {
    throw new Error(`Invalid ${label}.`);
  }
}

function isIPv4(value) {
  const p = value.split(".");
  return p.length === 4 && p.every(
    x => /^\d{1,3}$/.test(x) && Number(x) >= 0 && Number(x) <= 255
  );
}

function isIPv6(value) {
  return value.includes(":") && /^[0-9a-fA-F:.]+$/.test(value);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

async function mainMenu(env, chatId) {
  await sendMessage(env, chatId, "مدیریت DNS کلادفلر", {
    inline_keyboard: [[{ text: "🌐 فهرست دامنه‌ها", callback_data: "zones" }]]
  });
}

async function showZones(env, chatId) {
  const zones = await getZones(env);
  const buttons = zones.map(z => [{ text: z.name, callback_data: `zone:${z.id}` }]);
  buttons.push([{ text: "🔄 به‌روزرسانی", callback_data: "zones" }]);
  await sendMessage(env, chatId,
    zones.length ? "دامنه موردنظر را انتخاب کن:" : "دامنه‌ای پیدا نشد.",
    { inline_keyboard: buttons });
}

async function showZoneMenu(env, chatId, zone) {
  await sendMessage(env, chatId, `دامنه: ${zone.name}`, {
    inline_keyboard: [
      [{ text: "📋 مشاهده رکوردها", callback_data: `records:${zone.id}:1` }],
      [{ text: "➕ افزودن رکورد", callback_data: `add:${zone.id}` }],
      [{ text: "⬅️ دامنه‌ها", callback_data: "zones" }]
    ]
  });
}

async function showRecords(env, chatId, zoneId, page) {
  if (!Number.isInteger(page) || page < 1) page = 1;
  const zone = await getZone(env, zoneId);
  if (!zone) {
    await sendMessage(env, chatId, "دامنه معتبر نیست.");
    return;
  }

  const records = await getRecords(env, zoneId, page);
  const buttons = records.map(r => [{
    text: `${r.type} | ${r.name}`.slice(0, 60),
    callback_data: `record:${r.id}`
  }]);

  const nav = [];
  if (page > 1) nav.push({ text: "⬅️ قبلی", callback_data: `records:${zoneId}:${page - 1}` });
  if (records.length === 100) nav.push({ text: "بعدی ➡️", callback_data: `records:${zoneId}:${page + 1}` });
  if (nav.length) buttons.push(nav);
  buttons.push([{ text: "➕ افزودن", callback_data: `add:${zoneId}` }]);
  buttons.push([{ text: "⬅️ بازگشت", callback_data: `zone:${zoneId}` }]);

  await sendMessage(env, chatId,
    records.length ? `رکوردهای ${zone.name} — صفحه ${page}\nبرای مشاهده یا مدیریت روی رکورد بزن.` : "در این صفحه رکوردی وجود ندارد.",
    { inline_keyboard: buttons });
}

async function showTypes(env, chatId, zoneId) {
  const buttons = [];
  for (let i = 0; i < TYPES.length; i += 2) {
    buttons.push(TYPES.slice(i, i + 2).map(type => ({
      text: type, callback_data: `type:${zoneId}:${type}`
    })));
  }
  buttons.push([{ text: "⬅️ بازگشت", callback_data: `zone:${zoneId}` }]);
  await sendMessage(env, chatId, "نوع رکورد را انتخاب کن:", { inline_keyboard: buttons });
}

async function promptAdd(env, chatId, zone, type) {
  const template = { name: "www", ...TEMPLATES[type], ttl: 1 };
  const marker = `[[DNSBOT:ADD:${zone.id}:${type}]]`;
  await sendMessage(env, chatId,
    `افزودن رکورد ${type} به ${zone.name}\n\nبه این پیام Reply بده و JSON را با مقادیر واقعی جایگزین کن:\n\n${JSON.stringify(template, null, 2)}\n\nنام @ یعنی دامنه اصلی. TTL=1 یعنی Automatic.\n${marker}`,
    { force_reply: true });
}

async function promptEdit(env, chatId, zone, record) {
  const editable = { name: record.name, ttl: record.ttl };
  if (record.content !== undefined) editable.content = record.content;
  if (record.data !== undefined) editable.data = record.data;
  if (record.priority !== undefined) editable.priority = record.priority;
  if (record.proxied !== undefined) editable.proxied = record.proxied;
  if (record.comment !== undefined) editable.comment = record.comment;

  const marker = `[[DNSBOT:EDIT:${zone.id}:${record.type}:${record.id}]]`;
  await sendMessage(env, chatId,
    `ویرایش رکورد ${record.type}\n${record.name}\n\nبه این پیام Reply بده و فقط فیلدهایی را که می‌خواهی تغییر دهی، به شکل JSON ارسال کن.\n\n${JSON.stringify(editable, null, 2)}\n\n${marker}`,
    { force_reply: true });
}

async function showRecordMenu(env, chatId, zone, record) {
  await sendMessage(env, chatId, `رکورد انتخاب‌شده:\n\n${formatRecord(record)}`, {
    inline_keyboard: [
      [{ text: "✏️ ویرایش", callback_data: `edit:${record.id}` }],
      [{ text: "🗑 حذف", callback_data: `delete:${record.id}` }],
      [{ text: "📋 بازگشت به رکوردها", callback_data: `records:${zone.id}:1` }]
    ]
  });
}

async function promptDelete(env, chatId, zone, record) {
  const expires = Math.floor(Date.now() / 1000) + 300;
  const signature = await signDelete(env, record.id, expires);
  const callbackData = `D:${record.id}:${expires}:${signature}`;
  const warning = SENSITIVE_TYPES.has(record.type)
    ? "\n⚠️ هشدار: این نوع رکورد ممکن است روی DNS، DNSSEC یا صدور گواهی اثر بگذارد."
    : "";

  await sendMessage(env, chatId,
    `⚠️ آیا واقعاً می‌خواهی این رکورد را حذف کنی؟\n\n${formatRecord(record)}${warning}\n\nاین تأیید تا ۵ دقیقه معتبر است.`,
    { inline_keyboard: [
      [{ text: "🗑 تأیید حذف", callback_data: callbackData }],
      [{ text: "❌ لغو", callback_data: "cancel" }]
    ] });
}

async function confirmDelete(env, chatId, data) {
  const parts = data.split(":");
  if (parts.length !== 4) {
    await sendMessage(env, chatId, "تأیید حذف معتبر نیست.");
    return;
  }

  const [, recordId, expiresText, signature] = parts;
  const expires = Number(expiresText);
  if (!/^[a-f0-9]{32}$/i.test(recordId) ||
      !Number.isInteger(expires) ||
      expires < Math.floor(Date.now() / 1000)) {
    await sendMessage(env, chatId, "تأیید حذف منقضی شده است.");
    return;
  }

  const expected = await signDelete(env, recordId, expires);
  if (!constantTimeEqual(signature, expected)) {
    await sendMessage(env, chatId, "امضای تأیید حذف معتبر نیست.");
    return;
  }

  const found = await findRecord(env, recordId);
  if (!found) {
    await sendMessage(env, chatId, "این رکورد دیگر وجود ندارد.");
    return;
  }

  const current = await getRecord(env, found.zone.id, recordId);
  if (!current) {
    await sendMessage(env, chatId, "رکورد قبلاً حذف شده است.");
    return;
  }

  await cfRequest(env, "DELETE", `/zones/${found.zone.id}/dns_records/${recordId}`);
  await sendMessage(env, chatId, "✅ درخواست حذف با موفقیت انجام شد.");
}

async function signDelete(env, recordId, expires) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(env.TELEGRAM_WEBHOOK_SECRET),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC", key, new TextEncoder().encode(`${recordId}:${expires}`)
  );
  return base64url(new Uint8Array(signature)).slice(0, 16);
}

function base64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function formatRecord(record) {
  const lines = [
    `نوع: ${record.type}`, `نام: ${record.name}`,
    `مقدار: ${record.content ?? JSON.stringify(record.data ?? {})}`,
    `TTL: ${record.ttl}`, `ID: ${record.id}`
  ];
  if (record.priority !== undefined) lines.push(`Priority: ${record.priority}`);
  if (record.proxied !== undefined) lines.push(`Proxy: ${record.proxied ? "روشن" : "خاموش"}`);
  return lines.join("\n");
}

async function sendMessage(env, chatId, text, replyMarkup) {
  const response = await fetch(
    `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        text: String(text).slice(0, 3900),
        ...(replyMarkup ? { reply_markup: replyMarkup } : {})
      })
    }
  );

  if (!response.ok) console.error("Telegram sendMessage failed", { status: response.status });
}

async function answerCallback(env, callbackId, text = "") {
  await fetch(
    `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/answerCallbackQuery`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        callback_query_id: callbackId,
        ...(text ? { text } : {})
      })
    }
  );
}
