import assert from 'node:assert/strict';
import test from 'node:test';

import worker from '../src/index.js';
import {
  buildDiscordAlertEmbed,
  buildProgressBar,
  buildStatusCommandEmbed,
  DISCORD_EXPIRE_REFRESH_ID,
  DISCORD_NODE_REFRESH_PREFIX,
  DISCORD_PING_REFRESH_PREFIX,
  DISCORD_SIGNATURE_MAX_AGE_SECONDS,
  DISCORD_SLASH_COMMANDS,
  DISCORD_STATUS_REFRESH_ID,
  DISCORD_TRAFFIC_REFRESH_ID,
  getLoadLevelIcon,
  handleDiscordInteraction,
  isAuthorizedDiscordInteraction,
  sendDiscordBotNotification,
  verifyDiscordSignature
} from '../src/services/discord.js';
import { handleAdminAPI } from '../src/handlers/admin.js';
import { generateToken } from '../src/middleware/auth.js';
import { sendNotification } from '../src/services/notification.js';
import { clearAllCaches } from '../src/utils/cache.js';
import { clearAppearanceSettingsCache, clearSiteSettingsCache } from '../src/utils/settings.js';

function bytesToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function createEd25519TestKeys() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify']
  );
  const rawPub = await crypto.subtle.exportKey('raw', keyPair.publicKey);
  return {
    privateKey: keyPair.privateKey,
    publicKeyHex: bytesToHex(rawPub)
  };
}

async function signInteraction(privateKey, timestamp, rawBody) {
  const payload = new TextEncoder().encode(`${timestamp}${rawBody}`);
  const sig = await crypto.subtle.sign('Ed25519', privateKey, payload);
  return bytesToHex(sig);
}

function makeDiscordMockDb({ servers = [], metricsById = new Map(), settings = {}, appearance = null } = {}) {
  return {
    prepare(sql) {
      return {
        args: [],
        bind(...args) { this.args = args; return this; },
        async first() {
          if (sql.includes("key = 'site_options'")) {
            return { value: JSON.stringify(settings) };
          }
          if (sql.includes("key = 'appearance_options'") && appearance) {
            return { value: JSON.stringify(appearance) };
          }
          return null;
        },
        async all() {
          if (sql.includes('FROM servers')) {
            return { results: servers };
          }
          return { results: [] };
        },
        async run() {
          return { success: true, meta: { changes: 1 } };
        }
      };
    },
    async batch(statements) {
      return statements.map(stmt => {
        const startId = Number(stmt.args?.[0] || 0);
        const partition = Math.floor(startId / 10_000_000_000_000);
        const server = servers.find(item => Number(item.history_partition_id) === partition);
        const row = server ? metricsById.get(server.id) : null;
        return { results: row ? [row] : [] };
      });
    }
  };
}

test('Ed25519 signature verification validates valid signatures and rejects tampered payloads or stale timestamps', async () => {
  const { privateKey, publicKeyHex } = await createEd25519TestKeys();
  const nowSec = Math.floor(Date.now() / 1000);
  const timestamp = String(nowSec);
  const rawBody = JSON.stringify({ type: 1 });
  const signature = await signInteraction(privateKey, timestamp, rawBody);

  assert.equal(await verifyDiscordSignature(rawBody, signature, timestamp, publicKeyHex), true);
  assert.equal(await verifyDiscordSignature('{"type":2}', signature, timestamp, publicKeyHex), false);
  assert.equal(await verifyDiscordSignature(rawBody, '00'.repeat(64), timestamp, publicKeyHex), false);
  assert.equal(await verifyDiscordSignature(rawBody, signature, '', publicKeyHex), false);
  assert.equal(await verifyDiscordSignature(rawBody, signature, timestamp, 'invalid-hex'), false);

  const staleTs = String(nowSec - DISCORD_SIGNATURE_MAX_AGE_SECONDS - 1);
  const staleSig = await signInteraction(privateKey, staleTs, rawBody);
  assert.equal(await verifyDiscordSignature(rawBody, staleSig, staleTs, publicKeyHex, { now: nowSec * 1000 }), false);

  const futureTs = String(nowSec + DISCORD_SIGNATURE_MAX_AGE_SECONDS + 1);
  const futureSig = await signInteraction(privateKey, futureTs, rawBody);
  assert.equal(await verifyDiscordSignature(rawBody, futureSig, futureTs, publicKeyHex, { now: nowSec * 1000 }), false);

  const nonDigitTs = `${timestamp}abc`;
  const nonDigitSig = await signInteraction(privateKey, nonDigitTs, rawBody);
  assert.equal(await verifyDiscordSignature(rawBody, nonDigitSig, nonDigitTs, publicKeyHex, { now: nowSec * 1000 }), false);
});

test('POST /api/discord/interactions bypasses Turnstile & JWT, rejects invalid sig with 401, and responds to PING', async () => {
  clearAllCaches();
  const { privateKey, publicKeyHex } = await createEd25519TestKeys();
  const db = makeDiscordMockDb({
    settings: {
      jwt_secret: 'x'.repeat(32),
      turnstile_enabled: 'true',
      turnstile_secret_key: 'turnstile-secret'
    }
  });
  const env = {
    API_SECRET: 'test-secret',
    DISCORD_PUBLIC_KEY: publicKeyHex,
    DB: db
  };

  // Invalid signature -> 401
  const badReq = new Request('https://monitor.example.com/api/discord/interactions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Signature-Ed25519': 'ab'.repeat(64),
      'X-Signature-Timestamp': '1700000000'
    },
    body: JSON.stringify({ type: 1 })
  });
  const badRes = await worker.fetch(badReq, env, { waitUntil() {} });
  assert.equal(badRes.status, 401);

  // Valid PING -> 200 { type: 1 }
  const pingBody = JSON.stringify({ type: 1 });
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = await signInteraction(privateKey, ts, pingBody);
  const pingReq = new Request('https://monitor.example.com/api/discord/interactions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Signature-Ed25519': sig,
      'X-Signature-Timestamp': ts
    },
    body: pingBody
  });
  const pingRes = await worker.fetch(pingReq, env, { waitUntil() {} });
  assert.equal(pingRes.status, 200);
  assert.deepEqual(await pingRes.json(), { type: 1 });
});

test('/status slash command returns Embeds for non-hidden servers and omits hidden nodes', async () => {
  clearAllCaches();
  const { privateKey, publicKeyHex } = await createEd25519TestKeys();
  const now = Date.now();
  const servers = [
    { id: 'srv-1', name: 'Tokyo-01', region: 'jp', is_hidden: '0', sort_order: 0, history_partition_id: 1, timestamp: 0 },
    { id: 'srv-2', name: 'US-02', region: 'us', is_hidden: '0', sort_order: 1, history_partition_id: 2, timestamp: 0 },
    { id: 'srv-hidden', name: 'Secret-Node', region: 'sg', is_hidden: '1', sort_order: 2, history_partition_id: 3, timestamp: 0 }
  ];
  const metricsById = new Map([
    ['srv-1', {
      timestamp: now - 15_000,
      cpu: 35.4,
      ram_used: 2048,
      ram_total: 4096,
      net_in_speed: 1024 * 1024,
      net_out_speed: 512 * 1024,
      uptime: 90060
    }],
    ['srv-2', {
      timestamp: now - 900_000, // 15 minutes ago -> offline
      cpu: 0,
      ram_used: 0,
      ram_total: 2048,
      net_in_speed: 0,
      net_out_speed: 0,
      uptime: 0
    }],
    ['srv-hidden', {
      timestamp: now - 10_000,
      cpu: 99,
      ram_used: 1000,
      ram_total: 1000
    }]
  ]);

  const db = makeDiscordMockDb({
    servers,
    metricsById,
    settings: { notification_language: 'en' }
  });
  clearSiteSettingsCache();
  clearAppearanceSettingsCache();
  const env = { DISCORD_PUBLIC_KEY: publicKeyHex, DB: db };
  const body = JSON.stringify({ type: 2, data: { name: 'status' } });
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = await signInteraction(privateKey, ts, body);

  const response = await handleDiscordInteraction(new Request('https://monitor.example.com/api/discord/interactions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Signature-Ed25519': sig,
      'X-Signature-Timestamp': ts
    },
    body
  }), env);

  assert.equal(response.status, 200);
  const json = await response.json();
  assert.equal(json.type, 4);
  assert.equal(json.data.embeds.length, 1);

  const embed = json.data.embeds[0];
  assert.match(embed.title, /Server Status Overview/);
  assert.match(embed.description, /Total: \*\*2\*\* \| 🟢 Online: \*\*1\*\* \| 🔴 Offline: \*\*1\*\*/);
  assert.equal(embed.fields.length, 2);
  assert.equal(embed.fields[0].inline, true);
  assert.match(embed.fields[0].name, /Tokyo-01 \[JP\]/);
  assert.match(embed.fields[0].value, /`CPU` ▰▰▱▱▱ \*\*35\.4%\*\*/);
  assert.match(embed.fields[0].value, /`RAM` ▰▰▰▱▱ \*\*50\.0%\*\*/);
  assert.match(embed.fields[0].value, /↓1\.0M/);
  assert.match(embed.fields[0].value, /1d 1h/);
  // US-02 already starts with "US-", so duplicate [US] tag is omitted
  assert.equal(embed.fields[1].name, '🔴 US-02');
  assert.match(embed.fields[1].value, /Offline/);

  // Refresh button Action Row is attached
  assert.equal(json.data.components.length, 1);
  assert.equal(json.data.components[0].type, 1);
  assert.equal(json.data.components[0].components[0].custom_id, DISCORD_STATUS_REFRESH_ID);
  assert.equal(json.data.components[0].components[0].label, 'Refresh');
});

test('progress bars, high-load alerts, and Refresh button (type 3 -> type 7 UPDATE_MESSAGE) work properly', async () => {
  assert.equal(buildProgressBar(0), '▱▱▱▱▱');
  assert.equal(buildProgressBar(50), '▰▰▰▱▱');
  assert.equal(buildProgressBar(91.1), '▰▰▰▰▰');
  assert.equal(buildProgressBar(50, 8), '▰▰▰▰▱▱▱▱');
  assert.equal(getLoadLevelIcon(30), '🟢');
  assert.equal(getLoadLevelIcon(70), '🟡');
  assert.equal(getLoadLevelIcon(91.1), '🔴');

  clearAllCaches();
  clearSiteSettingsCache();
  clearAppearanceSettingsCache();
  const { privateKey, publicKeyHex } = await createEd25519TestKeys();
  const now = Date.now();
  const servers = [
    { id: 'srv-hot', name: 'US-Muse', region: 'us', is_hidden: '0', sort_order: 0, history_partition_id: 1, timestamp: 0 }
  ];
  const metricsById = new Map([
    ['srv-hot', { timestamp: now - 5_000, cpu: 2.5, ram_used: 911, ram_total: 1000, net_in_speed: 46, net_out_speed: 91, uptime: 7380 }]
  ]);
  const db = makeDiscordMockDb({
    servers,
    metricsById,
    settings: { notification_language: 'zh' }
  });
  const body = JSON.stringify({
    type: 3,
    data: { custom_id: DISCORD_STATUS_REFRESH_ID, component_type: 2 }
  });
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = await signInteraction(privateKey, ts, body);

  const res = await handleDiscordInteraction(new Request('https://monitor.example.com/api/discord/interactions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Signature-Ed25519': sig, 'X-Signature-Timestamp': ts },
    body
  }), { DISCORD_PUBLIC_KEY: publicKeyHex, DB: db });

  assert.equal(res.status, 200);
  const json = await res.json();
  assert.equal(json.type, 7); // UPDATE_MESSAGE
  assert.equal(json.data.embeds[0].fields[0].name, '🟢 US-Muse ⚠️');
  assert.match(json.data.embeds[0].fields[0].value, /91\.1%\*\* 🔴/);
  assert.equal(json.data.components[0].components[0].label, '刷新');
});

test('Discord Bot outbound notification sends Embed to channel when no user ID is set', async () => {
  const requests = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    requests.push({
      url: String(url),
      method: options.method,
      headers: options.headers,
      body: JSON.parse(options.body)
    });
    return {
      ok: true,
      status: 200,
      headers: new Headers(),
      async json() { return { id: 'msg-1' }; },
      async text() { return ''; }
    };
  };

  try {
    const err = await sendNotification({
      discord_bot_enabled: 'true',
      discord_bot_token: 'Bot secret-bot-token',
      discord_channel_id: '123456789012345678',
      discord_user_id: '',
      notification_language: 'en'
    }, 'Tokyo-01 went offline', {
      event: 'Node Offline Alert',
      emoji: '❌',
      clients: ['Tokyo-01']
    });

    assert.equal(err, undefined);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].url, 'https://discord.com/api/v10/channels/123456789012345678/messages');
    assert.equal(requests[0].headers.Authorization, 'Bot secret-bot-token');
    assert.equal(requests[0].body.embeds.length, 1);
    assert.equal(requests[0].body.embeds[0].color, 0xef4444);
    assert.match(requests[0].body.embeds[0].title, /Node Offline Alert/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('Discord Bot outbound notification prefers DM channel when discord_user_id is configured', async () => {
  const requests = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    const u = String(url);
    requests.push({
      url: u,
      headers: options.headers,
      body: JSON.parse(options.body)
    });
    if (u.endsWith('/users/@me/channels')) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        async json() { return { id: 'dm-channel-999' }; },
        async text() { return ''; }
      };
    }
    return {
      ok: true,
      status: 200,
      headers: new Headers(),
      async json() { return { id: 'msg-dm-1' }; },
      async text() { return ''; }
    };
  };

  try {
    const err = await sendDiscordBotNotification({
      discord_bot_enabled: 'true',
      discord_bot_token: 'dm-test-token',
      discord_channel_id: '123456789012345678',
      discord_user_id: '987654321098765432'
    }, {
      event: 'Node IP Change Alert',
      emoji: '🌐',
      clients: ['HK-01'],
      time: '2026/11/27 12:00:00'
    }, 'HK-01 IPv4: 1.1.1.1 -> 2.2.2.2');

    assert.equal(err, undefined);
    assert.equal(requests.length, 2);
    assert.equal(requests[0].url, 'https://discord.com/api/v10/users/@me/channels');
    assert.deepEqual(requests[0].body, { recipient_id: '987654321098765432' });
    assert.equal(requests[1].url, 'https://discord.com/api/v10/channels/dm-channel-999/messages');
    assert.equal(requests[1].body.embeds[0].color, 0x3b82f6);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('buildDiscordAlertEmbed uses formatted notification template and localized labels', () => {
  const embed = buildDiscordAlertEmbed({
    event: '测试通知',
    emoji: '✅',
    clients: ['Node-1'],
    message: 'raw message',
    time: '2026/11/27 12:00:00'
  }, '自定义通知模板正文', {
    notification_language: 'zh',
    site_title: 'My Monitor'
  });
  assert.equal(embed.color, 0x22c55e);
  assert.equal(embed.description, '自定义通知模板正文');
  assert.equal(embed.fields[0].name, '节点');
  assert.equal(embed.fields[1].name, '事件');
  assert.equal(embed.fields[2].name, '时间');
  assert.equal(embed.footer.text, 'My Monitor');

  // Masked IP asterisks outside code spans/blocks should be escaped so Discord does not render italics
  const maskedEmbed = buildDiscordAlertEmbed({
    event: '节点 IP 变更告警',
    emoji: '🌐',
    clients: ['US-Muse'],
    time: '2026/11/27 17:20:44'
  }, 'US-Muse IPv4: 104.*.*.139 -> 104.*.*.237\nIPv6: 2001:*:*:7334\n`104.*.*.139`\n```text\n104.*.*.139\n```', {
    notification_language: 'zh',
    site_title: 'Yori Monitor'
  });
  assert.match(maskedEmbed.description, /104\\\*\.\\\*\.139 -> 104\\\*\.\\\*\.237|104\.\\\*\.\\\*\.139 -> 104\.\\\*\.\\\*\.237/);
  assert.equal(
    maskedEmbed.description,
    'US-Muse IPv4: 104.\\*.\\*.139 -> 104.\\*.\\*.237\nIPv6: 2001:\\*:\\*:7334\n`104.*.*.139`\n```text\n104.*.*.139\n```'
  );
  assert.equal(maskedEmbed.footer.text, 'Yori Monitor');
});

test('/status supports custom per-node template and {{#servers}} loop template', async () => {
  clearAllCaches();
  const { privateKey, publicKeyHex } = await createEd25519TestKeys();
  const now = Date.now();
  const servers = [
    { id: 'srv-1', name: 'HK-01', region: 'hk', server_group: 'Prod', is_hidden: '0', sort_order: 0, history_partition_id: 1, timestamp: 0 }
  ];
  const metricsById = new Map([
    ['srv-1', { timestamp: now - 5_000, cpu: 12.5, ram_used: 1024, ram_total: 2048, net_in_speed: 2048, net_out_speed: 1024, uptime: 3660 }]
  ]);

  // 1) Per-node template
  clearSiteSettingsCache();
  clearAppearanceSettingsCache();
  const dbPerNode = makeDiscordMockDb({
    servers,
    metricsById,
    settings: {
      notification_language: 'zh',
      discord_status_template: '[{{group}}] {{status}} | CPU {{cpu}}% | RAM {{ram}}% | 上行 {{net_out}}'
    }
  });
  const body = JSON.stringify({ type: 2, data: { name: 'status' } });
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = await signInteraction(privateKey, ts, body);

  const res1 = await handleDiscordInteraction(new Request('https://monitor.example.com/api/discord/interactions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Signature-Ed25519': sig, 'X-Signature-Timestamp': ts },
    body
  }), { DISCORD_PUBLIC_KEY: publicKeyHex, DB: dbPerNode });
  const json1 = await res1.json();
  assert.equal(json1.data.embeds[0].fields[0].value, '[Prod] 在线 | CPU 12.5% | RAM 50.0% | 上行 1.0 KB/s');

  // 2) Full {{#servers}} loop template
  clearSiteSettingsCache();
  clearAppearanceSettingsCache();
  const dbLoop = makeDiscordMockDb({
    servers,
    metricsById,
    settings: {
      notification_language: 'zh',
      discord_status_template: '总计 {{total}} 台（在线 {{online}}）：\n{{#servers}}- {{status_icon}} {{name}}{{region_tag}}：CPU {{cpu}}% / 内存 {{ram}}%\n{{/servers}}'
    }
  });
  const res2 = await handleDiscordInteraction(new Request('https://monitor.example.com/api/discord/interactions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Signature-Ed25519': sig, 'X-Signature-Timestamp': ts },
    body
  }), { DISCORD_PUBLIC_KEY: publicKeyHex, DB: dbLoop });
  const json2 = await res2.json();
  assert.equal(json2.data.embeds[0].fields.length, 0);
  assert.equal(json2.data.embeds[0].description, '总计 1 台（在线 1）：\n- 🟢 HK-01 [HK]：CPU 12.5% / 内存 50.0%');
});

test('send_test_notification reads site_title from appearance_options without ReferenceError', async () => {
  clearSiteSettingsCache();
  clearAppearanceSettingsCache();
  const sys = { password: 'hash', jwt_secret: 'x'.repeat(32) };
  const db = makeDiscordMockDb({
    appearance: { site_title: 'Yori Panel' }
  });
  const env = { API_SECRET: 'secret', DB: db };
  const token = await generateToken(env, sys);

  const requests = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options = {}) => {
    requests.push({ url: String(url), body: options.body ? JSON.parse(options.body) : null });
    return { ok: true, status: 200, async json() { return { id: 'msg-test' }; } };
  };

  try {
    const res = await handleAdminAPI(new Request('https://monitor.example.com/admin/api', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({
        action: 'send_test_notification',
        discord_bot_enabled: 'true',
        discord_bot_token: 'bot-token',
        discord_channel_id: '123456789012345678',
        notification_language: 'zh',
        notification_template: '{{message}}'
      })
    }), env, sys);
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.success, true);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].body.embeds[0].footer.text, 'Yori Panel');
    assert.equal(requests[0].body.embeds[0].fields[0].value, 'Yori Panel');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('/node, /traffic, /expire, /ping commands, autocomplete, and refresh buttons work end-to-end', async () => {
  clearAllCaches();
  clearSiteSettingsCache();
  clearAppearanceSettingsCache();
  const { privateKey, publicKeyHex } = await createEd25519TestKeys();
  const now = Date.now();
  const futureDate = (days) => {
    const d = new Date(now + days * 86400000);
    return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(d.getUTCDate()).padStart(2, '0')}`;
  };

  const servers = [
    {
      id: 'srv-us',
      name: 'US-Muse',
      region: 'us',
      server_group: 'Prod',
      is_hidden: '0',
      sort_order: 0,
      history_partition_id: 1,
      traffic_limit: '1000',
      traffic_calc_type: 'total',
      expire_date: futureDate(5),
      price: '$12.00/月',
      billing_cycle: 'month',
      auto_renewal: '0',
      ddns_enabled: '1',
      ddns_domain: 'muse.example.com',
      ddns_record_type: 'AUTO',
      os: 'Ubuntu 22.04',
      cpu_cores: 4
    },
    {
      id: 'srv-jp',
      name: 'JP-Tokyo',
      region: 'jp',
      server_group: 'Edge',
      is_hidden: '0',
      sort_order: 1,
      history_partition_id: 2,
      traffic_limit: '500',
      traffic_calc_type: 'total',
      expire_date: futureDate(40),
      price: '¥120.00/年',
      billing_cycle: 'year',
      auto_renewal: '1'
    },
    {
      id: 'srv-secret',
      name: 'Hidden-Box',
      region: 'sg',
      is_hidden: '1',
      sort_order: 2,
      history_partition_id: 3,
      traffic_limit: '100'
    }
  ];

  const GB = 1024 * 1024 * 1024;
  const metricsById = new Map([
    ['srv-us', {
      timestamp: now - 5_000,
      cpu: 18.5,
      load_avg: '0.42, 0.35, 0.28',
      ram_used: 920,
      ram_total: 1024,
      disk_used: 15360,
      disk_total: 40960,
      net_in_speed: 2048,
      net_out_speed: 4096,
      tcp_conn: 55,
      udp_conn: 7,
      net_rx_monthly: 500 * GB,
      net_tx_monthly: 400 * GB,
      ping_ct: 145,
      ping_cu: 132,
      ping_cm: 168,
      loss_ct: 0,
      loss_cu: 1,
      ip_v4: '198.51.100.77',
      uptime: 7200
    }],
    ['srv-jp', {
      timestamp: now - 5_000,
      cpu: 6.2,
      ram_used: 256,
      ram_total: 1024,
      disk_used: 4096,
      disk_total: 20480,
      net_in_speed: 512,
      net_out_speed: 256,
      net_rx_monthly: 100 * GB,
      net_tx_monthly: 50 * GB,
      ping_ct: 45,
      ping_cu: 38,
      ping_cm: 52,
      uptime: 86400
    }]
  ]);

  const db = makeDiscordMockDb({
    servers,
    metricsById,
    settings: {
      notification_language: 'zh',
      notification_timezone: 'UTC',
      custom_ct_name: '电信',
      custom_cu_name: '联通',
      custom_cm_name: '移动'
    },
    appearance: { site_title: 'Yori Monitor' }
  });
  const env = { DISCORD_PUBLIC_KEY: publicKeyHex, DB: db };

  async function callInteraction(payload) {
    const body = JSON.stringify(payload);
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = await signInteraction(privateKey, ts, body);
    const res = await handleDiscordInteraction(new Request('https://monitor.example.com/api/discord/interactions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Signature-Ed25519': sig, 'X-Signature-Timestamp': ts },
      body
    }), env);
    assert.equal(res.status, 200);
    return res.json();
  }

  // 1) Autocomplete filters visible nodes and excludes hidden ones
  const ac = await callInteraction({
    type: 4,
    data: { name: 'node', options: [{ name: 'name', value: 'us', focused: true }] }
  });
  assert.equal(ac.type, 8);
  assert.equal(ac.data.choices.length, 1);
  assert.equal(ac.data.choices[0].name, 'US-Muse');
  assert.equal(ac.data.choices[0].value, 'srv-us');

  const acHidden = await callInteraction({
    type: 4,
    data: { name: 'node', options: [{ name: 'name', value: 'Hidden', focused: true }] }
  });
  assert.equal(acHidden.data.choices.length, 0);

  // 2) /node detailed card + no raw IP leak + refresh button
  const nodeRes = await callInteraction({
    type: 2,
    data: { name: 'node', options: [{ name: 'name', value: 'US-Muse' }] }
  });
  assert.equal(nodeRes.type, 4);
  const nodeEmbed = nodeRes.data.embeds[0];
  assert.equal(nodeEmbed.title, '🟢 US-Muse ⚠️');
  assert.equal(nodeEmbed.footer.text, 'Yori Monitor');
  assert.doesNotMatch(JSON.stringify(nodeEmbed), /198\.51\.100\.77/);
  assert.doesNotMatch(JSON.stringify(nodeEmbed), /muse\.example\.com/);
  assert.equal(nodeRes.data.components[0].components[0].custom_id, `${DISCORD_NODE_REFRESH_PREFIX}srv-us`);

  const nodeRefresh = await callInteraction({
    type: 3,
    data: { custom_id: `${DISCORD_NODE_REFRESH_PREFIX}srv-us` }
  });
  assert.equal(nodeRefresh.type, 7);
  assert.equal(nodeRefresh.data.embeds[0].title, '🟢 US-Muse ⚠️');

  // 3) /traffic ranking sorted descending by usage %
  const trafficRes = await callInteraction({ type: 2, data: { name: 'traffic' } });
  const trafficEmbed = trafficRes.data.embeds[0];
  assert.equal(trafficEmbed.fields.length, 2);
  assert.equal(trafficEmbed.fields[0].name, '🔴 US-Muse');
  assert.match(trafficEmbed.fields[0].value, /90\.0%/);
  assert.equal(trafficEmbed.fields[1].name, '🟢 JP-Tokyo');
  assert.match(trafficEmbed.fields[1].value, /30\.0%/);
  assert.equal(trafficRes.data.components[0].components[0].custom_id, DISCORD_TRAFFIC_REFRESH_ID);

  const trafficRefresh = await callInteraction({ type: 3, data: { custom_id: DISCORD_TRAFFIC_REFRESH_ID } });
  assert.equal(trafficRefresh.type, 7);

  // 4) /expire sorted ascending by remaining days + billing totals
  const expireRes = await callInteraction({ type: 2, data: { name: 'expire' } });
  const expireEmbed = expireRes.data.embeds[0];
  assert.equal(expireEmbed.fields.length, 2);
  assert.equal(expireEmbed.fields[0].name, '🔴 US-Muse');
  assert.equal(expireEmbed.fields[1].name, '🔄 JP-Tokyo');
  assert.match(expireEmbed.description, /\$12\.00/);
  assert.match(expireEmbed.description, /¥10\.00/);
  assert.equal(expireRes.data.components[0].components[0].custom_id, DISCORD_EXPIRE_REFRESH_ID);

  // 5) /ping overview sorted by lowest average latency + single node ping
  const pingAll = await callInteraction({ type: 2, data: { name: 'ping' } });
  const pingEmbed = pingAll.data.embeds[0];
  assert.equal(pingEmbed.fields.length, 2);
  assert.equal(pingEmbed.fields[0].name, '🟢 JP-Tokyo');
  assert.match(pingEmbed.fields[0].value, /电信 \*\*45ms\*\*/);
  assert.equal(pingEmbed.fields[1].name, '🟡 US-Muse');
  assert.equal(pingAll.data.components[0].components[0].custom_id, DISCORD_PING_REFRESH_PREFIX);

  const pingOne = await callInteraction({
    type: 2,
    data: { name: 'ping', options: [{ name: 'name', value: 'srv-jp' }] }
  });
  assert.equal(pingOne.data.embeds[0].fields.length, 3);
  assert.equal(pingOne.data.components[0].components[0].custom_id, `${DISCORD_PING_REFRESH_PREFIX}:srv-jp`);

  const pingRefresh = await callInteraction({
    type: 3,
    data: { custom_id: `${DISCORD_PING_REFRESH_PREFIX}:srv-jp` }
  });
  assert.equal(pingRefresh.type, 7);
});

test('admin sync_discord_commands registers all 5 slash commands via Discord API', async () => {
  const sys = { password: 'hash', jwt_secret: 'x'.repeat(32) };
  const db = makeDiscordMockDb({});
  const env = { API_SECRET: 'secret', DB: db };
  const token = await generateToken(env, sys);

  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), method: options.method || 'GET', body: options.body ? JSON.parse(options.body) : null });
    if (String(url).endsWith('/oauth2/applications/@me')) {
      return { ok: true, status: 200, async json() { return { id: 'app-999888777' }; } };
    }
    return {
      ok: true,
      status: 200,
      async json() { return DISCORD_SLASH_COMMANDS.map(cmd => ({ id: `id-${cmd.name}`, name: cmd.name })); }
    };
  };

  try {
    const res = await handleAdminAPI(new Request('https://monitor.example.com/admin/api', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({
        action: 'sync_discord_commands',
        discord_bot_token: 'bot-token-123'
      })
    }), env, sys);
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.success, true);
    assert.equal(json.applicationId, 'app-999888777');
    assert.deepEqual(json.commands, ['/status', '/node', '/traffic', '/expire', '/ping']);
    assert.equal(calls.length, 2);
    assert.equal(calls[0].method, 'GET');
    assert.equal(calls[1].method, 'PUT');
    assert.equal(calls[1].url, 'https://discord.com/api/v10/applications/app-999888777/commands');
    assert.equal(calls[1].body.length, 5);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('Discord interactions reject replay timestamps, enforce allowlist/private-site access, and respect display switches', async () => {
  clearAllCaches();
  clearSiteSettingsCache();
  clearAppearanceSettingsCache();
  const { privateKey, publicKeyHex } = await createEd25519TestKeys();
  const now = Date.now();
  const nowSec = Math.floor(now / 1000);
  const futureDate = (days) => {
    const d = new Date(now + days * 86400000);
    return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(d.getUTCDate()).padStart(2, '0')}`;
  };

  const servers = [
    {
      id: 'srv-1',
      name: 'Node-1',
      region: 'us',
      is_hidden: '0',
      sort_order: 0,
      history_partition_id: 1,
      traffic_limit: '100',
      traffic_calc_type: 'total',
      expire_date: futureDate(10),
      price: '$9.99/月',
      billing_cycle: 'month',
      auto_renewal: '0',
      ddns_enabled: '1',
      ddns_domain: 'secret-ddns.example.com'
    }
  ];
  const metricsById = new Map([
    ['srv-1', {
      timestamp: now - 5_000,
      cpu: 10,
      ram_used: 512,
      ram_total: 1024,
      net_rx_monthly: 20 * 1024 ** 3,
      net_tx_monthly: 10 * 1024 ** 3
    }]
  ]);

  async function postInteraction(payload, env, ts = String(Math.floor(Date.now() / 1000))) {
    const body = JSON.stringify(payload);
    const sig = await signInteraction(privateKey, ts, body);
    return handleDiscordInteraction(new Request('https://monitor.example.com/api/discord/interactions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Signature-Ed25519': sig,
        'X-Signature-Timestamp': ts
      },
      body
    }), env);
  }

  // 1) Replay timestamp outside +-300s returns 401
  const replayEnv = {
    DISCORD_PUBLIC_KEY: publicKeyHex,
    DB: makeDiscordMockDb({ servers, metricsById, settings: { notification_language: 'en' } })
  };
  const replayRes = await postInteraction({ type: 2, data: { name: 'status' } }, replayEnv, String(nowSec - 301));
  assert.equal(replayRes.status, 401);

  // 2) Private site without allowlist blocks commands and autocomplete, while PING stays allowed
  clearSiteSettingsCache();
  const privateEnv = {
    DISCORD_PUBLIC_KEY: publicKeyHex,
    DB: makeDiscordMockDb({
      servers,
      metricsById,
      settings: { is_public: 'false', notification_language: 'en' }
    })
  };
  const pingPrivate = await postInteraction({ type: 1 }, privateEnv);
  assert.equal(pingPrivate.status, 200);
  assert.deepEqual(await pingPrivate.json(), { type: 1 });

  const privateStatus = await (await postInteraction({ type: 2, data: { name: 'status' }, user: { id: '11111111111111111' } }, privateEnv)).json();
  assert.equal(privateStatus.type, 4);
  assert.equal(privateStatus.data.flags, 64);
  assert.match(privateStatus.data.content, /not authorized/i);

  const privateAc = await (await postInteraction({
    type: 4,
    data: { name: 'node', options: [{ name: 'name', value: 'Node', focused: true }] },
    user: { id: '11111111111111111' }
  }, privateEnv)).json();
  assert.equal(privateAc.type, 8);
  assert.deepEqual(privateAc.data.choices, []);

  // 3) Configured discord_user_id / discord_channel_id acts as allowlist
  assert.equal(isAuthorizedDiscordInteraction({ user: { id: '99999999999999999' } }, {
    discord_user_id: '99999999999999999',
    discord_channel_id: '88888888888888888'
  }), true);
  assert.equal(isAuthorizedDiscordInteraction({ channel_id: '88888888888888888', member: { user: { id: '77777777777777777' } } }, {
    discord_user_id: '99999999999999999',
    discord_channel_id: '88888888888888888'
  }), true);
  assert.equal(isAuthorizedDiscordInteraction({ channel_id: '11111111111111111', user: { id: '77777777777777777' } }, {
    discord_user_id: '99999999999999999',
    discord_channel_id: '88888888888888888'
  }), false);

  clearSiteSettingsCache();
  const allowlistEnv = {
    DISCORD_PUBLIC_KEY: publicKeyHex,
    DB: makeDiscordMockDb({
      servers,
      metricsById,
      settings: {
        is_public: 'false',
        discord_user_id: '99999999999999999',
        discord_channel_id: '88888888888888888',
        notification_language: 'zh',
        show_tf: 'false',
        show_expire: 'false',
        show_price: 'false'
      }
    })
  };

  const strangerRefresh = await (await postInteraction({
    type: 3,
    channel_id: '11111111111111111',
    user: { id: '22222222222222222' },
    data: { custom_id: DISCORD_STATUS_REFRESH_ID }
  }, allowlistEnv)).json();
  assert.equal(strangerRefresh.type, 4);
  assert.equal(strangerRefresh.data.flags, 64);
  assert.match(strangerRefresh.data.content, /无权限/);

  // 4) Authorized caller respects show_tf / show_expire / show_price display switches
  const authedNode = await (await postInteraction({
    type: 2,
    channel_id: '88888888888888888',
    data: { name: 'node', options: [{ name: 'name', value: 'srv-1' }] }
  }, allowlistEnv)).json();
  const nodeJsonStr = JSON.stringify(authedNode.data.embeds[0]);
  assert.doesNotMatch(nodeJsonStr, /secret-ddns\.example\.com/);
  assert.doesNotMatch(nodeJsonStr, /本月流量|Monthly Traffic/);
  assert.doesNotMatch(nodeJsonStr, /账单与到期|Billing/);
  assert.doesNotMatch(nodeJsonStr, /\$9\.99/);

  const authedTraffic = await (await postInteraction({
    type: 2,
    user: { id: '99999999999999999' },
    data: { name: 'traffic' }
  }, allowlistEnv)).json();
  assert.equal(authedTraffic.data.embeds[0].fields.length, 0);
  assert.match(authedTraffic.data.embeds[0].description, /站点设置已隐藏/);

  const authedExpire = await (await postInteraction({
    type: 2,
    user: { id: '99999999999999999' },
    data: { name: 'expire' }
  }, allowlistEnv)).json();
  assert.equal(authedExpire.data.embeds[0].fields.length, 0);
  assert.match(authedExpire.data.embeds[0].description, /站点设置已隐藏/);

  // show_expire=true + show_price=false hides price while keeping expiration calendar
  clearSiteSettingsCache();
  const noPriceEnv = {
    DISCORD_PUBLIC_KEY: publicKeyHex,
    DB: makeDiscordMockDb({
      servers,
      metricsById,
      settings: {
        is_public: 'true',
        notification_language: 'en',
        show_expire: 'true',
        show_price: 'false'
      }
    })
  };
  const expireNoPrice = await (await postInteraction({ type: 2, data: { name: 'expire' } }, noPriceEnv)).json();
  assert.equal(expireNoPrice.data.embeds[0].fields.length, 1);
  assert.doesNotMatch(JSON.stringify(expireNoPrice.data.embeds[0]), /\$9\.99|Monthly est/);
});

test('Discord {{#servers}} loop preserves $ patterns and Embed charBudget includes footer length', () => {
  const now = Date.now();
  const servers = Array.from({ length: 20 }, (_, i) => ({
    id: `srv-${i}`,
    name: i === 0 ? 'US-$&-Price-$1' : `Node-${i}-LongName-${'x'.repeat(25)}`,
    region: 'us',
    is_hidden: '0',
    history_partition_id: i + 1
  }));
  const metricsById = new Map(
    servers.map(s => [s.id, {
      timestamp: now - 5_000,
      cpu: 50,
      ram_used: 512,
      ram_total: 1024,
      net_in_speed: 1024,
      net_out_speed: 1024,
      uptime: 3600
    }])
  );

  // 1) $& / $1 in server names must not expand in {{#servers}} replacement
  const loopEmbed = buildStatusCommandEmbed(servers.slice(0, 1), metricsById, new Map(), now, {
    notification_language: 'en',
    discord_status_template: 'List:\n{{#servers}}{{name}}={{cpu}}%\n{{/servers}}'
  });
  assert.equal(loopEmbed.description, 'List:\nUS-$&-Price-$1=50.0%');

  // 2) Long site_title (1800 chars) + 20 nodes stays strictly within Discord 6000-char Embed limit
  const longFooterEmbed = buildStatusCommandEmbed(servers, metricsById, new Map(), now, {
    notification_language: 'en',
    site_title: 'T'.repeat(1800),
    discord_status_template: 'A'.repeat(250)
  });
  const totalChars =
    longFooterEmbed.title.length +
    longFooterEmbed.description.length +
    longFooterEmbed.footer.text.length +
    longFooterEmbed.fields.reduce((sum, f) => sum + f.name.length + f.value.length, 0);
  assert.ok(totalChars <= 6000, `Expected embed char count <= 6000, got ${totalChars}`);
  assert.ok(longFooterEmbed.fields.length < 20);
  assert.match(longFooterEmbed.description, /omitted/);
});

test('admin save_settings validates enabled Discord Bot unconditionally even without tg_notify/expire/resource rules', async () => {
  clearSiteSettingsCache();
  clearAppearanceSettingsCache();
  const sys = { password: 'hash', jwt_secret: 'x'.repeat(32) };
  const db = makeDiscordMockDb({});
  const env = { API_SECRET: 'secret', DB: db };
  const token = await generateToken(env, sys);

  const postSave = (extra) => handleAdminAPI(new Request('https://monitor.example.com/admin/api', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({
      action: 'save_settings',
      settings: {
        tg_notify: '0',
        expire_reminder: '0',
        resource_alert_rules: [],
        discord_bot_enabled: 'true',
        ...extra
      }
    })
  }), env, sys);

  const noToken = await postSave({ discord_bot_token: '', discord_channel_id: '123456789012345678' });
  assert.equal(noToken.status, 400);
  assert.equal((await noToken.json()).error, 'discordBotTokenRequired');

  const noTarget = await postSave({ discord_bot_token: 'bot-tok', discord_channel_id: '', discord_user_id: '' });
  assert.equal(noTarget.status, 400);
  assert.equal((await noTarget.json()).error, 'discordTargetRequired');

  const badId = await postSave({ discord_bot_token: 'bot-tok', discord_channel_id: 'abc' });
  assert.equal(badId.status, 400);
  assert.equal((await badId.json()).error, 'invalidDiscordId');

  const okRes = await postSave({ discord_bot_token: 'bot-tok', discord_channel_id: '123456789012345678' });
  assert.equal(okRes.status, 200);
  assert.equal((await okRes.json()).success, true);
});
