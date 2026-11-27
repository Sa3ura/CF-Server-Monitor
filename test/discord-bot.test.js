import assert from 'node:assert/strict';
import test from 'node:test';

import worker from '../src/index.js';
import {
  buildDiscordAlertEmbed,
  handleDiscordInteraction,
  sendDiscordBotNotification,
  verifyDiscordSignature
} from '../src/services/discord.js';
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

function makeDiscordMockDb({ servers = [], metricsById = new Map(), settings = {} } = {}) {
  return {
    prepare(sql) {
      return {
        args: [],
        bind(...args) { this.args = args; return this; },
        async first() {
          if (sql.includes("key = 'site_options'")) {
            return { value: JSON.stringify(settings) };
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

test('Ed25519 signature verification validates valid signatures and rejects tampered payloads', async () => {
  const { privateKey, publicKeyHex } = await createEd25519TestKeys();
  const timestamp = '1700000000';
  const rawBody = JSON.stringify({ type: 1 });
  const signature = await signInteraction(privateKey, timestamp, rawBody);

  assert.equal(await verifyDiscordSignature(rawBody, signature, timestamp, publicKeyHex), true);
  assert.equal(await verifyDiscordSignature('{"type":2}', signature, timestamp, publicKeyHex), false);
  assert.equal(await verifyDiscordSignature(rawBody, '00'.repeat(64), timestamp, publicKeyHex), false);
  assert.equal(await verifyDiscordSignature(rawBody, signature, '', publicKeyHex), false);
  assert.equal(await verifyDiscordSignature(rawBody, signature, timestamp, 'invalid-hex'), false);
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
  const ts = '1700000100';
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
  assert.match(embed.fields[0].name, /Tokyo-01 \[JP\]/);
  assert.match(embed.fields[0].value, /CPU: \*\*35\.4%\*\* \| RAM: \*\*50\.0%\*\*/);
  assert.match(embed.fields[0].value, /1\.0 MB\/s/);
  assert.match(embed.fields[0].value, /1d 1h 1m/);
  assert.match(embed.fields[1].name, /US-02 \[US\]/);
  assert.match(embed.fields[1].value, /Offline/);
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
  const ts = '1700000200';
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
