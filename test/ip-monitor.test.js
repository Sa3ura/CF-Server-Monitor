import assert from 'node:assert/strict';
import test from 'node:test';

import {
  evaluateIpChange,
  extractReportedIps,
  isValidDdnsDomain,
  maskIpAddress,
  parsePendingIpState,
  serializePendingIpState,
  syncCloudflareDnsRecord
} from '../src/services/ipMonitor.js';
import { handleAdminAPI } from '../src/handlers/admin.js';
import { handleServerAPI } from '../src/handlers/dashboard.js';
import { generateToken } from '../src/middleware/auth.js';
import { sendNotification, stripMarkdownAsterisks } from '../src/services/notification.js';
import { clearAllCaches } from '../src/utils/cache.js';
import { clearAppearanceSettingsCache, clearSiteSettingsCache } from '../src/utils/settings.js';

function makeIpMonitorDb(server, settings = {}, appearance = {}) {
  const updates = [];
  return {
    updates,
    prepare(sql) {
      return {
        args: [],
        bind(...args) { this.args = args; return this; },
        async first() {
          if (sql.includes("key = 'site_options'")) {
            return { value: JSON.stringify(settings) };
          }
          if (sql.includes("key = 'appearance_options'")) {
            return { value: JSON.stringify(appearance) };
          }
          if (sql.includes('FROM servers WHERE id = ?')) {
            return server;
          }
          return null;
        },
        async all() {
          return { results: server ? [server] : [] };
        },
        async run() {
          if (sql.startsWith('UPDATE servers SET last_ipv4')) {
            const [last_ipv4, last_ipv6, pending_ip, pending_ip_count, id] = this.args;
            updates.push({ last_ipv4, last_ipv6, pending_ip, pending_ip_count, id });
          }
          return { success: true, meta: { changes: 1 } };
        }
      };
    }
  };
}

test('extractReportedIps only falls back to CF-Connecting-IP when both reported IPs are blank', () => {
  assert.deepEqual(
    extractReportedIps({ ip_v4: '1.2.3.4', ip_v6: '0' }, '2001:db8::10'),
    { v4: '1.2.3.4', v6: '' }
  );
  assert.deepEqual(
    extractReportedIps({ ip_v4: '0', ip_v6: '0' }, '2001:db8::10'),
    { v4: '', v6: '2001:db8::10' }
  );
  assert.deepEqual(
    extractReportedIps({ ip_v4: '0', ip_v6: '0' }, '::ffff:198.51.100.42'),
    { v4: '198.51.100.42', v6: '' }
  );
  assert.deepEqual(
    extractReportedIps({ ip_v4: '1.2.3.4', ip_v6: '2001:db8::1' }, '9.9.9.9'),
    { v4: '1.2.3.4', v6: '2001:db8::1' }
  );
});

test('pending IP state round-trips single-stack and dual-stack entries', () => {
  const single = serializePendingIpState({ v4: { ip: '2.2.2.2', count: 1 }, v6: null });
  assert.deepEqual(single, { pending_ip: '2.2.2.2', pending_ip_count: 1 });
  assert.deepEqual(parsePendingIpState(single.pending_ip, single.pending_ip_count), {
    v4: { ip: '2.2.2.2', count: 1 },
    v6: null
  });

  const dual = serializePendingIpState({
    v4: { ip: '2.2.2.2', count: 1 },
    v6: { ip: '2001:db8::2', count: 1 }
  });
  assert.equal(dual.pending_ip_count, 1);
  assert.deepEqual(parsePendingIpState(dual.pending_ip, dual.pending_ip_count), {
    v4: { ip: '2.2.2.2', count: 1 },
    v6: { ip: '2001:db8::2', count: 1 }
  });
});

test('evaluateIpChange establishes baseline silently and requires 2 consecutive heartbeats before alerting + syncing DDNS', async () => {
  clearSiteSettingsCache();
  const server = {
    id: 'srv-ddns-1',
    name: 'Home-NAS',
    last_ipv4: '',
    last_ipv6: '',
    pending_ip: '',
    pending_ip_count: 0,
    ddns_enabled: '1',
    ddns_domain: 'nas.example.com',
    ddns_record_type: 'AUTO'
  };
  const settings = {
    jwt_secret: 'x'.repeat(32),
    tg_bot_token: '123:tg',
    tg_chat_id: '999',
    notification_language: 'zh'
  };
  const db = makeIpMonitorDb(server, settings);
  const env = {
    DB: db,
    CF_DNS_API_TOKEN: 'cf-dns-token',
    CF_ZONE_ID: 'zone-123'
  };

  const fetchCalls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options = {}) => {
    const u = String(url);
    fetchCalls.push({ url: u, method: options.method || 'GET', body: options.body ? JSON.parse(options.body) : null });
    if (u.includes('/dns_records?')) {
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            success: true,
            result: [{ id: 'rec-v4-1', type: 'A', name: 'nas.example.com', content: '1.1.1.1', ttl: 120, proxied: false }]
          };
        }
      };
    }
    if (u.includes('/dns_records/rec-v4-1')) {
      return {
        ok: true,
        status: 200,
        async json() { return { success: true, result: { id: 'rec-v4-1' } }; }
      };
    }
    return {
      ok: true,
      status: 200,
      async json() { return { ok: true }; },
      async text() { return ''; }
    };
  };

  const pendingTasks = [];
  const waitUntil = (p) => pendingTasks.push(p);

  try {
    // 1. Initial baseline heartbeat -> writes last_ipv4 without alerting
    const r1 = await evaluateIpChange(env, server, { ip_v4: '1.1.1.1', ip_v6: '2001:db8::1' }, { waitUntil });
    assert.equal(r1.changed, false);
    assert.equal(server.last_ipv4, '1.1.1.1');
    assert.equal(server.last_ipv6, '2001:db8::1');
    assert.equal(fetchCalls.length, 0);

    // 2. First heartbeat with new IPv4 (2.2.2.2) -> pending only, no alert
    const r2 = await evaluateIpChange(env, server, { ip_v4: '2.2.2.2', ip_v6: '2001:db8::1' }, { waitUntil });
    assert.equal(r2.changed, false);
    assert.equal(server.pending_ip, '2.2.2.2');
    assert.equal(server.pending_ip_count, 1);
    assert.equal(server.last_ipv4, '1.1.1.1');
    assert.equal(fetchCalls.length, 0);

    // 3. Transient flap back to 1.1.1.1 -> clears pending, no alert
    const r3 = await evaluateIpChange(env, server, { ip_v4: '1.1.1.1', ip_v6: '2001:db8::1' }, { waitUntil });
    assert.equal(r3.changed, false);
    assert.equal(server.pending_ip, '');
    assert.equal(server.pending_ip_count, 0);

    // 4. New IPv4 (3.3.3.3) appears once -> pending
    const r4 = await evaluateIpChange(env, server, { ip_v4: '3.3.3.3', ip_v6: '2001:db8::1' }, { waitUntil });
    assert.equal(r4.changed, false);
    assert.equal(server.pending_ip, '3.3.3.3');
    assert.equal(server.pending_ip_count, 1);

    // 5. IPv6-only heartbeat (no v4 reported) must NOT clear pending_ip for v4 or falsely trigger v4
    const r5 = await evaluateIpChange(env, server, { ip_v4: '0', ip_v6: '2001:db8::1' }, { waitUntil });
    assert.equal(r5.changed, false);
    assert.equal(server.pending_ip, '3.3.3.3');

    // 6. Second heartbeat with 3.3.3.3 -> confirmed change!
    const r6 = await evaluateIpChange(env, server, { ip_v4: '3.3.3.3', ip_v6: '2001:db8::1' }, { waitUntil });
    assert.equal(r6.changed, true);
    assert.equal(r6.changes.length, 1);
    assert.equal(r6.changes[0].oldIp, '1.1.1.1');
    assert.equal(r6.changes[0].newIp, '3.3.3.3');
    assert.equal(server.last_ipv4, '3.3.3.3');
    assert.equal(server.pending_ip, '');
    assert.equal(server.pending_ip_count, 0);

    await Promise.all(pendingTasks);

    // Verify CF DNS GET + PATCH and Telegram notification
    assert.equal(fetchCalls.length, 3);
    assert.equal(fetchCalls[0].method, 'GET');
    assert.match(fetchCalls[0].url, /zones\/zone-123\/dns_records\?type=A&name=nas\.example\.com/);
    assert.equal(fetchCalls[1].method, 'PATCH');
    assert.equal(fetchCalls[1].url, 'https://api.cloudflare.com/client/v4/zones/zone-123/dns_records/rec-v4-1');
    assert.deepEqual(fetchCalls[1].body, {
      type: 'A',
      name: 'nas.example.com',
      content: '3.3.3.3',
      ttl: 120,
      proxied: false
    });
    assert.match(fetchCalls[2].url, /api\.telegram\.org\/bot123:tg\/sendMessage/);
    assert.match(fetchCalls[2].body.text, /节点 IP 变更告警/);
    assert.match(fetchCalls[2].body.text, /1\.1\.1\.1 -> 3\.3\.3\.3/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('syncCloudflareDnsRecord handles missing env and DNS API failures safely', async () => {
  const missingEnv = await syncCloudflareDnsRecord({}, { domain: 'a.example.com', recordType: 'A', newIp: '1.2.3.4' });
  assert.equal(missingEnv.attempted, false);

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: false,
    status: 403,
    async json() { return { success: false, errors: [{ message: 'Invalid token' }] }; }
  });
  try {
    const failed = await syncCloudflareDnsRecord(
      { CF_DNS_API_TOKEN: 'bad', CF_ZONE_ID: 'z1' },
      { domain: 'a.example.com', recordType: 'A', newIp: '1.2.3.4' }
    );
    assert.equal(failed.attempted, true);
    assert.equal(failed.ok, false);
    assert.equal(failed.error, 'Invalid token');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('maskIpAddress masks IPv4 and IPv6 addresses for privacy', () => {
  assert.equal(maskIpAddress('216.12.34.171'), '216.*.*.171');
  assert.equal(maskIpAddress('::ffff:198.51.100.42'), '198.*.*.42');
  assert.equal(maskIpAddress('2001:db8:85a3::8a2e:370:7334'), '2001:*:*:7334');
  assert.equal(maskIpAddress('invalid'), '');
});

test('evaluateIpChange masks IPs in notifications when ip_change_mask_ip is true without affecting DDNS real IP', async () => {
  clearSiteSettingsCache();
  clearAppearanceSettingsCache();
  const server = {
    id: 'srv-mask-1',
    name: 'Privacy-Node',
    last_ipv4: '1.1.10.20',
    last_ipv6: '',
    pending_ip: '3.3.30.40',
    pending_ip_count: 1,
    ddns_enabled: '1',
    ddns_domain: 'priv.example.com',
    ddns_record_type: 'A'
  };
  const db = makeIpMonitorDb(server, {
    jwt_secret: 'x'.repeat(32),
    discord_bot_enabled: 'true',
    discord_bot_token: 'bot-token',
    discord_channel_id: '123456789012345678',
    notification_language: 'zh',
    ip_change_mask_ip: 'true'
  }, {
    site_title: 'Yori Status'
  });
  const env = { DB: db, CF_DNS_API_TOKEN: 'cf-token', CF_ZONE_ID: 'zone-1' };
  const fetchCalls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options = {}) => {
    const u = String(url);
    fetchCalls.push({ url: u, method: options.method || 'GET', body: options.body ? JSON.parse(options.body) : null });
    if (u.includes('/dns_records?')) {
      return {
        ok: true,
        status: 200,
        async json() { return { success: true, result: [{ id: 'rec-1', type: 'A', content: '1.1.10.20' }] }; }
      };
    }
    return {
      ok: true,
      status: 200,
      async json() { return { success: true }; },
      async text() { return ''; }
    };
  };

  try {
    await evaluateIpChange(env, server, { ip_v4: '3.3.30.40' });
    assert.equal(server.last_ipv4, '3.3.30.40');
    assert.equal(fetchCalls[1].body.content, '3.3.30.40');
    const embed = fetchCalls[2].body.embeds[0];
    assert.equal(embed.footer.text, 'Yori Status');
    assert.match(embed.description, /1\.\\\*\.\\\*\.20 -> 3\.\\\*\.\\\*\.40/);
    assert.doesNotMatch(embed.description, /3\.3\.30\.40/);
    assert.equal(embed.fields[3].value, '`1.*.*.20` → `3.*.*.40` | DNS(priv.example.com): Updated');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('admin edit validates DDNS domain and dashboard strips IP tracking / DDNS fields from public API', async () => {
  clearAllCaches();
  const sys = { password: 'hash', jwt_secret: 'x'.repeat(32), is_public: 'true' };
  const serverRow = {
    id: '550e8400-e29b-41d4-a716-446655440000',
    name: 'Node-A',
    history_partition_id: 1,
    is_hidden: '0',
    last_ipv4: '1.2.3.4',
    last_ipv6: '2001:db8::1',
    pending_ip: '5.6.7.8',
    pending_ip_count: 1,
    ddns_enabled: '1',
    ddns_domain: 'node-a.example.com',
    ddns_record_type: 'A'
  };
  const db = makeIpMonitorDb(serverRow, sys);
  const env = { API_SECRET: 'secret', DB: db };
  const token = await generateToken(env, sys);

  // Admin edit rejects ddns_enabled=1 without domain
  const missingDomainRes = await handleAdminAPI(new Request('https://example.com/admin/api', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({
      action: 'edit',
      id: serverRow.id,
      name: 'Node-A',
      ddns_enabled: '1',
      ddns_domain: ''
    })
  }), env, sys);
  assert.equal(missingDomainRes.status, 400);
  const missingDomainJson = await missingDomainRes.json();
  assert.equal(missingDomainJson.error, 'ddnsDomainRequired');

  // Admin edit rejects invalid domain
  assert.equal(isValidDdnsDomain('not a domain!'), false);
  const invalidDomainRes = await handleAdminAPI(new Request('https://example.com/admin/api', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({
      action: 'edit',
      id: serverRow.id,
      name: 'Node-A',
      ddns_enabled: '1',
      ddns_domain: 'bad_domain'
    })
  }), env, sys);
  assert.equal(invalidDomainRes.status, 400);
  assert.equal((await invalidDomainRes.json()).error, 'invalidDdnsDomain');

  // Public /api/server strips IP tracking and DDNS fields
  const publicRes = await handleServerAPI(
    new Request(`https://example.com/api/server?id=${serverRow.id}`),
    env,
    sys
  );
  assert.equal(publicRes.status, 200);
  const publicJson = await publicRes.json();
  for (const field of ['last_ipv4', 'last_ipv6', 'pending_ip', 'pending_ip_count', 'ddns_enabled', 'ddns_domain', 'ddns_record_type']) {
    assert.equal(field in publicJson, false, `${field} should not be exposed in public API`);
  }

  // export_servers strips runtime IP tracking fields while preserving DDNS config fields
  const exportRes = await handleAdminAPI(new Request('https://example.com/admin/api', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ action: 'export_servers' })
  }), env, sys);
  assert.equal(exportRes.status, 200);
  const exportJson = await exportRes.json();
  assert.equal(exportJson.servers.length, 1);
  for (const field of ['last_ipv4', 'last_ipv6', 'pending_ip', 'pending_ip_count']) {
    assert.equal(field in exportJson.servers[0], false, `${field} should be omitted from export_servers`);
  }
  assert.equal(exportJson.servers[0].ddns_enabled, '1');
  assert.equal(exportJson.servers[0].ddns_domain, 'node-a.example.com');
  assert.equal(exportJson.servers[0].ddns_record_type, 'A');
});

test('evaluateIpChange uses CAS optimistic locking to prevent duplicate DDNS updates and alerts under concurrency', async () => {
  clearSiteSettingsCache();
  clearAppearanceSettingsCache();
  const row = {
    id: 'srv-cas-1',
    name: 'CAS-Node',
    last_ipv4: '1.1.1.1',
    last_ipv6: '',
    pending_ip: '2.2.2.2',
    pending_ip_count: 1,
    ddns_enabled: '1',
    ddns_domain: 'cas.example.com',
    ddns_record_type: 'A'
  };
  const settings = {
    jwt_secret: 'x'.repeat(32),
    tg_bot_token: '123:tg',
    tg_chat_id: '999',
    notification_language: 'zh'
  };

  // Stateful CAS-aware D1 mock
  const casDb = {
    prepare(sql) {
      return {
        args: [],
        bind(...args) { this.args = args; return this; },
        async first() {
          if (sql.includes("key = 'site_options'")) return { value: JSON.stringify(settings) };
          if (sql.includes("key = 'appearance_options'")) return { value: JSON.stringify({}) };
          return null;
        },
        async all() {
          return { results: [] };
        },
        async run() {
          if (sql.startsWith('UPDATE servers SET last_ipv4')) {
            const [
              nextV4, nextV6, nextPendingIp, nextPendingCount,
              id, expectedV4, expectedV6, expectedPendingIp, expectedPendingCount
            ] = this.args;
            if (
              row.id !== id ||
              String(row.last_ipv4 || '') !== String(expectedV4) ||
              String(row.last_ipv6 || '') !== String(expectedV6) ||
              String(row.pending_ip || '') !== String(expectedPendingIp) ||
              (Number(row.pending_ip_count) || 0) !== Number(expectedPendingCount)
            ) {
              return { success: true, meta: { changes: 0 } };
            }
            // Yield microtask to allow concurrent caller to race before CAS state commits? No: atomic check-and-set in SQLite!
            row.last_ipv4 = nextV4;
            row.last_ipv6 = nextV6;
            row.pending_ip = nextPendingIp;
            row.pending_ip_count = nextPendingCount;
            return { success: true, meta: { changes: 1 } };
          }
          return { success: true, meta: { changes: 1 } };
        }
      };
    }
  };

  const fetchCalls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options = {}) => {
    const u = String(url);
    fetchCalls.push({ url: u, method: options.method || 'GET' });
    if (u.includes('/dns_records?')) {
      return {
        ok: true,
        status: 200,
        async json() { return { success: true, result: [{ id: 'rec-cas', type: 'A', content: '1.1.1.1' }] }; }
      };
    }
    return {
      ok: true,
      status: 200,
      async json() { return { success: true }; },
      async text() { return ''; }
    };
  };

  const snapshot1 = { ...row };
  const snapshot2 = { ...row };
  const pendingTasks = [];
  const waitUntil = (p) => pendingTasks.push(p);

  try {
    const [res1, res2] = await Promise.all([
      evaluateIpChange({ DB: casDb, CF_DNS_API_TOKEN: 'cf-token', CF_ZONE_ID: 'z-1' }, snapshot1, { ip_v4: '2.2.2.2' }, { waitUntil }),
      evaluateIpChange({ DB: casDb, CF_DNS_API_TOKEN: 'cf-token', CF_ZONE_ID: 'z-1' }, snapshot2, { ip_v4: '2.2.2.2' }, { waitUntil })
    ]);
    await Promise.all(pendingTasks);

    const changedCount = [res1, res2].filter(r => r.changed).length;
    const conflictedCount = [res1, res2].filter(r => r.conflicted).length;
    assert.equal(changedCount, 1);
    assert.equal(conflictedCount, 1);
    assert.equal(row.last_ipv4, '2.2.2.2');
    assert.equal(row.pending_ip, '');
    assert.equal(row.pending_ip_count, 0);

    const patchCalls = fetchCalls.filter(c => c.method === 'PATCH');
    const tgCalls = fetchCalls.filter(c => c.url.includes('api.telegram.org'));
    assert.equal(patchCalls.length, 1);
    assert.equal(tgCalls.length, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('stripMarkdownAsterisks preserves masked IP asterisks for WeCom and OneBot plain-text channels', async () => {
  assert.equal(
    stripMarkdownAsterisks('**Alert** IPv4: 216.*.*.171 -> 104.*.*.237 / IPv6: 2001:*:*:7334'),
    'Alert IPv4: 216.*.*.171 -> 104.*.*.237 / IPv6: 2001:*:*:7334'
  );

  const payloads = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options = {}) => {
    payloads.push({ url: String(url), body: JSON.parse(options.body) });
    return { ok: true, status: 200, async json() { return { errcode: 0 }; }, async text() { return ''; } };
  };

  try {
    const msg = '**Node** IPv4: 216.*.*.171 -> 104.*.*.237\nIPv6: 2001:*:*:7334';
    await sendNotification({
      tg_bot_token: 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test',
      notification_template: '{{message}}'
    }, msg, { event: 'IP Changed', emoji: '🌐', clients: ['Node'] });

    await sendNotification({
      tg_bot_token: 'onebot:http://127.0.0.1:3000/send_private_msg?access_token=test',
      tg_chat_id: '123456',
      notification_template: '{{message}}'
    }, msg, { event: 'IP Changed', emoji: '🌐', clients: ['Node'] });

    assert.equal(payloads.length, 2);
    assert.equal(
      payloads[0].body.text.content,
      'Node IPv4: 216.*.*.171 -> 104.*.*.237\nIPv6: 2001:*:*:7334'
    );
    assert.match(payloads[1].body.message[0].data.text, /Node IPv4: 216\.\*\.\*\.171 -> 104\.\*\.\*\.237/);
    assert.match(payloads[1].body.message[0].data.text, /2001:\*:\*:7334/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
