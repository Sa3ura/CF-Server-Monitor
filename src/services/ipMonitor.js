import { normalizeClientIp } from '../utils/metrics.js';
import { isEnabledFlag } from '../utils/serverBilling.js';
import { loadSiteSettings, normalizeBooleanSetting } from '../utils/settings.js';
import { hasNotificationTarget, sendNotification } from './notification.js';
import { getNotificationMessages } from './notificationMessages.js';

export const ALLOWED_DDNS_RECORD_TYPES = ['AUTO', 'A', 'AAAA'];
const DDNS_DOMAIN_RE = /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;
const CLOUDFLARE_API_BASE = 'https://api.cloudflare.com/client/v4';
const IP_CHANGE_REQUIRED_HEARTBEATS = 2;

export function normalizeDdnsDomain(value) {
  return String(value ?? '').trim().toLowerCase().replace(/\.+$/, '');
}

export function isValidDdnsDomain(value) {
  const domain = normalizeDdnsDomain(value);
  if (!domain) return false;
  return DDNS_DOMAIN_RE.test(domain);
}

export function normalizeDdnsRecordType(value) {
  const upper = String(value ?? '').trim().toUpperCase();
  return ALLOWED_DDNS_RECORD_TYPES.includes(upper) ? upper : 'AUTO';
}

function expandIpv6Address(ip) {
  const halves = String(ip || '').split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':').filter(Boolean) : [];
  const missing = 8 - (left.length + right.length);
  if (missing < 0) return null;
  return [...left, ...Array(missing).fill('0'), ...right].slice(0, 8);
}

export function maskIpAddress(value) {
  const parsed = normalizeClientIp(value);
  if (!parsed) return '';
  if (parsed.family === 'v4') {
    const parts = parsed.value.split('.');
    return parts.length === 4 ? `${parts[0]}.*.*.${parts[3]}` : parsed.value;
  }
  const groups = expandIpv6Address(parsed.value);
  if (groups && groups.length >= 2) {
    return `${groups[0]}:*:*:${groups[groups.length - 1]}`;
  }
  const rawParts = parsed.value.split(':').filter(Boolean);
  return rawParts.length >= 2 ? `${rawParts[0]}:*:*:${rawParts[rawParts.length - 1]}` : '*:*:*:*';
}

export function extractReportedIps(metrics = {}, fallbackClientIp = '') {
  const parsedV4 = normalizeClientIp(metrics?.ip_v4);
  const parsedV6 = normalizeClientIp(metrics?.ip_v6);
  let v4 = parsedV4?.family === 'v4' ? parsedV4.value : '';
  let v6 = parsedV6?.family === 'v6' ? parsedV6.value : '';

  if (fallbackClientIp) {
    const parsedFallback = normalizeClientIp(fallbackClientIp);
    if (parsedFallback?.family === 'v4' && !v4) {
      v4 = parsedFallback.value;
    } else if (parsedFallback?.family === 'v6' && !v6) {
      v6 = parsedFallback.value;
    }
  }

  return { v4, v6 };
}

function normalizeStoredIp(value, expectedFamily) {
  const parsed = normalizeClientIp(value);
  if (!parsed || parsed.family !== expectedFamily) return '';
  return parsed.value;
}

export function parsePendingIpState(pendingIpRaw, pendingCountRaw) {
  const state = { v4: null, v6: null };
  const raw = String(pendingIpRaw ?? '').trim();
  if (!raw) return state;

  const fallbackCount = Math.max(1, parseInt(pendingCountRaw, 10) || 1);

  if (raw.startsWith('{')) {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        for (const family of ['v4', 'v6']) {
          const entry = parsed[family];
          if (!entry) continue;
          const rawIp = typeof entry === 'string' ? entry : entry.ip;
          const ip = normalizeStoredIp(rawIp, family);
          if (!ip) continue;
          const count = typeof entry === 'object'
            ? Math.max(1, parseInt(entry.count, 10) || fallbackCount)
            : fallbackCount;
          state[family] = { ip, count };
        }
        return state;
      }
    } catch (_) {}
  }

  const parsedSingle = normalizeClientIp(raw);
  if (parsedSingle) {
    state[parsedSingle.family] = { ip: parsedSingle.value, count: fallbackCount };
  }
  return state;
}

export function serializePendingIpState(state = {}) {
  const hasV4 = Boolean(state.v4?.ip);
  const hasV6 = Boolean(state.v6?.ip);
  if (!hasV4 && !hasV6) {
    return { pending_ip: '', pending_ip_count: 0 };
  }
  if (hasV4 && !hasV6) {
    return { pending_ip: state.v4.ip, pending_ip_count: state.v4.count };
  }
  if (!hasV4 && hasV6) {
    return { pending_ip: state.v6.ip, pending_ip_count: state.v6.count };
  }
  return {
    pending_ip: JSON.stringify({ v4: state.v4, v6: state.v6 }),
    pending_ip_count: Math.max(state.v4.count, state.v6.count)
  };
}

export function shouldSyncDdnsForFamily(server = {}, family = 'v4') {
  if (!isEnabledFlag(server.ddns_enabled)) return false;
  if (!isValidDdnsDomain(server.ddns_domain)) return false;

  const recordType = normalizeDdnsRecordType(server.ddns_record_type);
  if (recordType === 'AUTO') return true;
  if (family === 'v4') return recordType === 'A';
  if (family === 'v6') return recordType === 'AAAA';
  return false;
}

export async function syncCloudflareDnsRecord(env, { domain, recordType, newIp }) {
  const token = String(env?.CF_DNS_API_TOKEN || '').trim();
  const zoneId = String(env?.CF_ZONE_ID || '').trim();
  if (!token || !zoneId) {
    return { attempted: false, ok: false, reason: 'missing_cf_dns_env' };
  }

  const normalizedDomain = normalizeDdnsDomain(domain);
  if (!normalizedDomain || !recordType || !newIp) {
    return { attempted: false, ok: false, reason: 'invalid_ddns_params' };
  }

  const headers = {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  };

  try {
    const queryUrl = `${CLOUDFLARE_API_BASE}/zones/${encodeURIComponent(zoneId)}/dns_records?type=${encodeURIComponent(recordType)}&name=${encodeURIComponent(normalizedDomain)}`;
    const listResponse = await fetch(queryUrl, { method: 'GET', headers });
    const listData = await listResponse.json().catch(() => null);

    if (!listResponse.ok || !listData?.success) {
      const errMsg = listData?.errors?.[0]?.message || `HTTP ${listResponse.status}`;
      console.warn('[DDNS] Failed to list Cloudflare DNS records:', { domain: normalizedDomain, recordType, error: errMsg });
      return { attempted: true, ok: false, error: errMsg };
    }

    const record = Array.isArray(listData.result) ? listData.result[0] : null;
    if (!record?.id) {
      console.warn('[DDNS] No matching DNS record found:', { domain: normalizedDomain, recordType });
      return { attempted: true, ok: false, error: 'record_not_found' };
    }

    if (String(record.content || '').trim() === newIp) {
      return { attempted: true, ok: true, action: 'unchanged', recordId: record.id };
    }

    const patchUrl = `${CLOUDFLARE_API_BASE}/zones/${encodeURIComponent(zoneId)}/dns_records/${encodeURIComponent(record.id)}`;
    const patchBody = {
      type: recordType,
      name: normalizedDomain,
      content: newIp
    };
    if (record.ttl !== undefined) patchBody.ttl = record.ttl;
    if (typeof record.proxied === 'boolean') patchBody.proxied = record.proxied;

    const patchResponse = await fetch(patchUrl, {
      method: 'PATCH',
      headers,
      body: JSON.stringify(patchBody)
    });
    const patchData = await patchResponse.json().catch(() => null);

    if (!patchResponse.ok || !patchData?.success) {
      const errMsg = patchData?.errors?.[0]?.message || `HTTP ${patchResponse.status}`;
      console.warn('[DDNS] Failed to patch Cloudflare DNS record:', { domain: normalizedDomain, recordType, recordId: record.id, error: errMsg });
      return { attempted: true, ok: false, error: errMsg };
    }

    return { attempted: true, ok: true, action: 'updated', recordId: record.id };
  } catch (e) {
    console.warn('[DDNS] Cloudflare DNS sync error:', e?.message || e);
    return { attempted: true, ok: false, error: e?.message || String(e) };
  }
}

function evaluateSingleStack(currentIp, lastIp, pendingEntry) {
  if (!currentIp) {
    return {
      nextLastIp: lastIp,
      nextPending: pendingEntry,
      dirty: false,
      change: null
    };
  }

  // First heartbeat with no stored baseline: establish baseline silently without alerting
  if (!lastIp) {
    return {
      nextLastIp: currentIp,
      nextPending: null,
      dirty: true,
      change: null
    };
  }

  if (currentIp === lastIp) {
    return {
      nextLastIp: lastIp,
      nextPending: null,
      dirty: Boolean(pendingEntry),
      change: null
    };
  }

  const nextCount = pendingEntry?.ip === currentIp ? pendingEntry.count + 1 : 1;
  if (nextCount >= IP_CHANGE_REQUIRED_HEARTBEATS) {
    return {
      nextLastIp: currentIp,
      nextPending: null,
      dirty: true,
      change: { oldIp: lastIp, newIp: currentIp }
    };
  }

  return {
    nextLastIp: lastIp,
    nextPending: { ip: currentIp, count: nextCount },
    dirty: pendingEntry?.ip !== currentIp || pendingEntry?.count !== nextCount,
    change: null
  };
}

async function runIpChangeSideEffects(env, server, changes) {
  const ddnsDomain = normalizeDdnsDomain(server.ddns_domain);
  const enrichedChanges = [];

  for (const change of changes) {
    let ddnsResult = null;
    if (shouldSyncDdnsForFamily(server, change.family)) {
      ddnsResult = await syncCloudflareDnsRecord(env, {
        domain: ddnsDomain,
        recordType: change.recordType,
        newIp: change.newIp
      });
    }
    enrichedChanges.push({ ...change, ddnsDomain, ddnsResult });
  }

  if (!env?.DB) return;
  const settings = await loadSiteSettings(env.DB);
  if (!hasNotificationTarget(settings)) return;

  const messages = getNotificationMessages(settings);
  const serverName = server.name || server.id;
  const shouldMaskIp = normalizeBooleanSetting(settings?.ip_change_mask_ip) === 'true';

  const lines = [];
  const embedFields = [];
  for (const item of enrichedChanges) {
    const displayOldIp = shouldMaskIp ? (maskIpAddress(item.oldIp) || item.oldIp) : item.oldIp;
    const displayNewIp = shouldMaskIp ? (maskIpAddress(item.newIp) || item.newIp) : item.newIp;
    let ddnsSuffix = '';
    if (item.ddnsResult?.attempted) {
      ddnsSuffix = item.ddnsResult.ok
        ? ` | DNS(${item.ddnsDomain}): ${item.ddnsResult.action === 'unchanged' ? 'OK' : 'Updated'}`
        : ` | DNS(${item.ddnsDomain}): Failed (${item.ddnsResult.error})`;
    }
    const detailLine = typeof messages.ipChangeDetail === 'function'
      ? messages.ipChangeDetail({
          protocol: item.protocol,
          oldIp: displayOldIp,
          newIp: displayNewIp,
          ddnsStatus: ddnsSuffix
        })
      : `${item.protocol}: ${displayOldIp} -> ${displayNewIp}${ddnsSuffix}`;
    lines.push(`${serverName}  ${detailLine}`);
    embedFields.push({
      name: `${item.protocol} (${item.recordType})`,
      value: `\`${displayOldIp}\` → \`${displayNewIp}\`${ddnsSuffix}`,
      inline: false
    });
  }

  const msg = lines.join('\n');
  const notifyErr = await sendNotification(settings, msg, {
    event: messages.events?.ipChanged || 'Node IP Changed',
    emoji: '🌐',
    clients: [serverName],
    count: 1,
    message: msg,
    embedFields
  });
  if (notifyErr) {
    console.warn('[IPMonitor] Notification failed:', notifyErr);
  }
}

export async function evaluateIpChange(env, server, metrics, options = {}) {
  try {
    if (!env?.DB || !server?.id || !metrics) {
      return { changed: false, changes: [] };
    }

    const { v4, v6 } = extractReportedIps(metrics, options.clientIp || '');
    if (!v4 && !v6) {
      return { changed: false, changes: [] };
    }

    const currentLastV4 = normalizeStoredIp(server.last_ipv4, 'v4');
    const currentLastV6 = normalizeStoredIp(server.last_ipv6, 'v6');
    const pendingState = parsePendingIpState(server.pending_ip, server.pending_ip_count);

    const v4Eval = evaluateSingleStack(v4, currentLastV4, pendingState.v4);
    const v6Eval = evaluateSingleStack(v6, currentLastV6, pendingState.v6);

    const serializedPending = serializePendingIpState({
      v4: v4Eval.nextPending,
      v6: v6Eval.nextPending
    });

    const dirty = v4Eval.dirty ||
      v6Eval.dirty ||
      serializedPending.pending_ip !== String(server.pending_ip || '') ||
      serializedPending.pending_ip_count !== (Number(server.pending_ip_count) || 0);

    if (!dirty) {
      return { changed: false, changes: [] };
    }

    const nextFields = {
      last_ipv4: v4Eval.nextLastIp,
      last_ipv6: v6Eval.nextLastIp,
      pending_ip: serializedPending.pending_ip,
      pending_ip_count: serializedPending.pending_ip_count
    };

    try {
      await env.DB.prepare(
        'UPDATE servers SET last_ipv4 = ?, last_ipv6 = ?, pending_ip = ?, pending_ip_count = ? WHERE id = ?'
      ).bind(
        nextFields.last_ipv4,
        nextFields.last_ipv6,
        nextFields.pending_ip,
        nextFields.pending_ip_count,
        server.id
      ).run();
    } catch (e) {
      const message = String(e?.message || e);
      if (/no such column/i.test(message)) {
        console.warn('[IPMonitor] Missing IP tracking columns in servers table; run database migration first.');
        return { changed: false, changes: [] };
      }
      throw e;
    }

    // Mutate passed object & patch isolate/DO caches to prevent duplicate triggers before TTL expiry
    Object.assign(server, nextFields);
    options.patchCache?.(server.id, nextFields);

    const changes = [];
    if (v4Eval.change) {
      changes.push({
        family: 'v4',
        protocol: 'IPv4',
        recordType: 'A',
        ...v4Eval.change
      });
    }
    if (v6Eval.change) {
      changes.push({
        family: 'v6',
        protocol: 'IPv6',
        recordType: 'AAAA',
        ...v6Eval.change
      });
    }

    if (changes.length > 0) {
      const sideEffectPromise = runIpChangeSideEffects(env, server, changes).catch(e => {
        console.error('[IPMonitor] Async IP change side-effects failed:', e);
      });
      if (typeof options.waitUntil === 'function') {
        options.waitUntil(sideEffectPromise);
      } else {
        await sideEffectPromise;
      }
    }

    return {
      changed: changes.length > 0,
      changes,
      state: nextFields
    };
  } catch (e) {
    console.error('[IPMonitor] evaluate failed:', e);
    return { changed: false, changes: [] };
  }
}
