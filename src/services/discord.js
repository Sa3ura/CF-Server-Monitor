import { getLatestMetricsForAllServers } from '../database/schema.js';
import { getAllServers } from '../utils/cache.js';
import { mergeMetricsIntoServer } from '../utils/metrics.js';
import { getWorkerLatestReportUpdates } from '../utils/latestReportCache.js';
import { GB, getTrafficUsageBytes, normalizeTrafficLimitGb } from '../utils/traffic.js';
import {
  detectBillingCycle,
  detectCurrencySymbol,
  isEnabledFlag,
  normalizeBillingCycle,
  normalizeCurrency,
  normalizePrice
} from '../utils/serverBilling.js';
import { getNotificationMessages } from './notificationMessages.js';
import {
  loadSettings,
  normalizeBooleanSetting,
  normalizeDiscordBotToken,
  normalizeDiscordSnowflake,
  normalizeNotificationTimezone
} from '../utils/settings.js';
import {
  NOTIFICATION_MAX_RETRIES,
  NOTIFICATION_RETRY_DELAY_MS
} from '../utils/config.js';

export const DISCORD_API_BASE = 'https://discord.com/api/v10';
export const DISCORD_SIGNATURE_MAX_AGE_SECONDS = 300;
export const DISCORD_STATUS_REFRESH_ID = 'cfsm:status:refresh';
export const DISCORD_NODE_REFRESH_PREFIX = 'cfsm:node:refresh:';
export const DISCORD_TRAFFIC_REFRESH_ID = 'cfsm:traffic:refresh';
export const DISCORD_EXPIRE_REFRESH_ID = 'cfsm:expire:refresh';
export const DISCORD_PING_REFRESH_PREFIX = 'cfsm:ping:refresh';

export const DISCORD_SLASH_COMMANDS = Object.freeze([
  {
    name: 'status',
    description: 'Query server monitoring status overview',
    type: 1,
    integration_types: [0, 1],
    contexts: [0, 1, 2]
  },
  {
    name: 'node',
    description: 'Query detailed metrics for a specific node',
    type: 1,
    integration_types: [0, 1],
    contexts: [0, 1, 2],
    options: [
      {
        name: 'name',
        description: 'Node name or ID',
        type: 3,
        required: true,
        autocomplete: true
      }
    ]
  },
  {
    name: 'traffic',
    description: 'Show monthly traffic usage ranking',
    type: 1,
    integration_types: [0, 1],
    contexts: [0, 1, 2]
  },
  {
    name: 'expire',
    description: 'Show server expiration calendar and billing summary',
    type: 1,
    integration_types: [0, 1],
    contexts: [0, 1, 2]
  },
  {
    name: 'ping',
    description: 'Show network latency probes (CT/CU/CM & custom)',
    type: 1,
    integration_types: [0, 1],
    contexts: [0, 1, 2],
    options: [
      {
        name: 'name',
        description: 'Optional node name or ID',
        type: 3,
        required: false,
        autocomplete: true
      }
    ]
  }
]);

const BILLING_CYCLE_MONTHS = Object.freeze({
  month: 1,
  quarter: 3,
  half_year: 6,
  year: 12,
  two_years: 24,
  three_years: 36,
  four_years: 48,
  five_years: 60
});

const PING_PROBE_DEFS = Object.freeze([
  { pingField: 'ping_ct', lossField: 'loss_ct', nameKey: 'custom_ct_name', fallback: 'CT' },
  { pingField: 'ping_cu', lossField: 'loss_cu', nameKey: 'custom_cu_name', fallback: 'CU' },
  { pingField: 'ping_cm', lossField: 'loss_cm', nameKey: 'custom_cm_name', fallback: 'CM' },
  { pingField: 'ping_bd', lossField: 'loss_bd', nameKey: 'custom_bd_name', fallback: 'BGP' },
  { pingField: 'ping_node_1', lossField: 'loss_node_1', nameKey: 'node_1_name', fallback: 'Node 1' },
  { pingField: 'ping_node_2', lossField: 'loss_node_2', nameKey: 'node_2_name', fallback: 'Node 2' },
  { pingField: 'ping_node_3', lossField: 'loss_node_3', nameKey: 'node_3_name', fallback: 'Node 3' },
  { pingField: 'ping_node_4', lossField: 'loss_node_4', nameKey: 'node_4_name', fallback: 'Node 4' }
]);

const DAY_MS = 24 * 60 * 60 * 1000;
const DISCORD_USER_AGENT = 'DiscordBot (https://github.com/huilang-me/CF-Server-Monitor, 1.0)';
const DISCORD_SNOWFLAKE_RE = /^\d{15,25}$/;
const DISCORD_ONLINE_THRESHOLD_MS = 300000;
const DISCORD_DO_FETCH_TIMEOUT_MS = 700;
const DISCORD_API_TIMEOUT_MS = 10000;
const DISCORD_DM_CHANNEL_CACHE_MAX_ENTRIES = 50;
const DISCORD_EMBED_MAX_FIELDS = 25;
const DISCORD_EMBED_TOTAL_CHAR_LIMIT = 5800;

const dmChannelCache = new Map();

function createTokenFingerprint(token) {
  const value = String(token || '');
  let h1 = 0x811c9dc5;
  let h2 = 0x9e3779b9;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    h1 = Math.imul(h1 ^ code, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ (code + i), 0x85ebca6b) >>> 0;
  }
  return `${value.length}:${h1.toString(16)}:${h2.toString(16)}`;
}

function setDmChannelCacheEntry(key, channelId) {
  dmChannelCache.delete(key);
  dmChannelCache.set(key, channelId);
  while (dmChannelCache.size > DISCORD_DM_CHANNEL_CACHE_MAX_ENTRIES) {
    dmChannelCache.delete(dmChannelCache.keys().next().value);
  }
}

export function isDiscordBotEnabled(settings = {}) {
  return normalizeBooleanSetting(settings?.discord_bot_enabled) === 'true';
}

export function hasDiscordBotTarget(settings = {}) {
  if (!isDiscordBotEnabled(settings)) return false;
  const token = normalizeDiscordBotToken(settings?.discord_bot_token);
  const channelId = normalizeDiscordSnowflake(settings?.discord_channel_id);
  const userId = normalizeDiscordSnowflake(settings?.discord_user_id);
  return Boolean(token && (channelId || userId));
}

export function validateDiscordBotTarget(settings = {}) {
  const token = normalizeDiscordBotToken(settings?.discord_bot_token);
  const channelId = normalizeDiscordSnowflake(settings?.discord_channel_id);
  const userId = normalizeDiscordSnowflake(settings?.discord_user_id);

  if (!token) return { valid: false, error: 'discordBotTokenRequired' };
  if (!channelId && !userId) return { valid: false, error: 'discordTargetRequired' };
  if (channelId && !DISCORD_SNOWFLAKE_RE.test(channelId)) return { valid: false, error: 'invalidDiscordId' };
  if (userId && !DISCORD_SNOWFLAKE_RE.test(userId)) return { valid: false, error: 'invalidDiscordId' };
  return { valid: true, token, channelId, userId };
}

function truncateText(value, maxLength) {
  const text = String(value ?? '');
  if (text.length <= maxLength) return text;
  return maxLength > 1 ? `${text.slice(0, maxLength - 1)}…` : text.slice(0, maxLength);
}

export function resolveDiscordEmbedColor(context = {}) {
  const emoji = String(context.emoji || '');
  const event = String(context.event || '');

  if (emoji === '🌐' || emoji === '🔄' || /\bIP\b/i.test(event)) {
    return 0x3b82f6;
  }
  if (emoji === '✅' || /恢复|测试|成功|续费|recovered|test|renewed|normaliz|rétabli|pulih/i.test(event)) {
    return 0x22c55e;
  }
  if (emoji === '❌' || emoji === '📈' || /离线|告警|失败|异常|offline|alert|alerta|alerte|peringatan|アラート/i.test(event)) {
    return 0xef4444;
  }
  if (emoji === '⚠️' || /到期|提醒|expir|vencimiento|kedaluwarsa|リマインダー/i.test(event)) {
    return 0xf59e0b;
  }
  return 0x5865f2;
}

function escapeDiscordMaskedIps(text) {
  const source = String(text || '');
  if (!source.includes('*')) return source;
  // Preserve fenced code blocks and inline code spans untouched; escape * in masked IPs outside code so Discord does not parse *.* / *:* as italics
  return source
    .split(/(```[\s\S]*?```|`[^`\n]+`)/g)
    .map((segment, index) => {
      if (index % 2 === 1) return segment;
      return segment
        .replace(/\b(\d{1,3})\.\*\.\*\.(\d{1,3})\b/g, '$1.\\*.\\*.$2')
        .replace(/\b([0-9a-fA-F]{1,4}):\*:\*:([0-9a-fA-F]{1,4})\b/g, '$1:\\*:\\*:$2');
    })
    .join('');
}

export function buildDiscordAlertEmbed(context = {}, formattedMsg = '', settings = {}) {
  const labels = getNotificationMessages(settings)?.discord || {};
  const event = String(context.event || 'Notification').trim();
  const emoji = String(context.emoji || '').trim();
  const title = truncateText(`${emoji ? `${emoji} ` : ''}${event}`.trim(), 256);
  const rawDescription = escapeDiscordMaskedIps(String(formattedMsg || context.message || '').trim());
  const description = truncateText(rawDescription || '-', 4096);
  const footerText = truncateText(String(settings?.site_title || '').trim() || 'CF Server Monitor', 2048);

  const fields = [];
  const serverNames = String(context.client || context.clients || '').trim();
  if (serverNames) {
    fields.push({
      name: labels.node || 'Node / Server',
      value: truncateText(serverNames, 1024),
      inline: true
    });
  }
  if (event) {
    fields.push({
      name: labels.event || 'Event',
      value: truncateText(event, 1024),
      inline: true
    });
  }
  if (context.time) {
    fields.push({
      name: labels.time || 'Time',
      value: truncateText(String(context.time), 1024),
      inline: true
    });
  }
  if (Array.isArray(context.embedFields)) {
    for (const field of context.embedFields) {
      if (!field || !field.name || !field.value) continue;
      if (fields.length >= DISCORD_EMBED_MAX_FIELDS) break;
      fields.push({
        name: truncateText(field.name, 256),
        value: truncateText(field.value, 1024),
        inline: Boolean(field.inline)
      });
    }
  }

  return {
    title,
    description,
    color: resolveDiscordEmbedColor(context),
    fields,
    footer: { text: footerText },
    timestamp: new Date().toISOString()
  };
}

async function discordApiRequest(path, token, body, retries = NOTIFICATION_MAX_RETRIES, method = 'POST') {
  let lastError;
  for (let i = 0; i < retries; i++) {
    try {
      const headers = {
        'Authorization': `Bot ${token}`,
        'User-Agent': DISCORD_USER_AGENT
      };
      const init = { method, headers };
      if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
        init.signal = AbortSignal.timeout(DISCORD_API_TIMEOUT_MS);
      }
      if (method !== 'GET' && body !== undefined) {
        headers['Content-Type'] = 'application/json';
        init.body = JSON.stringify(body);
      }
      const response = await fetch(`${DISCORD_API_BASE}${path}`, init);

      if (response.ok) {
        return response.json().catch(() => ({}));
      }

      const errorText = await response.text().catch(() => '');
      const err = new Error(`HTTP ${response.status}${errorText ? `: ${errorText.slice(0, 200)}` : ''}`);
      err.status = response.status;

      // Retry on 429 rate limits and 5xx server errors only
      if (response.status === 429 || response.status >= 500) {
        lastError = err;
        if (i < retries - 1) {
          let delayMs = NOTIFICATION_RETRY_DELAY_MS;
          const retryAfter = Number(response.headers?.get?.('Retry-After'));
          if (Number.isFinite(retryAfter) && retryAfter > 0) {
            delayMs = Math.min(3000, Math.ceil(retryAfter * 1000));
          }
          await new Promise(resolve => setTimeout(resolve, delayMs));
          continue;
        }
      }
      throw err;
    } catch (e) {
      lastError = e;
      if (e?.status && e.status !== 429 && e.status < 500) break;
      if (i < retries - 1) {
        await new Promise(resolve => setTimeout(resolve, NOTIFICATION_RETRY_DELAY_MS));
      }
    }
  }
  throw lastError || new Error('Discord API request failed');
}

export async function syncDiscordSlashCommands(settings = {}) {
  const token = normalizeDiscordBotToken(settings?.discord_bot_token);
  if (!token) {
    return { ok: false, error: 'discordBotTokenRequired' };
  }
  try {
    const appInfo = await discordApiRequest('/oauth2/applications/@me', token, undefined, NOTIFICATION_MAX_RETRIES, 'GET');
    const appId = String(appInfo?.id || '').trim();
    if (!appId) {
      return { ok: false, error: 'Failed to resolve Discord Application ID' };
    }
    const registered = await discordApiRequest(
      `/applications/${encodeURIComponent(appId)}/commands`,
      token,
      DISCORD_SLASH_COMMANDS,
      NOTIFICATION_MAX_RETRIES,
      'PUT'
    );
    const commandNames = Array.isArray(registered)
      ? registered.map(item => `/${item.name}`).filter(Boolean)
      : DISCORD_SLASH_COMMANDS.map(item => `/${item.name}`);
    return {
      ok: true,
      applicationId: appId,
      commands: commandNames
    };
  } catch (e) {
    return {
      ok: false,
      error: e?.message || String(e)
    };
  }
}

async function resolveDiscordTargetChannelId(token, channelId, userId) {
  if (!userId) return { targetChannelId: channelId, isDm: false };

  const cacheKey = `${createTokenFingerprint(token)}:${userId}`;
  const cachedChannelId = dmChannelCache.get(cacheKey);
  if (cachedChannelId) {
    return { targetChannelId: cachedChannelId, isDm: true, cacheKey };
  }

  const dmChannel = await discordApiRequest('/users/@me/channels', token, {
    recipient_id: userId
  });
  if (!dmChannel?.id) {
    throw new Error('Failed to create Discord DM channel');
  }
  setDmChannelCacheEntry(cacheKey, dmChannel.id);
  return { targetChannelId: dmChannel.id, isDm: true, cacheKey };
}

export async function sendDiscordBotNotification(settings, context = {}, formattedMsg = '') {
  const validated = validateDiscordBotTarget(settings);
  if (!validated.valid) {
    return `Discord Bot 通知配置错误: ${validated.error}`;
  }

  const { token, channelId, userId } = validated;
  const embed = buildDiscordAlertEmbed(context, formattedMsg, settings);

  try {
    let target = await resolveDiscordTargetChannelId(token, channelId, userId);
    try {
      await discordApiRequest(`/channels/${encodeURIComponent(target.targetChannelId)}/messages`, token, {
        embeds: [embed]
      });
    } catch (e) {
      // Cached DM channel might have been invalidated; refresh once on 403/404
      if (target.isDm && target.cacheKey && (e?.status === 403 || e?.status === 404)) {
        dmChannelCache.delete(target.cacheKey);
        target = await resolveDiscordTargetChannelId(token, channelId, userId);
        await discordApiRequest(`/channels/${encodeURIComponent(target.targetChannelId)}/messages`, token, {
          embeds: [embed]
        });
      } else {
        throw e;
      }
    }
    return undefined;
  } catch (e) {
    return `Discord Bot 通知发送失败: ${e?.message || e}`;
  }
}

function hexToUint8Array(hex) {
  const value = String(hex || '').trim();
  if (!value || value.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(value)) {
    return null;
  }
  const bytes = new Uint8Array(value.length / 2);
  for (let i = 0; i < value.length; i += 2) {
    bytes[i / 2] = parseInt(value.slice(i, i + 2), 16);
  }
  return bytes;
}

export async function verifyDiscordSignature(rawBody, signatureHex, timestamp, publicKeyHex, options = {}) {
  const ts = String(timestamp ?? '');
  if (!ts || !/^\d{1,15}$/.test(ts)) return false;

  const nowMs = Number.isFinite(options?.now) ? options.now : Date.now();
  const nowSec = Math.floor(nowMs / 1000);
  const maxAgeSec = Number.isFinite(options?.maxAgeSeconds) ? options.maxAgeSeconds : DISCORD_SIGNATURE_MAX_AGE_SECONDS;
  if (Math.abs(nowSec - Number(ts)) > maxAgeSec) {
    return false;
  }

  const signature = hexToUint8Array(signatureHex);
  const publicKey = hexToUint8Array(publicKeyHex);
  if (!signature || signature.length !== 64 || !publicKey || publicKey.length !== 32) {
    return false;
  }

  try {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      publicKey,
      { name: 'Ed25519' },
      false,
      ['verify']
    );
    const message = new TextEncoder().encode(`${ts}${rawBody}`);
    return await crypto.subtle.verify('Ed25519', cryptoKey, signature, message);
  } catch (_) {
    return false;
  }
}

export function isAuthorizedDiscordInteraction(interaction, settings = {}) {
  const allowedUserId = normalizeDiscordSnowflake(settings?.discord_user_id);
  const allowedChannelId = normalizeDiscordSnowflake(settings?.discord_channel_id);
  const actorUserId = String(interaction?.user?.id || interaction?.member?.user?.id || '').trim();
  const channelId = String(interaction?.channel_id || '').trim();

  const hasAllowlist = Boolean(allowedUserId || allowedChannelId);
  if (hasAllowlist) {
    return Boolean(
      (allowedUserId && actorUserId === allowedUserId) ||
      (allowedChannelId && channelId === allowedChannelId)
    );
  }

  return settings?.is_public === undefined
    ? true
    : normalizeBooleanSetting(settings.is_public) !== 'false';
}

function resolveDisplayFlags(settings = {}) {
  return {
    showTraffic: settings?.show_tf === undefined ? true : normalizeBooleanSetting(settings.show_tf) === 'true',
    showExpire: settings?.show_expire === undefined ? true : normalizeBooleanSetting(settings.show_expire) === 'true',
    showPrice: settings?.show_price === undefined ? true : normalizeBooleanSetting(settings.show_price) === 'true'
  };
}

function formatBytesPerSecond(bytesPerSec) {
  const value = Number(bytesPerSec);
  if (!Number.isFinite(value) || value <= 0) return '0 B/s';
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  let unitIndex = 0;
  let scaled = value;
  while (scaled >= 1024 && unitIndex < units.length - 1) {
    scaled /= 1024;
    unitIndex++;
  }
  return `${scaled >= 10 || unitIndex === 0 ? scaled.toFixed(0) : scaled.toFixed(1)} ${units[unitIndex]}`;
}

function formatCompactBytesPerSecond(bytesPerSec) {
  const value = Number(bytesPerSec);
  if (!Number.isFinite(value) || value <= 0) return '0B';
  const units = ['B', 'K', 'M', 'G'];
  let unitIndex = 0;
  let scaled = value;
  while (scaled >= 1024 && unitIndex < units.length - 1) {
    scaled /= 1024;
    unitIndex++;
  }
  return `${scaled >= 10 || unitIndex === 0 ? scaled.toFixed(0) : scaled.toFixed(1)}${units[unitIndex]}`;
}

function formatDuration(secondsValue, maxParts = 3) {
  const totalSeconds = Math.floor(Number(secondsValue) || 0);
  if (totalSeconds <= 0) return '0m';
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const parts = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0 || days > 0) parts.push(`${hours}h`);
  parts.push(`${minutes}m`);
  return parts.slice(0, maxParts).join(' ');
}

function resolveUptimeSeconds(metrics = {}, fallbackMetrics = null, now = Date.now()) {
  const direct = Number(metrics.uptime ?? fallbackMetrics?.uptime);
  if (Number.isFinite(direct) && direct > 0) return direct;
  const bootTime = Number(metrics.boot_time ?? fallbackMetrics?.boot_time);
  if (Number.isFinite(bootTime) && bootTime > 0) {
    const bootMs = bootTime < 10000000000 ? bootTime * 1000 : bootTime;
    if (now > bootMs) return Math.floor((now - bootMs) / 1000);
  }
  return 0;
}

function pickNewestRealtimeMetrics(update) {
  if (!update || !Array.isArray(update.samples) || update.samples.length === 0) return null;
  let newest = null;
  let newestTs = 0;
  for (const sample of update.samples) {
    const data = sample?.data || sample?.payload || sample?.metrics;
    if (!data || typeof data !== 'object') continue;
    const rawTs = Number(sample?.ts ?? sample?.timestamp ?? data.timestamp ?? data.last_updated ?? 0);
    const ts = rawTs > 0 && rawTs < 10000000000 ? rawTs * 1000 : rawTs;
    if (!newest || ts >= newestTs) {
      newestTs = ts;
      newest = { ...data, timestamp: ts || Number(update.reportTs) || 0 };
    }
  }
  return newest;
}

async function fetchStatusRealtimeMap(env, serverIds) {
  const map = new Map();
  if (!Array.isArray(serverIds) || serverIds.length === 0) return map;

  for (const update of getWorkerLatestReportUpdates(serverIds)) {
    const metrics = pickNewestRealtimeMetrics(update);
    if (metrics) map.set(String(update.serverId), metrics);
  }

  if (!env?.METRICS_BROADCASTER) return map;

  try {
    const id = env.METRICS_BROADCASTER.idFromName('global');
    const stub = env.METRICS_BROADCASTER.get(id);
    const response = await Promise.race([
      stub.fetch('http://internal/latest-report-updates', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ serverIds: serverIds.slice(0, 500) })
      }),
      new Promise(resolve => setTimeout(() => resolve(null), DISCORD_DO_FETCH_TIMEOUT_MS))
    ]);

    if (response && response.ok) {
      const payload = await response.json();
      for (const update of Array.isArray(payload?.updates) ? payload.updates : []) {
        const metrics = pickNewestRealtimeMetrics(update);
        if (!metrics) continue;
        const serverId = String(update.serverId);
        const existing = map.get(serverId);
        if (!existing || Number(metrics.timestamp || 0) >= Number(existing.timestamp || 0)) {
          map.set(serverId, metrics);
        }
      }
    }
  } catch (_) {}

  return map;
}

export function buildProgressBar(percent, length = 5) {
  const numeric = Number(percent);
  const clamped = Number.isFinite(numeric) ? Math.max(0, Math.min(100, numeric)) : 0;
  const filled = Math.round((clamped / 100) * length);
  return '▰'.repeat(filled) + '▱'.repeat(Math.max(0, length - filled));
}

export function getLoadLevelIcon(percent) {
  const numeric = Number(percent);
  if (!Number.isFinite(numeric) || numeric < 60) return '🟢';
  if (numeric < 85) return '🟡';
  return '🔴';
}

function getInlineLoadBadge(percent) {
  const numeric = Number(percent);
  if (!Number.isFinite(numeric) || numeric < 60) return '';
  return numeric >= 85 ? ' 🔴' : ' 🟡';
}

function formatServerDisplayName(name, regionCode) {
  const base = String(name || '').trim();
  if (!regionCode) return base;
  const upperBase = base.toUpperCase();
  const hasRegionPrefix =
    upperBase.startsWith(`${regionCode}-`) ||
    upperBase.startsWith(`${regionCode} `) ||
    upperBase.startsWith(`${regionCode}_`) ||
    upperBase.startsWith(`[${regionCode}]`);
  return hasRegionPrefix ? base : `${base} [${regionCode}]`;
}

export function buildRefreshActionRow(settings = {}, customId = DISCORD_STATUS_REFRESH_ID) {
  const labels = getNotificationMessages(settings)?.discord || {};
  return [
    {
      type: 1,
      components: [
        {
          type: 2,
          style: 2,
          label: labels.refresh || 'Refresh',
          emoji: { name: '🔄' },
          custom_id: truncateText(customId, 100)
        }
      ]
    }
  ];
}

export function buildStatusActionRow(settings = {}) {
  return buildRefreshActionRow(settings, DISCORD_STATUS_REFRESH_ID);
}

function renderDiscordTemplate(template, vars = {}) {
  return String(template || '').replace(/\{\{\s*([A-Za-z0-9_]+)\s*\}\}/g, (_, key) => (
    Object.prototype.hasOwnProperty.call(vars, key) ? String(vars[key] ?? '') : ''
  ));
}

function formatStatusTimestamp(now = Date.now(), settings = {}) {
  const date = new Date(now);
  if (Number.isNaN(date.getTime())) return '';
  const timeZone = normalizeNotificationTimezone(settings?.notification_timezone);
  const formatter = new Intl.DateTimeFormat('en-US', {
    timeZone,
    hour12: false,
    hourCycle: 'h23',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
  const parts = Object.fromEntries(formatter.formatToParts(date).map(part => [part.type, part.value]));
  return `${Number(parts.year)}/${Number(parts.month)}/${Number(parts.day)} ${String(parts.hour).padStart(2, '0')}:${String(parts.minute).padStart(2, '0')}:${String(parts.second).padStart(2, '0')}`;
}

export function buildStatusCommandEmbed(servers = [], latestMetricsMap = new Map(), realtimeMap = new Map(), now = Date.now(), settings = {}) {
  const messages = getNotificationMessages(settings);
  const labels = messages?.discord || {};
  const siteTitle = String(settings?.site_title || '').trim();
  const customTemplate = String(settings?.discord_status_template || '').trim();

  let onlineCount = 0;
  let offlineCount = 0;
  const nodeEntries = [];

  for (const server of servers) {
    const snap = mergeServerSnapshot(server, latestMetricsMap, realtimeMap, now);
    const { serverId, merged, effectiveMetrics, lastTs, isOnline, regionCode, displayName } = snap;
    if (isOnline) onlineCount++;
    else offlineCount++;

    const cpuNum = Number(merged.cpu || 0);
    const cpu = cpuNum.toFixed(1);
    const ramTotal = Number(merged.ram_total || 0);
    const ramUsed = Number(merged.ram_used || 0);
    const ramNum = ramTotal > 0 ? (ramUsed / ramTotal) * 100 : 0;
    const ramPct = ramNum.toFixed(1);
    const diskTotal = Number(merged.disk_total || 0);
    const diskUsed = Number(merged.disk_used || 0);
    const diskNum = diskTotal > 0 ? (diskUsed / diskTotal) * 100 : 0;
    const diskPct = diskNum.toFixed(1);
    const cpuBar = buildProgressBar(cpuNum);
    const ramBar = buildProgressBar(ramNum);
    const diskBar = buildProgressBar(diskNum);
    const cpuIcon = getLoadLevelIcon(cpuNum);
    const ramIcon = getLoadLevelIcon(ramNum);
    const diskIcon = getLoadLevelIcon(diskNum);
    const cpuBadge = getInlineLoadBadge(cpuNum).trim();
    const ramBadge = getInlineLoadBadge(ramNum).trim();
    const diskBadge = getInlineLoadBadge(diskNum).trim();
    const peakLoad = Math.max(cpuNum, ramNum);
    const loadIcon = isOnline ? getLoadLevelIcon(peakLoad) : '⚫';
    const highLoadSuffix = isOnline && peakLoad >= 85 ? ' ⚠️' : '';
    const down = formatBytesPerSecond(merged.net_in_speed);
    const up = formatBytesPerSecond(merged.net_out_speed);
    const downShort = formatCompactBytesPerSecond(merged.net_in_speed);
    const upShort = formatCompactBytesPerSecond(merged.net_out_speed);
    const uptimeSeconds = resolveUptimeSeconds(merged, effectiveMetrics, now);
    const uptime = formatDuration(uptimeSeconds);
    const uptimeShort = formatDuration(uptimeSeconds, 2);
    const regionTag = regionCode ? ` [${regionCode}]` : '';
    const statusIcon = isOnline ? '🟢' : '🔴';
    const statusText = isOnline ? (labels.online || 'Online') : (labels.offline || 'Offline');
    const lastSeenText = lastTs > 0
      ? (typeof labels.lastSeen === 'function' ? labels.lastSeen(formatDuration((now - lastTs) / 1000, 2)) : `${formatDuration((now - lastTs) / 1000, 2)} ago`)
      : (labels.noReport || 'No report');
    const defaultDetail = isOnline
      ? `\`CPU\` ${cpuBar} **${cpu}%**${getInlineLoadBadge(cpuNum)}\n\`RAM\` ${ramBar} **${ramPct}%**${getInlineLoadBadge(ramNum)}\n-# ↓${downShort} ↑${upShort} · ${uptimeShort}`
      : `${labels.offline || 'Offline'} · ${lastSeenText}`;

    nodeEntries.push({
      isOnline,
      name: truncateText(`${statusIcon} ${displayName}${highLoadSuffix}`, 256),
      defaultValue: defaultDetail,
      vars: {
        id: serverId,
        name: merged.name || serverId,
        group: merged.server_group || '',
        region: regionCode,
        region_tag: regionTag,
        status_icon: statusIcon,
        status: statusText,
        load_icon: loadIcon,
        cpu,
        cpu_bar: cpuBar,
        cpu_icon: cpuIcon,
        cpu_badge: cpuBadge,
        ram: ramPct,
        ram_bar: ramBar,
        ram_icon: ramIcon,
        ram_badge: ramBadge,
        ram_used: String(Math.round(ramUsed)),
        ram_total: String(Math.round(ramTotal)),
        disk: diskPct,
        disk_bar: diskBar,
        disk_icon: diskIcon,
        disk_badge: diskBadge,
        net_in: down,
        net_out: up,
        net_in_short: downShort,
        net_out_short: upShort,
        uptime,
        uptime_short: uptimeShort,
        last_seen: lastSeenText,
        detail: defaultDetail
      }
    });
  }

  let color = 0x22c55e;
  if (servers.length === 0) {
    color = 0x5865f2;
  } else if (onlineCount === 0) {
    color = 0xef4444;
  } else if (offlineCount > 0) {
    color = 0xf59e0b;
  }

  const footerText = truncateText(siteTitle || 'CF Server Monitor', 2048);
  const topVars = {
    site_title: siteTitle || 'CF Server Monitor',
    total: String(servers.length),
    online: String(onlineCount),
    offline: String(offlineCount),
    time: formatStatusTimestamp(now, settings)
  };

  // 完整自定义模板：包含 {{#servers}}...{{/servers}} 循环块
  const loopMatch = customTemplate.match(/\{\{\s*#servers\s*\}\}([\s\S]*?)\{\{\s*\/servers\s*\}\}/);
  if (customTemplate && loopMatch) {
    const itemTemplate = loopMatch[1].replace(/^\r?\n/, '').replace(/\r?\n$/, '');
    const renderedItems = nodeEntries.length > 0
      ? nodeEntries.map(entry => renderDiscordTemplate(itemTemplate, { ...topVars, ...entry.vars })).join('\n')
      : (labels.noServers || 'No visible servers configured.');
    const renderedBody = renderDiscordTemplate(
      customTemplate.replace(loopMatch[0], () => renderedItems),
      topVars
    ).trim();

    return {
      title: truncateText(`🖥️ ${siteTitle || labels.statusTitle || 'Server Status Overview'}`, 256),
      description: truncateText(renderedBody || (labels.noServers || 'No visible servers configured.'), 4096),
      color,
      fields: [],
      footer: { text: footerText },
      timestamp: new Date(now).toISOString()
    };
  }

  const title = truncateText(`🖥️ ${labels.statusTitle || 'Server Status Overview'}`, 256);
  const summaryLine = `${labels.total || 'Total'}: **${servers.length}** | 🟢 ${labels.online || 'Online'}: **${onlineCount}** | 🔴 ${labels.offline || 'Offline'}: **${offlineCount}**`;
  const fields = [];
  let charBudget = Math.max(0, DISCORD_EMBED_TOTAL_CHAR_LIMIT - title.length - summaryLine.length - footerText.length - 120);
  let overflowCount = 0;

  for (const entry of nodeEntries) {
    if (fields.length >= DISCORD_EMBED_MAX_FIELDS) {
      overflowCount++;
      continue;
    }
    const renderedValue = customTemplate
      ? truncateText(renderDiscordTemplate(customTemplate, { ...topVars, ...entry.vars }).trim() || entry.defaultValue, 1024)
      : entry.defaultValue;
    const fieldCost = entry.name.length + renderedValue.length;
    if (charBudget - fieldCost < 0) {
      overflowCount++;
      continue;
    }
    charBudget -= fieldCost;
    fields.push({
      name: entry.name,
      value: renderedValue,
      inline: true
    });
  }

  let description = summaryLine;
  if (servers.length === 0) {
    description = `${summaryLine}\n\n${labels.noServers || 'No visible servers configured.'}`;
  } else if (overflowCount > 0) {
    const omittedText = typeof labels.omitted === 'function'
      ? labels.omitted(overflowCount)
      : `+${overflowCount} more node(s) omitted to fit Discord embed limits.`;
    description = `${summaryLine}\n\n*${omittedText}*`;
  }

  return {
    title,
    description: truncateText(description, 4096),
    color,
    fields,
    footer: { text: footerText },
    timestamp: new Date(now).toISOString()
  };
}

function formatBytes(bytes) {
  const num = Number(bytes);
  if (!Number.isFinite(num) || num <= 0) return '0 B';
  if (num < 1024) return `${Math.round(num)} B`;
  const kb = num / 1024;
  if (kb < 1024) return `${kb >= 100 ? kb.toFixed(0) : kb.toFixed(1)} KB`;
  const mb = kb / 1024;
  if (mb < 1024) return `${mb >= 100 ? mb.toFixed(0) : mb.toFixed(1)} MB`;
  const gb = mb / 1024;
  if (gb < 1024) return `${gb >= 100 ? gb.toFixed(1) : gb.toFixed(2)} GB`;
  const tb = gb / 1024;
  return `${tb.toFixed(2)} TB`;
}

function formatMiB(mib) {
  const num = Number(mib);
  if (!Number.isFinite(num) || num <= 0) return '0 MB';
  return formatBytes(num * 1024 * 1024);
}

function getZonedDateSerial(timestamp, timezone) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return NaN;
  const timeZone = normalizeNotificationTimezone(timezone);
  const formatter = new Intl.DateTimeFormat('en-US', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  });
  const parts = Object.fromEntries(formatter.formatToParts(date).map(part => [part.type, part.value]));
  return Math.floor(Date.UTC(Number(parts.year), Number(parts.month) - 1, Number(parts.day)) / DAY_MS);
}

function parseDateSerial(dateString) {
  const match = String(dateString || '').trim().match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return NaN;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) {
    return NaN;
  }
  return Math.floor(date.getTime() / DAY_MS);
}

function formatExpireDaysLabel(days, messages, labels) {
  if (days < 0) {
    return typeof labels.expired === 'function' ? labels.expired(Math.abs(days)) : `Expired ${Math.abs(days)}d ago`;
  }
  if (days === 0) {
    return labels.expiresToday || 'Expires today';
  }
  return typeof messages.daysLeft === 'function' ? messages.daysLeft(days) : `${days}d left`;
}

function getLatencyIcon(ms, loss = null) {
  if (Number.isFinite(loss) && loss >= 5) return '🔴';
  if (!Number.isFinite(ms) || ms <= 0) return '⚪';
  if (ms < 80) return '🟢';
  if (ms < 180) return '🟡';
  return '🔴';
}

function extractActiveProbes(merged = {}, settings = {}) {
  const probes = [];
  for (const def of PING_PROBE_DEFS) {
    const rawPing = merged[def.pingField];
    const pingNum = rawPing !== null && rawPing !== undefined && rawPing !== '' ? Number(rawPing) : NaN;
    const rawLoss = merged[def.lossField];
    const lossNum = rawLoss !== null && rawLoss !== undefined && rawLoss !== '' && rawLoss !== false && rawLoss !== 'false'
      ? Number(rawLoss)
      : NaN;
    const hasPing = Number.isFinite(pingNum) && pingNum > 0;
    const hasLoss = Number.isFinite(lossNum) && lossNum > 0;
    if (!hasPing && !hasLoss) continue;
    const label = String(settings?.[def.nameKey] || '').trim() || def.fallback;
    probes.push({
      label,
      ping: hasPing ? Math.round(pingNum) : null,
      loss: Number.isFinite(lossNum) && lossNum >= 0 ? Math.round(lossNum) : null
    });
  }
  return probes;
}

function mergeServerSnapshot(server, latestMetricsMap, realtimeMap, now) {
  const serverId = String(server.id || '');
  const dbMetrics = latestMetricsMap.get(serverId) || null;
  const rtMetrics = realtimeMap.get(serverId) || null;
  let effectiveMetrics = dbMetrics;
  if (rtMetrics && (!dbMetrics || Number(rtMetrics.timestamp || 0) >= Number(dbMetrics.timestamp || 0))) {
    effectiveMetrics = dbMetrics ? { ...dbMetrics, ...rtMetrics } : rtMetrics;
  }
  const merged = { ...server };
  if (effectiveMetrics) {
    mergeMetricsIntoServer(merged, effectiveMetrics);
  }
  const lastTs = Number(effectiveMetrics?.timestamp || merged.last_updated || 0);
  const isOnline = lastTs > 0 && (now - lastTs) < DISCORD_ONLINE_THRESHOLD_MS;
  const regionCode = merged.region ? String(merged.region).toUpperCase() : '';
  const displayName = formatServerDisplayName(merged.name || serverId, regionCode);
  return {
    serverId,
    server,
    merged,
    effectiveMetrics,
    lastTs,
    isOnline,
    regionCode,
    displayName
  };
}

export function resolveMatchingServer(servers = [], query = '') {
  const normalized = String(query || '').trim();
  if (!normalized) return null;
  const lower = normalized.toLowerCase();

  const byId = servers.find(s => String(s.id || '').trim() === normalized);
  if (byId) return byId;

  const byExactName = servers.find(s => String(s.name || '').trim().toLowerCase() === lower);
  if (byExactName) return byExactName;

  const byPrefix = servers.find(s => String(s.name || '').trim().toLowerCase().startsWith(lower));
  if (byPrefix) return byPrefix;

  return servers.find(s => {
    const name = String(s.name || '').toLowerCase();
    const region = String(s.region || '').toLowerCase();
    const group = String(s.server_group || '').toLowerCase();
    return name.includes(lower) || region.includes(lower) || group.includes(lower);
  }) || null;
}

export function buildNodeDetailEmbed(server, latestMetricsMap = new Map(), realtimeMap = new Map(), now = Date.now(), settings = {}) {
  const messages = getNotificationMessages(settings);
  const labels = messages?.discord || {};
  const siteTitle = String(settings?.site_title || '').trim();
  const snap = mergeServerSnapshot(server, latestMetricsMap, realtimeMap, now);
  const { merged, effectiveMetrics, lastTs, isOnline, regionCode, displayName } = snap;

  const cpuNum = Number(merged.cpu || 0);
  const ramTotal = Number(merged.ram_total || 0);
  const ramUsed = Number(merged.ram_used || 0);
  const ramNum = ramTotal > 0 ? (ramUsed / ramTotal) * 100 : 0;
  const diskTotal = Number(merged.disk_total || 0);
  const diskUsed = Number(merged.disk_used || 0);
  const diskNum = diskTotal > 0 ? (diskUsed / diskTotal) * 100 : 0;
  const peakLoad = Math.max(cpuNum, ramNum, diskNum);
  const highLoadSuffix = isOnline && peakLoad >= 85 ? ' ⚠️' : '';
  const statusIcon = isOnline ? '🟢' : '🔴';

  const uptimeText = formatDuration(resolveUptimeSeconds(merged, effectiveMetrics, now));
  const lastSeenText = lastTs > 0
    ? (typeof labels.lastSeen === 'function' ? labels.lastSeen(formatDuration((now - lastTs) / 1000)) : `${formatDuration((now - lastTs) / 1000)} ago`)
    : (labels.noReport || 'No report');

  const metaParts = [];
  if (merged.server_group) metaParts.push(`${labels.group || 'Group'}: **${merged.server_group}**`);
  if (regionCode) metaParts.push(`${labels.region || 'Region'}: **${regionCode}**`);
  metaParts.push(isOnline ? `${labels.uptime || 'Uptime'}: **${uptimeText}**` : `${labels.offline || 'Offline'} · ${lastSeenText}`);

  const specParts = [];
  if (merged.os) specParts.push(String(merged.os).trim());
  if (Number(merged.cpu_cores) > 0) specParts.push(`${merged.cpu_cores} vCPU`);
  if (merged.cpu_info) specParts.push(truncateText(String(merged.cpu_info).trim(), 48));

  const descLines = [metaParts.join(' · ')];
  if (specParts.length > 0) {
    descLines.push(`-# ${specParts.join(' · ')}`);
  }

  const fields = [];
  if (isOnline) {
    const loadAvg = String(merged.load_avg || '').trim();
    fields.push({
      name: 'CPU',
      value: `${buildProgressBar(cpuNum)} **${cpuNum.toFixed(1)}%**${getInlineLoadBadge(cpuNum)}${loadAvg && loadAvg !== '0' ? `\n-# Load: ${loadAvg}` : ''}`,
      inline: true
    });
    fields.push({
      name: 'RAM',
      value: `${buildProgressBar(ramNum)} **${ramNum.toFixed(1)}%**${getInlineLoadBadge(ramNum)}\n-# ${formatMiB(ramUsed)} / ${formatMiB(ramTotal)}`,
      inline: true
    });
    fields.push({
      name: 'Disk',
      value: `${buildProgressBar(diskNum)} **${diskNum.toFixed(1)}%**${getInlineLoadBadge(diskNum)}\n-# ${formatMiB(diskUsed)} / ${formatMiB(diskTotal)}`,
      inline: true
    });

    const down = formatBytesPerSecond(merged.net_in_speed);
    const up = formatBytesPerSecond(merged.net_out_speed);
    const tcp = Number(merged.tcp_conn || 0);
    const udp = Number(merged.udp_conn || 0);
    fields.push({
      name: labels.network || 'Network',
      value: `↓ **${down}** · ↑ **${up}**\n-# TCP ${tcp} · UDP ${udp}`,
      inline: true
    });
  }

  const { showTraffic, showExpire, showPrice } = resolveDisplayFlags(settings);

  // Monthly traffic
  if (showTraffic) {
    const limitGb = normalizeTrafficLimitGb(merged.traffic_limit);
    const usedBytes = getTrafficUsageBytes(merged.net_rx_monthly, merged.net_tx_monthly, merged.traffic_calc_type);
    if (limitGb > 0 || usedBytes > 0) {
      if (limitGb > 0) {
        const pct = (usedBytes / (limitGb * GB)) * 100;
        fields.push({
          name: labels.traffic || 'Monthly Traffic',
          value: `${buildProgressBar(pct)} **${pct.toFixed(1)}%**${getInlineLoadBadge(pct)}\n-# ${formatBytes(usedBytes)} / ${limitGb} GB`,
          inline: true
        });
      } else {
        fields.push({
          name: labels.traffic || 'Monthly Traffic',
          value: `↓ ${formatBytes(merged.net_rx_monthly)} · ↑ ${formatBytes(merged.net_tx_monthly)}\n-# ${labels.unlimitedTraffic || 'Unlimited'}`,
          inline: true
        });
      }
    }
  }

  // Latency probes
  const probes = extractActiveProbes(merged, settings);
  if (probes.length > 0) {
    const probeText = probes.map(p => {
      const icon = getLatencyIcon(p.ping, p.loss);
      const pingStr = p.ping !== null ? `**${p.ping}ms**` : '--';
      const lossStr = p.loss !== null && p.loss > 0 ? ` (${p.loss}%)` : '';
      return `${icon} ${p.label}: ${pingStr}${lossStr}`;
    }).join(' · ');
    fields.push({
      name: labels.latency || 'Latency',
      value: truncateText(probeText, 1024),
      inline: false
    });
  }

  // Billing & expiry
  const expireDate = String(merged.expire_date || '').trim();
  const expireSerial = showExpire ? parseDateSerial(expireDate) : NaN;
  const priceText = showPrice ? String(merged.price || '').trim() : '';
  if (Number.isFinite(expireSerial) || (priceText && priceText !== '-1')) {
    const parts = [];
    if (showExpire && Number.isFinite(expireSerial)) {
      const todaySerial = getZonedDateSerial(now, settings?.notification_timezone);
      const days = expireSerial - todaySerial;
      const renewBadge = isEnabledFlag(merged.auto_renewal)
        ? `🔄 ${labels.autoRenew || 'Auto-renew'}`
        : (labels.manualRenew || 'Manual renew');
      parts.push(`\`${expireDate}\` (${formatExpireDaysLabel(days, messages, labels)} · ${renewBadge})`);
    }
    if (showPrice && priceText && priceText !== '-1') {
      const currency = normalizeCurrency(merged.currency) || detectCurrencySymbol(priceText);
      const normalizedAmount = normalizePrice(priceText);
      parts.push(normalizedAmount && normalizedAmount !== '-1' ? `${currency}${normalizedAmount}` : priceText);
    }
    if (parts.length > 0) {
      fields.push({
        name: labels.billing || 'Billing & Expiry',
        value: parts.join(' · '),
        inline: true
      });
    }
  }

  const color = !isOnline ? 0xef4444 : (peakLoad >= 85 ? 0xf59e0b : 0x22c55e);
  return {
    title: truncateText(`${statusIcon} ${displayName}${highLoadSuffix}`, 256),
    description: truncateText(descLines.join('\n'), 4096),
    color,
    fields: fields.slice(0, DISCORD_EMBED_MAX_FIELDS),
    footer: { text: truncateText(siteTitle || 'CF Server Monitor', 2048) },
    timestamp: new Date(now).toISOString()
  };
}

export function buildTrafficCommandEmbed(servers = [], latestMetricsMap = new Map(), realtimeMap = new Map(), now = Date.now(), settings = {}) {
  const messages = getNotificationMessages(settings);
  const labels = messages?.discord || {};
  const siteTitle = String(settings?.site_title || '').trim();
  const title = truncateText(`📊 ${labels.trafficTitle || 'Monthly Traffic Ranking'}`, 256);
  const footerText = truncateText(siteTitle || 'CF Server Monitor', 2048);
  const { showTraffic } = resolveDisplayFlags(settings);

  if (!showTraffic) {
    return {
      title,
      description: truncateText(labels.featureDisabled || 'This information is hidden by site settings.', 4096),
      color: 0x5865f2,
      fields: [],
      footer: { text: footerText },
      timestamp: new Date(now).toISOString()
    };
  }

  const limitedEntries = [];
  const unlimitedEntries = [];

  for (const server of servers) {
    const snap = mergeServerSnapshot(server, latestMetricsMap, realtimeMap, now);
    const limitGb = normalizeTrafficLimitGb(snap.merged.traffic_limit);
    const usedBytes = getTrafficUsageBytes(
      snap.merged.net_rx_monthly,
      snap.merged.net_tx_monthly,
      snap.merged.traffic_calc_type
    );
    if (limitGb > 0) {
      const pct = (usedBytes / (limitGb * GB)) * 100;
      limitedEntries.push({ ...snap, limitGb, usedBytes, pct });
    } else if (usedBytes > 0) {
      unlimitedEntries.push({ ...snap, usedBytes });
    }
  }

  limitedEntries.sort((a, b) => b.pct - a.pct || b.usedBytes - a.usedBytes);
  unlimitedEntries.sort((a, b) => b.usedBytes - a.usedBytes);

  const highCount = limitedEntries.filter(e => e.pct >= 85).length;
  const warnCount = limitedEntries.filter(e => e.pct >= 70 && e.pct < 85).length;
  const ordered = [...limitedEntries, ...unlimitedEntries];

  const fields = [];
  let charBudget = Math.max(0, DISCORD_EMBED_TOTAL_CHAR_LIMIT - title.length - footerText.length - 200);
  let overflowCount = 0;

  for (const item of ordered) {
    if (fields.length >= DISCORD_EMBED_MAX_FIELDS) {
      overflowCount++;
      continue;
    }
    let name;
    let value;
    if (item.limitGb) {
      const icon = item.pct >= 85 ? '🔴' : (item.pct >= 70 ? '🟡' : '🟢');
      name = truncateText(`${icon} ${item.displayName}`, 256);
      value = `${buildProgressBar(item.pct)} **${item.pct.toFixed(1)}%**\n-# ${formatBytes(item.usedBytes)} / ${item.limitGb} GB`;
    } else {
      name = truncateText(`⚪ ${item.displayName}`, 256);
      value = `**${formatBytes(item.usedBytes)}**\n-# ${labels.unlimitedTraffic || 'Unlimited'}`;
    }
    if (charBudget - (name.length + value.length) < 0) {
      overflowCount++;
      continue;
    }
    charBudget -= (name.length + value.length);
    fields.push({ name, value, inline: true });
  }

  const summaryParts = [`${labels.total || 'Total'}: **${ordered.length}**`];
  if (highCount > 0) summaryParts.push(`🔴 ≥85%: **${highCount}**`);
  if (warnCount > 0) summaryParts.push(`🟡 70–85%: **${warnCount}**`);
  let description = ordered.length > 0
    ? summaryParts.join(' | ')
    : (labels.noTrafficData || 'No nodes with monthly traffic limits or usage yet.');
  if (overflowCount > 0) {
    const omittedText = typeof labels.omitted === 'function' ? labels.omitted(overflowCount) : `+${overflowCount} omitted`;
    description += `\n\n*${omittedText}*`;
  }

  const color = highCount > 0 ? 0xef4444 : (warnCount > 0 ? 0xf59e0b : 0x22c55e);
  return {
    title,
    description: truncateText(description, 4096),
    color,
    fields,
    footer: { text: footerText },
    timestamp: new Date(now).toISOString()
  };
}

export function buildExpireCommandEmbed(servers = [], now = Date.now(), settings = {}) {
  const messages = getNotificationMessages(settings);
  const labels = messages?.discord || {};
  const siteTitle = String(settings?.site_title || '').trim();
  const title = truncateText(`📅 ${labels.expireTitle || 'Server Expiration Calendar'}`, 256);
  const footerText = truncateText(siteTitle || 'CF Server Monitor', 2048);
  const { showExpire, showPrice } = resolveDisplayFlags(settings);

  if (!showExpire) {
    return {
      title,
      description: truncateText(labels.featureDisabled || 'This information is hidden by site settings.', 4096),
      color: 0x5865f2,
      fields: [],
      footer: { text: footerText },
      timestamp: new Date(now).toISOString()
    };
  }

  const todaySerial = getZonedDateSerial(now, settings?.notification_timezone);

  const expireEntries = [];
  const monthlyByCurrency = new Map();

  for (const server of servers) {
    const regionCode = server.region ? String(server.region).toUpperCase() : '';
    const displayName = formatServerDisplayName(server.name || server.id, regionCode);

    // Accumulate billing estimate per currency
    let priceSummary = '';
    if (showPrice) {
      const priceRaw = String(server.price || '').trim();
      const normalizedAmount = normalizePrice(priceRaw);
      const amountNum = normalizedAmount && normalizedAmount !== '-1' ? Number(normalizedAmount) : 0;
      const currency = normalizeCurrency(server.currency) || detectCurrencySymbol(priceRaw) || '$';
      if (amountNum > 0) {
        const cycle = normalizeBillingCycle(detectBillingCycle(priceRaw) || server.billing_cycle);
        const months = BILLING_CYCLE_MONTHS[cycle] || 1;
        monthlyByCurrency.set(currency, (monthlyByCurrency.get(currency) || 0) + (amountNum / months));
        priceSummary = ` · ${currency}${amountNum.toFixed(2)}`;
      }
    }

    const expireDate = String(server.expire_date || '').trim();
    const expireSerial = parseDateSerial(expireDate);
    if (!Number.isFinite(expireSerial)) continue;

    const days = expireSerial - todaySerial;
    expireEntries.push({
      displayName,
      expireDate,
      days,
      autoRenew: isEnabledFlag(server.auto_renewal),
      priceSummary
    });
  }

  expireEntries.sort((a, b) => a.days - b.days);

  const urgentCount = expireEntries.filter(e => !e.autoRenew && e.days <= 7).length;
  const soonCount = expireEntries.filter(e => !e.autoRenew && e.days > 7 && e.days <= 30).length;

  const descLines = [];
  if (expireEntries.length === 0) {
    descLines.push(labels.noExpireData || 'No nodes have expiration dates configured.');
  } else {
    const summaryParts = [`${labels.total || 'Total'}: **${expireEntries.length}**`];
    if (urgentCount > 0) summaryParts.push(`🔴 ≤7d: **${urgentCount}**`);
    if (soonCount > 0) summaryParts.push(`🟡 ≤30d: **${soonCount}**`);
    descLines.push(summaryParts.join(' | '));
  }

  if (monthlyByCurrency.size > 0) {
    const monthlyStr = Array.from(monthlyByCurrency.entries())
      .map(([sym, val]) => `**${sym}${val.toFixed(2)}**`)
      .join(' + ');
    const yearlyStr = Array.from(monthlyByCurrency.entries())
      .map(([sym, val]) => `**${sym}${(val * 12).toFixed(2)}**`)
      .join(' + ');
    descLines.push(`💰 ${labels.monthlyTotal || 'Monthly est.'}: ${monthlyStr} · ${labels.yearlyTotal || 'Yearly est.'}: ${yearlyStr}`);
  }

  const fields = [];
  let charBudget = Math.max(0, DISCORD_EMBED_TOTAL_CHAR_LIMIT - title.length - descLines.join('\n').length - footerText.length - 128);
  let overflowCount = 0;

  for (const item of expireEntries) {
    if (fields.length >= DISCORD_EMBED_MAX_FIELDS) {
      overflowCount++;
      continue;
    }
    const icon = item.autoRenew ? '🔄' : (item.days <= 7 ? '🔴' : (item.days <= 30 ? '🟡' : '🟢'));
    const name = truncateText(`${icon} ${item.displayName}`, 256);
    const daysLabel = formatExpireDaysLabel(item.days, messages, labels);
    const renewText = item.autoRenew ? (labels.autoRenew || 'Auto-renew') : (labels.manualRenew || 'Manual renew');
    const value = `**${daysLabel}** · \`${item.expireDate}\`\n-# ${renewText}${item.priceSummary}`;
    if (charBudget - (name.length + value.length) < 0) {
      overflowCount++;
      continue;
    }
    charBudget -= (name.length + value.length);
    fields.push({ name, value, inline: true });
  }

  if (overflowCount > 0) {
    const omittedText = typeof labels.omitted === 'function' ? labels.omitted(overflowCount) : `+${overflowCount} omitted`;
    descLines.push(`\n*${omittedText}*`);
  }

  const color = urgentCount > 0 ? 0xef4444 : (soonCount > 0 ? 0xf59e0b : 0x22c55e);
  return {
    title,
    description: truncateText(descLines.join('\n'), 4096),
    color,
    fields,
    footer: { text: footerText },
    timestamp: new Date(now).toISOString()
  };
}

export function buildPingCommandEmbed(servers = [], latestMetricsMap = new Map(), realtimeMap = new Map(), now = Date.now(), settings = {}, targetServer = null) {
  const messages = getNotificationMessages(settings);
  const labels = messages?.discord || {};
  const siteTitle = String(settings?.site_title || '').trim();
  const footerText = truncateText(siteTitle || 'CF Server Monitor', 2048);

  if (targetServer) {
    const snap = mergeServerSnapshot(targetServer, latestMetricsMap, realtimeMap, now);
    const probes = extractActiveProbes(snap.merged, settings);
    const title = truncateText(`📡 ${snap.displayName} · ${labels.pingTitle || 'Network Latency'}`, 256);
    const fields = probes.map(p => ({
      name: `${getLatencyIcon(p.ping, p.loss)} ${p.label}`,
      value: `${p.ping !== null ? `**${p.ping} ms**` : '--'}${p.loss !== null ? `\n-# ${labels.loss || 'Loss'}: ${p.loss}%` : ''}`,
      inline: true
    }));
    const validPings = probes.map(p => p.ping).filter(v => v !== null);
    const maxPing = validPings.length > 0 ? Math.max(...validPings) : 0;
    const hasLoss = probes.some(p => p.loss !== null && p.loss >= 5);
    const color = !snap.isOnline || hasLoss || maxPing >= 180 ? 0xef4444 : (maxPing >= 80 ? 0xf59e0b : 0x22c55e);
    return {
      title,
      description: probes.length > 0
        ? `${snap.isOnline ? '🟢 ' + (labels.online || 'Online') : '🔴 ' + (labels.offline || 'Offline')}`
        : (labels.noPingData || 'No latency probe data available yet.'),
      color,
      fields: fields.slice(0, DISCORD_EMBED_MAX_FIELDS),
      footer: { text: footerText },
      timestamp: new Date(now).toISOString()
    };
  }

  const title = truncateText(`📡 ${labels.pingTitle || 'Network Latency'}`, 256);
  const rows = [];
  for (const server of servers) {
    const snap = mergeServerSnapshot(server, latestMetricsMap, realtimeMap, now);
    if (!snap.isOnline) continue;
    const probes = extractActiveProbes(snap.merged, settings);
    if (probes.length === 0) continue;
    const validPings = probes.map(p => p.ping).filter(v => v !== null);
    const avgPing = validPings.length > 0 ? validPings.reduce((a, b) => a + b, 0) / validPings.length : Infinity;
    const hasLoss = probes.some(p => p.loss !== null && p.loss >= 5);
    rows.push({ ...snap, probes, avgPing, hasLoss });
  }
  rows.sort((a, b) => a.avgPing - b.avgPing);

  const fields = [];
  let charBudget = Math.max(0, DISCORD_EMBED_TOTAL_CHAR_LIMIT - title.length - footerText.length - 160);
  let overflowCount = 0;

  for (const row of rows) {
    if (fields.length >= DISCORD_EMBED_MAX_FIELDS) {
      overflowCount++;
      continue;
    }
    const leadIcon = getLatencyIcon(row.avgPing, row.hasLoss ? 5 : 0);
    const name = truncateText(`${leadIcon} ${row.displayName}`, 256);
    const value = truncateText(row.probes.map(p => {
      const pingText = p.ping !== null ? `**${p.ping}ms**` : '--';
      const lossText = p.loss !== null && p.loss > 0 ? ` (${p.loss}%)` : '';
      return `${p.label} ${pingText}${lossText}`;
    }).join('\n'), 1024);
    if (charBudget - (name.length + value.length) < 0) {
      overflowCount++;
      continue;
    }
    charBudget -= (name.length + value.length);
    fields.push({ name, value, inline: true });
  }

  let description = rows.length > 0
    ? `${labels.online || 'Online'}: **${rows.length}**`
    : (labels.noPingData || 'No latency probe data available yet.');
  if (overflowCount > 0) {
    const omittedText = typeof labels.omitted === 'function' ? labels.omitted(overflowCount) : `+${overflowCount} omitted`;
    description += `\n\n*${omittedText}*`;
  }

  const anyBad = rows.some(r => r.hasLoss || r.avgPing >= 180);
  const anyWarn = rows.some(r => r.avgPing >= 80);
  const color = rows.length === 0 ? 0x5865f2 : (anyBad ? 0xef4444 : (anyWarn ? 0xf59e0b : 0x22c55e));

  return {
    title,
    description: truncateText(description, 4096),
    color,
    fields,
    footer: { text: footerText },
    timestamp: new Date(now).toISOString()
  };
}

function getCommandOptionValue(interaction, optionName) {
  const options = Array.isArray(interaction?.data?.options) ? interaction.data.options : [];
  const found = options.find(opt => String(opt?.name || '').toLowerCase() === optionName);
  return found?.value !== undefined && found?.value !== null ? String(found.value).trim() : '';
}

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store'
    }
  });
}

async function loadVisibleStatusContext(env, preloadedSettings = null) {
  const [servers, settings] = await Promise.all([
    getAllServers(env.DB, false),
    preloadedSettings ? Promise.resolve(preloadedSettings) : loadSettings(env.DB)
  ]);
  const serverIds = servers.map(server => String(server.id || '')).filter(Boolean);
  const [latestMetricsMap, realtimeMap] = await Promise.all([
    getLatestMetricsForAllServers(env.DB),
    fetchStatusRealtimeMap(env, serverIds)
  ]);
  return { servers, settings, latestMetricsMap, realtimeMap };
}

async function buildStatusInteractionData(env, preloadedSettings = null) {
  const { servers, settings, latestMetricsMap, realtimeMap } = await loadVisibleStatusContext(env, preloadedSettings);
  const embed = buildStatusCommandEmbed(servers, latestMetricsMap, realtimeMap, Date.now(), settings);
  return {
    embeds: [embed],
    components: buildRefreshActionRow(settings, DISCORD_STATUS_REFRESH_ID)
  };
}

async function buildNodeInteractionData(env, query, preloadedSettings = null) {
  const { servers, settings, latestMetricsMap, realtimeMap } = await loadVisibleStatusContext(env, preloadedSettings);
  const matched = resolveMatchingServer(servers, query);
  if (!matched) {
    const labels = getNotificationMessages(settings)?.discord || {};
    const msg = typeof labels.nodeNotFound === 'function'
      ? labels.nodeNotFound(query || '-')
      : `No visible node matched: \`${query || '-'}\``;
    return { content: msg, flags: 64 };
  }
  const embed = buildNodeDetailEmbed(matched, latestMetricsMap, realtimeMap, Date.now(), settings);
  return {
    embeds: [embed],
    components: buildRefreshActionRow(settings, `${DISCORD_NODE_REFRESH_PREFIX}${matched.id}`)
  };
}

async function buildTrafficInteractionData(env, preloadedSettings = null) {
  const { servers, settings, latestMetricsMap, realtimeMap } = await loadVisibleStatusContext(env, preloadedSettings);
  const embed = buildTrafficCommandEmbed(servers, latestMetricsMap, realtimeMap, Date.now(), settings);
  return {
    embeds: [embed],
    components: buildRefreshActionRow(settings, DISCORD_TRAFFIC_REFRESH_ID)
  };
}

async function buildExpireInteractionData(env, preloadedSettings = null) {
  const [servers, settings] = await Promise.all([
    getAllServers(env.DB, false),
    preloadedSettings ? Promise.resolve(preloadedSettings) : loadSettings(env.DB)
  ]);
  const embed = buildExpireCommandEmbed(servers, Date.now(), settings);
  return {
    embeds: [embed],
    components: buildRefreshActionRow(settings, DISCORD_EXPIRE_REFRESH_ID)
  };
}

async function buildPingInteractionData(env, query = '', preloadedSettings = null) {
  const { servers, settings, latestMetricsMap, realtimeMap } = await loadVisibleStatusContext(env, preloadedSettings);
  let targetServer = null;
  if (query) {
    targetServer = resolveMatchingServer(servers, query);
    if (!targetServer) {
      const labels = getNotificationMessages(settings)?.discord || {};
      const msg = typeof labels.nodeNotFound === 'function'
        ? labels.nodeNotFound(query)
        : `No visible node matched: \`${query}\``;
      return { content: msg, flags: 64 };
    }
  }
  const embed = buildPingCommandEmbed(servers, latestMetricsMap, realtimeMap, Date.now(), settings, targetServer);
  const refreshId = targetServer
    ? `${DISCORD_PING_REFRESH_PREFIX}:${targetServer.id}`
    : DISCORD_PING_REFRESH_PREFIX;
  return {
    embeds: [embed],
    components: buildRefreshActionRow(settings, refreshId)
  };
}

async function handleNodeAutocomplete(env, interaction) {
  const focused = (Array.isArray(interaction?.data?.options) ? interaction.data.options : [])
    .find(opt => opt?.focused);
  const query = String(focused?.value || '').trim().toLowerCase();
  const servers = await getAllServers(env.DB, false);
  const choices = [];
  for (const server of servers) {
    if (choices.length >= 25) break;
    const regionCode = server.region ? String(server.region).toUpperCase() : '';
    const displayName = formatServerDisplayName(server.name || server.id, regionCode);
    if (query) {
      const hay = `${server.name || ''} ${displayName} ${server.region || ''} ${server.server_group || ''} ${server.id || ''}`.toLowerCase();
      if (!hay.includes(query)) continue;
    }
    choices.push({
      name: truncateText(displayName, 100),
      value: truncateText(String(server.id || server.name || ''), 100)
    });
  }
  return jsonResponse({
    type: 8,
    data: { choices }
  });
}

export async function handleDiscordInteraction(request, env) {
  const publicKey = String(env?.DISCORD_PUBLIC_KEY || '').trim();
  const signature = request.headers.get('X-Signature-Ed25519') || '';
  const timestamp = request.headers.get('X-Signature-Timestamp') || '';
  const rawBody = await request.text();

  const isValid = publicKey && await verifyDiscordSignature(rawBody, signature, timestamp, publicKey);
  if (!isValid) {
    return new Response('Invalid request signature', {
      status: 401,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' }
    });
  }

  let interaction;
  try {
    interaction = JSON.parse(rawBody || '{}');
  } catch (_) {
    return jsonResponse({ error: 'Invalid JSON payload' }, 400);
  }

  // Discord PING verification
  if (interaction?.type === 1) {
    return jsonResponse({ type: 1 });
  }

  const settings = await loadSettings(env.DB);
  const authorized = isAuthorizedDiscordInteraction(interaction, settings);

  // APPLICATION_COMMAND_AUTOCOMPLETE
  if (interaction?.type === 4) {
    if (!authorized) {
      return jsonResponse({ type: 8, data: { choices: [] } });
    }
    const commandName = String(interaction?.data?.name || '').toLowerCase();
    if (commandName === 'node' || commandName === 'ping') {
      try {
        return await handleNodeAutocomplete(env, interaction);
      } catch (e) {
        console.error(`[Discord] /${commandName} autocomplete failed:`, e);
        return jsonResponse({ type: 8, data: { choices: [] } });
      }
    }
    return jsonResponse({ type: 8, data: { choices: [] } });
  }

  // APPLICATION_COMMAND
  if (interaction?.type === 2) {
    if (!authorized) {
      const labels = getNotificationMessages(settings)?.discord || {};
      return jsonResponse({
        type: 4,
        data: {
          content: labels.unauthorized || 'You are not authorized to use this command.',
          flags: 64
        }
      });
    }
    const commandName = String(interaction?.data?.name || '').toLowerCase();
    try {
      let data = null;
      if (commandName === 'status') {
        data = await buildStatusInteractionData(env, settings);
      } else if (commandName === 'node') {
        data = await buildNodeInteractionData(env, getCommandOptionValue(interaction, 'name'), settings);
      } else if (commandName === 'traffic') {
        data = await buildTrafficInteractionData(env, settings);
      } else if (commandName === 'expire') {
        data = await buildExpireInteractionData(env, settings);
      } else if (commandName === 'ping') {
        data = await buildPingInteractionData(env, getCommandOptionValue(interaction, 'name'), settings);
      }

      if (data) {
        return jsonResponse({ type: 4, data });
      }
    } catch (e) {
      console.error(`[Discord] /${commandName} command failed:`, e);
      return jsonResponse({
        type: 4,
        data: {
          content: `Failed to execute /${commandName}.`,
          flags: 64
        }
      });
    }

    return jsonResponse({
      type: 4,
      data: {
        content: `Unknown command: /${commandName || 'unknown'}`,
        flags: 64
      }
    });
  }

  // MESSAGE_COMPONENT (in-place Refresh buttons across all command cards)
  if (interaction?.type === 3) {
    if (!authorized) {
      const labels = getNotificationMessages(settings)?.discord || {};
      return jsonResponse({
        type: 4,
        data: {
          content: labels.unauthorized || 'You are not authorized to use this command.',
          flags: 64
        }
      });
    }
    const customId = String(interaction?.data?.custom_id || '');
    try {
      let data = null;
      if (customId === DISCORD_STATUS_REFRESH_ID) {
        data = await buildStatusInteractionData(env, settings);
      } else if (customId.startsWith(DISCORD_NODE_REFRESH_PREFIX)) {
        data = await buildNodeInteractionData(env, customId.slice(DISCORD_NODE_REFRESH_PREFIX.length), settings);
      } else if (customId === DISCORD_TRAFFIC_REFRESH_ID) {
        data = await buildTrafficInteractionData(env, settings);
      } else if (customId === DISCORD_EXPIRE_REFRESH_ID) {
        data = await buildExpireInteractionData(env, settings);
      } else if (customId === DISCORD_PING_REFRESH_PREFIX) {
        data = await buildPingInteractionData(env, '', settings);
      } else if (customId.startsWith(`${DISCORD_PING_REFRESH_PREFIX}:`)) {
        data = await buildPingInteractionData(env, customId.slice(DISCORD_PING_REFRESH_PREFIX.length + 1), settings);
      }

      if (data) {
        // If target node was deleted/hidden, send ephemeral notice instead of breaking card update
        if (data.flags === 64 && !data.embeds) {
          return jsonResponse({ type: 4, data });
        }
        return jsonResponse({ type: 7, data });
      }
    } catch (e) {
      console.error('[Discord] refresh button failed:', e);
      return jsonResponse({
        type: 4,
        data: {
          content: 'Failed to refresh card.',
          flags: 64
        }
      });
    }

    return jsonResponse({
      type: 4,
      data: {
        content: 'Unknown action.',
        flags: 64
      }
    });
  }

  return jsonResponse({ error: 'Unsupported interaction type' }, 400);
}
