import { getLatestMetricsForAllServers } from '../database/schema.js';
import { getAllServers } from '../utils/cache.js';
import { mergeMetricsIntoServer } from '../utils/metrics.js';
import { getWorkerLatestReportUpdates } from '../utils/latestReportCache.js';
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
export const DISCORD_STATUS_REFRESH_ID = 'cfsm:status:refresh';
const DISCORD_USER_AGENT = 'DiscordBot (https://github.com/huilang-me/CF-Server-Monitor, 1.0)';
const DISCORD_SNOWFLAKE_RE = /^\d{15,25}$/;
const DISCORD_ONLINE_THRESHOLD_MS = 300000;
const DISCORD_DO_FETCH_TIMEOUT_MS = 700;
const DISCORD_EMBED_MAX_FIELDS = 25;
const DISCORD_EMBED_TOTAL_CHAR_LIMIT = 5800;

const dmChannelCache = new Map();

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

export function buildDiscordAlertEmbed(context = {}, formattedMsg = '', settings = {}) {
  const labels = getNotificationMessages(settings)?.discord || {};
  const event = String(context.event || 'Notification').trim();
  const emoji = String(context.emoji || '').trim();
  const title = truncateText(`${emoji ? `${emoji} ` : ''}${event}`.trim(), 256);
  const rawDescription = String(formattedMsg || context.message || '').trim();
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

async function discordApiRequest(path, token, body, retries = NOTIFICATION_MAX_RETRIES) {
  let lastError;
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(`${DISCORD_API_BASE}${path}`, {
        method: 'POST',
        headers: {
          'Authorization': `Bot ${token}`,
          'Content-Type': 'application/json',
          'User-Agent': DISCORD_USER_AGENT
        },
        body: JSON.stringify(body)
      });

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

async function resolveDiscordTargetChannelId(token, channelId, userId) {
  if (!userId) return { targetChannelId: channelId, isDm: false };

  const cacheKey = `${token}:${userId}`;
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
  dmChannelCache.set(cacheKey, dmChannel.id);
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

export async function verifyDiscordSignature(rawBody, signatureHex, timestamp, publicKeyHex) {
  const ts = String(timestamp || '');
  if (!ts) return false;

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

function formatDuration(secondsValue) {
  const totalSeconds = Math.floor(Number(secondsValue) || 0);
  if (totalSeconds <= 0) return '0m';
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const parts = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0 || days > 0) parts.push(`${hours}h`);
  parts.push(`${minutes}m`);
  return parts.join(' ');
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

export function buildProgressBar(percent, length = 8) {
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

export function buildStatusActionRow(settings = {}) {
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
          custom_id: DISCORD_STATUS_REFRESH_ID
        }
      ]
    }
  ];
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
    const peakLoad = Math.max(cpuNum, ramNum);
    const loadIcon = isOnline ? getLoadLevelIcon(peakLoad) : '⚫';
    const highLoadSuffix = isOnline && peakLoad >= 85 ? ' ⚠️' : '';
    const down = formatBytesPerSecond(merged.net_in_speed);
    const up = formatBytesPerSecond(merged.net_out_speed);
    const uptime = formatDuration(resolveUptimeSeconds(merged, effectiveMetrics, now));
    const regionCode = merged.region ? String(merged.region).toUpperCase() : '';
    const regionTag = regionCode ? ` [${regionCode}]` : '';
    const displayName = formatServerDisplayName(merged.name || serverId, regionCode);
    const statusIcon = isOnline ? '🟢' : '🔴';
    const statusText = isOnline ? (labels.online || 'Online') : (labels.offline || 'Offline');
    const lastSeenText = lastTs > 0
      ? (typeof labels.lastSeen === 'function' ? labels.lastSeen(formatDuration((now - lastTs) / 1000)) : `${formatDuration((now - lastTs) / 1000)} ago`)
      : (labels.noReport || 'No report');
    const defaultDetail = isOnline
      ? `\`CPU\` ${cpuBar} **${cpu}%**${getInlineLoadBadge(cpuNum)}\n\`RAM\` ${ramBar} **${ramPct}%**${getInlineLoadBadge(ramNum)}\n-# ↓${down} ↑${up} · ${uptime}`
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
        ram: ramPct,
        ram_bar: ramBar,
        ram_icon: ramIcon,
        ram_used: String(Math.round(ramUsed)),
        ram_total: String(Math.round(ramTotal)),
        disk: diskPct,
        disk_bar: diskBar,
        disk_icon: diskIcon,
        net_in: down,
        net_out: up,
        uptime,
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
      customTemplate.replace(loopMatch[0], renderedItems),
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
  let charBudget = DISCORD_EMBED_TOTAL_CHAR_LIMIT - title.length - summaryLine.length - 64;
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

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store'
    }
  });
}

async function buildStatusInteractionData(env) {
  const [servers, settings] = await Promise.all([
    getAllServers(env.DB, false),
    loadSettings(env.DB)
  ]);
  const serverIds = servers.map(server => String(server.id || '')).filter(Boolean);
  const [latestMetricsMap, realtimeMap] = await Promise.all([
    getLatestMetricsForAllServers(env.DB),
    fetchStatusRealtimeMap(env, serverIds)
  ]);
  const embed = buildStatusCommandEmbed(servers, latestMetricsMap, realtimeMap, Date.now(), settings);
  const components = buildStatusActionRow(settings);
  return {
    embeds: [embed],
    components
  };
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

  // APPLICATION_COMMAND
  if (interaction?.type === 2) {
    const commandName = String(interaction?.data?.name || '').toLowerCase();
    if (commandName === 'status') {
      try {
        const data = await buildStatusInteractionData(env);
        return jsonResponse({
          type: 4,
          data
        });
      } catch (e) {
        console.error('[Discord] /status command failed:', e);
        return jsonResponse({
          type: 4,
          data: {
            content: 'Failed to query server status.',
            flags: 64
          }
        });
      }
    }

    return jsonResponse({
      type: 4,
      data: {
        content: `Unknown command: /${commandName || 'unknown'}`,
        flags: 64
      }
    });
  }

  // MESSAGE_COMPONENT (e.g. Refresh button on /status card)
  if (interaction?.type === 3) {
    const customId = String(interaction?.data?.custom_id || '');
    if (customId === DISCORD_STATUS_REFRESH_ID) {
      try {
        const data = await buildStatusInteractionData(env);
        return jsonResponse({
          type: 7,
          data
        });
      } catch (e) {
        console.error('[Discord] /status refresh button failed:', e);
        return jsonResponse({
          type: 4,
          data: {
            content: 'Failed to refresh server status.',
            flags: 64
          }
        });
      }
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
