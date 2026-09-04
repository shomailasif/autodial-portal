/**
 * Shared protocol between the agent (customer PC) and the portal (admin cloud).
 * Kept dependency-free so both the portal and the packaged agent agree.
 */

/** How often the agent reports health to the portal (milliseconds). */
const HEARTBEAT_INTERVAL_MS = 3000;

/** If a customer hasn't reported in this long, the portal marks it offline. */
const STALE_AFTER_MS = 10000;

/** Response the heartbeat API returns to the agent. */
function heartbeatResponse({ ok, disabled, config, reason }) {
  const body = { ok, disabled: !!disabled };
  if (disabled) body.reason = reason || "disabled";
  if (config) body.config = config;
  return body;
}

module.exports = { HEARTBEAT_INTERVAL_MS, STALE_AFTER_MS, heartbeatResponse };
