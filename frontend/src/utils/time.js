const MOUNTAIN_TIME_ZONE = "America/Denver";

function parseDate(value) {
  if (!value) return null;
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value;
  }

  let normalized = value;
  if (typeof value === "string") {
    const trimmed = value.trim();
    const hasZone = /([zZ]|[+-]\d{2}:\d{2})$/.test(trimmed);
    const looksLikeDateTime = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(trimmed);
    normalized = looksLikeDateTime && !hasZone
      ? `${trimmed.replace(" ", "T")}Z`
      : trimmed;
  }

  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatMountainTime(value, options = {}) {
  const date = parseDate(value);
  if (!date) return "--:--:--";
  return date.toLocaleTimeString("en-US", {
    timeZone: MOUNTAIN_TIME_ZONE,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    ...options,
  });
}

export function formatMountainDateTime(value, options = {}) {
  const date = parseDate(value);
  if (!date) return "";
  return date.toLocaleString("en-US", {
    timeZone: MOUNTAIN_TIME_ZONE,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZoneName: "short",
    ...options,
  });
}
