/**
 * Small, dependency-light predicates shared by the rules.
 *
 * Stellar key validation delegates to `@stellar/stellar-base`, which verifies
 * the base32 encoding *and* the CRC16 checksum. That matters: a typo'd account
 * ID is the single most common `stellar.toml` defect, and a regex like
 * `/^G[A-Z2-7]{55}$/` happily accepts it.
 */
import { StrKey, Networks } from '@stellar/stellar-base';

/**
 * Common disposable / throwaway email domains. Kept as a static, dependency-free
 * list: the linter runs offline and must not pull in a runtime package just to
 * catch a low-quality contact address.
 */
export const DISPOSABLE_EMAIL_DOMAINS = [
  'mailinator.com',
  'guerrillamail.com',
  'guerrillamailblock.com',
  'tempmail.com',
  'temp-mail.org',
  '10minutemail.com',
  '10minutemail.net',
  'throwawaymail.com',
  'throwawayemail.com',
  'fakeinbox.com',
  'yopmail.com',
  'mailcatch.com',
  'getnada.com',
  'doublemail.com',
  'spamgourmet.com',
  'sharklasers.com',
  'mailinator.org',
] as const;

export type DisposableEmailDomain = (typeof DISPOSABLE_EMAIL_DOMAINS)[number];

/**
 * True when `email` carries a disposable or throwaway domain. The host is
 * compared case-insensitively against the curated denylist so `user@MAILANATOR.COM`
 * is still flagged.
 */
export function isDisposableEmail(email: unknown): boolean {
  if (!isString(email)) return false;
  const at = email.indexOf('@');
  if (at < 0) return false;
  const host = email.slice(at + 1).toLowerCase();
  return DISPOSABLE_EMAIL_DOMAINS.some((domain) => domain === host);
}

/** Maximum file size SEP-1 permits. */
export const MAX_FILE_BYTES = 100 * 1024;

/** Network passphrases SEP-1 documents. Anything else is suspicious. */
export const KNOWN_PASSPHRASES: Record<string, string> = {
  [Networks.PUBLIC]: 'Public',
  [Networks.TESTNET]: 'Testnet',
  [Networks.FUTURENET]: 'Futurenet',
};

export function isString(v: unknown): v is string {
  return typeof v === 'string';
}

export function isBoolean(v: unknown): v is boolean {
  return typeof v === 'boolean';
}

export function isInteger(v: unknown): v is number {
  return typeof v === 'number' && Number.isInteger(v);
}

export function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every(isString);
}

/** A `G...` account ID, checksum included. */
export function isAccountId(v: unknown): boolean {
  return isString(v) && StrKey.isValidEd25519PublicKey(v);
}

/** A `M...` muxed account ID. */
export function isMuxedAccountId(v: unknown): boolean {
  return isString(v) && StrKey.isValidMed25519PublicKey(v);
}

/** A `C...` contract ID, checksum included. */
export function isContractId(v: unknown): boolean {
  return isString(v) && StrKey.isValidContract(v);
}

/*
 * Any absolute http(s) URL.
 */
export function isUrl(v: unknown): boolean {
  if (!isString(v)) return false;
  try {
    const u = new URL(v);
    return u.protocol === 'https:' || u.protocol === 'http:';
  } catch {
    return false;
  }
}

/**
 * SEP-1 requires `https://` for every endpoint field.
 */
export function isHttpsUrl(v: unknown): boolean {
  if (!isString(v)) return false;
  try {
    return new URL(v).protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Deliberately permissive: enough to catch `user@` or `not-an-email`, without
 * pretending to implement RFC 5322. Rejecting a valid exotic address would be
 * worse than missing an invalid one.
 */
export function isEmail(v: unknown): boolean {
  return isString(v) && /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/.test(v);
}

/** E.164: a leading `+`, then 2–15 digits, no separators. */
export function isE164(v: unknown): boolean {
  return isString(v) && /^\+[1-9]\d{1,14}$/.test(v);
}

export function isHex(v: unknown, length?: number): boolean {
  if (!isString(v) || !/^[0-9a-fA-F]+$/.test(v)) return false;
  return length === undefined || v.length === length;
}

/** Extracts a lowercase hostname from a URL, or `undefined` if unparseable. */
export function hostOf(url: unknown): string | undefined {
  if (!isString(url)) return undefined;
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

/**
 * True when `host` is `base` or a subdomain of it.
 *
 * SEP-1's "same domain" language is about organisational control, so
 * `www.example.com` satisfies a requirement anchored at `example.com`.
 */
export function isSameOrSubdomain(host: string, base: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  const b = base
    .toLowerCase()
    .replace(/^www\./, '')
    .replace(/\.$/, '');
  return h === b || h.endsWith(`.${b}`);
}

/** `host:port` or `domain:port`, as used by `[[VALIDATORS]].HOST`. */
export function isHostPort(v: unknown): boolean {
  if (!isString(v)) return false;
  const at = v.lastIndexOf(':');
  if (at <= 0 || at === v.length - 1) return false;
  const port = Number(v.slice(at + 1));
  if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
  const host = v.slice(0, at);
  return host.length > 0 && !/\s/.test(host);
}

/** Endpoint fields must not carry a trailing slash; clients concatenate paths. */
export function hasTrailingSlash(v: unknown): boolean {
  if (!isString(v)) return false;
  try {
    const u = new URL(v);
    return u.pathname.endsWith('/') && u.pathname !== '/';
  } catch {
    return v.endsWith('/');
  }
}
