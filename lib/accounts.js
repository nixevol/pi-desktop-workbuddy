var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var accounts_exports = {};
__export(accounts_exports, {
  ENCRYPTED_CREDENTIAL_CODE: () => ENCRYPTED_CREDENTIAL_CODE,
  WORKBUDDY_AUTH_FILE_ENV: () => WORKBUDDY_AUTH_FILE_ENV,
  WORKBUDDY_LIVE_FILENAME: () => WORKBUDDY_LIVE_FILENAME,
  WorkBuddyAccountPool: () => WorkBuddyAccountPool,
  WorkBuddyEncryptedCredentialError: () => WorkBuddyEncryptedCredentialError,
  candidateAuthDirs: () => candidateAuthDirs,
  cheapIdentityId: () => cheapIdentityId,
  defaultDesktopAuthDirs: () => defaultDesktopAuthDirs,
  encryptedFieldOpener: () => encryptedFieldOpener,
  isEncryptedCredentialError: () => isEncryptedCredentialError,
  parseWorkBuddyAuth: () => parseWorkBuddyAuth,
  primeAtRestKeys: () => primeAtRestKeys,
  workbuddyAccountId: () => workbuddyAccountId
});
module.exports = __toCommonJS(accounts_exports);
var import_node_crypto = require("node:crypto");
var import_promises = require("node:fs/promises");
var import_node_os = require("node:os");
var import_node_path = require("node:path");
var import_upstream = require("./upstream");
var import_at_rest = require("./at-rest");
const WORKBUDDY_LIVE_FILENAME = "workbuddy-desktop.info";
const WORKBUDDY_AUTH_FILE_ENV = "WORKBUDDY_AUTH_FILE";
function nonEmptyEnv(value) {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : void 0;
}
function defaultDesktopAuthDirs(platform = process.platform, home = (0, import_node_os.homedir)(), env = process.env) {
  if (platform === "darwin") {
    return [(0, import_node_path.join)(home, "Library", "Application Support", "CodeBuddyExtension", "Data", "Public", "auth")];
  }
  if (platform === "win32") {
    const local = nonEmptyEnv(env["LOCALAPPDATA"]) ?? (0, import_node_path.join)(home, "AppData", "Local");
    const roaming = nonEmptyEnv(env["APPDATA"]) ?? (0, import_node_path.join)(home, "AppData", "Roaming");
    return [
      (0, import_node_path.join)(local, "CodeBuddyExtension", "Data", "Public", "auth"),
      (0, import_node_path.join)(roaming, "CodeBuddyExtension", "Data", "Public", "auth")
    ];
  }
  if (platform === "linux") {
    const config = nonEmptyEnv(env["XDG_CONFIG_HOME"]) ?? (0, import_node_path.join)(home, ".config");
    return [(0, import_node_path.join)(config, "CodeBuddyExtension", "Data", "Public", "auth")];
  }
  return [];
}
function expiryToMs(value) {
  if (value <= 0) return 0;
  return value > 1e12 ? value : value * 1e3;
}
function optionalString(value) {
  return typeof value === "string" && value !== "" ? value : void 0;
}
const ENCRYPTED_CREDENTIAL_CODE = "ENCRYPTED_CREDENTIAL";
class WorkBuddyEncryptedCredentialError extends Error {
  code = ENCRYPTED_CREDENTIAL_CODE;
  constructor(sourcePath) {
    super(
      `workbuddy: ${sourcePath} holds encrypted credentials, but no WorkBuddy desktop app could be located to provide the key. If the app IS installed, it is simply outside the paths this plugin probes \u2014 set WORKBUDDY_APP_EXECUTABLE to its full .exe path (then restart DSH) and the credential will open. Signing in again will not help: the credential itself is intact. Run \`dsh-workbuddy-xdpool doctor\` to see which paths were probed.`
    );
    this.name = "WorkBuddyEncryptedCredentialError";
  }
}
function isEncryptedCredentialError(value) {
  return typeof value === "object" && value !== null && value.code === ENCRYPTED_CREDENTIAL_CODE;
}
function decryptableString(value, decrypt) {
  if (typeof value === "string") return { value, encrypted: false, failed: false };
  if ((0, import_at_rest.isEncryptedFieldWrapper)(value)) {
    if (decrypt === void 0) return { value: "", encrypted: true, failed: true };
    try {
      return { value: decrypt(value), encrypted: true, failed: false };
    } catch {
      return { value: "", encrypted: true, failed: true };
    }
  }
  return { value: "", encrypted: false, failed: false };
}
function parseWorkBuddyAuth(text, sourcePath, decrypt) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return void 0;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return void 0;
  const document = parsed;
  let auth;
  let identity;
  if (typeof document["auth"] === "object" && document["auth"] !== null) {
    auth = document["auth"];
    identity = typeof document["account"] === "object" && document["account"] !== null ? document["account"] : {};
  } else {
    auth = document;
    identity = document;
  }
  const accessField = decryptableString(auth["accessToken"], decrypt);
  if (accessField.encrypted && accessField.failed) {
    throw new WorkBuddyEncryptedCredentialError(sourcePath);
  }
  const accessToken = accessField.value;
  if (accessToken === "") return void 0;
  const refreshExpiresAtMs = typeof auth["refreshExpiresAt"] === "number" ? expiryToMs(auth["refreshExpiresAt"]) : void 0;
  if (refreshExpiresAtMs !== void 0 && refreshExpiresAtMs > 0 && refreshExpiresAtMs < Date.now()) {
    return void 0;
  }
  const lastRefreshAtMs = typeof auth["lastRefreshTime"] === "number" ? expiryToMs(auth["lastRefreshTime"]) : void 0;
  return {
    accessToken,
    refreshToken: decryptableString(auth["refreshToken"], decrypt).value,
    expiresAtMs: typeof auth["expiresAt"] === "number" ? expiryToMs(auth["expiresAt"]) : 0,
    ...refreshExpiresAtMs === void 0 ? {} : { refreshExpiresAtMs },
    ...lastRefreshAtMs === void 0 ? {} : { lastRefreshAtMs },
    ...optionalString(decryptableString(identity["nickname"], decrypt).value) === void 0 ? {} : { nickname: optionalString(decryptableString(identity["nickname"], decrypt).value) },
    ...optionalString(identity["uin"]) === void 0 ? {} : { uin: optionalString(identity["uin"]) },
    ...optionalString(identity["uid"]) === void 0 ? {} : { uid: optionalString(identity["uid"]) },
    ...optionalString(identity["enterpriseId"]) === void 0 ? {} : { enterpriseId: optionalString(identity["enterpriseId"]) },
    domain: typeof auth["domain"] === "string" ? auth["domain"] : "",
    sourcePath
  };
}
function isLiveAuthFile(path) {
  return (0, import_node_path.basename)(path) === WORKBUDDY_LIVE_FILENAME;
}
function compareFreshness(a, b) {
  const aLive = isLiveAuthFile(a.sourcePath) ? 1 : 0;
  const bLive = isLiveAuthFile(b.sourcePath) ? 1 : 0;
  if (aLive !== bLive) return bLive - aLive;
  const aIssued = a.lastRefreshAtMs ?? 0;
  const bIssued = b.lastRefreshAtMs ?? 0;
  if (aIssued !== bIssued) return bIssued - aIssued;
  return b.expiresAtMs - a.expiresAtMs;
}
function isFresher(candidate, incumbent) {
  return compareFreshness(candidate, incumbent) < 0;
}
function workbuddyAccountId(credential) {
  const stable = credential.uin ?? credential.uid ?? credential.nickname ?? "unknown";
  return (0, import_node_crypto.createHash)("sha256").update(`workbuddy\0${stable}`).digest("hex").slice(0, 16);
}
function accountLabel(credential) {
  const name = credential.nickname ?? "WorkBuddy";
  const discriminator = (credential.uid ?? credential.uin ?? "").slice(0, 8);
  return discriminator === "" ? name : `${name}#${discriminator}`;
}
async function authFilesIn(dir) {
  let entries;
  try {
    entries = await (0, import_promises.readdir)(dir);
  } catch {
    return [];
  }
  const files = entries.filter((name) => name.endsWith(".info"));
  files.sort((a, b) => a < b ? 1 : a > b ? -1 : 0);
  return files.map((name) => (0, import_node_path.join)(dir, name));
}
async function readCredential(path) {
  let text;
  try {
    text = await (0, import_promises.readFile)(path, "utf8");
  } catch {
    return void 0;
  }
  const decrypt = text.includes('"$wbEncrypted"') ? await encryptedFieldOpener() : void 0;
  try {
    return parseWorkBuddyAuth(text, path, decrypt);
  } catch (error) {
    if (isEncryptedCredentialError(error)) throw error;
    return void 0;
  }
}
function cheapIdentityId(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return void 0;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return void 0;
  const document = parsed;
  const identity = typeof document["account"] === "object" && document["account"] !== null ? document["account"] : document;
  const uin = typeof identity["uin"] === "string" && identity["uin"] !== "" ? identity["uin"] : void 0;
  const uid = typeof identity["uid"] === "string" && identity["uid"] !== "" ? identity["uid"] : void 0;
  if (uin === void 0 && uid === void 0) return void 0;
  return workbuddyAccountId({ ...uin === void 0 ? {} : { uin }, ...uid === void 0 ? {} : { uid } });
}
async function cheapIdentityIdFromFile(path) {
  try {
    return cheapIdentityId(await (0, import_promises.readFile)(path, "utf8"));
  } catch {
    return void 0;
  }
}
async function encryptedFieldOpener() {
  await (0, import_at_rest.readAtRestKey)().catch(() => void 0);
  return (field) => {
    if (!(0, import_at_rest.isEncryptedFieldWrapper)(field)) throw new Error("workbuddy: not an encrypted field wrapper");
    const keyId = (0, import_at_rest.encryptedFieldKeyId)(field);
    if (keyId === void 0) throw new Error("workbuddy: encrypted field has no key id");
    const key = (0, import_at_rest.atRestKeyFor)(keyId);
    if (key === void 0) throw new Error("workbuddy: no at-rest key available for this encrypted field");
    return (0, import_at_rest.openEncryptedField)(field, key);
  };
}
async function primeAtRestKeys() {
  await (0, import_at_rest.readAtRestKey)().catch(() => void 0);
}
function candidateAuthDirs(env = process.env) {
  const dirs = [];
  const override = nonEmptyEnv(env[WORKBUDDY_AUTH_FILE_ENV]);
  if (override !== void 0) {
    dirs.push(override.toLowerCase().endsWith(".info") ? (0, import_node_path.resolve)(override, "..") : override);
  }
  dirs.push(...defaultDesktopAuthDirs(process.env["DSH_TEST_PLATFORM"]));
  return dirs;
}
const IDLE_WEIGHT_PER_HOUR = 0.5;
const IDLE_WEIGHT_MAX = 5;
function idleWeight(lastUsedAt, now) {
  if (lastUsedAt === void 0) return 1 + IDLE_WEIGHT_MAX;
  const hours = (now - lastUsedAt) / 36e5;
  const idle = Math.min(Math.max(hours, 0) * IDLE_WEIGHT_PER_HOUR, IDLE_WEIGHT_MAX);
  return 1 + idle;
}
const EXHAUST_COOLDOWN_MS = 30 * 60 * 1e3;
class WorkBuddyAccountPool {
  logger;
  authDirs;
  cooldownMs;
  /**
   * How long an account stays out of rotation after the upstream reports its
   * credits are spent. Credit packs reset on their own schedule rather than on a
   * rate-limit window, so this is much longer than `cooldownMs`.
   */
  exhaustCooldownMs;
  client;
  refreshMarginMs;
  accounts = [];
  distribution;
  /** Cursor for round-robin mode; unused under priority distribution. */
  cursor = 0;
  lastScanAtMs = 0;
  preferredId;
  /**
   * Account ids the user switched off on the card.
   *
   * Disabling is a user preference rather than a property of the credential:
   * `scan()` rebuilds every account object from the auth files, so the set
   * lives on the pool and is re-applied from settings after each scan.
   */
  disabledIds = /* @__PURE__ */ new Set();
  /**
   * Account ids the user threw out of the pool for good.
   *
   * Enforced BEFORE the credential is parsed: `scan()` skips a file whose
   * identity is already ignored, so an ignored account costs no at-rest key
   * lookup (which spawns the desktop app on 5.6.0+) and cannot re-enter the pool
   * when the app writes a fresh sign-in for it. That is the difference from
   * {@link disabledIds}, which only filters at pick time and leaves the account
   * listed, readable and re-discoverable.
   *
   * The set is supplied by the host from the plugin's own ignore file, and is
   * replaced wholesale on every {@link applyIgnored} so removing an entry takes
   * effect on the next scan without a restart.
   */
  ignoredIds = /* @__PURE__ */ new Set();
  /**
   * Per-account credit floor, keyed by account id. 0 (or absent) means "spend
   * it all".
   *
   * A reserved balance is protection, not a hard limit the upstream knows
   * about: the pool simply stops picking that account once its last known
   * balance is at or below the floor, so the user keeps a cushion instead of
   * draining every account to zero.
   */
  creditReserves = /* @__PURE__ */ new Map();
  /**
   * Last known credit balance per account, epoch ms aside.
   *
   * Refreshed in the background after a successful request, so a pick can
   * consult it. An account with no reading is treated as usable: refusing to
   * pick an account just because its balance has not been checked yet would
   * strand a healthy pool, and the first 402 still cools it as before.
   */
  creditBalances = /* @__PURE__ */ new Map();
  /**
   * Last time each account served a request, epoch ms. Drives the idle term
   * of the priority-mode weighting below: an account that just served loses to
   * one that has been idle, so a small pool stops hammering a single account.
   *
   * In-memory on purpose: it only biases the next pick, so a cold start that
   * treats every account as idle is the right default. Not keyed by id lookup
   * misses because a removed account simply disappears from the map on re-scan.
   */
  lastUsedAt = /* @__PURE__ */ new Map();
  refreshInflight = /* @__PURE__ */ new Map();
  constructor(options = {}) {
    this.logger = options.logger;
    this.authDirs = options.authDirs ?? candidateAuthDirs();
    this.cooldownMs = options.cooldownMs ?? 6e4;
    this.exhaustCooldownMs = options.exhaustCooldownMs ?? EXHAUST_COOLDOWN_MS;
    this.client = options.client;
    this.refreshMarginMs = options.refreshMarginMs ?? 5 * 60 * 1e3;
    this.distribution = options.distribution ?? "priority";
  }
  /**
   * Re-apply configuration that only affects discovery and cooldown policy,
   * without rebuilding the pool. A later `scan()` uses the new auth dirs and
   * cooldown window; existing accounts keep their in-memory state.
   */
  applyConfig(options) {
    if (options.authDirs !== void 0 && options.authDirs.length > 0) {
      this.authDirs = options.authDirs;
    }
    if (options.cooldownMs !== void 0 && options.cooldownMs >= 1e3) {
      this.cooldownMs = options.cooldownMs;
    }
    if (options.exhaustCooldownMs !== void 0 && options.exhaustCooldownMs >= 1e3) {
      this.exhaustCooldownMs = options.exhaustCooldownMs;
    }
    if (options.distribution !== void 0) {
      this.distribution = options.distribution;
    }
    if (options.disabledAccountIds !== void 0) {
      this.disabledIds = new Set(options.disabledAccountIds);
    }
    if (options.creditReserves !== void 0) this.setCreditReserves(options.creditReserves);
  }
  /**
   * Replace the permanent ignore list.
   *
   * Also drops any already-discovered account that is now ignored, so the change
   * is visible without waiting for the next scan: the card refreshes its status
   * document right after the write, and an account still sitting in `accounts`
   * would keep showing up there.
   */
  applyIgnored(ids) {
    this.ignoredIds = new Set(ids);
    if (this.ignoredIds.size === 0) return;
    this.accounts = this.accounts.filter((account) => !this.ignoredIds.has(account.id));
  }
  /** Whether this account has been thrown out of the pool for good. */
  isIgnored(accountId) {
    return this.ignoredIds.has(accountId);
  }
  /** Every ignored id currently in force, in insertion order. */
  ignoredIdsInOrder() {
    return [...this.ignoredIds];
  }
  /** Rescan the auth directories and merge newly discovered accounts. */
  async scan() {
    const found = [];
    for (const dir of this.authDirs) {
      for (const file of await authFilesIn(dir)) {
        if (this.ignoredIds.size > 0) {
          const cheapId = await cheapIdentityIdFromFile(file);
          if (cheapId !== void 0 && this.ignoredIds.has(cheapId)) continue;
        }
        const credential = await readCredential(file);
        if (credential === void 0) continue;
        if (this.ignoredIds.size > 0 && this.ignoredIds.has(workbuddyAccountId(credential))) continue;
        found.push(credential);
      }
    }
    const byId = /* @__PURE__ */ new Map();
    for (const account of this.accounts) byId.set(account.id, account);
    for (const credential of found) {
      const id = workbuddyAccountId(credential);
      const existing = byId.get(id);
      if (existing === void 0) {
        byId.set(id, {
          id,
          label: accountLabel(credential),
          credential,
          cooldownUntilMs: 0,
          modelCooldowns: {},
          rateLimitHits: 0
        });
        continue;
      }
      if (isFresher(credential, existing.credential)) {
        byId.set(id, { ...existing, credential, label: accountLabel(credential) });
      }
    }
    const ordered = [...byId.values()];
    ordered.sort((a, b) => compareFreshness(a.credential, b.credential));
    this.accounts = ordered;
    this.lastScanAtMs = Date.now();
    return this.accounts;
  }
  /** All accounts, cooldown state included. */
  list(region) {
    if (region === void 0) return this.accounts;
    return this.accounts.filter((account) => (0, import_upstream.regionOf)(account.credential.domain) === region);
  }
  /**
   * Accounts currently eligible to serve a request.
   *
   * With a `modelId`, an account is eligible when it is not account-wide cooled
   * AND that model is not cooling on it — so a 429 on `hy4-preview` only keeps
   * that model out while `hy3` on the same account stays usable. Without a
   * model id the legacy account-wide check applies (callers that cannot name a
   * model, e.g. CLI diagnostics).
   */
  available(now, modelId, region) {
    return this.accounts.filter((account) => {
      if (this.disabledIds.has(account.id)) return false;
      const reserve = this.creditReserves.get(account.id);
      if (reserve !== void 0 && reserve > 0) {
        const balance = this.creditBalances.get(account.id);
        if (balance !== void 0 && balance <= reserve) return false;
      }
      if (account.cooldownUntilMs > now) return false;
      if (modelId !== void 0 && (account.modelCooldowns[modelId] ?? 0) > now) return false;
      if (region !== void 0 && (0, import_upstream.regionOf)(account.credential.domain) !== region) return false;
      return true;
    });
  }
  /** Round-robin: the legacy cursor walk, kept for the distribution that asks for it. */
  pickRoundRobin(pool) {
    const index = this.cursor % pool.length;
    const account = pool[index];
    if (account === void 0) return void 0;
    this.cursor = (index + 1) % pool.length;
    return account;
  }
  /**
   * Priority mode: weighted random over the eligible accounts.
   *
   * The weight is an idle bonus — `1 + min(idleHours * perHour, max)` — so an
   * account that has never served (or has been idle for a while) outranks one
   * that just answered. Reference panel logic drops its success-rate term
   * entirely because a lifetime error counter penalises an account forever;
   * instantaneous health is already handled by cooldowns, which is why those
   * accounts never reach this list.
   *
   * A pool with no idle history (fresh process) hashes to equal weights, which
   * spreads the very first picks instead of always returning index 0.
   */
  pickByWeight(pool) {
    if (pool.length === 1) return pool[0];
    const now = Date.now();
    const weights = pool.map((account) => idleWeight(this.lastUsedAt.get(account.id), now));
    const total = weights.reduce((sum, weight) => sum + weight, 0);
    if (!Number.isFinite(total) || total <= 0) return pool[0];
    let roll = Math.random() * total;
    for (let index = 0; index < pool.length; index += 1) {
      roll -= weights[index] ?? 0;
      if (roll < 0) return pool[index];
    }
    return pool[pool.length - 1];
  }
  /**
   * Pick the account to serve a request.
   *
   * Two distributions, chosen by the `distribution` setting:
   *
   * - **priority** (default, and what the card ships with): one account serves
   *   every request until it is rate-limited, then the next in order takes over.
   *   Credits drain one account at a time, and a cooling account returns to the
   *   head of the queue the moment its window resets — it was never consumed, so
   *   it resumes straight away.
   * - **round-robin**: consecutive requests rotate through the pool so spend
   *   spreads evenly across every account.
   *
   * In both modes an explicit user selection (`prefer`) heads the list, a
   * cooling account is skipped for that model only, and an unrecognised setting
   * falls back to priority.
   *
   * Scans on first use, and rescans when every known account is cooling down: a
   * fresh desktop login is the usual way out of an exhausted pool.
   */
  async acquire(modelId, region) {
    if (this.accounts.length === 0) await this.scan();
    let pool = this.available(Date.now(), modelId, region);
    if (pool.length === 0) {
      await this.scan();
      pool = this.available(Date.now(), modelId, region);
    }
    if (pool.length === 0) return void 0;
    if (this.preferredId !== void 0) {
      const preferred = pool.find((account2) => account2.id === this.preferredId);
      if (preferred !== void 0) {
        await this.ensureFresh(preferred);
        return preferred;
      }
    }
    const account = this.distribution === "round-robin" ? this.pickRoundRobin(pool) : this.distribution === "balanced" ? this.pickByWeight(pool) : pool[0];
    if (account === void 0) return void 0;
    await this.ensureFresh(account);
    return account;
  }
  /** Pin the account the plugin card should prefer; tokens stay out of settings. */
  /** How the pool currently spreads requests. Shown on the card. */
  currentDistribution() {
    return this.distribution;
  }
  prefer(accountId) {
    this.preferredId = accountId;
  }
  /** Whether the user switched this account off on the card. */
  isDisabled(accountId) {
    return this.disabledIds.has(accountId);
  }
  /** Every account id the user switched off, in discovery order. */
  disabledIdsInOrder() {
    return this.accounts.filter((account) => this.disabledIds.has(account.id)).map((account) => account.id);
  }
  /**
   * Record that an account actually served a request.
   *
   * Called by the shim once the upstream answers 200 — only then is the account
   * the one the user is really being served by. `balanced` mode reads the same map
   * for its idle weighting, so a request that failed over to another account must
   * not count as used for the account that was merely tried.
   */
  noteServed(accountId) {
    if (!this.accounts.some((account) => account.id === accountId)) return;
    this.lastUsedAt.set(accountId, Date.now());
  }
  /**
   * Record an account latest known credit balance.
   *
   * Called after a request and by the card balance refresh, so the reserve
   * check has something to compare against. A reading for an unknown account is
   * dropped: `scan()` rebuilds the account list and a stale id would otherwise
   * accumulate forever.
   */
  noteCredits(accountId, balance) {
    if (!Number.isFinite(balance)) return;
    if (!this.accounts.some((account) => account.id === accountId)) return;
    this.creditBalances.set(accountId, balance);
  }
  /** Last known balance for one account, or undefined when never read. */
  creditsOf(accountId) {
    return this.creditBalances.get(accountId);
  }
  /** The credit floor the user set for one account; 0 when unset. */
  creditReserveOf(accountId) {
    return this.creditReserves.get(accountId) ?? 0;
  }
  /**
   * Replace every reserve. Called from settings on each apply, so the map
   * mirrors the saved document exactly instead of accumulating old keys.
   */
  setCreditReserves(reserves) {
    const next = /* @__PURE__ */ new Map();
    for (const [id, value] of Object.entries(reserves)) {
      if (Number.isFinite(value) && value > 0) next.set(id, Math.floor(value));
    }
    this.creditReserves = next;
  }
  /** Every reserve currently in force, keyed by account id. */
  creditReservesInOrder() {
    const out = {};
    for (const account of this.accounts) {
      const reserve = this.creditReserves.get(account.id);
      if (reserve !== void 0 && reserve > 0) out[account.id] = reserve;
    }
    return out;
  }
  /**
   * Whether an account is held back only by its reserve.
   *
   * Separates "resting to protect credits" from every other reason an account
   * is out of rotation, which is what the card shows the user.
   */
  isReserved(accountId) {
    const reserve = this.creditReserves.get(accountId);
    if (reserve === void 0 || reserve <= 0) return false;
    const balance = this.creditBalances.get(accountId);
    return balance !== void 0 && balance <= reserve;
  }
  /**
   * The account that served the most recent request, if any.
   *
   * Distinct from "who would serve the next one": this is a record of what
   * actually happened, which is what the card needs to answer "which account am
   * I using right now?". Under `balanced` there is no deterministic next account
   * at all, so a recorded fact is the only honest answer.
   *
   * Returns undefined before the first request of the process, and after every
   * known account has been re-scanned away (a login swapped out under us).
   */
  lastServedId() {
    let newest;
    for (const [id, at] of this.lastUsedAt) {
      if (!this.accounts.some((account) => account.id === id)) continue;
      if (newest === void 0 || at > newest.at) newest = { id, at };
    }
    return newest?.id;
  }
  /** Best-effort refresh of one account after a session-dead upstream answer. */
  async refreshAccount(accountId) {
    const account = this.accounts.find((item) => item.id === accountId);
    if (account === void 0) return;
    await this.ensureFresh(account);
  }
  /**
   * Refresh the account's access token when it is within the margin (or already
   * expired), in-flight de-duped per account. A failed refresh keeps the
   * existing token when it has not yet expired, so an unreachable refresh
   * endpoint never takes down a working session.
   */
  async ensureFresh(account) {
    if (this.client === void 0) return;
    const credential = account.credential;
    const expiring = credential.expiresAtMs <= 0 || credential.expiresAtMs <= Date.now() + this.refreshMarginMs;
    if (!expiring) return;
    const existing = this.refreshInflight.get(account.id);
    if (existing !== void 0) {
      await existing;
      return;
    }
    const run = (async () => {
      if (credential.refreshToken === "") {
        if (credential.expiresAtMs > Date.now() + 3e4) return;
        this.logger?.warn(`dsh-workbuddy-xdpool: ${account.label} token expired with no refresh token; sign in again`);
        return;
      }
      try {
        const outcome = await this.client.refreshToken(credential);
        account.credential = {
          ...credential,
          accessToken: outcome.accessToken,
          ...outcome.refreshToken === void 0 ? {} : { refreshToken: outcome.refreshToken },
          expiresAtMs: outcome.expiresInSec !== void 0 ? Date.now() + outcome.expiresInSec * 1e3 : credential.expiresAtMs,
          ...outcome.domain === void 0 || outcome.domain === "" ? {} : { domain: outcome.domain }
        };
        this.logger?.info?.(`dsh-workbuddy-xdpool: refreshed token for ${account.label}`);
      } catch (error) {
        if (credential.expiresAtMs > Date.now() + 3e4) {
          this.logger?.warn?.(`dsh-workbuddy-xdpool: token refresh failed but token still valid for ${account.label}`, error);
        } else {
          this.logger?.error?.(`dsh-workbuddy-xdpool: token refresh failed and token expired for ${account.label}`, error);
        }
      }
    })();
    this.refreshInflight.set(account.id, run);
    try {
      await run;
    } finally {
      this.refreshInflight.delete(account.id);
    }
  }
  /**
   * Cool a whole account after the upstream reports its credits are spent.
   *
   * Credit exhaustion is an ACCOUNT condition, unlike a model rate limit: every
   * model on that account is unusable until the quota resets, so this cools the
   * account as a whole (no `modelId`) for the configured exhaustion window. The
   * shim then rotates to a different account instead of failing the request.
   */
  penalizeExhausted(accountId) {
    const until = Date.now() + this.exhaustCooldownMs;
    this.penalize(accountId, until);
    this.logger?.warn(
      `dsh-workbuddy-xdpool: account credits exhausted; cooling the whole account until ${new Date(until).toISOString()}`
    );
  }
  /**
   * Mark an account (or one of its models) rate-limited.
   *
   * With `modelId`, only that model on the account is cooled — the account's
   * other models stay in rotation, matching the upstream's per-model rate
   * limit ("可切换其他模型继续使用"). Without a model id the whole account is
   * cooled, which callers should reserve for limits that truly span every model.
   */
  penalize(accountId, resetAtMs, modelId) {
    const account = this.accounts.find((item) => item.id === accountId);
    if (account === void 0) return;
    account.rateLimitHits += 1;
    const until = resetAtMs ?? Date.now() + this.cooldownMs;
    if (modelId !== void 0 && modelId !== "") {
      account.modelCooldowns[modelId] = Math.max(account.modelCooldowns[modelId] ?? 0, until);
      this.logger?.warn(
        `dsh-workbuddy-xdpool: ${account.label} rate-limited on model ${modelId}; cooling that model until ${new Date(until).toISOString()}`
      );
      return;
    }
    account.cooldownUntilMs = Math.max(account.cooldownUntilMs, until);
    this.logger?.warn(
      `dsh-workbuddy-xdpool: account ${account.label} rate-limited; cooling until ${new Date(until).toISOString()}`
    );
  }
  /** Clear all cooldowns (account-wide and per-model), e.g. from a reset command. */
  resetCooldowns() {
    for (const account of this.accounts) {
      account.cooldownUntilMs = 0;
      account.modelCooldowns = {};
      account.rateLimitHits = 0;
    }
  }
  /** Diagnostics snapshot. Account-wide cooling count (per-model cooling excluded:
   *  the account as a whole stays usable when only one model is limited). */
  status() {
    const now = Date.now();
    return {
      count: this.accounts.length,
      cooling: this.accounts.filter((account) => account.cooldownUntilMs > now).length,
      lastScanAtMs: this.lastScanAtMs
    };
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  ENCRYPTED_CREDENTIAL_CODE,
  WORKBUDDY_AUTH_FILE_ENV,
  WORKBUDDY_LIVE_FILENAME,
  WorkBuddyAccountPool,
  WorkBuddyEncryptedCredentialError,
  candidateAuthDirs,
  cheapIdentityId,
  defaultDesktopAuthDirs,
  encryptedFieldOpener,
  isEncryptedCredentialError,
  parseWorkBuddyAuth,
  primeAtRestKeys,
  workbuddyAccountId
});
