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
var at_rest_exports = {};
__export(at_rest_exports, {
  WORKBUDDY_APP_EXECUTABLE_ENV: () => WORKBUDDY_APP_EXECUTABLE_ENV,
  atRestKeyFor: () => atRestKeyFor,
  clearAtRestKeyCache: () => clearAtRestKeyCache,
  deriveAtRestKey: () => deriveAtRestKey,
  deriveAtRestKeyId: () => deriveAtRestKeyId,
  encryptedFieldKeyId: () => encryptedFieldKeyId,
  fetchAtRestKeyPayload: () => fetchAtRestKeyPayload,
  findWorkbuddyAppExecutable: () => findWorkbuddyAppExecutable,
  isEncryptedFieldWrapper: () => isEncryptedFieldWrapper,
  isWorkbuddyBundle: () => isWorkbuddyBundle,
  macosBundleExecutable: () => macosBundleExecutable,
  macosNestedAppBundles: () => macosNestedAppBundles,
  openEncryptedField: () => openEncryptedField,
  readAtRestKey: () => readAtRestKey,
  readAtRestKeyById: () => readAtRestKeyById,
  setAtRestKeysForTest: () => setAtRestKeysForTest,
  workbuddyAppExecutableCandidates: () => workbuddyAppExecutableCandidates
});
module.exports = __toCommonJS(at_rest_exports);
var import_node_child_process = require("node:child_process");
var import_node_crypto = require("node:crypto");
var import_node_fs = require("node:fs");
var import_node_os = require("node:os");
var import_node_path = require("node:path");
var import_node_child_process2 = require("node:child_process");
const FRAMING_CODE = {
  file: 1,
  field: 2,
  record: 3,
  stream: 4
};
const STANDARD_FORMAT_ID = {
  file: "WBEF1",
  field: "WBEV1",
  record: "WBER1",
  stream: "WBES1"
};
const AAD_DOMAIN = Buffer.from("WB-AAD\0", "ascii");
const SYMMETRIC_SCHEME = "sym-v1";
const WORKBUDDY_APP_EXECUTABLE_ENV = "WORKBUDDY_APP_EXECUTABLE";
const KEY_FETCH_TIMEOUT_MS = 3e4;
const APP_EXECUTABLE_NAMES = ["WorkBuddy.exe", "WorkBuddyAI.exe"];
const MACOS_APP_BUNDLE_NAMES = ["WorkBuddy.app", "WorkBuddy AI.app"];
function encodeUint32(value) {
  const bytes = Buffer.allocUnsafe(4);
  bytes.writeUInt32BE(value);
  return bytes;
}
function encodeLengthPrefixed(value) {
  const bytes = Buffer.from(value, "utf8");
  return Buffer.concat([encodeUint32(bytes.length), bytes]);
}
function fieldAad(keyId, suite, scheme = SYMMETRIC_SCHEME) {
  if (!/^[0-9a-f]{16}$/u.test(keyId)) throw new Error(`workbuddy: envelope keyId is malformed`);
  return Buffer.concat([
    AAD_DOMAIN,
    Buffer.from([1]),
    encodeLengthPrefixed(STANDARD_FORMAT_ID["field"]),
    encodeLengthPrefixed(scheme),
    encodeUint32(suite),
    encodeLengthPrefixed(keyId),
    Buffer.from([FRAMING_CODE["field"]]),
    // encodeOptionalUint64(undefined): field framing carries no sequence.
    Buffer.from([0]),
    // final === undefined
    Buffer.from([0])
  ]);
}
function isEncryptedFieldWrapper(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const wrapper = value;
  const keys = Object.keys(wrapper).sort();
  return keys.length === 2 && keys[0] === "$wbEncrypted" && keys[1] === "envelope" && wrapper["$wbEncrypted"] === 1 && typeof wrapper["envelope"] === "string";
}
function deriveAtRestKeyId(key) {
  return (0, import_node_crypto.createHash)("sha256").update(key).digest("hex").slice(0, 16);
}
function deriveAtRestKey(payloadJson) {
  let payload;
  try {
    payload = JSON.parse(payloadJson);
  } catch {
    throw new Error("workbuddy: at-rest key payload is not valid JSON");
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new Error("workbuddy: at-rest key payload is not an object");
  }
  const secret = payload["atRestSecretKey"];
  if (typeof secret !== "string" || secret === "") {
    throw new Error("workbuddy: at-rest key payload carries no atRestSecretKey");
  }
  return (0, import_node_crypto.createHash)("sha256").update(secret, "utf8").digest();
}
function openEncryptedField(field, key) {
  let envelope;
  try {
    envelope = JSON.parse(Buffer.from(field.envelope, "base64").toString("utf8"));
  } catch {
    throw new Error("workbuddy: encrypted field envelope is not valid JSON");
  }
  if (typeof envelope !== "object" || envelope === null || Array.isArray(envelope)) {
    throw new Error("workbuddy: encrypted field envelope is not an object");
  }
  const record = envelope;
  const suite = record["suite"];
  const keyId = record["keyId"];
  const nonce = record["nonce"];
  const authTag = record["authTag"];
  const ciphertext = record["ciphertext"];
  if (typeof suite !== "number" || typeof keyId !== "string") {
    throw new Error("workbuddy: encrypted field envelope is missing suite or keyId");
  }
  if (typeof nonce !== "string" || typeof authTag !== "string" || typeof ciphertext !== "string") {
    throw new Error("workbuddy: encrypted field envelope is missing nonce, authTag or ciphertext");
  }
  const expectedKeyId = deriveAtRestKeyId(key);
  if (keyId !== expectedKeyId) {
    throw new Error(`workbuddy: encrypted field belongs to key ${keyId}, not the available key ${expectedKeyId}`);
  }
  const decipher = (0, import_node_crypto.createDecipheriv)("aes-256-gcm", key, Buffer.from(nonce, "base64"), { authTagLength: 16 });
  decipher.setAAD(fieldAad(keyId, suite));
  decipher.setAuthTag(Buffer.from(authTag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertext, "base64")),
    decipher.final()
  ]).toString("utf8");
}
function encryptedFieldKeyId(field) {
  try {
    const record = JSON.parse(Buffer.from(field.envelope, "base64").toString("utf8"));
    return typeof record["keyId"] === "string" ? record["keyId"] : void 0;
  } catch {
    return void 0;
  }
}
function macosBundleExecutable(bundle) {
  let plist;
  try {
    plist = (0, import_node_fs.readFileSync)((0, import_node_path.join)(bundle, "Contents", "Info.plist"), "utf8");
  } catch {
    return void 0;
  }
  const match = /<key>\s*CFBundleExecutable\s*<\/key>\s*<string>([^<]*)<\/string>/u.exec(plist);
  const name = match?.[1]?.trim();
  if (name === void 0 || name === "" || name.includes("/") || name.includes("\\") || name === "." || name === "..") {
    return void 0;
  }
  return (0, import_node_path.join)(bundle, "Contents", "MacOS", name);
}
function windowsRegistryAppPaths() {
  if (process.platform !== "win32") return [];
  const roots = [
    ["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "/**"],
    ["HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "/**"],
    ["HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "/**"]
  ];
  const out = [];
  for (const [root] of roots) {
    let listing;
    try {
      listing = (0, import_node_child_process2.execFileSync)("reg", ["query", root, "/s", "/v", "DisplayName"], {
        encoding: "utf8",
        timeout: 1e4,
        windowsHide: true,
        maxBuffer: 8 * 1024 * 1024
      });
    } catch {
      continue;
    }
    const keys = listing.split(/\r?\n(?=HKEY_)/u).filter((block) => /WorkBuddy|CodeBuddy/iu.test(block));
    for (const key of keys) {
      const keyPath = /^(HKEY_[^\r\n]+)/u.exec(key)?.[1]?.trim();
      if (keyPath === void 0) continue;
      for (const name of ["DisplayIcon", "InstallLocation"]) {
        try {
          const value = (0, import_node_child_process2.execFileSync)("reg", ["query", keyPath, "/v", name], {
            encoding: "utf8",
            timeout: 5e3,
            windowsHide: true
          });
          const match = /REG_(?:SZ|EXPAND_SZ)\s+(.+)$/mu.exec(value);
          const raw = match?.[1]?.trim();
          if (raw === void 0 || raw === "") continue;
          const cleaned = raw.replace(/^"/u, "").replace(/",-?\d+$/u, "").replace(/,-?\d+$/u, "").trim();
          out.push(cleaned);
        } catch {
        }
      }
    }
  }
  return out;
}
function windowsFallbackAppPaths(env) {
  const out = [];
  const roots = /* @__PURE__ */ new Set();
  for (const key of ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)", "LOCALAPPDATA"]) {
    const value = env[key]?.trim();
    if (value !== void 0 && value !== "") roots.add(value);
  }
  for (let code = 67; code <= 90; code += 1) {
    const drive = String.fromCharCode(code) + ":\\";
    try {
      if (!(0, import_node_fs.existsSync)(drive)) continue;
    } catch {
      continue;
    }
    roots.add((0, import_node_path.join)(drive, "Program Files"));
    roots.add((0, import_node_path.join)(drive, "Program Files (x86)"));
    roots.add(drive);
  }
  for (const root of roots) {
    for (const name of APP_EXECUTABLE_NAMES) {
      out.push((0, import_node_path.join)(root, "WorkBuddy", name));
      out.push((0, import_node_path.join)(root, "WorkBuddy AI", name));
      out.push((0, import_node_path.join)(root, "Programs", "WorkBuddy", name));
    }
  }
  for (const root of roots) {
    try {
      for (const entry of (0, import_node_fs.readdirSync)(root)) {
        if (!/^(workbuddy|codebuddy)/iu.test(entry)) continue;
        for (const name of APP_EXECUTABLE_NAMES) out.push((0, import_node_path.join)(root, entry, name));
      }
    } catch {
    }
  }
  return out;
}
function workbuddyAppExecutableCandidates(platform = process.platform, home = (0, import_node_os.homedir)(), env = process.env, readBundleExecutable = macosBundleExecutable, registryPaths = windowsRegistryAppPaths) {
  const candidates = [env[WORKBUDDY_APP_EXECUTABLE_ENV]?.trim()];
  if (platform === "win32") {
    candidates.push(...registryPaths());
    candidates.push(...windowsFallbackAppPaths(env));
  } else if (platform === "darwin") {
    for (const name of MACOS_APP_BUNDLE_NAMES) {
      candidates.push(
        readBundleExecutable((0, import_node_path.join)("/Applications", name)),
        readBundleExecutable((0, import_node_path.join)(home, "Applications", name))
      );
    }
  }
  return candidates.filter((candidate) => candidate !== void 0 && candidate !== "");
}
const APP_BUNDLE_IDENTIFIER_PREFIXES = ["com.tencent.workbuddy", "com.workbuddy"];
function isWorkbuddyBundle(bundle) {
  let plist;
  try {
    plist = (0, import_node_fs.readFileSync)((0, import_node_path.join)(bundle, "Contents", "Info.plist"), "utf8");
  } catch {
    return false;
  }
  const match = /<key>\s*CFBundleIdentifier\s*<\/key>\s*<string>([^<]*)<\/string>/u.exec(plist);
  const identifier = match?.[1]?.trim().toLowerCase();
  if (identifier === void 0 || identifier === "") return false;
  return APP_BUNDLE_IDENTIFIER_PREFIXES.some((prefix) => identifier === prefix || identifier.startsWith(`${prefix}.`));
}
function macosNestedAppBundles(parent) {
  let entries;
  try {
    entries = (0, import_node_fs.readdirSync)(parent);
  } catch {
    return [];
  }
  const bundles = [];
  for (const entry of entries) {
    const nested = (0, import_node_path.join)(parent, entry);
    for (const name of MACOS_APP_BUNDLE_NAMES) {
      const bundle = (0, import_node_path.join)(nested, name);
      try {
        if (!(0, import_node_fs.statSync)(bundle).isDirectory()) continue;
      } catch {
        continue;
      }
      if (isWorkbuddyBundle(bundle)) bundles.push(bundle);
    }
  }
  return bundles;
}
function findWorkbuddyAppExecutable(platform = process.platform, home = (0, import_node_os.homedir)(), env = process.env) {
  for (const candidate of workbuddyAppExecutableCandidates(platform, home, env)) {
    try {
      if ((0, import_node_fs.existsSync)(candidate)) return candidate;
    } catch {
    }
  }
  if (platform === "darwin") {
    for (const parent of ["/Applications", (0, import_node_path.join)(home, "Applications")]) {
      for (const bundle of macosNestedAppBundles(parent)) {
        const executable = macosBundleExecutable(bundle);
        if (executable === void 0) continue;
        try {
          if ((0, import_node_fs.existsSync)(executable)) return executable;
        } catch {
        }
      }
    }
  }
  return void 0;
}
function fetchAtRestKeyPayload(executable) {
  return new Promise((resolve, reject) => {
    const source = "try{process.stdout.write(process._linkedBinding('electron_browser_workbuddy_storage').loggerGet())}catch(e){process.exitCode=3;process.stderr.write(String(e&&e.message||e))}";
    (0, import_node_child_process.execFile)(
      executable,
      ["-e", source],
      {
        env: { ...process.env, ELECTRON_RUN_AS_NODE: "1" },
        timeout: KEY_FETCH_TIMEOUT_MS,
        windowsHide: true,
        maxBuffer: 1024 * 1024
      },
      (error, stdout, stderr) => {
        if (error !== null) {
          reject(new Error(`workbuddy: the desktop app did not provide its at-rest key (${stderr.trim() || error.message})`));
          return;
        }
        const payload = stdout.trim();
        if (payload === "") {
          reject(new Error("workbuddy: the desktop app returned an empty at-rest key payload"));
          return;
        }
        resolve(payload);
      }
    );
  });
}
const atRestKeyById = /* @__PURE__ */ new Map();
let inflightKeys;
let lastKeyFailureAtMs = 0;
const KEY_FAILURE_BACKOFF_MS = 6e4;
function ensureAtRestKeys() {
  if (atRestKeyById.size > 0) return Promise.resolve();
  if (Date.now() - lastKeyFailureAtMs < KEY_FAILURE_BACKOFF_MS) return Promise.resolve();
  inflightKeys ??= (async () => {
    const candidates = workbuddyAppExecutableCandidates().filter((candidate) => {
      try {
        return (0, import_node_fs.existsSync)(candidate);
      } catch {
        return false;
      }
    });
    if (candidates.length === 0) {
      lastKeyFailureAtMs = Date.now();
      return;
    }
    let anySuccess = false;
    await Promise.all(candidates.map(async (executable) => {
      try {
        const payload = await fetchAtRestKeyPayload(executable);
        const key = deriveAtRestKey(payload);
        atRestKeyById.set(deriveAtRestKeyId(key), key);
        anySuccess = true;
      } catch {
      }
    }));
    if (anySuccess) {
      lastKeyFailureAtMs = 0;
    } else {
      lastKeyFailureAtMs = Date.now();
    }
  })().finally(() => {
    inflightKeys = void 0;
  });
  return inflightKeys;
}
function readAtRestKeyById(keyId) {
  return ensureAtRestKeys().then(() => atRestKeyById.get(keyId));
}
function atRestKeyFor(keyId) {
  return atRestKeyById.get(keyId);
}
function setAtRestKeysForTest(keys) {
  atRestKeyById.clear();
  for (const { keyId, key } of keys) atRestKeyById.set(keyId, key);
}
function readAtRestKey() {
  return ensureAtRestKeys().then(() => {
    for (const key of atRestKeyById.values()) return key;
    return void 0;
  });
}
function clearAtRestKeyCache() {
  atRestKeyById.clear();
  inflightKeys = void 0;
  lastKeyFailureAtMs = 0;
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  WORKBUDDY_APP_EXECUTABLE_ENV,
  atRestKeyFor,
  clearAtRestKeyCache,
  deriveAtRestKey,
  deriveAtRestKeyId,
  encryptedFieldKeyId,
  fetchAtRestKeyPayload,
  findWorkbuddyAppExecutable,
  isEncryptedFieldWrapper,
  isWorkbuddyBundle,
  macosBundleExecutable,
  macosNestedAppBundles,
  openEncryptedField,
  readAtRestKey,
  readAtRestKeyById,
  setAtRestKeysForTest,
  workbuddyAppExecutableCandidates
});
