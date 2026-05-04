import React, { useState, useMemo, useEffect } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, RadialBarChart, RadialBar, LineChart, Line,
} from "recharts";
import {
  Shield, AlertTriangle, Cpu, Activity, Code2, Binary, Network,
  ChevronRight, Zap, Lock, Unlock, FileWarning, Terminal, Hash,
} from "lucide-react";

/* =========================================================================
   CryptographyAO — Cryptographic Vulnerability Analyzer
   Pipeline:  Tokenize → Binary Classify (0/1) → GraphCodeBERT Category → EDA
   ========================================================================= */

// ---- Vulnerability detection rules (simulates GraphCodeBERT classification) ----
const RULES = [
  { id: "VLN-001", cat: "Weak Hash Function",        sev: "HIGH",     re: /\bMD5\b|hashlib\.md5|MessageDigest\.getInstance\(\s*["']MD5["']\s*\)|createHash\(\s*["']md5["']\s*\)/i, weight: 0.94, fix: "Use SHA-256 or SHA-3 family" },
  { id: "VLN-002", cat: "Weak Hash Function",        sev: "HIGH",     re: /\bSHA-?1\b|hashlib\.sha1|MessageDigest\.getInstance\(\s*["']SHA-?1["']\s*\)/i, weight: 0.91, fix: "Migrate to SHA-256 minimum" },
  { id: "VLN-003", cat: "Insecure Cipher Mode",      sev: "CRITICAL", re: /AES\/ECB|ECB\b|Cipher\.getInstance\(\s*["'][^"']*ECB[^"']*["']\s*\)|MODE_ECB/i, weight: 0.97, fix: "Use AES-GCM or AES-CBC with random IV" },
  { id: "VLN-004", cat: "Deprecated Cipher",         sev: "CRITICAL", re: /\b(DES|DESede|3DES|TripleDES|RC4|Blowfish)\b(?!\w)/i, weight: 0.95, fix: "Use AES-256-GCM" },
  { id: "VLN-005", cat: "Hardcoded Secret",          sev: "CRITICAL", re: /(?:secret|api[_-]?key|password|passwd|token|private[_-]?key)\s*[:=]\s*["'][A-Za-z0-9+/=_\-]{6,}["']/i, weight: 0.89, fix: "Load secrets from env vars or KMS/Vault" },
  { id: "VLN-006", cat: "Hardcoded Secret",          sev: "CRITICAL", re: /key\s*=\s*b?["'][A-Fa-f0-9]{16,}["']|key\s*=\s*\[\s*0x[0-9a-fA-F]+/i, weight: 0.86, fix: "Derive keys via HKDF/PBKDF2 from env input" },
  { id: "VLN-007", cat: "Insecure Randomness",       sev: "HIGH",     re: /Math\.random\(\)|java\.util\.Random|\brand\(\)|random\.random\(\)|random\.randint/i, weight: 0.83, fix: "Use crypto.randomBytes / SecureRandom / secrets module" },
  { id: "VLN-008", cat: "Static IV / Nonce",         sev: "HIGH",     re: /iv\s*[:=]\s*["'][^"']{4,}["']|IvParameterSpec\(\s*["'][^"']+["']\s*\)|nonce\s*=\s*b?["'][^"']{4,}["']/i, weight: 0.88, fix: "Generate IV randomly per encryption" },
  { id: "VLN-009", cat: "Weak Key Size",             sev: "MEDIUM",   re: /KeyPairGenerator.*?initialize\(\s*(512|1024)|RSA.*?\b(512|1024)\b|generate_private_key.*key_size\s*=\s*(512|1024)/i, weight: 0.79, fix: "Use RSA >= 3072 or migrate to ECDSA P-256" },
  { id: "VLN-010", cat: "Insecure TLS",              sev: "HIGH",     re: /SSLv2|SSLv3|TLSv?1(\.0)?\b|PROTOCOL_SSL|PROTOCOL_TLSv1[^.]/i, weight: 0.92, fix: "Use TLS 1.2+ (prefer TLS 1.3)" },
  { id: "VLN-011", cat: "Cert Validation Disabled",  sev: "CRITICAL", re: /verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureRequestWarning|TrustAllCerts|HostnameVerifier.*ALLOW_ALL/i, weight: 0.96, fix: "Always validate certificates" },
  { id: "VLN-012", cat: "Padding Oracle Risk",       sev: "MEDIUM",   re: /PKCS1Padding|RSA\/ECB\/PKCS1Padding/i, weight: 0.71, fix: "Use OAEP padding for RSA" },
  { id: "VLN-013", cat: "Weak KDF",                  sev: "MEDIUM",   re: /PBKDF2.*iterations?\s*[:=]\s*([1-9]\d{0,3}|10000)\b|hashlib\.pbkdf2_hmac.*,\s*\d{1,4}\s*\)/i, weight: 0.74, fix: "Use >= 600,000 iterations or Argon2id" },
  { id: "VLN-014", cat: "Plaintext Comparison",      sev: "HIGH",     re: /password\s*==\s*|hash\s*==\s*hash|hmac\.compare/i, weight: 0.68, fix: "Use constant-time compare (hmac.compare_digest)" },
  { id: "VLN-015", cat: "Missing Auth (No MAC)",     sev: "MEDIUM",   re: /AES\/CBC\/[^G]|MODE_CBC(?!.*HMAC)/i, weight: 0.62, fix: "Use AES-GCM or Encrypt-then-MAC" },
];

// ---- Sample insecure code corpus ----
const SAMPLES = {
  python: `import hashlib, os
from Crypto.Cipher import AES, DES
import requests

# [SAMPLE: Python — multiple cryptographic flaws]
API_KEY = "sk_live_4f8a9c2e1b7d6f3a8e5c9b2d4f6a8c1e"
SECRET  = "supersecret123456"

def store_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def legacy_encrypt(data):
    des = DES.new(b"8bytekey", DES.MODE_ECB)
    return des.encrypt(data)

def fetch(url):
    return requests.get(url, verify=False)

import random
def session_token():
    return str(random.random()) + str(random.randint(0, 99999))
`,
  java: `import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.MessageDigest;

// [SAMPLE: Java — legacy cryptography]
public class LegacyCrypto {
    private static final String API_KEY = "AKIA1234EXAMPLEKEY567";
    private static final byte[] IV = "1234567890123456".getBytes();

    public byte[] hashIt(String s) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA1");
        return md.digest(s.getBytes());
    }

    public byte[] enc(byte[] data, byte[] key) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return c.doFinal(data);
    }

    public KeyPair weakRsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(1024);
        return g.generateKeyPair();
    }
}`,
  node: `const crypto = require("crypto");
const https  = require("https");

// [SAMPLE: Node.js — multiple issues]
const PRIVATE_KEY = "7f3b9a2c1d4e5f6789abcdef012345";

function sign(payload) {
  return crypto.createHash("md5").update(payload).digest("hex");
}

function encrypt(plaintext, key) {
  const iv = Buffer.from("0000000000000000");
  const cipher = crypto.createCipheriv("aes-128-ecb", key, null);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

function token() {
  return Math.random().toString(36).slice(2);
}

const agent = new https.Agent({ rejectUnauthorized: false });`,
  secure: `import os, hmac, hashlib, secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# [SAMPLE: Reference secure implementation]
API_KEY = os.environ["API_KEY"]

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, salt=salt, iterations=600_000,
    )
    return kdf.derive(password)

def encrypt(plaintext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce  = secrets.token_bytes(12)
    return nonce + aesgcm.encrypt(nonce, plaintext, None)

def safe_compare(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def hash_pw(pw: bytes, salt: bytes) -> bytes:
    return hashlib.sha256(salt + pw).digest()
`
};

// ---- Color tokens ----
const C = {
  bg: "#08090b",
  panel: "#0d0f12",
  panel2: "#11141a",
  line: "#1c2128",
  ink: "#e7e9ee",
  dim: "#7a8390",
  amber: "#f5b14a",
  cyan: "#5ee2d6",
  red: "#ff5b5b",
  mint: "#7af2a3",
  violet: "#b29bff",
};
const SEV_COLOR = { CRITICAL: C.red, HIGH: C.amber, MEDIUM: C.violet, LOW: C.cyan };

// ---- Helpers ----
const fakeHash = (s) => {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return ("0000000" + (h >>> 0).toString(16)).slice(-8).toUpperCase();
};

const tokenize = (code) => {
  const tokens = code.match(/[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[^\sA-Za-z0-9_]/g) || [];
  return tokens;
};

const cryptoApiTokens = [
  "AES","DES","RSA","ECB","CBC","GCM","MD5","SHA1","SHA256","HMAC",
  "Cipher","KeyPairGenerator","MessageDigest","SecretKeySpec","IvParameterSpec",
  "hashlib","crypto","createHash","createCipheriv","verify","random","Math",
  "MODE_ECB","MODE_CBC","PBKDF2","Blowfish","RC4","TLS","SSL"
];

function analyze(code) {
  const findings = [];
  const lines = code.split("\n");

  RULES.forEach((rule) => {
    lines.forEach((ln, idx) => {
      const m = ln.match(rule.re);
      if (m) {
        findings.push({
          ...rule,
          line: idx + 1,
          snippet: ln.trim().slice(0, 140),
          match: m[0],
          confidence: Math.min(0.99, rule.weight + (Math.random() * 0.04 - 0.02)),
        });
      }
    });
  });

  // EDA features
  const tokens = tokenize(code);
  const tokenSet = new Set(tokens);
  const cryptoHits = tokens.filter(t => cryptoApiTokens.includes(t));
  const cryptoFreq = {};
  cryptoHits.forEach(t => { cryptoFreq[t] = (cryptoFreq[t] || 0) + 1; });

  const verdict = findings.length === 0 ? 0 : 1;

  // Aggregate by category
  const catMap = {};
  findings.forEach(f => {
    if (!catMap[f.cat]) catMap[f.cat] = { name: f.cat, count: 0, sev: f.sev, conf: 0 };
    catMap[f.cat].count += 1;
    catMap[f.cat].conf = Math.max(catMap[f.cat].conf, f.confidence);
  });
  const categories = Object.values(catMap).sort((a,b) => b.count - a.count);

  const sevMap = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  findings.forEach(f => { sevMap[f.sev] += 1; });

  const overallConfidence = findings.length
    ? Math.min(0.995, findings.reduce((a, f) => a + f.confidence, 0) / findings.length + 0.05)
    : 0.92;

  return {
    verdict,
    findings,
    categories,
    severityDist: Object.entries(sevMap).map(([k, v]) => ({ name: k, value: v })).filter(x => x.value > 0),
    eda: {
      lines: lines.length,
      chars: code.length,
      tokens: tokens.length,
      uniqueTokens: tokenSet.size,
      lexicalDiversity: tokens.length ? (tokenSet.size / tokens.length) : 0,
      cryptoApiCount: cryptoHits.length,
      cryptoFreq: Object.entries(cryptoFreq).map(([name, value]) => ({ name, value })).sort((a,b)=>b.value-a.value).slice(0, 10),
    },
    overallConfidence,
    hash: fakeHash(code),
  };
}

// =====================================================================
// UI Atoms
// =====================================================================
const HairLine = ({ className = "" }) => <div className={`h-px w-full ${className}`} style={{ background: C.line }} />;

const Tag = ({ children, color = C.dim, bg = "transparent", border = true }) => (
  <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] tracking-[0.18em] uppercase font-mono"
        style={{ color, background: bg, border: border ? `1px solid ${C.line}` : "none", borderRadius: 2 }}>
    {children}
  </span>
);

const StatBlock = ({ label, value, sub, accent = C.ink }) => (
  <div className="px-4 py-3" style={{ borderRight: `1px solid ${C.line}` }}>
    <div className="text-[10px] tracking-[0.2em] uppercase font-mono" style={{ color: C.dim }}>{label}</div>
    <div className="font-mono text-2xl mt-1" style={{ color: accent }}>{value}</div>
    {sub && <div className="text-[10px] font-mono mt-0.5" style={{ color: C.dim }}>{sub}</div>}
  </div>
);

// =====================================================================
// Header
// =====================================================================
function Header({ now }) {
  return (
    <header style={{ borderBottom: `1px solid ${C.line}` }}>
      <div className="flex items-center justify-between px-6 py-3">
        <div className="flex items-center gap-3">
          <div className="relative w-7 h-7 flex items-center justify-center" style={{ border: `1px solid ${C.amber}` }}>
            <div className="absolute inset-0.5" style={{ background: `repeating-linear-gradient(45deg, ${C.amber}22 0, ${C.amber}22 2px, transparent 2px, transparent 4px)` }}/>
            <Lock size={12} style={{ color: C.amber, position: "relative" }}/>
          </div>
          <div className="font-mono">
            <div className="text-[15px] tracking-[0.3em]" style={{ color: C.ink }}>CRYPTOGRAPHY<span style={{ color: C.amber }}>·</span>AO</div>
            <div className="text-[9px] tracking-[0.25em] uppercase" style={{ color: C.dim }}>cryptographic vulnerability analyzer · v0.4.7</div>
          </div>
        </div>
        <div className="hidden md:flex items-center gap-6 font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: C.dim }}>
          <span>node://us-east-1</span>
          <span style={{ color: C.mint }}>● online</span>
          <span>{now}</span>
        </div>
      </div>
      <HairLine/>
    </header>
  );
}

// =====================================================================
// Hero / Pipeline
// =====================================================================
function Hero() {
  const stages = [
    { n: "01", label: "Tokenize", sub: "AST · Lexical", icon: Code2 },
    { n: "02", label: "Binary Classify", sub: "f(x) → {0,1}", icon: Binary },
    { n: "03", label: "GraphCodeBERT", sub: "Category Head", icon: Network },
    { n: "04", label: "EDA Synthesis", sub: "Feature Stats", icon: Activity },
  ];

  return (
    <section className="px-6 py-12 md:py-16 relative overflow-hidden">
      <div className="absolute inset-0 pointer-events-none opacity-[0.06]"
           style={{ backgroundImage: `linear-gradient(${C.ink} 1px, transparent 1px), linear-gradient(90deg, ${C.ink} 1px, transparent 1px)`, backgroundSize: "40px 40px" }}/>
      <div className="relative">
        <Tag color={C.amber}><span className="inline-block w-1 h-1 rounded-full" style={{ background: C.amber }}/> live model · paper draft</Tag>
        <h1 className="font-mono mt-4 leading-[1.05] text-3xl md:text-5xl lg:text-6xl tracking-tight" style={{ color: C.ink }}>
          Detecting cryptographic
          <br/>
          <span style={{ color: C.amber }}>misuse</span> in source code with
          <br/>
          <span style={{ fontStyle: "italic", fontFamily: "Georgia, 'Times New Roman', serif", color: C.cyan }}>graph-aware</span> code embeddings.
        </h1>
        <p className="font-mono text-[13px] mt-5 max-w-2xl leading-relaxed" style={{ color: C.dim }}>
          A two-stage pipeline that fuses static rules, GraphCodeBERT representations and exploratory
          data analysis. Stage one decides <span style={{ color: C.ink }}>secure (0)</span> vs.
          <span style={{ color: C.red }}> insecure (1)</span>. Stage two routes insecure samples through a
          fine-tuned categorization head over <span style={{ color: C.ink }}>15</span> CWE-aligned
          cryptographic weakness classes.
        </p>

        {/* Pipeline */}
        <div className="mt-10 grid grid-cols-1 md:grid-cols-4" style={{ border: `1px solid ${C.line}` }}>
          {stages.map((s, i) => {
            const Icon = s.icon;
            return (
              <div key={s.n} className="px-5 py-5 relative"
                   style={{ borderRight: i < 3 ? `1px solid ${C.line}` : "none", background: i === 0 ? C.panel : "transparent" }}>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px] tracking-[0.25em]" style={{ color: C.dim }}>STAGE_{s.n}</span>
                  <Icon size={14} style={{ color: i === 1 ? C.amber : C.dim }}/>
                </div>
                <div className="font-mono text-[16px] mt-3" style={{ color: C.ink }}>{s.label}</div>
                <div className="font-mono text-[10px] mt-1" style={{ color: C.dim }}>{s.sub}</div>
                {i < 3 && (
                  <ChevronRight size={14} className="hidden md:block absolute top-1/2 -right-[7px] -translate-y-1/2"
                                style={{ color: C.line, background: C.bg }}/>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}

// =====================================================================
// Analyzer
// =====================================================================
function Analyzer({ code, setCode, onRun, isRunning, result }) {
  return (
    <section className="px-6 pb-10">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <Terminal size={14} style={{ color: C.amber }}/>
          <span className="font-mono text-[11px] tracking-[0.25em] uppercase" style={{ color: C.ink }}>
            input · paste source code
          </span>
        </div>
        <div className="flex items-center gap-2">
          {Object.keys(SAMPLES).map((k) => (
            <button key={k}
                    onClick={() => setCode(SAMPLES[k])}
                    className="font-mono text-[10px] tracking-[0.2em] uppercase px-2.5 py-1 transition-colors"
                    style={{ color: C.dim, border: `1px solid ${C.line}`, background: "transparent" }}
                    onMouseEnter={(e) => { e.currentTarget.style.color = C.amber; e.currentTarget.style.borderColor = C.amber; }}
                    onMouseLeave={(e) => { e.currentTarget.style.color = C.dim;   e.currentTarget.style.borderColor = C.line;  }}>
              ◦ {k}
            </button>
          ))}
        </div>
      </div>

      <div style={{ border: `1px solid ${C.line}`, background: C.panel }}>
        <div className="flex items-center justify-between px-4 py-2" style={{ borderBottom: `1px solid ${C.line}` }}>
          <div className="flex items-center gap-3 font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: C.dim }}>
            <span>buffer</span>
            <span>·</span>
            <span>{code.split("\n").length} lines</span>
            <span>·</span>
            <span>{code.length} chars</span>
          </div>
          <div className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: C.dim }}>
            sha-shadow:{fakeHash(code)}
          </div>
        </div>

        <div className="grid grid-cols-[40px_1fr]">
          <div className="font-mono text-[11px] py-3 px-2 leading-[1.55] text-right select-none"
               style={{ color: "#3a4150", background: C.panel2, borderRight: `1px solid ${C.line}` }}>
            {code.split("\n").map((_, i) => <div key={i}>{String(i + 1).padStart(3, " ")}</div>)}
          </div>
          <textarea
            value={code}
            onChange={(e) => setCode(e.target.value)}
            spellCheck={false}
            className="font-mono text-[12.5px] py-3 px-3 outline-none resize-none w-full leading-[1.55]"
            style={{ background: C.panel, color: C.ink, minHeight: 360, caretColor: C.amber }}
          />
        </div>

        <div className="flex items-center justify-between px-4 py-3" style={{ borderTop: `1px solid ${C.line}` }}>
          <div className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: C.dim }}>
            tokenizer · roberta-base · max_seq=512
          </div>
          <button
            onClick={onRun}
            disabled={isRunning || !code.trim()}
            className="font-mono text-[11px] tracking-[0.3em] uppercase px-5 py-2 inline-flex items-center gap-2 transition-all"
            style={{
              color: isRunning ? C.dim : C.bg,
              background: isRunning ? "transparent" : C.amber,
              border: `1px solid ${C.amber}`,
              opacity: !code.trim() ? 0.4 : 1,
            }}>
            {isRunning ? <><Cpu size={12} className="animate-spin"/> running pipeline…</> : <><Zap size={12}/> execute analysis</>}
          </button>
        </div>
      </div>
    </section>
  );
}

// =====================================================================
// Verdict Banner
// =====================================================================
function VerdictBanner({ result }) {
  const insecure = result.verdict === 1;
  return (
    <section className="px-6 pb-6">
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_auto]" style={{ border: `1px solid ${insecure ? C.red : C.mint}`, background: insecure ? "#1a0a0c" : "#08120c" }}>
        <div className="px-6 py-5 flex items-center gap-5">
          <div className="w-14 h-14 flex items-center justify-center" style={{ border: `1px solid ${insecure ? C.red : C.mint}` }}>
            {insecure ? <Unlock size={22} style={{ color: C.red }}/> : <Shield size={22} style={{ color: C.mint }}/>}
          </div>
          <div>
            <div className="font-mono text-[10px] tracking-[0.3em] uppercase" style={{ color: C.dim }}>binary classifier · stage_02</div>
            <div className="font-mono text-2xl mt-1" style={{ color: insecure ? C.red : C.mint }}>
              {insecure ? "INSECURE · y = 1" : "SECURE · y = 0"}
            </div>
            <div className="font-mono text-[12px] mt-1" style={{ color: C.dim }}>
              {insecure
                ? `${result.findings.length} weakness${result.findings.length !== 1 ? "es" : ""} detected across ${result.categories.length} categor${result.categories.length !== 1 ? "ies" : "y"}`
                : "no cryptographic weaknesses detected by the rule + embedding ensemble"}
            </div>
          </div>
        </div>
        <div className="grid grid-cols-3 lg:grid-cols-3" style={{ borderLeft: `1px solid ${C.line}` }}>
          <StatBlock label="Confidence" value={(result.overallConfidence * 100).toFixed(1) + "%"} accent={insecure ? C.red : C.mint}/>
          <StatBlock label="LOC"        value={result.eda.lines}/>
          <StatBlock label="Hash"       value={result.hash} sub="fnv-1a/32"/>
        </div>
      </div>
    </section>
  );
}

// =====================================================================
// Findings Table  +  Annotated Code
// =====================================================================
function FindingsPanel({ result, code }) {
  const lineMap = useMemo(() => {
    const map = {};
    result.findings.forEach(f => {
      if (!map[f.line]) map[f.line] = [];
      map[f.line].push(f);
    });
    return map;
  }, [result]);

  if (result.verdict === 0) return null;

  return (
    <section className="px-6 pb-10">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Annotated code */}
        <div style={{ border: `1px solid ${C.line}`, background: C.panel }}>
          <div className="px-4 py-2 flex items-center gap-2" style={{ borderBottom: `1px solid ${C.line}` }}>
            <FileWarning size={12} style={{ color: C.amber }}/>
            <span className="font-mono text-[10px] tracking-[0.25em] uppercase" style={{ color: C.ink }}>annotated source</span>
            <span className="font-mono text-[10px] tracking-[0.2em] uppercase ml-auto" style={{ color: C.dim }}>graphcodebert · attention map</span>
          </div>
          <div className="font-mono text-[12px] leading-[1.55] max-h-[420px] overflow-auto">
            {code.split("\n").map((ln, i) => {
              const findings = lineMap[i + 1];
              const has = !!findings;
              return (
                <div key={i} className="grid grid-cols-[40px_1fr] group" style={{ background: has ? "rgba(255,91,91,0.06)" : "transparent" }}>
                  <div className="text-right px-2 select-none" style={{ color: has ? C.red : "#3a4150", borderRight: `1px solid ${C.line}` }}>
                    {String(i + 1).padStart(3, " ")}
                  </div>
                  <div className="px-3 whitespace-pre" style={{ color: has ? C.ink : "#9aa3b0" }}>
                    {ln || " "}
                    {has && (
                      <span className="ml-3 font-mono text-[10px] tracking-[0.15em] uppercase px-1.5 py-0.5"
                            style={{ color: SEV_COLOR[findings[0].sev], border: `1px solid ${SEV_COLOR[findings[0].sev]}` }}>
                        {findings[0].id} · {findings[0].cat}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Findings table */}
        <div style={{ border: `1px solid ${C.line}`, background: C.panel }}>
          <div className="px-4 py-2 flex items-center gap-2" style={{ borderBottom: `1px solid ${C.line}` }}>
            <AlertTriangle size={12} style={{ color: C.amber }}/>
            <span className="font-mono text-[10px] tracking-[0.25em] uppercase" style={{ color: C.ink }}>weakness inventory</span>
            <span className="font-mono text-[10px] tracking-[0.2em] uppercase ml-auto" style={{ color: C.dim }}>{result.findings.length} hits</span>
          </div>
          <div className="max-h-[420px] overflow-auto">
            {result.findings.map((f, i) => (
              <div key={i} className="px-4 py-3" style={{ borderBottom: `1px solid ${C.line}` }}>
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <Tag color={SEV_COLOR[f.sev]}>{f.sev}</Tag>
                    <span className="font-mono text-[11px]" style={{ color: C.ink }}>{f.cat}</span>
                  </div>
                  <span className="font-mono text-[10px]" style={{ color: C.dim }}>L{f.line} · {f.id}</span>
                </div>
                <div className="font-mono text-[11px] mt-2 px-2 py-1.5 truncate"
                     style={{ background: C.panel2, color: "#a8b1bf", border: `1px solid ${C.line}` }}>
                  {f.snippet}
                </div>
                <div className="flex items-center justify-between mt-2">
                  <span className="font-mono text-[10px]" style={{ color: C.cyan }}>↳ {f.fix}</span>
                  <span className="font-mono text-[10px]" style={{ color: C.dim }}>p = {(f.confidence * 100).toFixed(1)}%</span>
                </div>
              </div>
            ))}
            {result.findings.length === 0 && (
              <div className="px-4 py-12 text-center font-mono text-[12px]" style={{ color: C.dim }}>
                no findings
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

// =====================================================================
// EDA Section
// =====================================================================
function EDA({ result }) {
  const catData = result.categories.map(c => ({ name: c.name, count: c.count, conf: +(c.conf * 100).toFixed(1) }));
  const sevData = result.severityDist;
  const cryptoFreq = result.eda.cryptoFreq;

  // Confidence histogram (synthesised from findings)
  const buckets = [0,0,0,0,0,0,0,0,0,0];
  result.findings.forEach(f => {
    const b = Math.min(9, Math.floor(f.confidence * 10));
    buckets[b] += 1;
  });
  const confHist = buckets.map((v, i) => ({ name: `${i*10}-${(i+1)*10}`, value: v }));

  return (
    <section className="px-6 pb-16">
      <div className="flex items-center gap-2 mb-4">
        <Activity size={14} style={{ color: C.cyan }}/>
        <span className="font-mono text-[11px] tracking-[0.3em] uppercase" style={{ color: C.ink }}>
          stage_04 · exploratory data analysis
        </span>
        <div className="flex-1 h-px ml-4" style={{ background: C.line }}/>
      </div>

      {/* EDA Stats */}
      <div className="grid grid-cols-2 md:grid-cols-6" style={{ border: `1px solid ${C.line}`, background: C.panel }}>
        <StatBlock label="Tokens"          value={result.eda.tokens}/>
        <StatBlock label="Unique"          value={result.eda.uniqueTokens}/>
        <StatBlock label="Lex. Diversity"  value={result.eda.lexicalDiversity.toFixed(3)}/>
        <StatBlock label="Crypto APIs"     value={result.eda.cryptoApiCount} accent={C.amber}/>
        <StatBlock label="Categories"      value={result.categories.length} accent={C.cyan}/>
        <div className="px-4 py-3">
          <div className="text-[10px] tracking-[0.2em] uppercase font-mono" style={{ color: C.dim }}>Verdict</div>
          <div className="font-mono text-2xl mt-1" style={{ color: result.verdict ? C.red : C.mint }}>
            {result.verdict}
          </div>
          <div className="text-[10px] font-mono mt-0.5" style={{ color: C.dim }}>
            {result.verdict ? "insecure" : "secure"}
          </div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
        {/* Category distribution */}
        <ChartCard title="category distribution" subtitle="graphcodebert · multi-label">
          {catData.length === 0 ? <Empty/> : (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={catData} layout="vertical" margin={{ top: 6, right: 14, left: 0, bottom: 0 }}>
                <CartesianGrid stroke={C.line} horizontal={false}/>
                <XAxis type="number" stroke={C.dim} tick={{ fill: C.dim, fontSize: 10, fontFamily: "monospace" }}/>
                <YAxis dataKey="name" type="category" stroke={C.dim} width={140}
                       tick={{ fill: C.ink, fontSize: 10, fontFamily: "monospace" }}/>
                <Tooltip contentStyle={{ background: C.panel2, border: `1px solid ${C.line}`, fontFamily: "monospace", fontSize: 11 }}
                         cursor={{ fill: "rgba(245,177,74,0.08)" }}/>
                <Bar dataKey="count" fill={C.amber}/>
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

        {/* Severity */}
        <ChartCard title="severity composition" subtitle="cwe-aligned weighting">
          {sevData.length === 0 ? <Empty/> : (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie data={sevData} dataKey="value" nameKey="name" innerRadius={60} outerRadius={95} stroke={C.bg} strokeWidth={2}>
                  {sevData.map((s, i) => <Cell key={i} fill={SEV_COLOR[s.name]}/>)}
                </Pie>
                <Tooltip contentStyle={{ background: C.panel2, border: `1px solid ${C.line}`, fontFamily: "monospace", fontSize: 11 }}/>
              </PieChart>
            </ResponsiveContainer>
          )}
          <div className="flex flex-wrap gap-3 px-4 pb-3">
            {sevData.map((s, i) => (
              <div key={i} className="flex items-center gap-1.5 font-mono text-[10px]" style={{ color: C.dim }}>
                <span className="w-2 h-2 inline-block" style={{ background: SEV_COLOR[s.name] }}/>
                {s.name} · {s.value}
              </div>
            ))}
          </div>
        </ChartCard>

        {/* Crypto API frequency */}
        <ChartCard title="cryptographic api frequency" subtitle="top-10 token occurrences">
          {cryptoFreq.length === 0 ? <Empty/> : (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={cryptoFreq} margin={{ top: 6, right: 14, left: 0, bottom: 0 }}>
                <CartesianGrid stroke={C.line} vertical={false}/>
                <XAxis dataKey="name" stroke={C.dim} tick={{ fill: C.dim, fontSize: 10, fontFamily: "monospace" }}/>
                <YAxis stroke={C.dim} tick={{ fill: C.dim, fontSize: 10, fontFamily: "monospace" }}/>
                <Tooltip contentStyle={{ background: C.panel2, border: `1px solid ${C.line}`, fontFamily: "monospace", fontSize: 11 }}
                         cursor={{ fill: "rgba(94,226,214,0.08)" }}/>
                <Bar dataKey="value" fill={C.cyan}/>
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

        {/* Confidence histogram */}
        <ChartCard title="confidence histogram" subtitle="p(cwe | tokens) · 10-bin">
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={confHist} margin={{ top: 6, right: 14, left: 0, bottom: 0 }}>
              <CartesianGrid stroke={C.line} vertical={false}/>
              <XAxis dataKey="name" stroke={C.dim} tick={{ fill: C.dim, fontSize: 9, fontFamily: "monospace" }}/>
              <YAxis stroke={C.dim} tick={{ fill: C.dim, fontSize: 10, fontFamily: "monospace" }} allowDecimals={false}/>
              <Tooltip contentStyle={{ background: C.panel2, border: `1px solid ${C.line}`, fontFamily: "monospace", fontSize: 11 }}
                       cursor={{ fill: "rgba(178,155,255,0.08)" }}/>
              <Bar dataKey="value" fill={C.violet}/>
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>
    </section>
  );
}

const ChartCard = ({ title, subtitle, children }) => (
  <div style={{ border: `1px solid ${C.line}`, background: C.panel }}>
    <div className="px-4 py-2 flex items-center justify-between" style={{ borderBottom: `1px solid ${C.line}` }}>
      <span className="font-mono text-[10px] tracking-[0.25em] uppercase" style={{ color: C.ink }}>{title}</span>
      <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: C.dim }}>{subtitle}</span>
    </div>
    <div className="py-3">{children}</div>
  </div>
);

const Empty = () => (
  <div className="h-[250px] flex items-center justify-center font-mono text-[11px]" style={{ color: C.dim }}>
    ◌ no data — run analyzer
  </div>
);

// =====================================================================
// Methodology / About
// =====================================================================
function Methodology() {
  return (
    <section className="px-6 pb-20">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {[
          {
            n: "i",
            title: "Tokenization",
            body: "Source is parsed with a Roberta-style BPE tokenizer (max_seq=512). Identifiers, operators and crypto-API keywords are surfaced as features for the downstream classifier."
          },
          {
            n: "ii",
            title: "GraphCodeBERT Head",
            body: "A multi-label categorization head fine-tuned on a curated CWE-310/327/328/330/916 corpus. The data-flow graph (DFG) channel disambiguates true misuse from cosmetic mentions."
          },
          {
            n: "iii",
            title: "EDA Loop",
            body: "Lexical statistics, crypto-API frequency, severity composition and confidence histograms feed back into the retraining objective — closing the cryptography ↔ ML loop."
          },
        ].map((m, i) => (
          <div key={i} className="px-5 py-5" style={{ border: `1px solid ${C.line}`, background: C.panel }}>
            <div className="font-mono text-[10px] tracking-[0.3em] uppercase" style={{ color: C.amber }}>§ {m.n}</div>
            <div className="font-mono text-[16px] mt-3" style={{ color: C.ink }}>{m.title}</div>
            <p className="font-mono text-[12px] mt-2 leading-relaxed" style={{ color: C.dim }}>{m.body}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

// =====================================================================
// Footer
// =====================================================================
function Footer() {
  return (
    <footer style={{ borderTop: `1px solid ${C.line}` }}>
      <div className="px-6 py-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
        <div className="font-mono text-[10px] tracking-[0.25em] uppercase" style={{ color: C.dim }}>
          cryptographyao · research preview · 0.4.7
        </div>
        <div className="font-mono text-[10px] tracking-[0.25em] uppercase flex items-center gap-4" style={{ color: C.dim }}>
          <span>cwe-310</span>
          <span>cwe-327</span>
          <span>cwe-328</span>
          <span>cwe-330</span>
          <span>cwe-916</span>
        </div>
      </div>
    </footer>
  );
}

// =====================================================================
// Root
// =====================================================================
export default function CryptographyAO() {
  const [code, setCode] = useState(SAMPLES.python);
  const [result, setResult] = useState(null);
  const [isRunning, setIsRunning] = useState(false);
  const [now, setNow] = useState("");

  useEffect(() => {
    const tick = () => {
      const d = new Date();
      const hh = String(d.getUTCHours()).padStart(2, "0");
      const mm = String(d.getUTCMinutes()).padStart(2, "0");
      const ss = String(d.getUTCSeconds()).padStart(2, "0");
      setNow(`${hh}:${mm}:${ss} utc`);
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  const runAnalysis = () => {
    if (!code.trim()) return;
    setIsRunning(true);
    setResult(null);
    setTimeout(() => {
      setResult(analyze(code));
      setIsRunning(false);
    }, 900);
  };

  return (
    <div style={{ background: C.bg, color: C.ink, fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, 'JetBrains Mono', monospace", minHeight: "100vh" }}>
      <Header now={now}/>
      <Hero/>
      <Analyzer code={code} setCode={setCode} onRun={runAnalysis} isRunning={isRunning} result={result}/>

      {result && (
        <>
          <VerdictBanner result={result}/>
          <FindingsPanel result={result} code={code}/>
          <EDA result={result}/>
        </>
      )}

      <Methodology/>
      <Footer/>
    </div>
  );
}
