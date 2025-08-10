// app.js (ESM 모듈)
// Ajv 2020-12 빌드 (draft-07을 쓰면 아래 임포트를 https://esm.sh/ajv@8 로 변경 가능)
import Ajv from 'https://esm.sh/ajv@8/dist/2020';
import * as asn1js from 'https://esm.sh/asn1js@3';
import { PKCS8ShroudedKeyBag, Certificate } from 'https://esm.sh/pkijs@3';

const $ = (sel) => document.querySelector(sel);
const enc = new TextEncoder();

const els = {
  payload: $('#payload'),
  password: $('#password'),
  btnValidate: $('#btnValidate'),
  btnSign: $('#btnSign'),
  status: $('#status'),
  output: $('#output'),
  certFp: $('#certFp'),
  spkiFp: $('#spkiFp'),
};

let ajv, validateFn;

/* ======================= 유틸 ======================= */
function setStatus(msg, cls='muted') { els.status.className = cls; els.status.textContent = msg; }
function showError(e) { setStatus(e?.message || String(e), 'err'); console.error(e); }
function showOk(msg) { setStatus(msg, 'ok'); }

function parseJSON(text) {
  try { return JSON.parse(text); } catch (e) { throw new Error('Payload JSON 파싱 오류: ' + e.message); }
}

function pemToDer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function derToBase64(der) {
  const bytes = new Uint8Array(der);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin); // x5c에는 표준 base64 사용
}

function b64urlFromString(str) {
  const bytes = enc.encode(str);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/,'');
}

function b64urlFromBytes(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/,'');
}

async function fetchText(path) {
  const res = await fetch(path, { cache: 'no-store' });
  if (!res.ok) throw new Error(`${path} 로드 실패: ${res.status}`);
  return res.text();
}

async function fetchArrayBuffer(path) {
  const res = await fetch(path, { cache: 'no-store' });
  if (!res.ok) throw new Error(`${path} 로드 실패: ${res.status}`);
  return res.arrayBuffer();
}

/* =================== Ajv 오류 리포트 =================== */
/** JSON Pointer("/a/0/b") → 경로 "a[0].b" */
function pointerToPath(ptr) {
  if (!ptr) return '(root)';
  const segs = ptr.split('/').slice(1).map(s => s.replace(/~1/g,'/').replace(/~0/g,'~'));
  return segs.map(s => (/^\d+$/.test(s) ? `[${s}]` : (s.includes('.') ? `["${s}"]` : `.${s}`)))
             .join('').replace(/^\./,'') || '(root)';
}
/** Pointer 경로의 값을 안전하게 조회 */
function getAt(obj, ptr) {
  try {
    return ptr.split('/').slice(1)
      .map(s => s.replace(/~1/g,'/').replace(/~0/g,'~'))
      .reduce((acc, k) => (acc == null ? undefined : acc[k]), obj);
  } catch { return undefined; }
}
function preview(val, max=140) {
  try {
    const s = typeof val === 'string' ? val : JSON.stringify(val);
    return s && s.length > max ? s.slice(0, max-3) + '...' : s;
  } catch { return String(val); }
}
function explainAjvError(e, payload) {
  const path = pointerToPath(e.instancePath || e.dataPath || '');
  const atVal = getAt(payload, e.instancePath || e.dataPath || '');
  const p = e.params || {};
  let hint;
  switch (e.keyword) {
    case 'required':
      hint = `필수 필드 누락 → '${p.missingProperty}'가 필요합니다.`; break;
    case 'additionalProperties':
      hint = `정의되지 않은 필드 → '${p.additionalProperty}'는 허용되지 않습니다.`; break;
    case 'type': {
      const expected = Array.isArray(p.type) ? p.type.join(' | ') : p.type;
      const actual = Array.isArray(atVal) ? 'array' : typeof atVal;
      hint = `타입 불일치 → 기대: ${expected}, 실제: ${actual}.`; break;
    }
    case 'enum':
      hint = `허용 값 아님 → 허용: ${JSON.stringify(e.schema ?? p.allowedValues)}.`; break;
    case 'const':
      hint = `상수와 불일치 → 기대: ${JSON.stringify(e.schema)}.`; break;
    case 'minimum':
    case 'exclusiveMinimum':
      hint = `값이 너무 작음 → 최소 ${p.limit}${e.keyword==='exclusiveMinimum'?' 초과 필요':''}.`; break;
    case 'maximum':
    case 'exclusiveMaximum':
      hint = `값이 너무 큼 → 최대 ${p.limit}${e.keyword==='exclusiveMaximum'?' 미만 필요':''}.`; break;
    case 'minLength': hint = `문자열 길이 부족 → 최소 ${p.limit}.`; break;
    case 'maxLength': hint = `문자열 길이 초과 → 최대 ${p.limit}.`; break;
    case 'pattern':  hint = `형식 불일치 → 정규식(${e.schema})와 일치하지 않습니다.`; break;
    case 'format':   hint = `형식 불일치 → 기대 포맷 '${e.schema}'.`; break;
    case 'minItems': hint = `배열 길이 부족 → 최소 ${p.limit}개.`; break;
    case 'maxItems': hint = `배열 길이 초과 → 최대 ${p.limit}개.`; break;
    case 'uniqueItems':
      hint = `배열 항목 중복 → 인덱스 ${p.i}와 ${p.j}가 동일합니다.`; break;
    case 'dependentRequired': {
      const deps = Array.isArray(p.deps) ? p.deps.join(', ') : String(p.deps || '');
      hint = `'${p.property}'가 있으면 ${deps}도 필요합니다.`; break;
    }
    case 'anyOf': hint = `anyOf 조건 중 하나를 만족해야 합니다.`; break;
    case 'oneOf': hint = `oneOf 조건 중 정확히 하나만 만족해야 합니다.`; break;
    case 'allOf': hint = `allOf 조건을 모두 만족해야 합니다.`; break;
    case 'if':    hint = `조건문(if)과 then/else 요구사항을 확인하세요.`; break;
    default:      hint = e.message || '검증 실패';
  }
  return { path, valuePreview: preview(atVal), message: hint };
}
function renderValidationReport(payload, errors) {
  const items = errors.map(e => explainAjvError(e, payload));
  // 경로 기준으로 묶어서 보기 좋게 출력
  const grouped = items.reduce((m, it) => {
    (m[it.path] ||= []).push(it);
    return m;
  }, {});
  let out = '';
  for (const [path, arr] of Object.entries(grouped)) {
    const value = arr[0].valuePreview;
    out += `• 경로: ${path}\n  값: ${value}\n`;
    for (const it of arr) out += `  - ${it.message}\n`;
    out += '\n';
  }
  return out.trim();
}

/* ============= 스키마 로드 & 컴파일 ============= */
async function initSchema() {
  const schema = await (await fetch('schema.json', { cache: 'no-store' })).json();
  ajv = new Ajv({ allErrors: true, strict: 'log' });
  validateFn = ajv.compile(schema);
}

/* ========= 인증서 로드 & 지문 계산 ========= */
async function loadCertificateDER() {
  const pem = await fetchText('cert.pem');
  return pemToDer(pem);
}
async function digestHex(algo, data) {
  const d = await crypto.subtle.digest(algo, data);
  const v = new Uint8Array(d);
  return Array.from(v).map(b => b.toString(16).padStart(2, '0')).join(':');
}
async function updateCertInfo() {
  try {
    const certDer = await loadCertificateDER();
    els.certFp.textContent = await digestHex('SHA-256', certDer);
    const asn1 = asn1js.fromBER(certDer);
    const cert = new Certificate({ schema: asn1.result });
    const spkiDer = cert.subjectPublicKeyInfo.toSchema().toBER(false);
    els.spkiFp.textContent = await digestHex('SHA-256', spkiDer);
  } catch (e) { showError(e); }
}

/* ======= 개인키 복호화 & 임포트 (PKCS#8) ======= */
async function importPrivateKeyFromEncryptedPkcs8(password) {
  const pem = await fetchText('key_encrypted.pem');
  const der = pemToDer(pem);
  const bag = PKCS8ShroudedKeyBag.fromBER(der);
  await bag.parseInternalValues({ password: enc.encode(password).buffer });
  const pkcs8Der = bag.parsedValue.toSchema().toBER(false);
  return crypto.subtle.importKey(
    'pkcs8',
    pkcs8Der,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

/* ================== JWT 서명 ================== */
async function signJWT(payloadObj, password) {
  if (!validateFn(payloadObj)) {
    const report = renderValidationReport(payloadObj, validateFn.errors || []);
    els.output.textContent = report;
    throw new Error('스키마 검증 실패');
  }

  const certDer = await loadCertificateDER();
  const header = { alg: 'RS256', typ: 'JWT', x5c: [ derToBase64(certDer) ] };
  const headerB64 = b64urlFromString(JSON.stringify(header));
  const payloadB64 = b64urlFromString(JSON.stringify(payloadObj));
  const signingInput = `${headerB64}.${payloadB64}`;

  const key = await importPrivateKeyFromEncryptedPkcs8(password);
  const sig = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    key,
    enc.encode(signingInput)
  );
  const signatureB64 = b64urlFromBytes(sig);
  return { token: `${signingInput}.${signatureB64}`, header, payload: payloadObj };
}

/* ================== 다운로드 ================== */
function downloadJSON(filename, obj) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

/* ================== UI 이벤트 ================== */
els.btnValidate.addEventListener('click', async () => {
  try {
    const payload = parseJSON(els.payload.value);
    if (!validateFn) await initSchema();
    if (!validateFn(payload)) {
      const report = renderValidationReport(payload, validateFn.errors || []);
      els.output.textContent = report;
      showError(new Error('스키마 검증 실패'));
    } else {
      els.output.textContent = '스키마 검증 성공';
      showOk('스키마 검증 성공');
    }
  } catch (e) { showError(e); }
});

els.btnSign.addEventListener('click', async () => {
  try {
    const password = els.password.value;
    if (!password) throw new Error('개인키 비밀번호를 입력하세요.');
    const payload = parseJSON(els.payload.value);
    if (!validateFn) await initSchema();
    setStatus('서명 중… 잠시만 기다려주세요 (반복 600,000회 키 유도).');

    const result = await signJWT(payload, password);

    els.output.textContent = result.token; // 화면에도 토큰 표시
    downloadJSON('signed_jwt.json', result);
    showOk('서명 완료! signed_jwt.json을 다운로드했습니다.');
  } catch (e) { showError(e); }
});

/* ================== 초기화 ================== */
initSchema().catch(showError);
updateCertInfo().catch(showError);
