// n8n Code node: "Risk Scoring"
// Mode: Run Once for All Items, Language: JavaScript
// Both HTTP Request nodes use: Never Error + Include Response Headers and Status,
// so their output is { body, headers, statusCode, statusMessage }.

// 1. Inputs: validated IP and full responses of both APIs
const ip = $('Validate Input').first().json.ip;
const vtRes = $('VirusTotal').first().json;
const abRes = $('AbuseIPDB').first().json;

// 2. Translate HTTP status code into a readable message
function describeError(service, code) {
  if (code === 200) return null;
  if (code === 401 || code === 403) return `${service}: помилка автентифікації (${code}), перевірте ключ у Credentials`;
  if (code === 429) return `${service}: вичерпано ліміт запитів (429)`;
  if (code === 400 || code === 422) return `${service}: некоректний запит (${code}), перевірте формат IP`;
  if (code === 404) return `${service}: дані не знайдено (404)`;
  return `${service}: неочікувана відповідь (${code})`;
}

const errors = [
  describeError('VirusTotal', vtRes.statusCode),
  describeError('AbuseIPDB', abRes.statusCode)
].filter(Boolean);

const vtOk = vtRes.statusCode === 200;
const abOk = abRes.statusCode === 200;

// 3. Use data only from sources that answered successfully
const vtStats = vtOk ? vtRes.body.data.attributes.last_analysis_stats : {};
const abuse = abOk ? abRes.body.data : {};

const abuseScore = abuse.abuseConfidenceScore ?? 0;
const vtMalicious = vtStats.malicious ?? 0;
const vtSuspicious = vtStats.suspicious ?? 0;

// 4. Thresholds: tune here
const ABUSE_HIGH = 50;
const VT_HIGH = 3;
const ABUSE_MEDIUM = 20;

// 5. Verdict
let verdict = 'LOW';
if (abuseScore >= ABUSE_HIGH || vtMalicious >= VT_HIGH) {
  verdict = 'HIGH';
} else if (abuseScore >= ABUSE_MEDIUM || vtMalicious >= 1 || vtSuspicious >= 1) {
  verdict = 'MEDIUM';
}

// 6. Missing data is not "no threat"
if (!vtOk && !abOk) {
  verdict = 'UNKNOWN';
} else if (errors.length > 0 && verdict === 'LOW') {
  verdict = 'LOW (неповні дані)';
}

return [{
  json: {
    ip,
    verdict,
    abuse_score: abOk ? `${abuseScore}%` : 'n/a',
    vt_malicious: vtOk ? vtMalicious : 'n/a',
    vt_suspicious: vtOk ? vtSuspicious : 'n/a',
    isp: abuse.isp ?? 'n/a',
    country: abuse.countryCode ?? 'n/a',
    is_tor: abuse.isTor ?? 'n/a',
    is_whitelisted: abuse.isWhitelisted ?? 'n/a',
    errors: errors.length > 0 ? errors.join('; ') : 'none'
  }
}];
