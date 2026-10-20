// n8n Code node: "Validate Input"
// Mode: Run Once for All Items, Language: JavaScript
// Input: Webhook item with body = { "ip": "x.x.x.x" }
// Output: { ip, valid, reason }

// 1. Take the value from the request body and trim spaces
const raw = $input.first().json.body?.ip;
const ip = typeof raw === 'string' ? raw.trim() : '';

// 2. IPv4 format: 4 numbers from 0 to 255 separated by dots
const parts = ip.split('.');
const isIPv4 = parts.length === 4 && parts.every(p =>
  /^\d{1,3}$/.test(p) &&          // 1-3 digits only
  Number(p) <= 255 &&             // not more than 255
  String(Number(p)) === p         // no leading zeros ("01")
);

// 3. Private and reserved ranges: no reputation data there,
//    and internal addresses must not be sent to third-party services
function isPrivateOrReserved(ip) {
  const [a, b] = ip.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||   // CGNAT
    (a === 169 && b === 254) ||             // link-local
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a >= 224;                                // multicast and reserved
}

// 4. Decision with a human-readable reason
let valid = true;
let reason = 'ok';
if (!ip) {
  valid = false; reason = 'поле ip порожнє або відсутнє';
} else if (!isIPv4) {
  valid = false; reason = 'не є коректною IPv4-адресою';
} else if (isPrivateOrReserved(ip)) {
  valid = false; reason = 'приватна або службова адреса, перевірка не потрібна';
}

return [{ json: { ip: ip || String(raw), valid, reason } }];
