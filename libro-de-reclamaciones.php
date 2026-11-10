<?php
/**
 * Libro de Reclamaciones Virtual - Perfil360 Solutions
 * Conforme a la Ley N° 29571 (Código de Protección y Defensa del Consumidor)
 * y el D.S. N° 011-2011-PCM (modificado por D.S. 101-2021-PCM).
 *
 * Layers: real client IP (Cloudflare-aware), per-IP and site-wide rate limits (flock),
 * honeypot + signed time trap, hCaptcha, CSRF + Origin check, strict validation and
 * spam heuristics, duplicate guard, HTML-only mail (internal first, then consumer copy),
 * security log. Every constant below can be overridden from config.smtp.php.
 */

// Never leak PHP errors to visitors; details go to the server error log / security.log only.
@ini_set('display_errors', '0');
@ini_set('display_startup_errors', '0');
@ini_set('log_errors', '1');
error_reporting(E_ALL);
date_default_timezone_set('America/Lima');

// ── Configuration ─────────────────────────────────────────────────────────────
if (!defined('DOMINIO_PERMITIDO')) define('DOMINIO_PERMITIDO', 'tuperfil360.com');

// Real values live in config.smtp.php (server only, not in git).
$smtpConfigFile = __DIR__ . '/config.smtp.php';
if (file_exists($smtpConfigFile)) {
    require $smtpConfigFile;
}

if (!defined('EMPRESA_NOMBRE_COMERCIAL')) define('EMPRESA_NOMBRE_COMERCIAL', 'Perfil360 Solutions');
if (!defined('EMPRESA_RAZON_SOCIAL')) define('EMPRESA_RAZON_SOCIAL', 'PERFIL360 SOLUTIONS S.A.C.');
if (!defined('EMPRESA_RUC'))          define('EMPRESA_RUC', 'PENDIENTE_RUC');            // TODO: set the real RUC
if (!defined('EMPRESA_DIRECCION'))    define('EMPRESA_DIRECCION', 'PENDIENTE_DIRECCION'); // TODO: set the real fiscal address
if (!defined('EMPRESA_EMAIL'))        define('EMPRESA_EMAIL', 'reclamaciones@tuperfil360.com');
if (!defined('EMPRESA_NOTIF_EMAIL'))  define('EMPRESA_NOTIF_EMAIL', EMPRESA_EMAIL);
if (!defined('SMTP_PORT'))            define('SMTP_PORT', 465);
if (!defined('SMTP_FROM_NAME'))       define('SMTP_FROM_NAME', 'Perfil360 Solutions');
if (!defined('SMTP_VERIFY_TLS'))      define('SMTP_VERIFY_TLS', true);   // set false only if the mail cert does not match SMTP_HOST
if (!defined('IP_HASH_SALT'))         define('IP_HASH_SALT', '');        // empty = per-install random salt file
if (!defined('RATE_LIMIT_IP_INTERVAL')) define('RATE_LIMIT_IP_INTERVAL', 1800);  // 1 submission / 30 min per IP
if (!defined('RATE_LIMIT_IP_DAILY'))    define('RATE_LIMIT_IP_DAILY', 5);        // 5 submissions / 24 h per IP
if (!defined('RATE_LIMIT_SITE_HOURLY')) define('RATE_LIMIT_SITE_HOURLY', 20);    // site-wide / hour
if (!defined('RATE_LIMIT_SITE_DAILY'))  define('RATE_LIMIT_SITE_DAILY', 80);     // site-wide / day
if (!defined('HCAPTCHA_SITE_KEY'))    define('HCAPTCHA_SITE_KEY', '');
if (!defined('HCAPTCHA_SECRET_KEY'))  define('HCAPTCHA_SECRET_KEY', '');

define('RC_DIR', __DIR__ . '/reclamaciones');
define('RC_MAX_BODY', 65536);        // reject larger POST bodies
define('RC_MIN_FILL_SECONDS', 5);    // time trap: faster than this is a bot
define('RC_MAX_FORM_AGE', 7200);     // time trap: form older than 2 h must be reloaded
define('RC_DUP_WINDOW', 86400);      // identical detalle+email within 24 h is a duplicate
define('RC_MAIL_BG', '#050F2C');
define('RC_MAIL_ACCENT', '#FF5500');

// ── Client IP (Cloudflare-aware) ──────────────────────────────────────────────
function rcCloudflareRanges(): array {
    return [
        // IPv4
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
        '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
        '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        // IPv6
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
        '2a06:98c0::/29', '2c0f:f248::/32',
    ];
}
function rcNormalizeIp(string $ip): string {
    $ip = trim($ip);
    if (stripos($ip, '::ffff:') === 0 && filter_var(substr($ip, 7), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $ip = substr($ip, 7);
    }
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
}
function rcIpInCidr(string $ip, string $cidr): bool {
    $bin = @inet_pton($ip);
    $parts = explode('/', $cidr);
    $net = @inet_pton($parts[0]);
    if ($bin === false || $net === false || strlen($bin) !== strlen($net)) return false;
    $bits  = (int)$parts[1];
    $bytes = intdiv($bits, 8);
    $rem   = $bits % 8;
    if ($bytes > 0 && substr($bin, 0, $bytes) !== substr($net, 0, $bytes)) return false;
    if ($rem === 0) return true;
    $mask = (0xFF << (8 - $rem)) & 0xFF;
    return (ord($bin[$bytes]) & $mask) === (ord($net[$bytes]) & $mask);
}
function rcIsCloudflareIp(string $ip): bool {
    if ($ip === '') return false;
    foreach (rcCloudflareRanges() as $cidr) {
        if (rcIpInCidr($ip, $cidr)) return true;
    }
    return false;
}
// REMOTE_ADDR only; CF-Connecting-IP is honoured solely when REMOTE_ADDR is a Cloudflare edge.
// X-Forwarded-For is client-controlled and is never trusted.
function rcClientIp(): string {
    static $ip = null;
    if ($ip !== null) return $ip;
    $remote = rcNormalizeIp((string)($_SERVER['REMOTE_ADDR'] ?? ''));
    if ($remote === '') return $ip = '0.0.0.0';
    $ip = $remote;
    if (rcIsCloudflareIp($remote) && !empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $cf = rcNormalizeIp((string)$_SERVER['HTTP_CF_CONNECTING_IP']);
        if ($cf !== '') $ip = $cf;
    }
    return $ip;
}
function rcIsHttps(): bool {
    if (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') return true;
    if ((int)($_SERVER['SERVER_PORT'] ?? 0) === 443) return true;
    $remote = rcNormalizeIp((string)($_SERVER['REMOTE_ADDR'] ?? ''));
    return rcIsCloudflareIp($remote) && stripos((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''), 'https') === 0;
}
function rcSalt(): string {
    static $salt = null;
    if ($salt !== null) return $salt;
    if (IP_HASH_SALT !== '') return $salt = (string)IP_HASH_SALT;
    $file = RC_DIR . '/.ip_salt';
    if (!file_exists($file) && is_dir(RC_DIR)) {
        $fp = @fopen($file, 'x');
        if ($fp) { fwrite($fp, bin2hex(random_bytes(32))); fclose($fp); @chmod($file, 0640); }
    }
    $val = file_exists($file) ? trim((string)@file_get_contents($file)) : '';
    // Last resort (directory unusable): stable per-install value, still not the raw IP.
    return $salt = ($val !== '' ? $val : hash('sha256', __FILE__ . php_uname('n')));
}
function rcIpHash(string $ip): string {
    $bin = @inet_pton($ip);
    if ($bin !== false && strlen($bin) === 16) {          // IPv6: hash the /64 so rotating the host part does not dodge limits
        $ip = bin2hex(substr($bin, 0, 8));
    }
    return hash('sha256', rcSalt() . '|' . $ip);
}
function rcUserAgent(): string {
    $ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
    return mb_substr(preg_replace('/[\x00-\x1F\x7F]+/', ' ', $ua), 0, 120, 'UTF-8');
}

// ── Session + response headers ────────────────────────────────────────────────
if (session_status() === PHP_SESSION_NONE) {
    @ini_set('session.use_strict_mode', '1');
    @ini_set('session.use_only_cookies', '1');
    session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => rcIsHttps(), 'httponly' => true, 'samesite' => 'Lax']);
    session_start();
}
if (!headers_sent()) {
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header("Content-Security-Policy: frame-ancestors 'none'");
    header('Referrer-Policy: same-origin');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
}

// ── Logging (never passwords, secrets or message bodies) ──────────────────────
function rcLog(string $event, array $ctx = []): void {
    $line = ['t' => date('c'), 'event' => $event, 'ip' => substr(rcIpHash(rcClientIp()), 0, 16), 'ua' => rcUserAgent()];
    foreach (['codigo', 'reason', 'wait', 'detail'] as $k) {
        if (isset($ctx[$k])) $line[$k] = mb_substr(preg_replace('/[\x00-\x1F\x7F]+/', ' ', (string)$ctx[$k]), 0, 200, 'UTF-8');
    }
    $file = RC_DIR . '/security.log';
    if (@filesize($file) > 2097152) @rename($file, $file . '.1');
    @file_put_contents($file, json_encode($line, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL, FILE_APPEND | LOCK_EX);
}

// ── Protected records directory ───────────────────────────────────────────────
function rcPrepareDir(string $dir): bool {
    if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) return false;
    @chmod($dir, 0750);
    $ht = $dir . '/.htaccess';
    $cur = file_exists($ht) ? (string)@file_get_contents($ht) : '';
    if (strpos($cur, 'Require all denied') === false) {
        @file_put_contents($ht, "# Deny all web access (Apache 2.4 and legacy).\nOptions -Indexes\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order allow,deny\n    Deny from all\n</IfModule>\n");
        @chmod($ht, 0640);
    }
    if (!file_exists($dir . '/index.html')) {
        @file_put_contents($dir . '/index.html', '');
        @chmod($dir . '/index.html', 0640);
    }
    return is_dir($dir) && is_writable($dir);
}

// ── Output / text helpers ─────────────────────────────────────────────────────
function esc(?string $s): string {
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function sanitizarCabecera(string $s): string {
    $s = str_ireplace(['%0d', '%0a'], ' ', $s);
    return trim(preg_replace('/[\x00-\x1F\x7F\s]+/u', ' ', $s));
}
function rcCleanText(string $s, bool $multiline): string {
    $s = str_replace(["\r\n", "\r"], "\n", $s);
    $s = preg_replace($multiline ? '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/' : '/[\x00-\x1F\x7F]/', $multiline ? '' : ' ', $s);
    $s = preg_replace('/[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{FEFF}]/u', '', $s);
    $s = $multiline ? preg_replace("/\n{3,}/", "\n\n", $s) : preg_replace('/\s+/u', ' ', $s);
    return trim((string)$s);
}
function rcField(string $key, bool $multiline = false): string {
    $v = $_POST[$key] ?? '';
    return is_string($v) ? rcCleanText($v, $multiline) : '';
}
function rcHostOk(string $host): bool {
    $host = rtrim(strtolower($host), '.');
    return $host === DOMINIO_PERMITIDO || $host === 'www.' . DOMINIO_PERMITIDO;
}
function rcUrlHostOk(string $url): bool {
    $host = parse_url($url, PHP_URL_HOST);
    return is_string($host) && $host !== '' && rcHostOk($host);
}
function rcDocOk(string $type, string $nro): bool {
    switch ($type) {
        case 'DNI':       return (bool)preg_match('/^\d{8}$/', $nro);
        case 'RUC':       return (bool)preg_match('/^(10|15|17|20)\d{9}$/', $nro);
        case 'CE':
        case 'PASAPORTE': return (bool)preg_match('/^[A-Z0-9]{6,12}$/', $nro);
    }
    return false;
}
function rcSpamReason(string $s, int $maxUrls): string {
    if ($s === '') return '';
    if (preg_match('~\[/?(?:url|link|img)\b|<\s*/?\s*(?:a|script|iframe|img|object|embed|form)\b|href\s*=|javascript\s*:|\b(?:viagra|casino|porn)\b~iu', $s)) return 'markup';
    $urls = preg_match_all('~(?:https?://|ftp://|www\.)\S+~iu', $s) + preg_match_all('~\b[a-z0-9-]+\.(?:com|net|org|ru|cn|xyz|top|info|biz|online|site|shop|club)/\S*~iu', $s);
    if ($urls > $maxUrls) return 'urls';
    if (substr_count(strtolower($s), 'http') > 2) return 'http';
    $compact = preg_replace('/\s+/u', '', $s);
    if (preg_match('/(.)\1{11,}/us', $compact)) return 'repeat';
    $len = mb_strlen($compact, 'UTF-8');
    if ($len >= 20) {
        $counts = array_count_values(preg_split('//u', $compact, -1, PREG_SPLIT_NO_EMPTY));
        if (max($counts) / $len > 0.5) return 'repeat';
    }
    return '';
}

// ── Time trap (HMAC-signed render timestamp) ──────────────────────────────────
function rcFormSecret(): string { return hash('sha256', 'form|' . rcSalt()); }
function rcIssueFormToken(): string {
    $ts = (string)time();
    return $ts . '.' . hash_hmac('sha256', $ts . '|' . session_id(), rcFormSecret());
}
function rcCheckFormToken(string $tok): string {
    if (!preg_match('/^(\d{9,11})\.([a-f0-9]{64})$/', $tok, $m)) return 'invalid';
    if (!hash_equals(hash_hmac('sha256', $m[1] . '|' . session_id(), rcFormSecret()), $m[2])) return 'invalid';
    $age = time() - (int)$m[1];
    if ($age < 0) return 'invalid';
    if ($age < RC_MIN_FILL_SECONDS) return 'fast';
    if ($age > RC_MAX_FORM_AGE) return 'expired';
    return '';
}

// ── Rate limits + duplicate guard (single JSON state, flock) ──────────────────
// Returns '' when allowed, otherwise: ip_gap | ip_daily | site_hour | site_day | dup | state.
// With $register=true the submission is counted atomically under the same lock.
function rcAntispam(string $ipHash, string $dupHash, bool $register, array &$info = []): string {
    $fp = @fopen(RC_DIR . '/antispam.json', 'c+');
    if (!$fp) return 'state';
    if (!flock($fp, LOCK_EX)) { fclose($fp); return 'state'; }
    @chmod(RC_DIR . '/antispam.json', 0640);
    $st = json_decode((string)stream_get_contents($fp), true);
    if (!is_array($st)) $st = [];
    $now  = time();
    $keep = function ($ts) use ($now) { return is_int($ts) && ($now - $ts) < 86400; };
    $ips  = [];
    $stIp = (isset($st['ip']) && is_array($st['ip'])) ? $st['ip'] : [];
    foreach ($stIp as $h => $list) {
        $list = is_array($list) ? array_values(array_filter($list, $keep)) : [];
        if ($list) $ips[$h] = $list;
    }
    $site = array_values(array_filter((isset($st['site']) && is_array($st['site'])) ? $st['site'] : [], $keep));
    $dups = [];
    $stDup = (isset($st['dup']) && is_array($st['dup'])) ? $st['dup'] : [];
    foreach ($stDup as $h => $ts) {
        if (is_int($ts) && ($now - $ts) < RC_DUP_WINDOW) $dups[$h] = $ts;
    }
    $mine   = $ips[$ipHash] ?? [];
    $reason = '';
    if ($mine && ($now - max($mine)) < RATE_LIMIT_IP_INTERVAL) {
        $reason = 'ip_gap';
        $info['wait'] = RATE_LIMIT_IP_INTERVAL - ($now - max($mine));
    } elseif (count($mine) >= RATE_LIMIT_IP_DAILY) {
        $reason = 'ip_daily';
        $info['wait'] = min($mine) + 86400 - $now;
    } else {
        $hour = count(array_filter($site, function ($ts) use ($now) { return ($now - $ts) < 3600; }));
        if ($hour >= RATE_LIMIT_SITE_HOURLY)      $reason = 'site_hour';
        elseif (count($site) >= RATE_LIMIT_SITE_DAILY) $reason = 'site_day';
        elseif ($dupHash !== '' && isset($dups[$dupHash])) $reason = 'dup';
    }
    if ($reason === '' && $register) {
        $mine[] = $now; $ips[$ipHash] = $mine; $site[] = $now;
        if ($dupHash !== '') $dups[$dupHash] = $now;
    }
    if ($register) {
        ftruncate($fp, 0); rewind($fp);
        fwrite($fp, json_encode(['ip' => $ips, 'site' => $site, 'dup' => $dups]));
        fflush($fp);
    }
    flock($fp, LOCK_UN); fclose($fp);
    return $reason;
}
function rcWaitText(int $seconds): string {
    $m = (int)ceil(max(60, $seconds) / 60);
    if ($m <= 1) return 'un minuto';
    if ($m < 60) return $m . ' minutos';
    $h = (int)ceil($m / 60);
    return $h === 1 ? '1 hora' : $h . ' horas';
}
function rcAntispamMessage(string $reason, array $info): string {
    switch ($reason) {
        case 'ip_gap':    return 'Ya registraste un reclamo recientemente. Por favor, espera ' . rcWaitText((int)($info['wait'] ?? 1800)) . ' antes de enviar otro.';
        case 'ip_daily':  return 'Alcanzaste el límite diario de envíos. Inténtalo nuevamente en ' . rcWaitText((int)($info['wait'] ?? 3600)) . '.';
        case 'site_hour':
        case 'site_day':  return 'Estamos recibiendo muchas solicitudes en este momento. Por favor, inténtalo más tarde.';
        case 'dup':       return 'Ya recibimos un reclamo con este mismo contenido. Si necesitas ayuda, escríbenos a ' . EMPRESA_EMAIL . '.';
    }
    return 'No pudimos procesar tu solicitud en este momento. Inténtalo más tarde.';
}

// ── hCaptcha (fails closed) ───────────────────────────────────────────────────
function rcVerifyHcaptcha(string $token, string $secret, string $ip, string &$reason): bool {
    $reason = '';
    if ($secret === '' || HCAPTCHA_SITE_KEY === '') { $reason = 'not_configured'; return false; }
    if ($token === '' || strlen($token) > 4096)      { $reason = 'no_token';        return false; }
    $payload = http_build_query(['secret' => $secret, 'response' => $token, 'remoteip' => $ip, 'sitekey' => HCAPTCHA_SITE_KEY]);
    $result = false;
    if (function_exists('curl_init')) {
        $ch = curl_init('https://hcaptcha.com/siteverify');
        curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $payload, CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10, CURLOPT_CONNECTTIMEOUT => 10, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2]);
        $result = curl_exec($ch);
        curl_close($ch);
    } else {
        $ctx = stream_context_create(['http' => ['method' => 'POST', 'header' => 'Content-Type: application/x-www-form-urlencoded', 'content' => $payload, 'timeout' => 10],
            'ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
        $result = @file_get_contents('https://hcaptcha.com/siteverify', false, $ctx);
    }
    if (!is_string($result) || $result === '') { $reason = 'unreachable'; return false; }
    $data = json_decode($result, true);
    if (!is_array($data) || ($data['success'] ?? false) !== true) { $reason = 'rejected'; return false; }
    if (isset($data['hostname']) && is_string($data['hostname']) && $data['hostname'] !== '' && !rcHostOk($data['hostname'])) {
        $reason = 'hostname'; return false;
    }
    return true;
}

// ── Email (HTML + plain-text alternative, no attachments) ─────────────────────
function rcEmailSections(array $d, bool $internal): array {
    $dash = function ($v) { $v = (string)$v; return $v === '' ? '—' : $v; };
    $tipo = (($d['reclamo_tipo'] ?? '') === 'queja') ? 'Queja' : 'Reclamo';
    $bien = (($d['bien_tipo'] ?? '') === 'producto') ? 'Producto' : 'Servicio';
    $sec = [];
    $sec[] = ['Datos de la reclamación', [
        ['Código', $d['codigo']],
        ['Fecha y hora', $d['fecha'] . ' (hora de Lima)'],
        ['Tipo de incidencia', $tipo],
        ['Estado', $dash($d['estado'] ?? 'Pendiente')],
        ['Plazo de respuesta', '15 días hábiles (D.S. 101-2021-PCM)'],
    ]];
    $sec[] = ['Proveedor', [
        ['Razón social', $dash(EMPRESA_RAZON_SOCIAL)],
        ['RUC', $dash(EMPRESA_RUC)],
        ['Domicilio', $dash(EMPRESA_DIRECCION)],
        ['Correo de reclamaciones', EMPRESA_EMAIL],
    ]];
    $c = [
        ['Nombres y apellidos', $dash($d['nombres'])],
        ['Tipo de documento', $dash($d['doc_tipo'])],
        ['Nro. de documento', $dash($d['doc_nro'])],
        ['Correo electrónico', $dash($d['email'])],
        ['Teléfono', $dash($d['telefono'])],
        ['Dirección', $dash($d['direccion'])],
        ['Departamento', $dash($d['departamento'])],
        ['Provincia', $dash($d['provincia'])],
        ['Distrito', $dash($d['distrito'])],
        ['Menor de edad', !empty($d['menor_edad']) ? 'Sí' : 'No'],
    ];
    if (!empty($d['menor_edad'])) {
        $c[] = ['Apoderado: nombres', $dash($d['apoderado_nombres'])];
        $c[] = ['Apoderado: tipo de documento', $dash($d['apoderado_doc_tipo'])];
        $c[] = ['Apoderado: nro. de documento', $dash($d['apoderado_doc_nro'])];
    }
    $sec[] = ['1. Identificación del consumidor', $c];
    $sec[] = ['2. Identificación del bien contratado', [
        ['Tipo de bien', $bien],
        ['Monto reclamado', 'S/. ' . $d['monto']],
        ['Descripción', $dash($d['bien_desc']), true],
    ]];
    $sec[] = ['3. Detalle y pedido del consumidor', [
        ['Detalle del hecho', $dash($d['detalle']), true],
        ['Pedido del consumidor', $dash($d['pedido']), true],
    ]];
    $sec[] = ['Declaraciones', [
        ['Veracidad de los datos', !empty($d['decl_veraz']) ? 'Aceptada' : 'No'],
        ['Tratamiento de datos personales (Ley N° 29733)', !empty($d['decl_datos']) ? 'Aceptada' : 'No'],
    ]];
    if ($internal) {
        $sec[] = ['Control interno', [['IP (hash con sal)', $dash($d['ip_hash'] ?? '')]]];
    }
    return $sec;
}
function rcRenderEmail(array $d, bool $internal): array {
    $bg = RC_MAIL_BG; $ac = RC_MAIL_ACCENT;
    $sections = rcEmailSections($d, $internal);
    $intro = $internal
        ? 'Se registró ' . (($d['reclamo_tipo'] ?? '') === 'queja' ? 'una nueva queja' : 'un nuevo reclamo') . ' en el Libro de Reclamaciones Virtual. Responde directamente a este correo para escribir al consumidor (Reply-To).'
        : 'Estimado(a) ' . $d['nombres'] . ', confirmamos la recepción de tu reclamación. Esta es tu constancia; conserva el código para cualquier seguimiento. Responderemos en un plazo máximo de 15 días hábiles.';
    $footer = $internal
        ? 'Mensaje automático del Libro de Reclamaciones Virtual de ' . SMTP_FROM_NAME . '.'
        : 'Constancia automática. Para dar seguimiento escribe a ' . EMPRESA_EMAIL . '. La formulación del reclamo no impide acudir a otras vías de solución de controversias ni es requisito previo para interponer una denuncia ante el INDECOPI.';

    $h  = '<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Hoja de Reclamación ' . esc($d['codigo']) . '</title></head>';
    $h .= '<body style="margin:0;padding:0;background:#f4f4f5;">';
    $h .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f4f4f5;"><tr><td align="center" style="padding:24px 12px;">';
    $h .= '<table role="presentation" width="640" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:640px;background:#ffffff;border:1px solid #e4e4e7;font-family:Arial,Helvetica,sans-serif;color:#222222;">';
    $h .= '<tr><td style="background:' . $bg . ';padding:22px 24px;text-align:center;">'
        . '<div style="font-size:20px;line-height:26px;font-weight:bold;color:#ffffff;">HOJA DE RECLAMACIÓN VIRTUAL</div>'
        . '<div style="font-size:15px;line-height:22px;font-weight:bold;color:' . $ac . ';padding-top:6px;">Código: ' . esc($d['codigo']) . '</div>'
        . '<div style="font-size:12px;line-height:18px;color:#ffffff;padding-top:4px;">Ley N° 29571 · ' . esc(SMTP_FROM_NAME) . '</div></td></tr>';
    $h .= '<tr><td style="padding:20px 24px 4px;font-size:14px;line-height:21px;color:#222222;">' . esc($intro) . '</td></tr>';
    foreach ($sections as $sec) {
        $h .= '<tr><td style="padding:16px 24px 0;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
            . '<tr><td colspan="2" style="background:#f1f1f4;border-left:4px solid ' . $ac . ';padding:8px 12px;font-size:13px;font-weight:bold;color:' . $bg . ';">' . esc($sec[0]) . '</td></tr>';
        foreach ($sec[1] as $row) {
            $val = !empty($row[2]) ? nl2br(esc($row[1])) : esc($row[1]);
            $h .= '<tr><td valign="top" width="200" style="width:200px;padding:8px 12px;border-bottom:1px solid #ececf0;font-size:13px;line-height:19px;font-weight:bold;color:#555555;">' . esc($row[0]) . '</td>'
                . '<td valign="top" style="padding:8px 12px;border-bottom:1px solid #ececf0;font-size:13px;line-height:19px;color:#222222;">' . $val . '</td></tr>';
        }
        $h .= '</table></td></tr>';
    }
    $h .= '<tr><td style="padding:20px 24px;font-size:11px;line-height:16px;color:#777777;text-align:center;border-top:1px solid #ececf0;margin-top:16px;">' . esc($footer) . '</td></tr>';
    $h .= '</table></td></tr></table></body></html>';

    $t = "HOJA DE RECLAMACIÓN VIRTUAL\r\nCódigo: " . $d['codigo'] . "\r\n\r\n" . $intro . "\r\n";
    foreach ($sections as $sec) {
        $t .= "\r\n== " . mb_strtoupper($sec[0], 'UTF-8') . " ==\r\n";
        foreach ($sec[1] as $row) {
            if (!empty($row[2]) && strpos($row[1], "\n") !== false) {
                $t .= $row[0] . ":\r\n  " . str_replace("\n", "\r\n  ", $row[1]) . "\r\n";
            } else {
                $t .= $row[0] . ': ' . $row[1] . "\r\n";
            }
        }
    }
    $t .= "\r\n-- \r\n" . $footer . "\r\n";
    return [$h, $t];
}
function rcEncodeHeader(string $s): string {
    $s = sanitizarCabecera($s);
    if ($s === '') return '';
    $words = [];
    foreach (array_chunk(preg_split('//u', $s, -1, PREG_SPLIT_NO_EMPTY), 10) as $chunk) {
        $words[] = '=?UTF-8?B?' . base64_encode(implode('', $chunk)) . '?=';
    }
    return implode("\r\n ", $words);
}
// Sends ONE message to ONE recipient. All header values are fixed or validated; $err is for the log only.
function rcSmtpSend(string $to, string $subject, string $html, string $text, string $replyTo, string &$err = ''): bool {
    if (!defined('SMTP_HOST') || !defined('SMTP_USER') || !defined('SMTP_PASS')) { $err = 'smtp_config_missing'; return false; }
    $to = sanitizarCabecera($to);
    if (!filter_var($to, FILTER_VALIDATE_EMAIL) || strlen($to) > 254) { $err = 'invalid_recipient'; return false; }
    $replyTo = sanitizarCabecera($replyTo);
    if (!filter_var($replyTo, FILTER_VALIDATE_EMAIL) || strlen($replyTo) > 254) $replyTo = EMPRESA_EMAIL;
    $eol = "\r\n";
    $boundary = '=_rc_' . bin2hex(random_bytes(12));
    $headers  = 'Date: ' . date('r') . $eol;
    $headers .= 'From: ' . rcEncodeHeader(SMTP_FROM_NAME) . ' <' . EMPRESA_EMAIL . '>' . $eol;
    $headers .= 'To: <' . $to . '>' . $eol;
    $headers .= 'Reply-To: <' . $replyTo . '>' . $eol;
    $headers .= 'Subject: ' . rcEncodeHeader($subject) . $eol;
    $headers .= 'Message-ID: <' . bin2hex(random_bytes(12)) . '@' . DOMINIO_PERMITIDO . '>' . $eol;
    $headers .= 'Auto-Submitted: auto-generated' . $eol;
    $headers .= 'MIME-Version: 1.0' . $eol;
    $headers .= 'Content-Type: multipart/alternative; boundary="' . $boundary . '"' . $eol;
    $body  = '--' . $boundary . $eol . 'Content-Type: text/plain; charset=UTF-8' . $eol . 'Content-Transfer-Encoding: base64' . $eol . $eol . chunk_split(base64_encode($text), 76, $eol);
    $body .= '--' . $boundary . $eol . 'Content-Type: text/html; charset=UTF-8' . $eol . 'Content-Transfer-Encoding: base64' . $eol . $eol . chunk_split(base64_encode($html), 76, $eol);
    $body .= '--' . $boundary . '--' . $eol;
    $message = $headers . $eol . $body;

    $verify    = (bool)SMTP_VERIFY_TLS;
    $transport = ((int)SMTP_PORT === 465 ? 'ssl://' : '') . SMTP_HOST . ':' . SMTP_PORT;
    $ctx = stream_context_create(['ssl' => ['verify_peer' => $verify, 'verify_peer_name' => $verify, 'allow_self_signed' => !$verify, 'peer_name' => SMTP_HOST]]);
    $fp = @stream_socket_client($transport, $errno, $errstr, 20, STREAM_CLIENT_CONNECT, $ctx);
    if (!$fp) { $err = "connect_failed: $errstr ($errno)"; return false; }
    stream_set_timeout($fp, 20);
    $read = function () use ($fp): string {
        $data = '';
        while (($line = fgets($fp, 515)) !== false) { $data .= $line; if (strlen($line) < 4 || $line[3] === ' ') break; }
        return $data;
    };
    $cmd = function (string $c) use ($fp, $read): string { fwrite($fp, $c . "\r\n"); return $read(); };
    $ok  = function (string $resp, array $codes) use (&$err): bool {
        foreach ($codes as $code) { if (strncmp($resp, $code, strlen($code)) === 0) return true; }
        $err = 'smtp_reply: ' . trim($resp);
        return false;
    };
    $fail = function () use ($fp) { @fwrite($fp, "QUIT\r\n"); @fclose($fp); return false; };

    if (!$ok($read(), ['220']))                                        return $fail();
    if (!$ok($cmd('EHLO ' . DOMINIO_PERMITIDO), ['250']))              return $fail();
    if (!$ok($cmd('AUTH LOGIN'), ['334']))                             return $fail();
    if (!$ok($cmd(base64_encode(SMTP_USER)), ['334']))                 return $fail();
    if (!$ok($cmd(base64_encode(SMTP_PASS)), ['235']))                 return $fail();
    if (!$ok($cmd('MAIL FROM:<' . SMTP_USER . '>'), ['250']))          return $fail();
    if (!$ok($cmd('RCPT TO:<' . $to . '>'), ['250', '251']))           return $fail();
    if (!$ok($cmd('DATA'), ['354']))                                   return $fail();
    if (!$ok($cmd($message . "\r\n."), ['250']))                       return $fail();
    $cmd('QUIT'); fclose($fp);
    return true;
}

// Repopulate helpers for the form (escaped)
function old(string $k): string { return isset($_POST[$k]) ? esc((string)$_POST[$k]) : ''; }
function sel(string $k, string $v, bool $default = false): string {
    $cur = $_POST[$k] ?? null;
    return ($cur === null ? $default : $cur === $v) ? ' selected' : '';
}
function chk(string $k, string $v, bool $default = false): string {
    $cur = $_POST[$k] ?? null;
    return ($cur === null ? $default : $cur === $v) ? ' checked' : '';
}

// ── Request handling ──────────────────────────────────────────────────────────
$success       = false;
$generatedCode = '';
$submittedData = [];
$errorMsg      = '';
$clientIP      = rcClientIp();
$ipHash        = rcIpHash($clientIP);
$dirOk         = rcPrepareDir(RC_DIR);
if (!$dirOk) {
    $errorMsg = 'El servicio no está disponible temporalmente. Inténtalo más tarde.';
    error_log('libro-de-reclamaciones: records directory is not usable');
}

$recordsFile = RC_DIR . '/records.json';
$lockFile    = RC_DIR . '/records.lock';

$method = (string)($_SERVER['REQUEST_METHOD'] ?? 'GET');
if (!in_array($method, ['GET', 'HEAD', 'POST'], true)) {
    http_response_code(405);
    header('Allow: GET, HEAD, POST');
    exit;
}

if ($method === 'POST' && $dirOk) {
    $hpFilled = !empty($_POST['company_site']);
    foreach ($_POST as $k => $v) { if (!is_string($v)) $_POST[$k] = ''; }   // no array injection into the templates

    // 1. Body size
    if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > RC_MAX_BODY) {
        rcLog('BODY_TOO_LARGE');
        http_response_code(413);
        $errorMsg = 'La solicitud es demasiado grande.';
    }

    // 2. Origin / Referer (parsed host must be the allowed domain or www.)
    if ($errorMsg === '') {
        $origin  = trim((string)($_SERVER['HTTP_ORIGIN'] ?? ''));
        $referer = trim((string)($_SERVER['HTTP_REFERER'] ?? ''));
        if ($origin !== '')       $originOk = rcUrlHostOk($origin);
        elseif ($referer !== '')  $originOk = rcUrlHostOk($referer);
        else                      $originOk = false;
        if (!$originOk) {
            rcLog('ORIGIN_REJECTED');
            $errorMsg = 'No pudimos validar el origen de la solicitud. Recarga la página e inténtalo de nuevo.';
        }
    }

    // 3. Honeypot (silent: bots get an empty 200)
    if ($errorMsg === '' && $hpFilled) {
        rcLog('HONEYPOT_TRIGGERED');
        http_response_code(200);
        exit;
    }

    // 4. CSRF (session-bound token + user-agent binding)
    if ($errorMsg === '') {
        $csrfPost = (string)($_POST['csrf_token'] ?? '');
        $csrfSess = (string)($_SESSION['csrf_token'] ?? '');
        $uaSess   = (string)($_SESSION['csrf_ua'] ?? '');
        if ($csrfPost === '' || $csrfSess === '' || !hash_equals($csrfSess, $csrfPost) || !hash_equals($uaSess, hash('sha256', (string)($_SERVER['HTTP_USER_AGENT'] ?? '')))) {
            rcLog('CSRF_FAILED');
            $errorMsg = 'Token de seguridad inválido. Recarga la página e inténtalo de nuevo.';
        }
    }

    // 5. Time trap
    if ($errorMsg === '') {
        $trap = rcCheckFormToken((string)($_POST['form_ts'] ?? ''));
        if ($trap !== '') {
            rcLog('TIMETRAP_' . strtoupper($trap));
            $errorMsg = $trap === 'fast'
                ? 'Enviaste el formulario demasiado rápido. Espera unos segundos e inténtalo de nuevo.'
                : 'El formulario expiró o no es válido. Recarga la página e inténtalo de nuevo.';
        }
    }

    // 6. Early (read-only) rate-limit check, before any heavier work
    if ($errorMsg === '') {
        $info = [];
        $why  = rcAntispam($ipHash, '', false, $info);
        if ($why !== '') {
            rcLog('RATE_LIMIT_' . strtoupper($why), ['wait' => $info['wait'] ?? '']);
            $errorMsg = rcAntispamMessage($why, $info);
        }
    }

    // 7. Validation
    if ($errorMsg === '') {
        foreach ($_POST as $val) {
            if (!mb_check_encoding($val, 'UTF-8')) { $errorMsg = 'Los datos enviados contienen caracteres no válidos.'; break; }
        }
    }
    if ($errorMsg === '') {
        $nombres            = rcField('nombres');
        $doc_tipo           = rcField('doc_tipo');
        $doc_nro            = strtoupper(preg_replace('/[\s\-]+/', '', rcField('doc_nro')));
        $emailRaw           = rcField('email');
        $telefono           = rcField('telefono');
        $direccion          = rcField('direccion');
        $departamento       = rcField('departamento');
        $provincia          = rcField('provincia');
        $distrito           = rcField('distrito');
        $menor_edad         = isset($_POST['menor_edad']);
        $apoderado_nombres  = $menor_edad ? rcField('apoderado_nombres') : '';
        $apoderado_doc_tipo = $menor_edad ? rcField('apoderado_doc_tipo') : '';
        $apoderado_doc_nro  = $menor_edad ? strtoupper(preg_replace('/[\s\-]+/', '', rcField('apoderado_doc_nro'))) : '';
        $bien_tipo          = rcField('bien_tipo');
        $bien_desc          = rcField('bien_desc', true);
        $reclamo_tipo       = rcField('reclamo_tipo');
        $detalle            = rcField('detalle', true);
        $pedido             = rcField('pedido', true);
        $montoRaw           = str_replace(',', '.', rcField('monto'));
        $decl_veraz         = isset($_POST['decl_veraz']);
        $decl_datos         = isset($_POST['decl_datos']);

        // [value, max length, min length, label, max URLs allowed]
        $limits = [
            [$nombres, 200, 2, 'nombres', 0], [$direccion, 300, 5, 'dirección', 0], [$departamento, 100, 2, 'departamento', 0],
            [$provincia, 100, 2, 'provincia', 0], [$distrito, 100, 2, 'distrito', 0], [$telefono, 20, 0, 'teléfono', 0],
            [$bien_desc, 500, 0, 'descripción', 2], [$detalle, 2000, 10, 'detalle', 2], [$pedido, 2000, 5, 'pedido', 2],
        ];
        if ($menor_edad) $limits[] = [$apoderado_nombres, 200, 2, 'apoderado', 0];

        $email = filter_var($emailRaw, FILTER_VALIDATE_EMAIL);
        $monto = '0.00';
        if ($montoRaw !== '') {
            if (preg_match('/^\d{1,7}(\.\d{1,2})?$/', $montoRaw)) $monto = number_format((float)$montoRaw, 2, '.', '');
            else $errorMsg = 'El monto reclamado no es válido.';
        }
        if ($errorMsg === '' && (!$nombres || !$doc_nro || !$email || !$direccion || !$departamento || !$provincia || !$distrito || !$detalle || !$pedido)) {
            $errorMsg = 'Por favor, rellena todos los campos obligatorios del formulario.';
        }
        if ($errorMsg === '' && (strlen((string)$email) > 254 || strlen($emailRaw) > 254)) $errorMsg = 'El correo electrónico no es válido.';
        if ($errorMsg === '' && (!in_array($doc_tipo, ['DNI', 'CE', 'PASAPORTE', 'RUC'], true) || !in_array($bien_tipo, ['producto', 'servicio'], true) || !in_array($reclamo_tipo, ['reclamo', 'queja'], true))) {
            $errorMsg = 'Hay datos del formulario que no son válidos. Recarga la página e inténtalo de nuevo.';
        }
        if ($errorMsg === '' && !rcDocOk($doc_tipo, $doc_nro)) $errorMsg = 'El número de documento no tiene un formato válido.';
        if ($errorMsg === '' && $telefono !== '' && (!preg_match('/^[0-9+()\-\s.]{6,20}$/', $telefono) || preg_match_all('/\d/', $telefono) < 6)) {
            $errorMsg = 'El teléfono no tiene un formato válido.';
        }
        if ($errorMsg === '' && $menor_edad) {
            if ($apoderado_nombres === '' || !in_array($apoderado_doc_tipo, ['DNI', 'CE', 'PASAPORTE'], true) || !rcDocOk($apoderado_doc_tipo, $apoderado_doc_nro)) {
                $errorMsg = 'Si el consumidor es menor de edad, ingresa los datos completos del apoderado.';
            }
        }
        if ($errorMsg === '' && (!$decl_veraz || !$decl_datos)) $errorMsg = 'Debes aceptar ambas declaraciones para presentar la reclamación.';
        if ($errorMsg === '') {
            foreach ($limits as $lim) {
                if (mb_strlen($lim[0], 'UTF-8') > $lim[1]) { $errorMsg = 'El campo ' . $lim[3] . ' excede la longitud permitida.'; break; }
                if ($lim[2] > 0 && mb_strlen($lim[0], 'UTF-8') < $lim[2]) { $errorMsg = 'El campo ' . $lim[3] . ' es demasiado corto.'; break; }
                $sp = rcSpamReason($lim[0], $lim[4]);
                if ($sp !== '') { rcLog('SPAM_CONTENT', ['reason' => $sp]); $errorMsg = 'El contenido enviado no es válido. Revisa los campos e inténtalo de nuevo.'; break; }
            }
        }
        if ($errorMsg === '' && !preg_match('/\p{L}.*\p{L}/su', $nombres)) $errorMsg = 'Ingresa tus nombres y apellidos completos.';
    }

    // 8. hCaptcha
    if ($errorMsg === '') {
        $capReason = '';
        if (!rcVerifyHcaptcha((string)($_POST['h-captcha-response'] ?? ''), HCAPTCHA_SECRET_KEY, $clientIP, $capReason)) {
            rcLog('CAPTCHA_FAILED', ['reason' => $capReason]);
            $errorMsg = ($capReason === 'not_configured' || $capReason === 'unreachable')
                ? 'No pudimos verificar el desafío de seguridad en este momento. Inténtalo más tarde.'
                : 'Por favor, completa el desafío de seguridad (captcha) antes de enviar.';
        }
    }

    // 9. Atomic reservation: per-IP limits, site-wide caps and duplicate guard
    if ($errorMsg === '') {
        $dupHash = hash('sha256', rcSalt() . '|dup|' . mb_strtolower($detalle, 'UTF-8') . '|' . strtolower((string)$email));
        $info = [];
        $why  = rcAntispam($ipHash, $dupHash, true, $info);
        if ($why !== '') {
            rcLog(($why === 'dup' ? 'DUPLICATE_REJECTED' : 'RATE_LIMIT_' . strtoupper($why)), ['wait' => $info['wait'] ?? '']);
            $errorMsg = rcAntispamMessage($why, $info);
        }
    }

    // 10. Save record (JSON backup stays on the server even if mail fails)
    if ($errorMsg === '') {
        $fp = @fopen($lockFile, 'c');
        if ($fp && flock($fp, LOCK_EX)) {
            $year    = date('Y');
            $records = [];
            $corrupt = false;
            if (file_exists($recordsFile)) {
                $raw = (string)file_get_contents($recordsFile);
                if (trim($raw) !== '') {
                    $records = json_decode($raw, true);
                    if (!is_array($records)) { $records = []; $corrupt = true; }
                }
            }
            if ($corrupt) {
                rcLog('RECORDS_CORRUPT');
                $errorMsg = 'No pudimos registrar tu reclamación en este momento. Inténtalo más tarde.';
            } else {
                $yearCount = 0;
                foreach ($records as $r) { if (isset($r['year']) && $r['year'] == $year) $yearCount++; }
                $generatedCode = sprintf('REC-%s-%04d', $year, $yearCount + 1);
                $submittedData = [
                    'codigo' => $generatedCode, 'year' => $year, 'fecha' => date('d/m/Y h:i A'),
                    'nombres' => $nombres, 'doc_tipo' => $doc_tipo, 'doc_nro' => $doc_nro,
                    'email' => $email, 'telefono' => $telefono, 'direccion' => $direccion,
                    'departamento' => $departamento, 'provincia' => $provincia, 'distrito' => $distrito,
                    'menor_edad' => $menor_edad,
                    'apoderado_nombres'  => $apoderado_nombres,
                    'apoderado_doc_tipo' => $apoderado_doc_tipo,
                    'apoderado_doc_nro'  => $apoderado_doc_nro,
                    'bien_tipo' => $bien_tipo, 'monto' => $monto, 'bien_desc' => $bien_desc,
                    'reclamo_tipo' => $reclamo_tipo, 'detalle' => $detalle, 'pedido' => $pedido,
                    'decl_veraz' => true, 'decl_datos' => true,
                    'ip_hash' => substr($ipHash, 0, 16),
                    'estado' => 'Pendiente', 'respuesta' => '',
                ];
                $records[] = $submittedData;
                if (file_put_contents($recordsFile, json_encode($records, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)) === false) {
                    rcLog('RECORDS_WRITE_FAILED');
                    $errorMsg = 'No pudimos registrar tu reclamación en este momento. Inténtalo más tarde.';
                } else {
                    @chmod($recordsFile, 0640);
                    $success = true;
                }
            }
            flock($fp, LOCK_UN);
        } else {
            $errorMsg = 'No pudimos registrar tu reclamación en este momento. Inténtalo más tarde.';
        }
        if ($fp) fclose($fp);
    }

    // 11. Mail: internal first; the consumer copy only if the internal mail was accepted
    if ($success) {
        $tipoTxt = $reclamo_tipo === 'queja' ? 'Queja' : 'Reclamo';
        $subjectInt = '[Libro de Reclamaciones] ' . $generatedCode . ' – ' . $tipoTxt . ' – ' . mb_substr(sanitizarCabecera($nombres), 0, 60, 'UTF-8');
        list($htmlBody, $textBody) = rcRenderEmail($submittedData, true);
        $errInt = '';
        $submittedData['constancia_enviada'] = false;
        if (rcSmtpSend(EMPRESA_NOTIF_EMAIL, $subjectInt, $htmlBody, $textBody, (string)$email, $errInt)) {
            list($htmlC, $textC) = rcRenderEmail($submittedData, false);
            $errCli = '';
            if (rcSmtpSend((string)$email, 'Constancia de reclamo ' . $generatedCode . ' – ' . SMTP_FROM_NAME, $htmlC, $textC, EMPRESA_EMAIL, $errCli)) {
                $submittedData['constancia_enviada'] = true;
            } else {
                rcLog('MAIL_FAILED', ['codigo' => $generatedCode, 'reason' => 'consumer', 'detail' => $errCli]);
            }
        } else {
            rcLog('MAIL_FAILED', ['codigo' => $generatedCode, 'reason' => 'internal', 'detail' => $errInt]);
        }
        rcLog('RECLAMO_OK', ['codigo' => $generatedCode]);

        $_SESSION['csrf_token']      = bin2hex(random_bytes(32));   // rotate after success
        $_SESSION['csrf_ua']         = hash('sha256', (string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
        $_SESSION['reclamo_success'] = $submittedData;
        header('Location: libro-de-reclamaciones.php?ok=1');
        exit;
    }
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    $_SESSION['csrf_ua']    = hash('sha256', (string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
}

if (isset($_GET['ok']) && !empty($_SESSION['reclamo_success'])) {
    $success       = true;
    $submittedData = $_SESSION['reclamo_success'];
    $generatedCode = $submittedData['codigo'] ?? '';
    unset($_SESSION['reclamo_success']);
}

// Fresh signed render timestamp for the time trap (re-issued on every render, including error re-renders).
$formToken = rcIssueFormToken();
?>
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex">
  <title>Libro de Reclamaciones | Perfil360 Solutions</title>
  <meta name="description" content="Libro de Reclamaciones Virtual de Perfil360 Solutions. Presenta tus quejas o reclamos conforme al Código de Protección y Defensa del Consumidor (Ley N° 29571).">
  <link rel="icon" href="assets/img/logos/favicon.ico" sizes="any">
  <link rel="icon" type="image/png" sizes="32x32" href="assets/img/logos/favicon-32.png">
  <link rel="apple-touch-icon" sizes="180x180" href="assets/img/logos/apple-touch-icon-180.png">
  <meta name="theme-color" content="#050F2C">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="style.css">
  <style>
    body { background: var(--cream); }
    .lr-header { background: var(--navy); border-bottom: 1px solid rgba(255,255,255,.06); }
    .lr-header-in { max-width: var(--max); margin: 0 auto; padding: 0 48px; height: 84px; display: flex; align-items: center; justify-content: space-between; gap: 16px; }
    .lr-header img { height: 64px; width: auto; }
    .lr-back { font-size: .82rem; font-weight: 500; color: rgba(255,255,255,.65); transition: color .2s; }
    .lr-back:hover { color: #fff; }

    .lr-main { max-width: 1040px; margin: 0 auto; padding: 56px 24px 72px; }
    .lr-hero { text-align: center; margin-bottom: 40px; }
    .lr-tag { display: inline-block; padding: 5px 14px; border-radius: 20px; border: 1px solid rgba(255,85,0,.45); color: var(--orange); font-size: .65rem; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; }
    .lr-hero h1 { font-size: clamp(2rem, 5vw, 3rem); font-weight: 900; color: var(--navy); letter-spacing: -.02em; margin: 14px 0 10px; }
    .lr-hero h1 span { color: var(--orange); }
    .lr-hero p { color: var(--mid); font-size: .92rem; max-width: 520px; margin: 0 auto; line-height: 1.65; }

    .lr-grid { display: grid; grid-template-columns: minmax(0, 2fr) minmax(0, 1fr); gap: 28px; align-items: start; }
    .lr-card { background: var(--white); border: 1px solid var(--border); border-radius: 16px; padding: 32px; box-shadow: 0 2px 14px rgba(5,15,44,.06); }
    .lr-side { display: flex; flex-direction: column; gap: 20px; }
    .lr-side .lr-card { padding: 24px; font-size: .8rem; }

    .lr-alert { background: #FEF2F2; border: 1px solid #FECACA; color: #B91C1C; padding: 12px 16px; border-radius: 12px; margin-bottom: 24px; font-size: .88rem; }
    .lr-sec { border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 24px; }
    .lr-sec:last-of-type { border-bottom: 0; margin-bottom: 0; }
    .lr-sec h2 { display: flex; align-items: center; gap: 10px; font-size: 1.05rem; font-weight: 800; color: var(--navy); margin-bottom: 18px; }
    .lr-num { width: 26px; height: 26px; border-radius: 8px; background: var(--navy); color: #fff; font-size: .75rem; font-weight: 800; display: inline-flex; align-items: center; justify-content: center; }
    .lr-fields { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    .lr-full { grid-column: 1 / -1; }
    .lr-label { display: block; font-size: .62rem; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; color: var(--mid); margin-bottom: 6px; }
    .lr-input { width: 100%; font-family: var(--f); font-size: .9rem; color: var(--ink); background: #fff; border: 1px solid var(--border); border-radius: 10px; padding: 11px 14px; outline: none; transition: border-color .2s, box-shadow .2s; }
    .lr-input::placeholder { color: rgba(12,18,32,.35); }
    .lr-input:focus { border-color: var(--orange); box-shadow: 0 0 0 3px rgba(255,85,0,.15); }
    textarea.lr-input { resize: none; }
    .lr-box { margin-top: 16px; padding: 14px 16px; background: var(--cream); border: 1px solid var(--border); border-radius: 12px; }
    .lr-check { display: flex; align-items: flex-start; gap: 10px; cursor: pointer; font-size: .8rem; color: var(--mid); line-height: 1.55; }
    .lr-check input, .lr-radio input { accent-color: var(--orange); width: 16px; height: 16px; margin-top: 2px; flex-shrink: 0; cursor: pointer; }
    .lr-radios { display: flex; gap: 24px; margin-top: 8px; }
    .lr-radio { display: flex; align-items: center; gap: 8px; cursor: pointer; font-size: .9rem; }
    .lr-types { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 8px; }
    .lr-type { display: flex; align-items: flex-start; gap: 10px; padding: 12px; border: 1px solid var(--border); border-radius: 12px; background: var(--cream); cursor: pointer; transition: border-color .2s, background .2s; }
    .lr-type:hover { border-color: rgba(255,85,0,.5); background: #fff; }
    .lr-type input { accent-color: var(--orange); width: 16px; height: 16px; margin-top: 2px; }
    .lr-type b { display: block; font-size: .72rem; letter-spacing: .1em; text-transform: uppercase; color: var(--navy); }
    .lr-type small { display: block; font-size: .7rem; color: var(--mid); line-height: 1.4; margin-top: 2px; }
    .lr-decl { margin-top: 24px; padding-top: 20px; border-top: 1px solid var(--border); display: flex; flex-direction: column; gap: 12px; }
    .lr-captcha { display: flex; justify-content: center; margin-top: 20px; }
    .lr-warn { text-align: center; color: #B45309; font-size: .72rem; margin-top: 20px; }
    .lr-submit { width: 100%; margin-top: 20px; justify-content: center; border: 0; cursor: pointer; padding: 16px 30px; letter-spacing: .06em; }
    .lr-submit:disabled { opacity: .6; cursor: default; }

    .lr-side h3 { font-size: .72rem; font-weight: 800; letter-spacing: .14em; text-transform: uppercase; color: var(--navy); margin-bottom: 14px; }
    .lr-dl dt { font-size: .6rem; letter-spacing: .14em; text-transform: uppercase; color: var(--mid); margin-top: 12px; }
    .lr-dl dt:first-child { margin-top: 0; }
    .lr-dl dd { font-size: .85rem; font-weight: 600; color: var(--navy); margin: 2px 0 0; }
    .lr-side p { color: var(--mid); line-height: 1.6; margin-bottom: 14px; }
    .lr-side .ft-libro { margin: 0 auto; }
    .lr-side a.lr-mail { display: block; text-align: center; margin-top: 12px; color: var(--orange); font-weight: 600; font-size: .8rem; }

    /* Success */
    .lr-ok { text-align: center; margin-bottom: 28px; }
    .lr-ok-ic { width: 60px; height: 60px; border-radius: 50%; background: #ECFDF5; border: 1px solid #A7F3D0; color: #059669; font-size: 1.8rem; display: inline-flex; align-items: center; justify-content: center; margin-bottom: 14px; }
    .lr-ok h1 { font-size: 1.9rem; font-weight: 900; color: var(--navy); margin-bottom: 8px; }
    .lr-ok p { color: var(--mid); font-size: .9rem; max-width: 520px; margin: 0 auto; line-height: 1.6; }
    .lr-sheet { background: #fff; border: 1px solid var(--border); border-radius: 14px; padding: 24px; }
    .lr-sheet-head { display: flex; justify-content: space-between; gap: 16px; flex-wrap: wrap; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 18px; }
    .lr-sheet-head h2 { font-size: 1.1rem; font-weight: 900; color: var(--navy); }
    .lr-sheet-head small { color: var(--mid); font-size: .72rem; }
    .lr-code { font-size: 1.2rem; font-weight: 900; color: #059669; }
    .lr-sheet h3 { font-size: .72rem; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; color: var(--orange); margin: 20px 0 10px; }
    .lr-kv { display: grid; grid-template-columns: 1fr 1fr; gap: 12px 20px; font-size: .82rem; color: var(--ink); }
    .lr-kv span { display: block; font-size: .6rem; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; color: var(--mid); margin-bottom: 2px; }
    .lr-pre { background: var(--cream); border: 1px solid var(--border); border-radius: 10px; padding: 12px; white-space: pre-wrap; font-size: .85rem; margin-top: 4px; }
    .lr-actions { display: flex; justify-content: center; gap: 14px; flex-wrap: wrap; margin-top: 28px; }
    .lr-ghost { border: 1.5px solid var(--navy); color: var(--navy); background: transparent; }
    .lr-ghost:hover { background: rgba(5,15,44,.06); box-shadow: none; transform: translateY(-2px); }

    @media (max-width: 860px) { .lr-grid { grid-template-columns: 1fr; } }
    @media (max-width: 640px) {
      .lr-header-in { padding: 0 20px; }
      .lr-main { padding: 36px 16px 56px; }
      .lr-card { padding: 22px 18px; }
      .lr-fields, .lr-types, .lr-kv { grid-template-columns: 1fr; }
    }
    .lr-hidden { display: none !important; }
    @media print {
      body { background: #fff; }
      .no-print, footer { display: none !important; }
      .lr-main { padding: 0; }
      .lr-sheet { border: 0; padding: 0; }
    }
  </style>
<?php if (defined('HCAPTCHA_SITE_KEY') && HCAPTCHA_SITE_KEY !== ''): ?>
  <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
<?php endif; ?>
</head>
<body>

  <header class="lr-header no-print">
    <div class="lr-header-in">
      <a href="index.html"><img src="assets/img/logos/LOGO%20COLOR%20BLANCO.webp" alt="Perfil360"></a>
      <a href="index.html" class="lr-back">&larr; Volver a la web</a>
    </div>
  </header>

  <main class="lr-main">

<?php if ($success): ?>
    <!-- SUCCESS -->
    <div class="lr-card">
      <div class="lr-ok no-print">
        <div class="lr-ok-ic">&#10003;</div>
        <h1>¡Reclamación registrada!</h1>
        <p>Tu reclamo/queja ha sido procesado correctamente. <?php if (!empty($submittedData['constancia_enviada'])): ?>Se ha enviado un cargo de recepción a <strong><?= esc($submittedData['email']) ?></strong>.<?php else: ?>Conserva tu código de reclamación; nos pondremos en contacto contigo.<?php endif; ?></p>
      </div>

      <div class="lr-sheet">
        <div class="lr-sheet-head">
          <div>
            <h2>HOJA DE RECLAMACIÓN VIRTUAL</h2>
            <small>Conforme a la Ley N° 29571 / D.S. N° 011-2011-PCM</small>
          </div>
          <div>
            <small>CÓDIGO DE RECLAMACIÓN</small>
            <div class="lr-code"><?= esc($submittedData['codigo']) ?></div>
            <small>Fecha de registro: <?= esc($submittedData['fecha']) ?></small>
          </div>
        </div>

        <div class="lr-kv">
          <div><span>Proveedor</span><?= esc(EMPRESA_RAZON_SOCIAL) ?></div>
          <div><span>RUC</span><?= esc(EMPRESA_RUC) ?></div>
          <div class="lr-full" style="grid-column:1/-1"><span>Domicilio fiscal</span><?= esc(EMPRESA_DIRECCION) ?></div>
        </div>

        <h3>1. Identificación del consumidor reclamante</h3>
        <div class="lr-kv">
          <div><span>Nombre</span><strong><?= esc($submittedData['nombres']) ?></strong></div>
          <div><span>Documento</span><?= esc($submittedData['doc_tipo']) ?> - <?= esc($submittedData['doc_nro']) ?></div>
          <div><span>Domicilio</span><?= esc($submittedData['direccion']) ?>, <?= esc($submittedData['distrito']) ?> - <?= esc($submittedData['provincia']) ?> (<?= esc($submittedData['departamento']) ?>)</div>
          <div><span>Contacto</span><?= esc($submittedData['email']) ?> | Tel: <?= esc($submittedData['telefono'] ?: '-') ?></div>
<?php if ($submittedData['menor_edad']): ?>
          <div style="grid-column:1/-1"><span>Representante / apoderado</span><?= esc($submittedData['apoderado_nombres']) ?> (<?= esc($submittedData['apoderado_doc_tipo']) ?> <?= esc($submittedData['apoderado_doc_nro']) ?>)</div>
<?php endif; ?>
        </div>

        <h3>2. Identificación del bien contratado</h3>
        <div class="lr-kv">
          <div><span>Tipo de bien</span><?= esc(ucfirst($submittedData['bien_tipo'])) ?></div>
          <div><span>Monto reclamado</span>S/. <?= esc($submittedData['monto']) ?></div>
          <div style="grid-column:1/-1"><span>Descripción</span><?= esc($submittedData['bien_desc'] ?: 'No especificado') ?></div>
        </div>

        <h3>3. Detalle de la reclamación y pedido del consumidor</h3>
        <div class="lr-kv">
          <div style="grid-column:1/-1"><span>Tipo de incidencia</span><strong style="text-transform:uppercase"><?= esc($submittedData['reclamo_tipo']) ?></strong></div>
          <div style="grid-column:1/-1"><span>Detalle</span><div class="lr-pre"><?= esc($submittedData['detalle']) ?></div></div>
          <div style="grid-column:1/-1"><span>Pedido concreto</span><div class="lr-pre"><?= esc($submittedData['pedido']) ?></div></div>
        </div>
      </div>

      <div class="lr-actions no-print">
        <button type="button" class="btn-fill" onclick="window.print()">Descargar / imprimir reclamo</button>
        <a href="index.html" class="btn-fill lr-ghost">Volver al inicio</a>
      </div>
    </div>

<?php else: ?>
    <!-- FORM -->
    <div class="lr-hero no-print">
      <span class="lr-tag">Ley N° 29571</span>
      <h1>Libro de Reclamaciones <span>Virtual</span></h1>
      <p>Para registrar tu queja o reclamo, completa todos los campos del formulario. Te responderemos en un plazo máximo de 15 días hábiles.</p>
    </div>

<?php if (!empty($errorMsg)): ?>
    <div class="lr-alert no-print" role="alert"><?= esc($errorMsg) ?></div>
<?php endif; ?>

    <div class="lr-grid">
      <div class="lr-card">
        <form method="POST" action="libro-de-reclamaciones.php">
          <input type="hidden" name="csrf_token" value="<?= esc($_SESSION['csrf_token'] ?? '') ?>">
          <input type="hidden" name="form_ts" value="<?= esc($formToken) ?>">
          <div style="position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;" aria-hidden="true">
            <label for="company_site">Sitio web de la empresa (dejar vacío)</label>
            <input type="text" name="company_site" id="company_site" tabindex="-1" autocomplete="off" value="">
          </div>

          <!-- 1 -->
          <div class="lr-sec">
            <h2><span class="lr-num">1</span> Identificación del consumidor</h2>
            <div class="lr-fields">
              <div class="lr-full">
                <label class="lr-label" for="nombres">Nombres y apellidos completos *</label>
                <input class="lr-input" type="text" id="nombres" name="nombres" required placeholder="Ingresa tus nombres completos" value="<?= old('nombres') ?>">
              </div>
              <div>
                <label class="lr-label" for="doc_tipo">Tipo de documento *</label>
                <select class="lr-input" id="doc_tipo" name="doc_tipo" required>
                  <option value="DNI"<?= sel('doc_tipo', 'DNI', true) ?>>DNI (Perú)</option>
                  <option value="CE"<?= sel('doc_tipo', 'CE') ?>>Carnet de Extranjería</option>
                  <option value="PASAPORTE"<?= sel('doc_tipo', 'PASAPORTE') ?>>Pasaporte</option>
                  <option value="RUC"<?= sel('doc_tipo', 'RUC') ?>>RUC</option>
                </select>
              </div>
              <div>
                <label class="lr-label" for="doc_nro">N° de documento *</label>
                <input class="lr-input" type="text" id="doc_nro" name="doc_nro" required placeholder="Número de documento" value="<?= old('doc_nro') ?>">
              </div>
              <div>
                <label class="lr-label" for="email">Correo electrónico *</label>
                <input class="lr-input" type="email" id="email" name="email" required placeholder="nombre@correo.com" value="<?= old('email') ?>">
              </div>
              <div>
                <label class="lr-label" for="telefono">Teléfono / celular</label>
                <input class="lr-input" type="tel" id="telefono" name="telefono" placeholder="Número de contacto" value="<?= old('telefono') ?>">
              </div>
              <div class="lr-full">
                <label class="lr-label" for="direccion">Dirección completa *</label>
                <input class="lr-input" type="text" id="direccion" name="direccion" required placeholder="Av., Calle, Nro., Dpto., Urb." value="<?= old('direccion') ?>">
              </div>
              <div>
                <label class="lr-label" for="departamento">Departamento *</label>
                <input class="lr-input" type="text" id="departamento" name="departamento" required placeholder="Ej: Lima" value="<?= old('departamento') ?>">
              </div>
              <div>
                <label class="lr-label" for="provincia">Provincia *</label>
                <input class="lr-input" type="text" id="provincia" name="provincia" required placeholder="Ej: Lima" value="<?= old('provincia') ?>">
              </div>
              <div class="lr-full">
                <label class="lr-label" for="distrito">Distrito *</label>
                <input class="lr-input" type="text" id="distrito" name="distrito" required placeholder="Ej: Miraflores" value="<?= old('distrito') ?>">
              </div>
            </div>

            <div class="lr-box">
              <label class="lr-check">
                <input type="checkbox" id="menor_edad" name="menor_edad" onclick="toggleApoderado()"<?= isset($_POST['menor_edad']) ? ' checked' : '' ?>>
                <span>Soy menor de edad (se requiere ingresar los datos de un tutor/apoderado).</span>
              </label>
              <div id="apoderado_fields" class="lr-fields lr-hidden" style="margin-top:16px;padding-top:16px;border-top:1px solid var(--border)">
                <div class="lr-full">
                  <label class="lr-label" for="apoderado_nombres">Nombres del apoderado *</label>
                  <input class="lr-input" type="text" id="apoderado_nombres" name="apoderado_nombres" placeholder="Nombres del padre, madre o apoderado" value="<?= old('apoderado_nombres') ?>">
                </div>
                <div>
                  <label class="lr-label" for="apoderado_doc_tipo">Tipo de doc. apoderado *</label>
                  <select class="lr-input" id="apoderado_doc_tipo" name="apoderado_doc_tipo">
                    <option value="DNI"<?= sel('apoderado_doc_tipo', 'DNI', true) ?>>DNI</option>
                    <option value="CE"<?= sel('apoderado_doc_tipo', 'CE') ?>>Carnet de Extranjería</option>
                    <option value="PASAPORTE"<?= sel('apoderado_doc_tipo', 'PASAPORTE') ?>>Pasaporte</option>
                  </select>
                </div>
                <div>
                  <label class="lr-label" for="apoderado_doc_nro">N° de doc. apoderado *</label>
                  <input class="lr-input" type="text" id="apoderado_doc_nro" name="apoderado_doc_nro" placeholder="N° de documento" value="<?= old('apoderado_doc_nro') ?>">
                </div>
              </div>
            </div>
          </div>

          <!-- 2 -->
          <div class="lr-sec">
            <h2><span class="lr-num">2</span> Identificación del bien contratado</h2>
            <div class="lr-fields">
              <div>
                <span class="lr-label">Tipo de bien *</span>
                <div class="lr-radios">
                  <label class="lr-radio"><input type="radio" name="bien_tipo" value="servicio" required<?= chk('bien_tipo', 'servicio', true) ?>> Servicio</label>
                  <label class="lr-radio"><input type="radio" name="bien_tipo" value="producto"<?= chk('bien_tipo', 'producto') ?>> Producto</label>
                </div>
              </div>
              <div>
                <label class="lr-label" for="monto">Monto reclamado (S/., opcional)</label>
                <input class="lr-input" type="number" step="0.01" min="0" id="monto" name="monto" placeholder="S/. 0.00" value="<?= old('monto') ?>">
              </div>
              <div class="lr-full">
                <label class="lr-label" for="bien_desc">Descripción del bien contratado</label>
                <textarea class="lr-input" rows="2" id="bien_desc" name="bien_desc" placeholder="Describe brevemente el servicio o producto contratado"><?= old('bien_desc') ?></textarea>
              </div>
            </div>
          </div>

          <!-- 3 -->
          <div class="lr-sec">
            <h2><span class="lr-num">3</span> Detalle del reclamo y pedido</h2>
            <span class="lr-label">Tipo de reclamación *</span>
            <div class="lr-types">
              <label class="lr-type">
                <input type="radio" name="reclamo_tipo" value="reclamo" required<?= chk('reclamo_tipo', 'reclamo', true) ?>>
                <div><b>Reclamo</b><small>Disconformidad relacionada a los productos o servicios contratados.</small></div>
              </label>
              <label class="lr-type">
                <input type="radio" name="reclamo_tipo" value="queja"<?= chk('reclamo_tipo', 'queja') ?>>
                <div><b>Queja</b><small>Disconformidad no relacionada a los productos o servicios. Malestar respecto a la atención.</small></div>
              </label>
            </div>
            <div class="lr-fields" style="margin-top:16px">
              <div class="lr-full">
                <label class="lr-label" for="detalle">Detalle de tu queja o reclamo *</label>
                <textarea class="lr-input" rows="4" id="detalle" name="detalle" required placeholder="Describe de forma detallada y ordenada lo ocurrido..."><?= old('detalle') ?></textarea>
              </div>
              <div class="lr-full">
                <label class="lr-label" for="pedido">Pedido concreto (¿qué solicitas?) *</label>
                <textarea class="lr-input" rows="3" id="pedido" name="pedido" required placeholder="Indica detalladamente tu solicitud (corrección, devolución, compensación, etc.)"><?= old('pedido') ?></textarea>
              </div>
            </div>
          </div>

          <div class="lr-decl">
            <label class="lr-check">
              <input type="checkbox" name="decl_veraz" value="1" required>
              <span>Declaro ser el usuario titular y que los datos consignados en esta Hoja de Reclamación son reales y verdaderos.</span>
            </label>
            <label class="lr-check">
              <input type="checkbox" name="decl_datos" value="1" required>
              <span>Acepto el tratamiento de mis datos personales para los fines de responder este reclamo, de acuerdo con la <strong>Ley N° 29733</strong> (Protección de Datos Personales).</span>
            </label>
          </div>

<?php if (HCAPTCHA_SITE_KEY !== ''): ?>
          <div class="lr-captcha"><div class="h-captcha" data-sitekey="<?= esc(HCAPTCHA_SITE_KEY) ?>"></div></div>
<?php else: ?>
          <p class="lr-warn">El formulario no está disponible temporalmente. Inténtalo más tarde.</p>
<?php endif; ?>
          <button type="submit" id="btn-submit" class="btn-fill lr-submit">PRESENTAR RECLAMACIÓN</button>
        </form>
      </div>

      <aside class="lr-side no-print">
        <div class="lr-card">
          <h3>Datos del proveedor</h3>
          <dl class="lr-dl">
            <dt>Razón social</dt><dd><?= esc(EMPRESA_RAZON_SOCIAL) ?></dd>
            <dt>RUC</dt><dd><?= esc(EMPRESA_RUC) ?></dd>
            <dt>Domicilio</dt><dd><?= esc(EMPRESA_DIRECCION) ?></dd>
            <dt>Correo de reclamaciones</dt><dd><a href="mailto:<?= esc(EMPRESA_EMAIL) ?>"><?= esc(EMPRESA_EMAIL) ?></a></dd>
          </dl>
        </div>
        <div class="lr-card">
          <h3>Libro de Reclamaciones</h3>
          <p>Conforme al Código de Protección y Defensa del Consumidor, contamos con un Libro de Reclamaciones Virtual a tu disposición.</p>
          <span class="ft-libro">
            <picture>
              <source srcset="assets/img/reclamaciones/libro-reclamaciones-card.webp" type="image/webp">
              <img src="assets/img/reclamaciones/libro-reclamaciones-card.png" alt="Libro de Reclamaciones virtual – INDECOPI" width="600" height="600" loading="lazy" decoding="async">
            </picture>
          </span>
        </div>
      </aside>
    </div>
<?php endif; ?>

  </main>

  <footer id="contacto">
    <div class="ft-top">
      <div class="ft-brand">
        <div class="ft-logo"><a href="index.html"><img src="assets/img/logos/LOGO%20ORIGINAL.webp" alt="Perfil360"></a></div>
        <p>Gestión Integral Multisectorial del Capital Humano, Outsourcing de Planillas, Intermediación Laboral y Consultoría Organizacional End-to-End.</p>
        <div class="ft-libro-wrap">
          <a class="ft-libro" href="libro-de-reclamaciones.php" aria-label="Libro de Reclamaciones virtual">
            <picture>
              <source srcset="assets/img/reclamaciones/libro-reclamaciones-card.webp" type="image/webp">
              <img src="assets/img/reclamaciones/libro-reclamaciones-card.png" alt="Libro de Reclamaciones virtual – INDECOPI" width="600" height="600" loading="lazy" decoding="async">
            </picture>
          </a>
          <a class="ft-libro-mail" href="mailto:reclamaciones@tuperfil360.com">reclamaciones@tuperfil360.com</a>
        </div>
      </div>
      <div class="ft-col">
        <p class="ft-h">Servicios</p>
        <a href="index.html#servicios">Reclutamiento &amp; Selección</a>
        <a href="index.html#servicios">Headhunting Ejecutivo</a>
        <a href="index.html#servicios">Outsourcing de Planillas</a>
        <a href="index.html#servicios">Evaluaciones 360°</a>
        <a href="index.html#servicios">Payroll Tech</a>
        <a href="index.html#servicios">Outplacement</a>
      </div>
      <div class="ft-col">
        <p class="ft-h">Empresa</p>
        <a href="index.html#proceso">Nuestro Proceso</a>
        <a href="index.html#compliance">Compliance MTPE</a>
        <a href="index.html#testimonios">Clientes</a>
        <a href="index.html#faq">Preguntas Frecuentes</a>
      </div>
      <div class="ft-col">
        <p class="ft-h">Contacto</p>
        <a href="mailto:comercial@tuperfil360.com">comercial@tuperfil360.com</a>
        <span>Lima Metropolitana, Perú</span>
        <span class="ft-badge">Registro MTPE Vigente</span>
      </div>
    </div>
    <div class="ft-bottom">
      <p>© <?= date('Y') ?> PERFIL360 SOLUTIONS S.A.C. — Todos los derechos reservados.</p>
      <div>
        <a href="index.html">Privacidad</a>
        <a href="index.html">Términos</a>
        <a href="libro-de-reclamaciones.php">Libro de Reclamaciones</a>
      </div>
    </div>
  </footer>

  <script>
    function toggleApoderado() {
      var cb = document.getElementById('menor_edad');
      var box = document.getElementById('apoderado_fields');
      if (!cb || !box) return;
      var n = document.getElementById('apoderado_nombres');
      var d = document.getElementById('apoderado_doc_nro');
      if (cb.checked) {
        box.classList.remove('lr-hidden');
        n.required = true; d.required = true;
      } else {
        box.classList.add('lr-hidden');
        n.required = false; d.required = false;
        n.value = ''; d.value = '';
      }
    }
    window.addEventListener('DOMContentLoaded', function () {
      toggleApoderado();
      var f = document.querySelector('form[method="POST"]');
      if (f) f.addEventListener('submit', function () {
        var b = document.getElementById('btn-submit');
        if (b) setTimeout(function () { b.disabled = true; }, 0);
      });
<?php if (!empty($errorMsg)): ?>
      if (typeof hcaptcha !== 'undefined') { hcaptcha.reset(); }
<?php endif; ?>
    });
  </script>
</body>
</html>
