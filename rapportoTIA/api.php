<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');

const SESSION_COOKIE = 'rapportotia_session';
const SESSION_TTL_SECONDS = 43200;
const LOGIN_WINDOW_SECONDS = 900;
const LOGIN_MAX_ATTEMPTS = 5;
const DATA_BACKUP_LIMIT = 100;

$configuredDataDir = trim((string) getenv('RAPPORTO_TIA_DATA_DIR'));
$dataDir = $configuredDataDir !== ''
    ? rtrim($configuredDataDir, "/\\")
    : (DIRECTORY_SEPARATOR === '\\' ? __DIR__ . DIRECTORY_SEPARATOR . 'data' : '/volume1/webapp-private/rapporto-tia');
$configuredAuthDir = trim((string) getenv('RAPPORTO_TIA_AUTH_DIR'));
$authDir = $configuredAuthDir !== ''
    ? rtrim($configuredAuthDir, "/\\")
    : (DIRECTORY_SEPARATOR === '\\' ? __DIR__ . DIRECTORY_SEPARATOR . 'auth-private' : '/volume1/webapp-private/rapporto-tia-auth');

$dataFile = $dataDir . DIRECTORY_SEPARATOR . 'records.json';
$usersFile = $authDir . DIRECTORY_SEPARATOR . 'users.json';
$sessionsFile = $authDir . DIRECTORY_SEPARATOR . 'sessions.json';
$attemptsFile = $authDir . DIRECTORY_SEPARATOR . 'login-attempts.json';
$setupFile = $authDir . DIRECTORY_SEPARATOR . 'setup-token.json';
$auditFile = $authDir . DIRECTORY_SEPARATOR . 'security-audit.jsonl';

function reply(int $status, array $body): void {
    http_response_code($status);
    echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
function nowIso(): string { return gmdate('Y-m-d\\TH:i:s\\Z'); }
function ensureDirectory(string $path): void {
    if (!is_dir($path) && !mkdir($path, 0770, true) && !is_dir($path)) throw new RuntimeException('Directory unavailable');
}
function decodeJson(string $raw, $default) {
    if (trim($raw) === '') return $default;
    $value = json_decode($raw, true);
    if (json_last_error() !== JSON_ERROR_NONE) throw new RuntimeException('Invalid JSON store');
    return $value;
}
function readJsonFile(string $file, $default) {
    if (!is_file($file)) return $default;
    $raw = file_get_contents($file);
    if ($raw === false) throw new RuntimeException('Store unavailable');
    return decodeJson($raw, $default);
}
function encodeJson($value): string {
    $json = json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json === false) throw new RuntimeException('JSON encoding failed');
    return $json . PHP_EOL;
}
function atomicWriteJson(string $file, $value): void {
    ensureDirectory(dirname($file));
    $json = encodeJson($value);
    $temp = $file . '.tmp-' . bin2hex(random_bytes(8));
    $handle = @fopen($temp, 'xb');
    if ($handle === false) throw new RuntimeException('Temporary store unavailable');
    try {
        $offset = 0; $length = strlen($json);
        while ($offset < $length) {
            $written = fwrite($handle, substr($json, $offset));
            if ($written === false || $written === 0) throw new RuntimeException('Temporary write failed');
            $offset += $written;
        }
        if (!fflush($handle)) throw new RuntimeException('Temporary flush failed');
        if (function_exists('fsync')) @fsync($handle);
    } catch (Throwable $error) {
        fclose($handle); @unlink($temp); throw $error;
    }
    fclose($handle);
    $check = file_get_contents($temp);
    if ($check === false) { @unlink($temp); throw new RuntimeException('Temporary verification failed'); }
    decodeJson($check, null);
    if (!@rename($temp, $file)) { @unlink($temp); throw new RuntimeException('Atomic replacement failed'); }
}
function withStoreLock(string $file, bool $exclusive, callable $callback) {
    ensureDirectory(dirname($file));
    $lock = @fopen($file . '.lock', 'c+');
    if ($lock === false) throw new RuntimeException('Lock unavailable');
    if (!flock($lock, $exclusive ? LOCK_EX : LOCK_SH)) { fclose($lock); throw new RuntimeException('Lock failed'); }
    try {
        $result = $callback(); flock($lock, LOCK_UN); fclose($lock); return $result;
    } catch (Throwable $error) {
        flock($lock, LOCK_UN); fclose($lock); throw $error;
    }
}
function mutateJsonStore(string $file, $default, callable $callback) {
    return withStoreLock($file, true, function () use ($file, $default, $callback) {
        $result = $callback(readJsonFile($file, $default));
        if (!is_array($result) || !array_key_exists('store', $result)) throw new RuntimeException('Invalid store mutation');
        atomicWriteJson($file, $result['store']);
        return $result['result'] ?? null;
    });
}
function requestBody(): array {
    $input = json_decode((string) file_get_contents('php://input'), true);
    if (!is_array($input)) reply(400, ['ok' => false, 'error' => 'Richiesta non valida']);
    return $input;
}
function requireSameOriginPost(): void {
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && ($_SERVER['HTTP_X_RAPPORTOTIA_REQUEST'] ?? '') !== '1')
        reply(403, ['ok' => false, 'error' => 'Richiesta non autorizzata']);
}
function usersDefault(): array { return ['version' => 1, 'users' => []]; }
function sessionsDefault(): array { return ['version' => 1, 'sessions' => []]; }
function attemptsDefault(): array { return ['version' => 1, 'attempts' => []]; }
function normalizedUsername(string $username): string { return strtolower(trim($username)); }
function validUsername(string $username): bool { return preg_match('/^[A-Za-z0-9._-]{3,64}$/', $username) === 1; }
function validPassword(string $password): bool {
    return strlen($password) >= 12 && strlen($password) <= 200
        && preg_match('/[A-Za-z]/', $password) === 1 && preg_match('/[0-9]/', $password) === 1;
}
function findUserByUsername(array $store, string $username): ?array {
    $needle = normalizedUsername($username);
    foreach (($store['users'] ?? []) as $user)
        if (is_array($user) && normalizedUsername((string) ($user['username'] ?? '')) === $needle) return $user;
    return null;
}
function findUserById(array $store, string $id): ?array {
    foreach (($store['users'] ?? []) as $user)
        if (is_array($user) && hash_equals((string) ($user['id'] ?? ''), $id)) return $user;
    return null;
}
function isInitialized(string $usersFile): bool {
    $store = readJsonFile($usersFile, usersDefault());
    return !empty($store['users']) && is_array($store['users']);
}
function setSessionCookie(string $token, int $expires): void {
    setcookie(SESSION_COOKIE, $token, ['expires' => $expires, 'path' => '/ste/', 'secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
}
function clearSessionCookie(): void {
    setcookie(SESSION_COOKIE, '', ['expires' => time() - 3600, 'path' => '/ste/', 'secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
}
function createSession(string $sessionsFile, array $user): void {
    $token = bin2hex(random_bytes(32)); $tokenHash = hash('sha256', $token); $now = time(); $expires = $now + SESSION_TTL_SECONDS;
    mutateJsonStore($sessionsFile, sessionsDefault(), function ($store) use ($user, $tokenHash, $now, $expires) {
        $sessions = [];
        foreach (($store['sessions'] ?? []) as $session)
            if (is_array($session) && (int) ($session['expiresAt'] ?? 0) > $now) $sessions[] = $session;
        $sessions[] = ['id' => bin2hex(random_bytes(16)), 'tokenHash' => $tokenHash, 'userId' => (string) $user['id'],
            'userVersion' => (int) ($user['sessionVersion'] ?? 1), 'createdAt' => $now, 'lastSeenAt' => $now, 'expiresAt' => $expires];
        $store['version'] = 1; $store['sessions'] = $sessions;
        return ['store' => $store, 'result' => null];
    });
    setSessionCookie($token, $expires);
}
function currentUser(string $usersFile, string $sessionsFile): ?array {
    $token = (string) ($_COOKIE[SESSION_COOKIE] ?? '');
    if ($token === '' || strlen($token) > 256) return null;
    $tokenHash = hash('sha256', $token); $now = time(); $matched = null;
    $sessions = readJsonFile($sessionsFile, sessionsDefault());
    foreach (($sessions['sessions'] ?? []) as $session) {
        if (!is_array($session) || (int) ($session['expiresAt'] ?? 0) <= $now) continue;
        if (hash_equals((string) ($session['tokenHash'] ?? ''), $tokenHash)) { $matched = $session; break; }
    }
    if ($matched === null) return null;
    $user = findUserById(readJsonFile($usersFile, usersDefault()), (string) ($matched['userId'] ?? ''));
    if ($user === null || empty($user['active'])) return null;
    if ((int) ($matched['userVersion'] ?? 0) !== (int) ($user['sessionVersion'] ?? 1)) return null;
    return $user;
}
function requireUser(string $usersFile, string $sessionsFile): array {
    $user = currentUser($usersFile, $sessionsFile);
    if ($user === null) { clearSessionCookie(); reply(401, ['ok' => false, 'error' => 'Autenticazione richiesta']); }
    return $user;
}
function audit(string $auditFile, string $event, ?string $userId = null): void {
    try {
        ensureDirectory(dirname($auditFile));
        $entry = json_encode(['time' => nowIso(), 'event' => $event, 'userId' => $userId,
            'ipHash' => hash('sha256', (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown'))], JSON_UNESCAPED_SLASHES) . PHP_EOL;
        $lock = fopen($auditFile . '.lock', 'c+');
        if ($lock !== false && flock($lock, LOCK_EX)) { file_put_contents($auditFile, $entry, FILE_APPEND); flock($lock, LOCK_UN); }
        if (is_resource($lock)) fclose($lock);
    } catch (Throwable $ignored) {}
}
function loginAttemptKey(string $username): string {
    return hash('sha256', (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . "\\n" . normalizedUsername($username));
}
function loginBlocked(string $attemptsFile, string $key): bool {
    $store = readJsonFile($attemptsFile, attemptsDefault()); $cutoff = time() - LOGIN_WINDOW_SECONDS;
    $times = $store['attempts'][$key] ?? [];
    return count(array_filter(is_array($times) ? $times : [], fn($value) => (int) $value >= $cutoff)) >= LOGIN_MAX_ATTEMPTS;
}
function recordLoginAttempt(string $attemptsFile, string $key, bool $success): void {
    mutateJsonStore($attemptsFile, attemptsDefault(), function ($store) use ($key, $success) {
        $cutoff = time() - LOGIN_WINDOW_SECONDS; $clean = [];
        foreach (($store['attempts'] ?? []) as $storedKey => $times) {
            $recent = array_values(array_filter(is_array($times) ? $times : [], fn($value) => (int) $value >= $cutoff));
            if ($recent) $clean[$storedKey] = $recent;
        }
        if ($success) unset($clean[$key]); else $clean[$key] = array_merge($clean[$key] ?? [], [time()]);
        $store['version'] = 1; $store['attempts'] = $clean;
        return ['store' => $store, 'result' => null];
    });
}
function validRecord($record): bool {
    if (!is_array($record) || !isset($record['name']) || !is_string($record['name']) || trim($record['name']) === '' || strlen(trim($record['name'])) > 160) return false;
    if (isset($record['stages']) && is_array($record['stages'])) return true;
    if (isset($record['axes']) && is_array($record['axes'])) {
        foreach ($record['axes'] as $axis)
            if (!is_array($axis) || !isset($axis['name'], $axis['config']) || !is_string($axis['name']) || trim($axis['name']) === ''
                || !is_array($axis['config']) || !isset($axis['config']['stages']) || !is_array($axis['config']['stages'])) return false;
        return true;
    }
    return false;
}
function readRecordsLocked(string $dataFile): array {
    return withStoreLock($dataFile, false, function () use ($dataFile) {
        $records = readJsonFile($dataFile, []);
        if (!is_array($records)) throw new RuntimeException('Invalid records store');
        return array_values($records);
    });
}
function archiveExcessBackups(string $backupDir): void {
    $files = glob($backupDir . DIRECTORY_SEPARATOR . 'records-before-*.json') ?: [];
    if (count($files) <= DATA_BACKUP_LIMIT) return;
    sort($files, SORT_STRING); $archiveDir = $backupDir . DIRECTORY_SEPARATOR . 'archive'; ensureDirectory($archiveDir);
    foreach (array_slice($files, 0, count($files) - DATA_BACKUP_LIMIT) as $file) {
        $destination = $archiveDir . DIRECTORY_SEPARATOR . basename($file);
        if (!file_exists($destination)) @rename($file, $destination);
    }
}
function mutateRecordsAtomic(string $dataFile, callable $mutation): array {
    return withStoreLock($dataFile, true, function () use ($dataFile, $mutation) {
        $records = readJsonFile($dataFile, []);
        if (!is_array($records)) throw new RuntimeException('Invalid records store');
        $result = $mutation(array_values($records));
        if (!is_array($result) || !isset($result['records']) || !is_array($result['records']))
            throw new RuntimeException('Invalid records mutation');
        $backupDir = dirname($dataFile) . DIRECTORY_SEPARATOR . 'backup'; ensureDirectory($backupDir);
        if (is_file($dataFile)) {
            $backup = $backupDir . DIRECTORY_SEPARATOR . 'records-before-' . gmdate('Ymd-His') . '-' . bin2hex(random_bytes(4)) . '.json';
            if (!copy($dataFile, $backup) || !is_array(readJsonFile($backup, null))) throw new RuntimeException('Backup failed');
        }
        atomicWriteJson($dataFile, array_values($result['records']));
        if (!is_array(readJsonFile($dataFile, null))) throw new RuntimeException('Records verification failed');
        archiveExcessBackups($backupDir);
        return $result;
    });
}

ensureDirectory($dataDir);
$method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
$queryAction = (string) ($_GET['action'] ?? '');

try {
    if ($method === 'GET' && $queryAction === 'status') {
        reply(200, ['ok' => true, 'initialized' => true, 'authenticated' => true, 'public' => true,
            'user' => ['username' => 'pubblico', 'role' => 'public']]);
    }
    if ($method === 'GET' && ($queryAction === '' || $queryAction === 'list')) {
        reply(200, ['ok' => true, 'records' => readRecordsLocked($dataFile)]);
    }
    if ($method === 'POST') {
        requireSameOriginPost(); $input = requestBody(); $action = (string) ($input['action'] ?? '');
        if (!in_array($action, ['save', 'delete', 'import'], true)) reply(400, ['ok' => false, 'error' => 'Richiesta non valida']);
        $result = mutateRecordsAtomic($dataFile, function ($records) use ($action, $input) {
            $updated = false;
            if ($action === 'save') {
                $record = $input['record'] ?? null; if (!validRecord($record)) reply(400, ['ok' => false, 'error' => 'Record non valido']);
                $record['name'] = trim((string) $record['name']); $index = null;
                foreach ($records as $i => $existing) if (isset($existing['name']) && strcasecmp((string) $existing['name'], $record['name']) === 0) { $index = $i; break; }
                if ($index === null) $records[] = $record; else { $records[$index] = $record; $updated = true; }
            } elseif ($action === 'delete') {
                $name = trim((string) ($input['name'] ?? '')); if ($name === '') reply(400, ['ok' => false, 'error' => 'Record non valido']);
                $before = count($records); $records = array_values(array_filter($records, fn($r) => !isset($r['name']) || strcasecmp((string) $r['name'], $name) !== 0));
                $updated = count($records) !== $before;
            } else {
                $incoming = $input['records'] ?? null; if (!is_array($incoming)) reply(400, ['ok' => false, 'error' => 'Importazione non valida']);
                foreach ($incoming as $record) {
                    if (!validRecord($record)) reply(400, ['ok' => false, 'error' => 'Importazione non valida']);
                    $record['name'] = trim((string) $record['name']); $index = null;
                    foreach ($records as $i => $existing) if (isset($existing['name']) && strcasecmp((string) $existing['name'], $record['name']) === 0) { $index = $i; break; }
                    if ($index === null) $records[] = $record; else { $records[$index] = $record; $updated = true; }
                }
            }
            return ['records' => $records, 'updated' => $updated];
        });
        reply(200, ['ok' => true, 'records' => $result['records'], 'updated' => $result['updated']]);
    }
    if (!in_array($method, ['GET', 'POST'], true)) reply(405, ['ok' => false, 'error' => 'Metodo non consentito']);
    reply(400, ['ok' => false, 'error' => 'Richiesta non valida']);
} catch (Throwable $error) {
    reply(500, ['ok' => false, 'error' => 'Errore interno del servizio']);
}
