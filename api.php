<?php
/*
 * ITHC CRM — API (PHP + MySQL)
 * ফ্রন্টএন্ড এখানে POST করে: { action, token, payload }
 * প্রতিটি অনুরোধে সার্ভারেই লগইন ও পারমিশন যাচাই হয়।
 */
require __DIR__ . '/config.php';

date_default_timezone_set('Asia/Dhaka');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

const ALL_PERMS = array(
    'lead.create', 'lead.read', 'lead.update', 'lead.archive',
    'comm.create', 'comm.read',
    'user.create', 'user.read', 'user.update', 'user.approve', 'user.reject',
    'user.activate', 'user.deactivate', 'user.role.change',
    'campaign.create', 'campaign.read', 'campaign.update',
    'dashboard.read', 'settings.read', 'settings.update', 'activity.read', 'department.read'
);
const CLOSED_STATUSES = array('CONVERTED', 'NOT_INTERESTED', 'LOST');
const LEAD_SOURCES = array('WhatsApp', 'Facebook Ads', 'Phone Call', 'Website/Form');
const COMM_TYPES = array('PHONE', 'WHATSAPP', 'MESSENGER', 'SMS', 'EMAIL');
const COMM_RESULTS = array('INTERESTED', 'INFORMATION_SENT', 'HOSPITAL_SUGGESTED', 'CALL_BACK', 'NO_RESPONSE', 'CONVERTED', 'NOT_INTERESTED');
const ROLES = array('MASTER_ADMIN', 'ADMIN', 'OPERATOR');
const SETTING_KEYS = array('MASTER_ADMIN_EMAIL', 'COMPANY_NAME', 'DEFAULT_LEAD_GRADE', 'FOLLOWUP_REMINDER');

$ME = null;

/* ---------- Response helpers ---------- */
function out($arr) {
    echo json_encode($arr, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
function ok($data = null, $message = '', $extra = array()) {
    out(array_merge(array('success' => true, 'message' => $message, 'data' => $data), $extra));
}
function fail($message) {
    out(array('success' => false, 'message' => $message));
}
function auth_fail() {
    out(array('success' => false, 'authError' => true, 'message' => 'লগইন সেশন শেষ হয়েছে। আবার লগইন করুন।'));
}

/* ---------- Input helpers ---------- */
function s($v, $max = 255) {
    $v = is_scalar($v) ? (string)$v : '';
    $v = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', '', $v);
    return mb_substr(trim($v), 0, $max, 'UTF-8');
}
function fid($prefix, $n, $w = 5) {
    return $prefix . '-' . str_pad((string)$n, $w, '0', STR_PAD_LEFT);
}
function pid($prefix, $str) {
    return preg_match('/^' . preg_quote($prefix, '/') . '-(\d+)$/i', (string)$str, $m) ? (int)$m[1] : 0;
}
function iso($dt) {
    return $dt ? date('c', strtotime($dt)) : '';
}
// খালি হলে null, ভুল হলে false, ঠিক হলে তারিখ স্ট্রিং
function valid_date($d) {
    $d = s($d, 10);
    if ($d === '') return null;
    $dt = DateTime::createFromFormat('Y-m-d', $d);
    return ($dt && $dt->format('Y-m-d') === $d) ? $d : false;
}

/* ---------- Settings / permissions ---------- */
function get_setting($key, $default = '') {
    $st = db()->prepare('SELECT setting_value FROM settings WHERE setting_key=?');
    $st->execute(array($key));
    $v = $st->fetchColumn();
    return $v === false ? $default : $v;
}
function set_setting($key, $value) {
    $st = db()->prepare('INSERT INTO settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)');
    $st->execute(array($key, $value));
}
function perms_for($role) {
    if ($role === 'MASTER_ADMIN') return ALL_PERMS;
    $st = db()->prepare('SELECT permission FROM role_permissions WHERE role=?');
    $st->execute(array($role));
    return array_values(array_intersect($st->fetchAll(PDO::FETCH_COLUMN), ALL_PERMS));
}
function can($perm) {
    global $ME;
    return $ME && in_array($perm, $ME['permissions'], true);
}
function need($perm) {
    if (!can($perm)) fail('এই কাজের অনুমতি আপনার নেই।');
}
function is_master() {
    global $ME;
    return $ME && $ME['role'] === 'MASTER_ADMIN';
}
function user_payload($u) {
    return array(
        'userId' => fid('USR', $u['id']),
        'email' => $u['gmail'],
        'role' => $u['role'],
        'fullName' => $u['full_name'],
        'permissions' => $u['permissions'],
    );
}

/* ---------- Auth / sessions ---------- */
function token_hash($token) {
    return hash('sha256', $token);
}
function authenticate($token) {
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) return null;
    $st = db()->prepare('SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > NOW()');
    $st->execute(array(token_hash($token)));
    $u = $st->fetch();
    if (!$u || $u['status'] !== 'APPROVED' || !(int)$u['active']) return null;
    $u['permissions'] = perms_for($u['role']);
    return $u;
}
function rl_count($bucket, $minutes) {
    $st = db()->prepare('SELECT COUNT(*) FROM rate_limits WHERE bucket=? AND created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)');
    $st->execute(array($bucket, $minutes));
    return (int)$st->fetchColumn();
}
function rl_hit($bucket) {
    $st = db()->prepare('INSERT INTO rate_limits (bucket, created_at) VALUES (?, NOW())');
    $st->execute(array($bucket));
}
function valid_password($pw) {
    return mb_strlen($pw, 'UTF-8') >= 8 && mb_strlen($pw, 'UTF-8') <= 100;
}

/* ---------- Audit log ---------- */
function log_activity($target, $action, $field = '', $old = '', $new = '', $note = '') {
    global $ME;
    $st = db()->prepare('INSERT INTO activity_logs (target_id, user_id, user_name, action, field_name, old_value, new_value, note, created_at) VALUES (?,?,?,?,?,?,?,?,NOW())');
    $st->execute(array(
        mb_substr((string)$target, 0, 30, 'UTF-8'),
        $ME ? $ME['id'] : null,
        $ME ? $ME['full_name'] : 'SYSTEM',
        mb_substr((string)$action, 0, 40, 'UTF-8'),
        mb_substr((string)$field, 0, 60, 'UTF-8'),
        mb_substr((string)$old, 0, 255, 'UTF-8'),
        mb_substr((string)$new, 0, 255, 'UTF-8'),
        mb_substr((string)$note, 0, 255, 'UTF-8'),
    ));
}

/* ---------- Row mappers ---------- */
function lead_row($r) {
    return array(
        'Lead_ID' => fid('ITHC', $r['id']),
        'Patient_Name' => $r['patient_name'],
        'Mobile' => $r['mobile'],
        'Department' => $r['department'],
        'Medical_Problem' => $r['medical_problem'],
        'Lead_Grade' => $r['lead_grade'],
        'Lead_Status' => $r['lead_status'],
        'Campaign_ID' => $r['campaign_id'] ? fid('CMP', $r['campaign_id']) : '',
        'Lead_Source' => $r['lead_source'],
        'Assigned_To' => $r['assigned_to'],
        'Communication_Count' => (int)$r['communication_count'],
        'Next_Followup_Date' => $r['next_followup_date'] ? $r['next_followup_date'] : '',
        'Patient_Note' => $r['patient_note'],
        'Version' => (int)$r['version'],
        'Active' => (bool)$r['active'],
        'Created_At' => iso($r['created_at']),
    );
}
function user_row($r) {
    return array(
        'User_ID' => fid('USR', $r['id']),
        'Full_Name' => $r['full_name'],
        'Gmail' => $r['gmail'],
        'Role' => $r['role'],
        'Status' => $r['status'],
        'Active' => (bool)$r['active'],
        'Created_At' => iso($r['created_at']),
    );
}

/* ---------- Lead validation (create + update) ---------- */
function validate_lead($p, $isUpdate) {
    $c = array();
    $c['patient_name'] = s(isset($p['Patient_Name']) ? $p['Patient_Name'] : '', 120);
    $c['mobile'] = s(isset($p['Mobile']) ? $p['Mobile'] : '', 25);
    $c['department'] = s(isset($p['Department']) ? $p['Department'] : '', 100);
    $c['medical_problem'] = s(isset($p['Medical_Problem']) ? $p['Medical_Problem'] : '', 2000);
    $c['patient_note'] = s(isset($p['Patient_Note']) ? $p['Patient_Note'] : '', 500);

    if ($c['patient_name'] === '') fail('রোগীর নাম দিন।');
    if (!preg_match('/^[0-9+\-\s()]{6,25}$/', $c['mobile'])) fail('মোবাইল নম্বর সঠিক নয়।');
    if ($c['medical_problem'] === '') fail('রোগীর সমস্যা লিখুন।');

    $st = db()->prepare('SELECT COUNT(*) FROM departments WHERE name=?');
    $st->execute(array($c['department']));
    if (!(int)$st->fetchColumn()) fail('বিভাগ সঠিক নয়।');

    $grade = s(isset($p['Lead_Grade']) ? $p['Lead_Grade'] : '', 1);
    if ($grade === '') $grade = get_setting('DEFAULT_LEAD_GRADE', 'C');
    if (!in_array($grade, array('A', 'B', 'C'), true)) fail('গ্রেড সঠিক নয়।');
    $c['lead_grade'] = $grade;

    $date = valid_date(isset($p['Next_Followup_Date']) ? $p['Next_Followup_Date'] : '');
    if ($date === false) fail('ফলো-আপ তারিখ সঠিক নয়।');
    $c['next_followup_date'] = $date;

    if ($isUpdate) {
        $status = s(isset($p['Lead_Status']) ? $p['Lead_Status'] : '', 40);
        $st = db()->prepare('SELECT COUNT(*) FROM statuses WHERE name=?');
        $st->execute(array($status));
        if (!(int)$st->fetchColumn()) fail('স্ট্যাটাস সঠিক নয়।');
        $c['lead_status'] = $status;
    } else {
        $src = s(isset($p['Lead_Source']) ? $p['Lead_Source'] : '', 40);
        $c['lead_source'] = in_array($src, LEAD_SOURCES, true) ? $src : 'WhatsApp';
        $cid = pid('CMP', isset($p['Campaign_ID']) ? $p['Campaign_ID'] : '');
        if ($cid) {
            $st = db()->prepare('SELECT COUNT(*) FROM campaigns WHERE id=?');
            $st->execute(array($cid));
            if (!(int)$st->fetchColumn()) fail('ক্যাম্পেইন পাওয়া যায়নি।');
            $c['campaign_id'] = $cid;
        } else {
            $c['campaign_id'] = null;
        }
    }
    return $c;
}

/* =====================================================================
 *                           MAIN ROUTER
 * ===================================================================== */
try {
    $raw = file_get_contents('php://input');
    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || strlen($raw) > 200000) fail('Invalid request');
    $req = json_decode($raw, true);
    if (!is_array($req)) fail('Invalid request');

    $action = s(isset($req['action']) ? $req['action'] : '', 40);
    $token = s(isset($req['token']) ? $req['token'] : '', 80);
    $p = (isset($req['payload']) && is_array($req['payload'])) ? $req['payload'] : array();
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';

    /* ----- Public actions (লগইন ছাড়া) ----- */
    if ($action === 'auth.login') {
        $email = strtolower(s(isset($p['email']) ? $p['email'] : '', 190));
        $pw = isset($p['password']) && is_string($p['password']) ? $p['password'] : '';
        $b1 = 'login:' . $email;
        $b2 = 'loginip:' . $ip;
        if (rl_count($b1, 15) >= 5 || rl_count($b2, 15) >= 40) {
            fail('অনেকবার ভুল চেষ্টা হয়েছে। ১৫ মিনিট পর আবার চেষ্টা করুন।');
        }
        $st = db()->prepare('SELECT * FROM users WHERE gmail=?');
        $st->execute(array($email));
        $u = $st->fetch();
        $hash = $u ? $u['password_hash'] : password_hash('dummy-password-for-timing', PASSWORD_DEFAULT);
        $pwOk = password_verify($pw, $hash);
        if (!$u || !$pwOk) {
            rl_hit($b1);
            rl_hit($b2);
            fail('ইমেইল বা পাসওয়ার্ড ভুল।');
        }
        if ($u['status'] === 'PENDING') fail('আপনার অ্যাকাউন্ট এখনো অনুমোদন হয়নি।');
        if ($u['status'] === 'REJECTED') fail('আপনার রেজিস্ট্রেশন গ্রহণ করা হয়নি।');
        if (!(int)$u['active']) fail('আপনার অ্যাকাউন্ট নিষ্ক্রিয় করা আছে।');

        $tok = bin2hex(random_bytes(32));
        $st = db()->prepare('INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ? HOUR), NOW())');
        $st->execute(array(token_hash($tok), $u['id'], (int)SESSION_HOURS));
        db()->prepare('DELETE FROM rate_limits WHERE bucket=?')->execute(array($b1));
        // পুরনো ডেটা পরিষ্কার
        db()->exec('DELETE FROM sessions WHERE expires_at < NOW()');
        db()->exec('DELETE FROM rate_limits WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 DAY)');

        $u['permissions'] = perms_for($u['role']);
        $ME = $u;
        log_activity(fid('USR', $u['id']), 'LOGIN', '', '', '', 'Signed in');
        ok(array('token' => $tok, 'user' => user_payload($u), 'companyName' => get_setting('COMPANY_NAME', 'ITHC CRM')));
    }

    if ($action === 'user.register' || $action === 'auth.register') {
        if (rl_count('reg:' . $ip, 60) >= 5) fail('অনেকবার চেষ্টা হয়েছে। কিছুক্ষণ পর আবার চেষ্টা করুন।');
        $name = s(isset($p['Full_Name']) ? $p['Full_Name'] : '', 120);
        $gmail = strtolower(s(isset($p['Gmail']) ? $p['Gmail'] : '', 190));
        $pw = isset($p['Password']) && is_string($p['Password']) ? $p['Password'] : '';
        if ($name === '') fail('পুরো নাম দিন।');
        if (!filter_var($gmail, FILTER_VALIDATE_EMAIL)) fail('ইমেইল সঠিক নয়।');
        if (!valid_password($pw)) fail('পাসওয়ার্ড কমপক্ষে ৮ অক্ষরের হতে হবে।');
        rl_hit('reg:' . $ip);
        $st = db()->prepare('SELECT COUNT(*) FROM users WHERE gmail=?');
        $st->execute(array($gmail));
        if ((int)$st->fetchColumn()) fail('এই ইমেইল দিয়ে আগেই রেজিস্ট্রেশন হয়েছে।');
        $st = db()->prepare("INSERT INTO users (full_name, gmail, password_hash, role, status, active, created_at) VALUES (?,?,?,'OPERATOR','PENDING',1,NOW())");
        $st->execute(array($name, $gmail, password_hash($pw, PASSWORD_DEFAULT)));
        ok(null, 'রেজিস্ট্রেশন জমা হয়েছে। অ্যাডমিনের অনুমোদনের অপেক্ষা করুন।');
    }

    /* ----- এরপর সব কিছুর জন্য লগইন দরকার ----- */
    $ME = authenticate($token);
    if (!$ME) auth_fail();

    switch ($action) {

        case 'auth.me':
            ok(array('user' => user_payload($ME), 'companyName' => get_setting('COMPANY_NAME', 'ITHC CRM')));
            break;

        case 'auth.logout':
            db()->prepare('DELETE FROM sessions WHERE token_hash=?')->execute(array(token_hash($token)));
            ok(null, 'Logged out');
            break;

        case 'auth.changePassword':
            $cur = isset($p['current']) && is_string($p['current']) ? $p['current'] : '';
            $new = isset($p['new']) && is_string($p['new']) ? $p['new'] : '';
            if (!password_verify($cur, $ME['password_hash'])) fail('বর্তমান পাসওয়ার্ড ভুল।');
            if (!valid_password($new)) fail('নতুন পাসওয়ার্ড কমপক্ষে ৮ অক্ষরের হতে হবে।');
            if ($new === $cur) fail('নতুন পাসওয়ার্ড আগেরটির মতো হতে পারবে না।');
            db()->prepare('UPDATE users SET password_hash=? WHERE id=?')->execute(array(password_hash($new, PASSWORD_DEFAULT), $ME['id']));
            // বর্তমান সেশন ছাড়া বাকি সব সেশন বাতিল
            db()->prepare('DELETE FROM sessions WHERE user_id=? AND token_hash<>?')->execute(array($ME['id'], token_hash($token)));
            log_activity(fid('USR', $ME['id']), 'PASSWORD_CHANGE', '', '', '', 'Password changed');
            ok(null, 'পাসওয়ার্ড পরিবর্তন হয়েছে।');
            break;

        /* ---------- Lookups ---------- */
        case 'departments.list':
            need('department.read');
            $rows = db()->query('SELECT id, name FROM departments ORDER BY name')->fetchAll();
            $data = array();
            foreach ($rows as $r) $data[] = array('Department_ID' => fid('DEP', $r['id'], 3), 'Department_Name' => $r['name']);
            ok($data);
            break;

        case 'status.list':
            $rows = db()->query('SELECT name FROM statuses ORDER BY sort_order, name')->fetchAll(PDO::FETCH_COLUMN);
            ok($rows);
            break;

        /* ---------- Dashboard ---------- */
        case 'dashboard':
            need('dashboard.read');
            $pdo = db();
            $row = $pdo->query("SELECT COUNT(*) AS total, SUM(lead_status='NEW') AS new_leads, SUM(lead_grade='A') AS ga, SUM(lead_grade='B') AS gb, SUM(lead_grade='C') AS gc, SUM(lead_status='CONVERTED') AS conv FROM leads WHERE active=1")->fetch();
            $st = $pdo->prepare("SELECT COUNT(*) FROM leads WHERE active=1 AND next_followup_date IS NOT NULL AND next_followup_date <= ? AND lead_status NOT IN ('CONVERTED','NOT_INTERESTED','LOST')");
            $st->execute(array(date('Y-m-d')));
            $followupDue = (int)$st->fetchColumn();
            $comms = (int)$pdo->query('SELECT COUNT(*) FROM communications c JOIN leads l ON l.id=c.lead_id WHERE l.active=1')->fetchColumn();
            $pending = can('user.read') ? (int)$pdo->query("SELECT COUNT(*) FROM users WHERE status='PENDING'")->fetchColumn() : 0;
            $totalCost = null;
            $avgCpl = null;
            if (can('campaign.read')) {
                $totalCost = (float)$pdo->query('SELECT COALESCE(SUM(cost),0) FROM campaigns')->fetchColumn();
                $withCampaign = (int)$pdo->query('SELECT COUNT(*) FROM leads WHERE active=1 AND campaign_id IS NOT NULL')->fetchColumn();
                $avgCpl = $withCampaign > 0 ? (string)round($totalCost / $withCampaign) : 'N/A';
            }
            ok(array(
                'totalActiveLeads' => (int)$row['total'],
                'newLeads' => (int)$row['new_leads'],
                'gradeA' => (int)$row['ga'],
                'gradeB' => (int)$row['gb'],
                'gradeC' => (int)$row['gc'],
                'followupDue' => $followupDue,
                'converted' => (int)$row['conv'],
                'totalCommunications' => $comms,
                'pendingUsers' => $pending,
                'totalCampaignCost' => $totalCost,
                'averageCPL' => $avgCpl,
            ));
            break;

        /* ---------- Leads ---------- */
        case 'lead.list':
            need('lead.read');
            $where = array('active=1');
            $args = array();
            $grade = s(isset($p['Lead_Grade']) ? $p['Lead_Grade'] : '', 1);
            if (in_array($grade, array('A', 'B', 'C'), true)) { $where[] = 'lead_grade=?'; $args[] = $grade; }
            $status = s(isset($p['Lead_Status']) ? $p['Lead_Status'] : '', 40);
            if ($status !== '') { $where[] = 'lead_status=?'; $args[] = $status; }
            $dept = s(isset($p['Department']) ? $p['Department'] : '', 100);
            if ($dept !== '') { $where[] = 'department=?'; $args[] = $dept; }
            $q = s(isset($p['q']) ? $p['q'] : '', 60);
            if ($q !== '') {
                $like = '%' . str_replace(array('\\', '%', '_'), array('\\\\', '\\%', '\\_'), $q) . '%';
                $idq = pid('ITHC', $q);
                if ($idq) { $where[] = '(patient_name LIKE ? OR mobile LIKE ? OR id=?)'; $args[] = $like; $args[] = $like; $args[] = $idq; }
                else { $where[] = '(patient_name LIKE ? OR mobile LIKE ?)'; $args[] = $like; $args[] = $like; }
            }
            $order = 'id DESC';
            if (!empty($p['priority'])) {
                $where[] = "lead_status NOT IN ('CONVERTED','NOT_INTERESTED','LOST')";
                $order = "FIELD(lead_grade,'A','B','C'), (next_followup_date IS NULL), next_followup_date ASC, id DESC";
            }
            $limit = isset($p['limit']) ? (int)$p['limit'] : 300;
            if ($limit < 1) $limit = 1;
            if ($limit > 500) $limit = 500;
            $st = db()->prepare('SELECT * FROM leads WHERE ' . implode(' AND ', $where) . ' ORDER BY ' . $order . ' LIMIT ' . $limit);
            $st->execute($args);
            $rows = array();
            foreach ($st->fetchAll() as $r) $rows[] = lead_row($r);
            ok(array('rows' => $rows, 'total' => count($rows)));
            break;

        case 'lead.get':
            need('lead.read');
            $st = db()->prepare('SELECT * FROM leads WHERE id=? AND active=1');
            $st->execute(array(pid('ITHC', isset($p['Lead_ID']) ? $p['Lead_ID'] : '')));
            $r = $st->fetch();
            if (!$r) fail('Lead পাওয়া যায়নি।');
            ok(lead_row($r));
            break;

        case 'lead.create':
            need('lead.create');
            $c = validate_lead($p, false);
            $st = db()->prepare("INSERT INTO leads (patient_name, mobile, department, medical_problem, lead_grade, lead_status, campaign_id, lead_source, assigned_to, communication_count, next_followup_date, patient_note, version, active, created_by, created_at) VALUES (?,?,?,?,?,'NEW',?,?,?,0,?,?,1,1,?,NOW())");
            $st->execute(array(
                $c['patient_name'], $c['mobile'], $c['department'], $c['medical_problem'], $c['lead_grade'],
                $c['campaign_id'], $c['lead_source'], $ME['full_name'], $c['next_followup_date'], $c['patient_note'], $ME['id']
            ));
            $lid = fid('ITHC', db()->lastInsertId());
            log_activity($lid, 'LEAD_CREATE', 'Lead_ID', '', $lid, 'Created lead');
            ok(array('Lead_ID' => $lid), 'রোগীর লিড তৈরি হয়েছে: ' . $lid);
            break;

        case 'lead.update':
            need('lead.update');
            $id = pid('ITHC', isset($p['Lead_ID']) ? $p['Lead_ID'] : '');
            $c = validate_lead($p, true);
            $pdo = db();
            $pdo->beginTransaction();
            $st = $pdo->prepare('SELECT * FROM leads WHERE id=? AND active=1 FOR UPDATE');
            $st->execute(array($id));
            $old = $st->fetch();
            if (!$old) { $pdo->rollBack(); fail('Lead পাওয়া যায়নি।'); }
            if ((int)(isset($p['Version']) ? $p['Version'] : 0) !== (int)$old['version']) {
                $pdo->rollBack();
                fail('এই রেকর্ডটি অন্য কেউ এর মধ্যে আপডেট করেছে। Refresh দিয়ে আবার চেষ্টা করুন।');
            }
            $map = array(
                'patient_name' => 'Patient_Name', 'mobile' => 'Mobile', 'department' => 'Department',
                'medical_problem' => 'Medical_Problem', 'lead_grade' => 'Lead_Grade', 'lead_status' => 'Lead_Status',
                'next_followup_date' => 'Next_Followup_Date', 'patient_note' => 'Patient_Note'
            );
            $sets = array(); $args = array(); $changes = array();
            foreach ($map as $col => $label) {
                $o = (string)(isset($old[$col]) ? $old[$col] : '');
                $n = (string)(isset($c[$col]) ? $c[$col] : '');
                if ($o !== $n) {
                    $sets[] = $col . '=?';
                    $args[] = ($n === '' && $col === 'next_followup_date') ? null : $n;
                    $changes[] = array($label, $o, $n);
                }
            }
            if (!$changes) { $pdo->commit(); ok(array('Version' => (int)$old['version']), 'কোনো পরিবর্তন নেই।'); }
            $sets[] = 'version=version+1';
            $sets[] = 'updated_at=NOW()';
            $args[] = $id;
            $pdo->prepare('UPDATE leads SET ' . implode(', ', $sets) . ' WHERE id=?')->execute($args);
            $lid = fid('ITHC', $id);
            foreach ($changes as $ch) {
                $hide = in_array($ch[0], array('Medical_Problem', 'Patient_Note'), true); // সংবেদনশীল লেখা লগে কপি করা হয় না
                log_activity($lid, 'LEAD_UPDATE', $ch[0], $hide ? '' : $ch[1], $hide ? '[edited]' : $ch[2], 'Lead updated');
            }
            $pdo->commit();
            ok(array('Version' => (int)$old['version'] + 1), 'রোগীর রেকর্ড আপডেট হয়েছে।');
            break;

        case 'lead.archive':
            need('lead.archive');
            $id = pid('ITHC', isset($p['Lead_ID']) ? $p['Lead_ID'] : '');
            $st = db()->prepare('UPDATE leads SET active=0, version=version+1, updated_at=NOW() WHERE id=? AND active=1');
            $st->execute(array($id));
            if (!$st->rowCount()) fail('Lead পাওয়া যায়নি।');
            log_activity(fid('ITHC', $id), 'LEAD_ARCHIVE', 'Active', '1', '0', 'Lead archived');
            ok(null, 'Lead archived');
            break;

        /* ---------- Communications ---------- */
        case 'comm.list':
            need('comm.read');
            $st = db()->prepare('SELECT * FROM communications WHERE lead_id=? ORDER BY id DESC LIMIT 200');
            $st->execute(array(pid('ITHC', isset($p['Lead_ID']) ? $p['Lead_ID'] : '')));
            $data = array();
            foreach ($st->fetchAll() as $r) {
                $data[] = array(
                    'Communication_ID' => fid('COM', $r['id']),
                    'Lead_ID' => fid('ITHC', $r['lead_id']),
                    'User_Name' => $r['user_name'],
                    'Communication_Type' => $r['comm_type'],
                    'Communication_Result' => $r['comm_result'],
                    'Communication_Note' => $r['note'],
                    'Communication_Date_Time' => iso($r['created_at']),
                );
            }
            ok($data);
            break;

        case 'comm.add':
            need('comm.create');
            $id = pid('ITHC', isset($p['Lead_ID']) ? $p['Lead_ID'] : '');
            $type = s(isset($p['Communication_Type']) ? $p['Communication_Type'] : '', 20);
            $result = s(isset($p['Communication_Result']) ? $p['Communication_Result'] : '', 30);
            $note = s(isset($p['Communication_Note']) ? $p['Communication_Note'] : '', 1000);
            $next = valid_date(isset($p['Next_Followup_Date']) ? $p['Next_Followup_Date'] : '');
            if (!in_array($type, COMM_TYPES, true)) fail('যোগাযোগের মাধ্যম সঠিক নয়।');
            if (!in_array($result, COMM_RESULTS, true)) fail('ফলাফল সঠিক নয়।');
            if ($note === '') fail('আলোচনার নোট লিখুন।');
            if ($next === false) fail('ফলো-আপ তারিখ সঠিক নয়।');
            $pdo = db();
            $pdo->beginTransaction();
            $st = $pdo->prepare('SELECT id FROM leads WHERE id=? AND active=1 FOR UPDATE');
            $st->execute(array($id));
            if (!$st->fetch()) { $pdo->rollBack(); fail('Lead পাওয়া যায়নি।'); }
            $pdo->prepare('INSERT INTO communications (lead_id, user_id, user_name, comm_type, comm_result, note, created_at) VALUES (?,?,?,?,?,?,NOW())')
                ->execute(array($id, $ME['id'], $ME['full_name'], $type, $result, $note));
            if ($next) {
                $pdo->prepare('UPDATE leads SET communication_count=communication_count+1, next_followup_date=? WHERE id=?')->execute(array($next, $id));
            } else {
                $pdo->prepare('UPDATE leads SET communication_count=communication_count+1 WHERE id=?')->execute(array($id));
            }
            log_activity(fid('ITHC', $id), 'COMM_ADD', 'Communication', '', $type . ' / ' . $result, 'Communication logged');
            $pdo->commit();
            ok(null, 'যোগাযোগের লগ সেভ হয়েছে।');
            break;

        /* ---------- Campaigns ---------- */
        case 'campaign.options':
            need('lead.create');
            $rows = db()->query('SELECT id, name FROM campaigns ORDER BY id DESC')->fetchAll();
            $data = array();
            foreach ($rows as $r) $data[] = array('Campaign_ID' => fid('CMP', $r['id']), 'Campaign_Name' => $r['name']);
            ok($data);
            break;

        case 'campaign.list':
            need('campaign.read');
            $rows = db()->query('SELECT c.*, (SELECT COUNT(*) FROM leads l WHERE l.campaign_id=c.id AND l.active=1) AS total_leads FROM campaigns c ORDER BY c.id DESC')->fetchAll();
            $data = array();
            foreach ($rows as $r) {
                $n = (int)$r['total_leads'];
                $data[] = array(
                    'Campaign_ID' => fid('CMP', $r['id']),
                    'Campaign_Name' => $r['name'],
                    'Campaign_Source' => $r['source'],
                    'Campaign_Cost' => (float)$r['cost'],
                    'Campaign_Date' => $r['start_date'] ? $r['start_date'] : '',
                    'Total_Leads' => $n,
                    'Cost_Per_Lead' => $n > 0 ? (string)round($r['cost'] / $n) : 'N/A',
                );
            }
            ok($data);
            break;

        case 'campaign.create':
            need('campaign.create');
            $name = s(isset($p['Campaign_Name']) ? $p['Campaign_Name'] : '', 150);
            $src = s(isset($p['Campaign_Source']) ? $p['Campaign_Source'] : '', 80);
            $costRaw = isset($p['Campaign_Cost']) ? trim((string)$p['Campaign_Cost']) : '';
            $cost = $costRaw === '' ? 0 : $costRaw;
            $date = valid_date(isset($p['Campaign_Date']) ? $p['Campaign_Date'] : '');
            if ($name === '') fail('ক্যাম্পেইনের নাম দিন।');
            if (!is_numeric($cost) || $cost < 0 || $cost > 1000000000) fail('খরচের পরিমাণ সঠিক নয়।');
            if ($date === false) fail('তারিখ সঠিক নয়।');
            if ($date === null) $date = date('Y-m-d');
            db()->prepare('INSERT INTO campaigns (name, source, cost, start_date, created_at) VALUES (?,?,?,?,NOW())')->execute(array($name, $src, $cost, $date));
            $cid = fid('CMP', db()->lastInsertId());
            log_activity($cid, 'CAMPAIGN_CREATE', 'Campaign_Name', '', $name, 'Campaign created');
            ok(array('Campaign_ID' => $cid), 'ক্যাম্পেইন যোগ হয়েছে।');
            break;

        /* ---------- Users ---------- */
        case 'user.list':
            need('user.read');
            $rows = db()->query('SELECT * FROM users ORDER BY id')->fetchAll();
            $data = array();
            foreach ($rows as $r) $data[] = user_row($r);
            ok($data);
            break;

        case 'user.create':
            need('user.create');
            $name = s(isset($p['Full_Name']) ? $p['Full_Name'] : '', 120);
            $gmail = strtolower(s(isset($p['Gmail']) ? $p['Gmail'] : '', 190));
            $pw = isset($p['Password']) && is_string($p['Password']) ? $p['Password'] : '';
            $role = s(isset($p['Role']) ? $p['Role'] : 'OPERATOR', 20);
            if ($name === '') fail('পুরো নাম দিন।');
            if (!filter_var($gmail, FILTER_VALIDATE_EMAIL)) fail('ইমেইল সঠিক নয়।');
            if (!valid_password($pw)) fail('পাসওয়ার্ড কমপক্ষে ৮ অক্ষরের হতে হবে।');
            if (!in_array($role, ROLES, true)) fail('Role সঠিক নয়।');
            if ($role === 'MASTER_ADMIN' && !is_master()) fail('শুধু MASTER_ADMIN আরেকজন MASTER_ADMIN বানাতে পারবেন।');
            $st = db()->prepare('SELECT COUNT(*) FROM users WHERE gmail=?');
            $st->execute(array($gmail));
            if ((int)$st->fetchColumn()) fail('এই ইমেইল আগেই আছে।');
            db()->prepare("INSERT INTO users (full_name, gmail, password_hash, role, status, active, created_at) VALUES (?,?,?,?, 'APPROVED', 1, NOW())")
                ->execute(array($name, $gmail, password_hash($pw, PASSWORD_DEFAULT), $role));
            $uid = fid('USR', db()->lastInsertId());
            log_activity($uid, 'USER_CREATE', 'Role', '', $role, 'User created: ' . $gmail);
            ok(array('User_ID' => $uid), 'টিম মেম্বার যোগ হয়েছে।');
            break;

        case 'user.approve':
        case 'user.reject':
        case 'user.activate':
        case 'user.deactivate':
        case 'user.role':
            $permMap = array(
                'user.approve' => 'user.approve', 'user.reject' => 'user.reject',
                'user.activate' => 'user.activate', 'user.deactivate' => 'user.deactivate',
                'user.role' => 'user.role.change'
            );
            need($permMap[$action]);
            $uid = pid('USR', isset($p['User_ID']) ? $p['User_ID'] : '');
            $st = db()->prepare('SELECT * FROM users WHERE id=?');
            $st->execute(array($uid));
            $t = $st->fetch();
            if (!$t) fail('ইউজার পাওয়া যায়নি।');
            $tid = fid('USR', $uid);
            if ((int)$t['id'] === (int)$ME['id'] && $action !== 'user.approve') fail('নিজের অ্যাকাউন্টে এটি করা যাবে না।');

            if ($action === 'user.approve') {
                db()->prepare("UPDATE users SET status='APPROVED' WHERE id=?")->execute(array($uid));
                log_activity($tid, 'USER_APPROVE', 'Status', $t['status'], 'APPROVED', $t['gmail']);
                ok(null, 'ইউজার অনুমোদিত হয়েছে।');
            }
            if ($action === 'user.reject') {
                if ($t['role'] === 'MASTER_ADMIN') fail('MASTER_ADMIN কে reject করা যাবে না।');
                db()->prepare("UPDATE users SET status='REJECTED' WHERE id=?")->execute(array($uid));
                db()->prepare('DELETE FROM sessions WHERE user_id=?')->execute(array($uid));
                log_activity($tid, 'USER_REJECT', 'Status', $t['status'], 'REJECTED', $t['gmail']);
                ok(null, 'ইউজার প্রত্যাখ্যান করা হয়েছে।');
            }
            if ($action === 'user.activate' || $action === 'user.deactivate') {
                if ($t['role'] === 'MASTER_ADMIN') fail('MASTER_ADMIN কে নিষ্ক্রিয় করা যাবে না।');
                $on = ($action === 'user.activate') ? 1 : 0;
                db()->prepare('UPDATE users SET active=? WHERE id=?')->execute(array($on, $uid));
                if (!$on) db()->prepare('DELETE FROM sessions WHERE user_id=?')->execute(array($uid));
                log_activity($tid, 'USER_' . strtoupper(substr($action, 5)), 'Active', (string)$t['active'], (string)$on, $t['gmail']);
                ok(null, 'ইউজারের স্ট্যাটাস আপডেট হয়েছে।');
            }
            // user.role
            $newRole = s(isset($p['Role']) ? $p['Role'] : '', 20);
            if (!in_array($newRole, ROLES, true)) fail('Role সঠিক নয়।');
            if (($t['role'] === 'MASTER_ADMIN' || $newRole === 'MASTER_ADMIN') && !is_master()) {
                fail('MASTER_ADMIN সংক্রান্ত পরিবর্তন শুধু MASTER_ADMIN করতে পারবেন।');
            }
            db()->prepare('UPDATE users SET role=? WHERE id=?')->execute(array($newRole, $uid));
            log_activity($tid, 'USER_ROLE', 'Role', $t['role'], $newRole, $t['gmail']);
            ok(null, 'Role পরিবর্তন হয়েছে: ' . $newRole);
            break;

        /* ---------- Audit ---------- */
        case 'activity.list':
            need('activity.read');
            $rows = db()->query('SELECT * FROM activity_logs ORDER BY id DESC LIMIT 200')->fetchAll();
            $data = array();
            foreach ($rows as $r) {
                $data[] = array(
                    'Activity_ID' => fid('ACT', $r['id']),
                    'Target_ID' => $r['target_id'],
                    'User_Name' => $r['user_name'],
                    'Action' => $r['action'],
                    'Field_Name' => $r['field_name'],
                    'Old_Value' => $r['old_value'],
                    'New_Value' => $r['new_value'],
                    'Activity_Note' => $r['note'],
                    'Activity_Date_Time' => iso($r['created_at']),
                );
            }
            ok(array('rows' => $data));
            break;

        /* ---------- Settings & permissions ---------- */
        case 'settings.get':
            need('settings.read');
            $data = array();
            foreach (db()->query('SELECT setting_key, setting_value FROM settings')->fetchAll() as $r) {
                $data[] = array('Setting_Key' => $r['setting_key'], 'Setting_Value' => $r['setting_value']);
            }
            $matrix = array('MASTER_ADMIN' => ALL_PERMS, 'ADMIN' => perms_for('ADMIN'), 'OPERATOR' => perms_for('OPERATOR'));
            ok($data, '', array('masterAdminEmail' => get_setting('MASTER_ADMIN_EMAIL'), 'permissionsMatrix' => $matrix));
            break;

        case 'settings.update':
            need('settings.update');
            $key = s(isset($p['key']) ? $p['key'] : '', 60);
            $val = s(isset($p['value']) ? $p['value'] : '', 190);
            if (!in_array($key, SETTING_KEYS, true)) fail('Setting key সঠিক নয়।');
            $oldVal = get_setting($key);
            if ($key === 'COMPANY_NAME') {
                if ($val === '') fail('প্রতিষ্ঠানের নাম দিন।');
            } elseif ($key === 'DEFAULT_LEAD_GRADE') {
                if (!in_array($val, array('A', 'B', 'C'), true)) fail('গ্রেড সঠিক নয়।');
            } elseif ($key === 'FOLLOWUP_REMINDER') {
                if (!ctype_digit($val) || (int)$val > 365) fail('দিনের সংখ্যা ০–৩৬৫ হতে হবে।');
            } elseif ($key === 'MASTER_ADMIN_EMAIL') {
                if (!is_master()) fail('শুধু MASTER_ADMIN এটি বদলাতে পারবেন।');
                $val = strtolower($val);
                if (!filter_var($val, FILTER_VALIDATE_EMAIL)) fail('ইমেইল সঠিক নয়।');
                if ($val !== strtolower($oldVal)) {
                    $st = db()->prepare('SELECT id FROM users WHERE gmail=?');
                    $st->execute(array($val));
                    $target = $st->fetch();
                    if (!$target) fail('আগে ওই ইমেইলে একটি অ্যাকাউন্ট তৈরি করুন, তারপর এটি Master Admin করুন।');
                    db()->prepare("UPDATE users SET role='MASTER_ADMIN', status='APPROVED', active=1 WHERE id=?")->execute(array($target['id']));
                }
            }
            if ($val !== $oldVal) {
                set_setting($key, $val);
                log_activity($key, 'SETTING_UPDATE', $key, $oldVal, $val, 'Setting changed');
            }
            ok(null, 'সেভ হয়েছে।');
            break;

        case 'permissions.update':
            need('settings.update');
            if (!is_master()) fail('শুধু MASTER_ADMIN পারমিশন বদলাতে পারবেন।');
            $matrix = (isset($p['matrix']) && is_array($p['matrix'])) ? $p['matrix'] : array();
            $pdo = db();
            $pdo->beginTransaction();
            foreach (array('ADMIN', 'OPERATOR') as $role) {
                $list = (isset($matrix[$role]) && is_array($matrix[$role])) ? $matrix[$role] : array();
                $list = array_values(array_unique(array_intersect(array_map('strval', $list), ALL_PERMS)));
                $pdo->prepare('DELETE FROM role_permissions WHERE role=?')->execute(array($role));
                $ins = $pdo->prepare('INSERT INTO role_permissions (role, permission) VALUES (?,?)');
                foreach ($list as $perm) $ins->execute(array($role, $perm));
            }
            log_activity('ROLE_RULES', 'PERMISSIONS_UPDATE', '', '', '', 'Role permission matrix updated');
            $pdo->commit();
            ok(null, 'Role পারমিশন আপডেট হয়েছে।');
            break;

        default:
            fail('Unknown action');
    }
    fail('Unknown action');

} catch (Throwable $e) {
    try { if (db()->inTransaction()) db()->rollBack(); } catch (Throwable $e2) {}
    error_log('ITHC CRM API error: ' . $e->getMessage());
    fail(DEBUG ? ('Server error: ' . $e->getMessage()) : 'সার্ভারে সমস্যা হয়েছে। আবার চেষ্টা করুন।');
}
