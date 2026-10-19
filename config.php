<?php
/*
 * ITHC CRM — কনফিগারেশন
 * StackCP → MySQL Databases থেকে ডেটাবেস তৈরি করে নিচের মানগুলো বসান।
 * এই ফাইলে পাসওয়ার্ড থাকে, তাই কাউকে শেয়ার করবেন না।
 */
define('DB_HOST', 'sdb-96.hosting.stackcp.net');
define('DB_NAME', 'ITCHCRM-353134312449');
define('DB_USER', 'ITCHCRM-353134312449');
define('DB_PASS', 'N[gX=£IwHzKE');

// install.php ব্যবহারের গোপন কী — একটা লম্বা, এলোমেলো লেখা দিন (কমপক্ষে 20 অক্ষর)
define('INSTALL_KEY', 'sjajei2s465foekfjru56e8w7rfgsfw5r4wrt4wer');

define('SESSION_HOURS', 12);   // লগইন কতক্ষণ বহাল থাকবে
define('DEBUG', false);        // সমস্যা খুঁজতে হলে সাময়িক true করুন, শেষে আবার false

function db() {
    static $pdo = null;
    if ($pdo === null) {
        $pdo = new PDO(
            'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4',
            DB_USER,
            DB_PASS,
            array(
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            )
        );
        $pdo->exec("SET time_zone = '+06:00'"); // বাংলাদেশ সময়
    }
    return $pdo;
}
