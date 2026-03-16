<?php
define('WPINC', 1);
define('ABSPATH', './');
define('WP_PLUGIN_DIR', './');
define('MINUTE_IN_SECONDS', 60);
define('HOUR_IN_SECONDS', 3600);
define('DAY_IN_SECONDS', 86400);

function plugin_dir_path($file) { return dirname($file) . '/'; }
function plugin_dir_url($file) { return 'http://example.com/wp-content/plugins/' . basename(dirname($file)) . '/'; }
function register_activation_hook($file, $func) { global $act_func; $act_func = $func; }
function add_action($hook, $func) {}
function add_filter($hook, $func) {}
function get_option($opt, $default = false) { return $default; }
function update_option($opt, $val) { return true; }
function current_time($type) { return date('Y-m-d H:i:s'); }
function wp_next_scheduled($hook) { return false; }
function wp_schedule_event($time, $freq, $hook) { return true; }
function get_site_url() { return 'http://example.com'; }
function get_bloginfo($info) { return '1.0'; }
function is_ssl() { return true; }
function username_exists($user) { return false; }
function wp_upload_dir() { return array('basedir' => '/tmp'); }
function __($text, $domain) { return $text; }
function _e($text, $domain) { echo $text; }
function esc_html($text) { return $text; }
function esc_attr($text) { return $text; }
function sanitize_text_field($text) { return $text; }
function wp_kses_post($text) { return $text; }

class WPDB {
    public $prefix = 'wp_';
    public function get_charset_collate() { return 'utf8_general_ci'; }
    public function prepare($sql, ...$args) { return $sql; }
    public function get_row($sql) { return null; }
    public function insert($table, $data) { return true; }
    public function update($table, $data, $where) { return true; }
}
$GLOBALS['wpdb'] = new WPDB();
$wpdb = $GLOBALS['wpdb'];

function dbDelta($sql) {}

require_once 'wp-security-monitor/wp-security-monitor.php';

echo "Loading classes...\n";

echo "Testing activation...\n";
if (isset($act_func)) {
    $act_func();
}

echo "Testing run_wpsm...\n";
run_wpsm();

echo "Finished Success\n";
