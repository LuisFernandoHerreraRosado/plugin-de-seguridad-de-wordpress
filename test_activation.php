<?php
define('WPINC', 1);
define('ABSPATH', './');
define('WP_PLUGIN_DIR', './');

function plugin_dir_path($file) { return dirname($file) . '/'; }
function plugin_dir_url($file) { return 'http://example.com/'; }
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
function phpversion() { return '7.4'; }

class WPDB {
    public $prefix = 'wp_';
    public function get_charset_collate() { return ''; }
    public function prepare($sql, ...$args) { return $sql; }
    public function get_row($sql) { return null; }
    public function insert($table, $data) { return true; }
}
$wpdb = new WPDB();
function dbDelta($sql) {}

require_once 'wp-security-monitor/wp-security-monitor.php';

if (isset($act_func)) {
    $act_func();
}
echo "Success\n";
