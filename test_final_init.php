<?php
define('WPINC', 1);
define('ABSPATH', './');
define('WPSM_PATH', './wp-security-monitor/');
define('WPSM_VERSION', '1.0.0');

function add_action($h, $f) { echo "Hooking action: $h\n"; }
function add_filter($h, $f) { echo "Hooking filter: $h\n"; }
function get_option($o, $d=false) { return $d; }
function update_option($o, $v) { return true; }
function plugin_dir_path($file) { return dirname($file) . '/'; }
function plugin_dir_url($file) { return 'http://example.com/'; }
function register_activation_hook($file, $func) {}

class WPDB { public $prefix = 'wp_'; public function get_charset_collate() { return ''; } }
$GLOBALS['wpdb'] = new WPDB();

require_once 'wp-security-monitor/wp-security-monitor.php';

echo "Running run_wpsm...\n";
run_wpsm();
echo "End Success\n";
