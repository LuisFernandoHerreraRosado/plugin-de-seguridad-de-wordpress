<?php
define('WPINC', 1);
define('ABSPATH', './');
define('WPSM_PATH', './wp-security-monitor/');
define('WPSM_VERSION', '1.0.0');

function add_action($h, $f) {}
function add_filter($h, $f) {}
function get_option($o, $d=false) { return $d; }
function update_option($o, $v) { return true; }

class WPDB { public $prefix = 'wp_'; public function get_charset_collate() { return ''; } }
$GLOBALS['wpdb'] = new WPDB();

require_once 'wp-security-monitor/includes/class-logger.php';
require_once 'wp-security-monitor/includes/class-site-identity.php';
require_once 'wp-security-monitor/includes/class-alerts.php';
require_once 'wp-security-monitor/includes/class-settings.php';
require_once 'wp-security-monitor/includes/class-scanner.php';
require_once 'wp-security-monitor/includes/class-file-integrity.php';
require_once 'wp-security-monitor/includes/class-login-monitor.php';
require_once 'wp-security-monitor/includes/class-cron.php';
require_once 'wp-security-monitor/includes/class-api.php';
require_once 'wp-security-monitor/includes/class-remote-sync.php';
require_once 'wp-security-monitor/includes/class-sensitive-data.php';
require_once 'wp-security-monitor/includes/class-admin.php';

$logger       = new WPSM_Logger();
$alerts       = new WPSM_Alerts();
$settings     = new WPSM_Settings();
$integrity    = new WPSM_File_Integrity();
$scanner      = new WPSM_Scanner( $logger, $integrity );
$login_mon    = new WPSM_Login_Monitor( $logger );
$cron         = new WPSM_Cron( $scanner );
$api          = new WPSM_API( $logger, $scanner, $integrity );
$remote_sync  = new WPSM_Remote_Sync( $logger );
$sensitive    = new WPSM_Sensitive_Data( $logger );
$admin        = new WPSM_Admin( $scanner, $logger, $settings );

$login_mon->init();
$cron->init();
$api->init();
$remote_sync->init();
$sensitive->init();
$admin->init();
echo "Success\n";
