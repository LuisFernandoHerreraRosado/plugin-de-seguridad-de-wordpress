<?php
/**
 * Plugin Name:       WP Security Monitor
 * Plugin URI:        https://example.com/wp-security-monitor
 * Description:       Monitorea la salud técnica y seguridad de tu sitio WordPress con preparación para dashboard externo.
 * Version:           1.0.0
 * Author:            Expert Developer
 * Author URI:        https://example.com
 * Text Domain:       wp-security-monitor
 * Domain Path:       /languages
 */

if ( ! defined( 'WPINC' ) ) {
	die;
}

define( 'WPSM_VERSION', '1.0.0' );
define( 'WPSM_PATH', plugin_dir_path( __FILE__ ) );
define( 'WPSM_URL', plugin_dir_url( __FILE__ ) );

/**
 * Activación del plugin
 */
register_activation_hook( __FILE__, 'wpsm_activate' );
function wpsm_activate() {
    require_once WPSM_PATH . 'includes/class-logger.php';
    $logger = new WPSM_Logger();
    $logger->create_tables();

    require_once WPSM_PATH . 'includes/class-file-integrity.php';
    $integrity = new WPSM_File_Integrity();
    $integrity->create_tables();

    require_once WPSM_PATH . 'includes/class-site-identity.php';
    WPSM_Site_Identity::get_instance()->get_uuid(); // Genera UUID si no existe

    require_once WPSM_PATH . 'includes/class-cron.php';
    WPSM_Cron::register_defaults();
}

/**
 * Carga de clases
 */
require_once WPSM_PATH . 'includes/class-logger.php';
require_once WPSM_PATH . 'includes/class-site-identity.php';
require_once WPSM_PATH . 'includes/class-alerts.php';
require_once WPSM_PATH . 'includes/class-settings.php';
require_once WPSM_PATH . 'includes/class-scanner.php';
require_once WPSM_PATH . 'includes/class-file-integrity.php';
require_once WPSM_PATH . 'includes/class-login-monitor.php';
require_once WPSM_PATH . 'includes/class-cron.php';
require_once WPSM_PATH . 'includes/class-api.php';
require_once WPSM_PATH . 'includes/class-remote-sync.php';
require_once WPSM_PATH . 'includes/class-admin.php';

/**
 * Inicialización
 */
function run_wpsm() {
    $logger       = new WPSM_Logger();
    $alerts       = new WPSM_Alerts();
    $settings     = new WPSM_Settings();
    $integrity    = new WPSM_File_Integrity();
    $scanner      = new WPSM_Scanner( $logger, $integrity );
    $login_mon    = new WPSM_Login_Monitor( $logger );
    $cron         = new WPSM_Cron( $scanner );
    $api          = new WPSM_API( $logger, $scanner, $integrity );
    $remote_sync  = new WPSM_Remote_Sync( $logger );
    $admin        = new WPSM_Admin( $scanner, $logger, $settings );

    // Iniciar módulos
    $login_mon->init();
    $cron->init();
    $api->init();
    $remote_sync->init();
    $admin->init();

    // Captura de errores críticos
    set_error_handler( function( $errno, $errstr, $errfile, $errline ) use ( $logger ) {
        if ( ! ( error_reporting() & $errno ) ) return;
        $severity = ( $errno === E_USER_ERROR || $errno === E_RECOVERABLE_ERROR ) ? 'critical' : 'medium';
        $logger->log( 'php_error', sprintf( 'PHP Error: %s in %s on line %d', $errstr, $errfile, $errline ), $severity );
    } );
}
add_action( 'plugins_loaded', 'run_wpsm' );
