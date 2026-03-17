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

if ( ! defined( 'ABSPATH' ) ) {
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
require_once WPSM_PATH . 'includes/class-sensitive-data.php';
require_once WPSM_PATH . 'includes/class-admin.php';

// Auth Module Classes
require_once WPSM_PATH . 'includes/auth/class-custom-login.php';
require_once WPSM_PATH . 'includes/auth/class-brute-force.php';
require_once WPSM_PATH . 'includes/auth/class-geoip.php';
require_once WPSM_PATH . 'includes/auth/class-password-policy.php';
require_once WPSM_PATH . 'includes/auth/class-user-protection.php';
require_once WPSM_PATH . 'includes/auth/class-session-manager.php';
require_once WPSM_PATH . 'includes/auth/class-2fa-manager.php';
require_once WPSM_PATH . 'includes/auth/class-2fa-totp.php';
require_once WPSM_PATH . 'includes/auth/class-2fa-email.php';
require_once WPSM_PATH . 'includes/auth/class-2fa-magic-link.php';
require_once WPSM_PATH . 'includes/auth/class-2fa-backup-codes.php';
require_once WPSM_PATH . 'includes/auth/class-captcha-base.php';
// Mover math captcha abajo para asegurar que base esté cargada

// Extensions Module Classes
require_once WPSM_PATH . 'includes/class-extensions-protection.php';
require_once WPSM_PATH . 'includes/class-extension-auditor.php';
require_once WPSM_PATH . 'includes/class-vulnerability-monitor.php';

// Core Module Classes
require_once WPSM_PATH . 'includes/class-core-hardening.php';
require_once WPSM_PATH . 'includes/class-core-updates.php';
require_once WPSM_PATH . 'includes/class-ssl-manager.php';
require_once WPSM_PATH . 'includes/class-db-prefix-manager.php';
require_once WPSM_PATH . 'includes/class-config-editor.php';

// Cargar hijos de captcha tras la base
require_once WPSM_PATH . 'includes/auth/class-captcha-math.php';

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
    $sensitive    = new WPSM_Sensitive_Data( $logger );
    $admin        = new WPSM_Admin( $scanner, $logger, $settings );

    // Iniciar módulos de autenticación y seguridad
    $custom_login = new WPSM_Custom_Login( $settings );
    $brute_force  = new WPSM_Brute_Force( $logger, $settings );
    $geoip        = new WPSM_GeoIP( $logger, $settings );
    $pwd_policy   = new WPSM_Password_Policy( $settings, $logger );
    $user_prot    = new WPSM_User_Protection( $logger, $settings );
    $session_mgr  = new WPSM_Session_Manager( $logger );
    $two_fa_mgr   = new WPSM_2FA_Manager( $settings );
    $captcha      = new WPSM_Captcha_Math( $settings );

    // Iniciar módulos de extensiones
    $ext_prot     = new WPSM_Extensions_Protection( $logger, $settings );
    $ext_auditor  = new WPSM_Extension_Auditor( $logger );
    $vuln_mon     = new WPSM_Vulnerability_Monitor( $logger, $settings );

    // Iniciar módulos de core
    $core_hard    = new WPSM_Core_Hardening( $logger, $settings );
    $core_updates = new WPSM_Core_Updates( $logger, $settings );
    $ssl_mgr      = new WPSM_SSL_Manager( $logger, $settings );

    // Registrar proveedores 2FA
    $two_fa_mgr->register_provider( 'totp', new WPSM_2FA_TOTP() );
    $two_fa_mgr->register_provider( 'email', new WPSM_2FA_Email() );
    $two_fa_mgr->register_provider( 'magic_link', new WPSM_2FA_Magic_Link() );
    $two_fa_mgr->register_provider( 'backup_codes', new WPSM_2FA_Backup_Codes() );

    // Iniciar módulos
    $login_mon->init();
    $cron->init();
    $api->init();
    $remote_sync->init();
    $sensitive->init();
    $admin->init();

    // Iniciar nuevos módulos
    $custom_login->init();
    $brute_force->init();
    $geoip->init();
    $pwd_policy->init();
    $user_prot->init();
    $session_mgr->init();
    $two_fa_mgr->init();
    $captcha->register_hooks();

    $ext_prot->init();
    $ext_auditor->init();
    $vuln_mon->init();

    $core_hard->init();
    $core_updates->init();
    $ssl_mgr->init();

    // Captura de errores críticos
    set_error_handler( function( $errno, $errstr, $errfile, $errline ) use ( $logger ) {
        if ( ! ( error_reporting() & $errno ) ) return false;
        $severity = ( $errno === E_USER_ERROR || $errno === E_RECOVERABLE_ERROR ) ? 'critical' : 'medium';
        $logger->log( 'php_error', sprintf( 'PHP Error: %s in %s on line %d', $errstr, $errfile, $errline ), $severity );
        return false; // Permite que el error siga su curso normal
    } );

    // Registrar inicio del plugin
    $logger->log( 'plugin_started', __( 'Módulo de Seguridad y Usuarios iniciado correctamente.', 'wp-security-monitor' ), 'low' );
}
add_action( 'plugins_loaded', 'run_wpsm' );
