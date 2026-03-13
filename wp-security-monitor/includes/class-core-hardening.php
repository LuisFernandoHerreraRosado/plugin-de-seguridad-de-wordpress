<?php
/**
 * Hardening del Core de WordPress
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Core_Hardening {
    private $logger;
    private $settings;

    public function __construct( $logger, $settings ) {
        $this->logger = $logger;
        $this->settings = $settings;
    }

    public function init() {
        // Bloquear editor de archivos
        if ( $this->settings->get_setting( 'disable_file_edit', 'yes' ) === 'yes' ) {
            if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) define( 'DISALLOW_FILE_EDIT', true );
            if ( ! defined( 'DISALLOW_FILE_MODS' ) ) define( 'DISALLOW_FILE_MODS', true );
        }

        // Desactivar concatenación de scripts en admin por seguridad/debug
        if ( ! defined( 'CONCATENATE_SCRIPTS' ) ) define( 'CONCATENATE_SCRIPTS', false );

        // Impedir relocalización de URLs
        if ( ! defined( 'RELOCATE' ) ) define( 'RELOCATE', false );

        // Bloquear uploads no filtrados
        if ( $this->settings->get_setting( 'block_unfiltered_uploads', 'yes' ) === 'yes' ) {
            if ( ! defined( 'ALLOW_UNFILTERED_UPLOADS' ) ) define( 'ALLOW_UNFILTERED_UPLOADS', false );
        }

        // Ocultar errores de DB en frontend
        if ( $this->settings->get_setting( 'hide_db_errors', 'yes' ) === 'yes' ) {
            global $wpdb;
            $wpdb->hide_errors();
        }

        // Desactivar reparación pública de base de datos
        if ( ! defined( 'WP_ALLOW_REPAIR' ) ) define( 'WP_ALLOW_REPAIR', false );

        // Refuerzo de cookies (vía filtros de WP)
        add_filter( 'auth_cookie_expiration', array( $this, 'secure_cookie_expiration' ), 10, 3 );

        // Bloquear acceso a archivos sensibles vía .htaccess (si es Apache)
        add_action( 'admin_init', array( $this, 'check_apache_security' ) );
    }

    public function secure_cookie_expiration( $expiration, $user_id, $remember ) {
        if ( ! $remember ) {
            return 2 * HOUR_IN_SECONDS; // 2 horas
        }
        return $expiration;
    }

    public function check_apache_security() {
        // Lógica para verificar o escribir reglas en .htaccess
    }

    public function rotate_salts() {
        require_once WPSM_PATH . 'includes/class-config-editor.php';
        $editor = new WPSM_Config_Editor();

        if ( ! $editor->is_writable() ) {
            return new WP_Error( 'not_writable', __( 'No se puede escribir en wp-config.php.', 'wp-security-monitor' ) );
        }

        $this->logger->log( 'system_action', __( 'Rotación de llaves de seguridad (salts) solicitada.', 'wp-security-monitor' ), 'high' );
        return true;
    }
}
