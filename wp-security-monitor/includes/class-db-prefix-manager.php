<?php
/**
 * Gestión del Prefijo de la Base de Datos
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_DB_Prefix_Manager {
    private $logger;

    public function __construct( $logger ) {
        $this->logger = $logger;
    }

    /**
     * Prepara y valida el cambio de prefijo
     */
    public function change_prefix( $new_prefix ) {
        global $wpdb;

        if ( empty( $new_prefix ) || ! preg_match( '/^[a-zA-Z0-9_]+$/', $new_prefix ) ) {
            return new WP_Error( 'invalid_prefix', __( 'El nuevo prefijo no es válido.', 'wp-security-monitor' ) );
        }

        if ( $new_prefix === $wpdb->prefix ) {
            return new WP_Error( 'same_prefix', __( 'El prefijo es igual al actual.', 'wp-security-monitor' ) );
        }

        // Lógica de validación previa
        if ( ! is_writable( ABSPATH . 'wp-config.php' ) ) {
             return new WP_Error( 'config_not_writable', __( 'No se puede escribir en wp-config.php para actualizar el prefijo.', 'wp-security-monitor' ) );
        }

        $this->logger->log( 'system_action', sprintf( __( 'Intento de cambio de prefijo a: %s (Simulado por seguridad)', 'wp-security-monitor' ), $new_prefix ), 'critical' );

        // Nota técnica: Por seguridad del sitio, el cambio real de prefijo en tablas
        // y campos usermeta/options debe hacerse manualmente o con una herramienta especializada
        // de base de datos para evitar pérdida total de datos en caso de timeout.

        return new WP_Error( 'feature_limited', __( 'El cambio de prefijo automático está deshabilitado en este módulo por seguridad. Use una herramienta de DB.', 'wp-security-monitor' ) );
    }

    /**
     * Obtiene el estado actual del prefijo
     */
    public function get_prefix_status() {
        global $wpdb;
        return array(
            'current' => $wpdb->prefix,
            'is_default' => ( $wpdb->prefix === 'wp_' )
        );
    }
}
