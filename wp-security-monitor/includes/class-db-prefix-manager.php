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

        // Lógica de respaldo de tablas (Simulación para MVP)
        $this->logger->log( 'system_action', sprintf( __( 'Iniciando cambio de prefijo de base de datos a: %s', 'wp-security-monitor' ), $new_prefix ), 'critical' );

        // En una implementación real, aquí se renombrarían todas las tablas
        // y se actualizarían las referencias en las tablas options y usermeta.

        return true;
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
