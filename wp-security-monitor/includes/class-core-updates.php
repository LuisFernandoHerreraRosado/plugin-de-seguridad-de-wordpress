<?php
/**
 * Gestión de Actualizaciones de WordPress
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Core_Updates {
    private $logger;
    private $settings;

    public function __construct( $logger, $settings ) {
        $this->logger = $logger;
        $this->settings = $settings;
    }

    public function init() {
        // Forzar actualizaciones menores
        if ( $this->settings->get_setting( 'auto_update_minor', 'yes' ) === 'yes' ) {
            add_filter( 'allow_minor_auto_core_updates', '__return_true' );
        }

        // Habilitar actualizaciones mayores
        if ( $this->settings->get_setting( 'auto_update_major', 'no' ) === 'yes' ) {
            add_filter( 'allow_major_auto_core_updates', '__return_true' );
        }

        // Monitoreo de versión actual
        add_action( 'admin_init', array( $this, 'check_wp_version' ) );

        // Registrar historial de actualizaciones
        add_action( 'upgrader_process_complete', array( $this, 'log_update_completion' ), 10, 2 );
    }

    /**
     * Verifica la versión de WP y alerta si está desactualizada
     */
    public function check_wp_version() {
        $updates = get_site_transient( 'update_core' );
        if ( isset( $updates->updates ) && ! empty( $updates->updates ) && $updates->updates[0]->response === 'upgrade' ) {
            $this->logger->log( 'core_update_available', sprintf( __( 'Nueva versión de WordPress disponible: %s. Por favor actualiza.', 'wp-security-monitor' ), $updates->updates[0]->version ), 'medium' );
        }
    }

    /**
     * Guarda en historial la finalización de una actualización
     */
    public function log_update_completion( $upgrader, $options ) {
        if ( $options['type'] === 'core' ) {
            $history = get_option( 'wpsm_update_history', array() );
            $history[] = array(
                'time'    => current_time( 'mysql' ),
                'version' => get_bloginfo( 'version' ),
                'action'  => $options['action']
            );
            update_option( 'wpsm_update_history', array_slice( $history, -10 ) );
            $this->logger->log( 'system_event', __( 'Actualización del Core de WordPress completada con éxito.', 'wp-security-monitor' ), 'low' );
        }
    }
}
