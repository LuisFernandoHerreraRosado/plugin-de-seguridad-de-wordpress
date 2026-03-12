<?php
/**
 * Sincronización Remota (Heartbeat)
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Remote_Sync {
    private $logger;

    public function __construct( $logger ) {
        $this->logger = $logger;
    }

    public function init() {
        add_action( 'wpsm_scheduled_sync', array( $this, 'send_heartbeat' ) );
    }

    public function send_heartbeat() {
        $remote_url = get_option( 'wpsm_remote_dashboard_url' );
        if ( ! $remote_url ) return;

        $identity = WPSM_Site_Identity::get_instance();
        $data = array(
            'uuid'       => $identity->get_uuid(),
            'site_url'   => get_site_url(),
            'timestamp'  => current_time( 'timestamp' ),
            'status'     => 'online',
            'plugin_v'   => WPSM_VERSION
        );

        $response = wp_remote_post( $remote_url . '/sync-heartbeat', array(
            'body'    => json_encode( $data ),
            'headers' => array(
                'Content-Type' => 'application/json',
                'X-WPSM-TOKEN' => get_option( 'wpsm_remote_token' )
            )
        ) );

        if ( is_wp_error( $response ) ) {
            $this->logger->log( 'sync_error', 'Error enviando heartbeat: ' . $response->get_error_message(), 'medium' );
        } else {
            update_option( 'wpsm_last_sync_time', current_time( 'mysql' ) );
        }
    }
}
