<?php
/**
 * Gestión de Ajustes
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Settings {
    public function get_setting( $key, $default = '' ) {
        return get_option( 'wpsm_' . $key, $default );
    }

    public function update_setting( $key, $value ) {
        return update_option( 'wpsm_' . $key, $value );
    }

    public function get_all_settings() {
        return array(
            'alert_email'   => $this->get_setting( 'alert_email', get_option( 'admin_email' ) ),
            'scan_frequency'=> $this->get_setting( 'scan_frequency', 'daily' ),
            'remote_sync'   => $this->get_setting( 'remote_sync', 'no' ),
            'api_key'       => $this->get_setting( 'api_key', '' )
        );
    }
}
