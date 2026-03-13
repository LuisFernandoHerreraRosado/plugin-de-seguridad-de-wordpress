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
            'alert_email'         => $this->get_setting( 'alert_email', get_option( 'admin_email' ) ),
            'scan_frequency'     => $this->get_setting( 'scan_frequency', 'daily' ),
            'remote_sync'        => $this->get_setting( 'remote_sync', 'no' ),
            'api_key'            => $this->get_setting( 'api_key', '' ),
            'login_slug'         => $this->get_setting( 'login_slug', '' ),
            'brute_force_enable' => $this->get_setting( 'brute_force_enable', 'yes' ),
            'max_retries'        => $this->get_setting( 'max_retries', 5 ),
            'lockout_duration'   => $this->get_setting( 'lockout_duration', 30 ),
            'geoip_enable'       => $this->get_setting( 'geoip_enable', 'no' ),
            'geoip_mode'         => $this->get_setting( 'geoip_mode', 'alert' ),
            'allowed_countries'  => $this->get_setting( 'allowed_countries', array() ),
            'pwd_min_length'     => $this->get_setting( 'pwd_min_length', 12 ),
            'pwd_complexity'     => $this->get_setting( 'pwd_complexity', 'high' ),
            'pwd_expiry_days'    => $this->get_setting( 'pwd_expiry_days', 90 ),
            'pwd_history_limit'  => $this->get_setting( 'pwd_history_limit', 5 ),
            'two_factor_enable'  => $this->get_setting( 'two_factor_enable', 'no' ),
            'captcha_enable'     => $this->get_setting( 'captcha_enable', 'no' )
        );
    }
}
