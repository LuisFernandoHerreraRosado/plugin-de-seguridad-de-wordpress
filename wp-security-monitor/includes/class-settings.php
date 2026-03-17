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
            'captcha_enable'     => $this->get_setting( 'captcha_enable', 'no' ),
            'block_zip_upload'   => $this->get_setting( 'block_zip_upload', 'no' ),
            'restrict_ext_ops'   => $this->get_setting( 'restrict_ext_ops', 'no' ),
            'force_ftp'          => $this->get_setting( 'force_ftp', 'no' ),
            'vulnerability_scan' => $this->get_setting( 'vulnerability_scan', 'yes' ),
            'auto_update_minor'  => $this->get_setting( 'auto_update_minor', 'yes' ),
            'auto_update_major'  => $this->get_setting( 'auto_update_major', 'no' ),
            'disable_file_edit'  => $this->get_setting( 'disable_file_edit', 'yes' ),
            'hide_db_errors'     => $this->get_setting( 'hide_db_errors', 'yes' ),
            'block_unfiltered_uploads' => $this->get_setting( 'block_unfiltered_uploads', 'yes' ),
            'disable_debug'      => $this->get_setting( 'disable_debug', 'yes' ),
            'disable_comments'   => $this->get_setting( 'disable_comments', 'no' ),
            'spam_protection_enable' => $this->get_setting( 'spam_protection_enable', 'no' ),
            'spam_min_time'      => $this->get_setting( 'spam_min_time', 5 ),
            'spam_max_links'     => $this->get_setting( 'spam_max_links', 3 )
        );
    }
}
