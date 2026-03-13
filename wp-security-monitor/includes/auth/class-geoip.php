<?php
/**
 * Validación por GeoIP
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_GeoIP {
    private $logger;
    private $settings;

    public function __construct( $logger, $settings ) {
        $this->logger = $logger;
        $this->settings = $settings;
    }

    public function init() {
        if ( $this->settings->get_setting( 'geoip_enable', 'no' ) !== 'yes' ) {
            return;
        }

        add_action( 'wp_login', array( $this, 'validate_login_geography' ), 10, 2 );
        add_action( 'wp_login_failed', array( $this, 'log_failed_login_geography' ) );
    }

    public function validate_login_geography( $user_login, $user ) {
        $ip = $this->get_ip();
        $geo = $this->get_geo_data( $ip );

        $allowed_countries_str = $this->settings->get_setting( 'allowed_countries', '' );
        $allowed_countries = ! empty( $allowed_countries_str ) ? array_map( 'trim', explode( ',', $allowed_countries_str ) ) : array();

        $mode = $this->settings->get_setting( 'geoip_mode', 'alert' );

        $this->logger->log( 'geoip_info', sprintf( __( 'Login desde %s, %s (IP: %s)', 'wp-security-monitor' ), $geo['city'], $geo['country'], $ip ), 'low', $geo );

        if ( ! empty( $allowed_countries ) && ! in_array( $geo['country_code'], $allowed_countries ) ) {
            if ( $mode === 'block' ) {
                wp_logout();
                wp_die( __( 'Acceso denegado desde su ubicación actual.', 'wp-security-monitor' ) );
            } elseif ( $mode === 'verify' ) {
                update_user_meta( $user->ID, 'wpsm_extra_verification_required', true );
            }

            $this->logger->log( 'geoip_warning', sprintf( __( 'Acceso inusual detectado para %s desde %s', 'wp-security-monitor' ), $user_login, $geo['country'] ), 'high' );
        }
    }

    public function log_failed_login_geography( $username ) {
        $ip = $this->get_ip();
        $geo = $this->get_geo_data( $ip );

        $this->logger->log( 'geoip_failed_attempt', sprintf( __( 'Fallo de login desde %s, %s (IP: %s)', 'wp-security-monitor' ), $geo['city'], $geo['country'], $ip ), 'medium', $geo );
    }

    private function get_geo_data( $ip ) {
        if ( $ip === '127.0.0.1' || $ip === '::1' ) {
            return array( 'country' => 'Localhost', 'country_code' => 'LH', 'city' => 'Localhost' );
        }

        $cache_key = 'wpsm_geo_' . md5( $ip );
        $cached = get_transient( $cache_key );
        if ( $cached ) return $cached;

        $response = wp_remote_get( 'https://ipapi.co/' . $ip . '/json/' );

        if ( is_wp_error( $response ) ) {
            return array( 'country' => 'Unknown', 'country_code' => 'XX', 'city' => 'Unknown' );
        }

        $data = json_decode( wp_remote_retrieve_body( $response ), true );

        $geo = array(
            'country'      => isset( $data['country_name'] ) ? $data['country_name'] : 'Unknown',
            'country_code' => isset( $data['country_code'] ) ? $data['country_code'] : 'XX',
            'city'         => isset( $data['city'] ) ? $data['city'] : 'Unknown'
        );

        set_transient( $cache_key, $geo, DAY_IN_SECONDS );

        return $geo;
    }

    private function get_ip() {
        return $_SERVER['REMOTE_ADDR'];
    }
}
