<?php
/**
 * Protección contra Fuerza Bruta
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Brute_Force {
    private $logger;
    private $settings;

    public function __construct( $logger, $settings ) {
        $this->logger = $logger;
        $this->settings = $settings;
    }

    public function init() {
        if ( $this->settings->get_setting( 'brute_force_enable', 'yes' ) !== 'yes' ) {
            return;
        }

        add_filter( 'authenticate', array( $this, 'check_brute_force' ), 30, 3 );
        add_action( 'wp_login_failed', array( $this, 'record_failed_attempt' ) );
        add_filter( 'login_errors', array( $this, 'obfuscate_login_errors' ) );
    }

    public function check_brute_force( $user, $username, $password ) {
        if ( is_wp_error( $user ) ) return $user;

        $ip = $this->get_ip();

        $allowlist = array( '127.0.0.1', '::1' );
        if ( in_array( $ip, $allowlist ) ) return $user;

        if ( $this->is_ip_locked( $ip ) ) {
            return new WP_Error( 'too_many_retries', __( 'Demasiados intentos fallidos. Por favor, inténtelo de nuevo más tarde.', 'wp-security-monitor' ) );
        }

        return $user;
    }

    public function record_failed_attempt( $username ) {
        $ip = $this->get_ip();
        $retries = get_transient( 'wpsm_retries_' . $ip );
        $retries = $retries ? $retries + 1 : 1;

        $max_retries = $this->settings->get_setting( 'max_retries', 5 );
        $lockout_duration = $this->settings->get_setting( 'lockout_duration', 30 ) * MINUTE_IN_SECONDS;

        set_transient( 'wpsm_retries_' . $ip, $retries, $lockout_duration );

        if ( $retries >= $max_retries ) {
            set_transient( 'wpsm_lockout_' . $ip, true, $lockout_duration );
            $this->logger->log( 'brute_force_lockout', sprintf( __( 'IP %s bloqueada por %d minutos tras %d intentos.', 'wp-security-monitor' ), $ip, $lockout_duration / 60, $retries ), 'high' );
        }

        if ( ! get_user_by( 'login', $username ) && ! get_user_by( 'email', $username ) ) {
            $this->logger->log( 'non_existent_user_attempt', sprintf( __( 'Intento con usuario inexistente: %s desde %s', 'wp-security-monitor' ), $username, $ip ), 'medium' );
        }
    }

    public function obfuscate_login_errors( $error ) {
        return __( 'Error: Credenciales incorrectas o cuenta bloqueada.', 'wp-security-monitor' );
    }

    private function is_ip_locked( $ip ) {
        return get_transient( 'wpsm_lockout_' . $ip ) !== false;
    }

    /**
     * Obtiene la IP real de forma segura
     */
    private function get_ip() {
        return $_SERVER['REMOTE_ADDR'];
    }
}
