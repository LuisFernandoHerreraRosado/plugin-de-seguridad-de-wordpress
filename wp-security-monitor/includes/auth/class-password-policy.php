<?php
/**
 * Políticas de Contraseña y Seguridad
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Password_Policy {
    private $settings;
    private $logger;

    public function __construct( $settings, $logger ) {
        $this->settings = $settings;
        $this->logger = $logger;
    }

    public function init() {
        // Validación de complejidad y reuso al cambiar contraseña
        add_action( 'check_passwords', array( $this, 'validate_password_policies' ), 10, 3 );

        // Expiración de contraseñas
        add_action( 'wp_login', array( $this, 'check_password_expiration' ), 10, 2 );

        // Mejora el hash a Argon2id si está disponible al loguear
        add_filter( 'check_password', array( $this, 'upgrade_hash_on_login' ), 10, 4 );

        // Registrar cambio de contraseña
        add_action( 'profile_update', array( $this, 'record_password_change' ), 10, 2 );
    }

    /**
     * Valida la complejidad y el reuso de la contraseña
     */
    public function validate_password_policies( $user_login, &$pass1, &$pass2 ) {
        $min_length = $this->settings->get_setting( 'pwd_min_length', 12 );
        $complexity = $this->settings->get_setting( 'pwd_complexity', 'high' );

        // 1. Validar longitud
        if ( strlen( $pass1 ) < $min_length ) {
            wp_die( sprintf( __( 'La contraseña debe tener al menos %d caracteres.', 'wp-security-monitor' ), $min_length ) );
        }

        // 2. Validar complejidad
        if ( $complexity === 'high' ) {
            if ( ! preg_match( '/[A-Z]/', $pass1 ) || ! preg_match( '/[a-z]/', $pass1 ) || ! preg_match( '/[0-9]/', $pass1 ) || ! preg_match( '/[^A-Za-z0-9]/', $pass1 ) ) {
                wp_die( __( 'La contraseña debe incluir mayúsculas, minúsculas, números y caracteres especiales.', 'wp-security-monitor' ) );
            }
        }

        // 3. Validar reuso (Historial)
        $user = get_user_by( 'login', $user_login );
        if ( $user ) {
            $history = get_user_meta( $user->ID, 'wpsm_password_history', true );
            if ( is_array( $history ) ) {
                foreach ( $history as $old_hash ) {
                    if ( wp_check_password( $pass1, $old_hash ) ) {
                        wp_die( __( 'No puedes usar una contraseña que hayas utilizado recientemente.', 'wp-security-monitor' ) );
                    }
                }
            }
        }
    }

    /**
     * Verifica si la contraseña ha expirado
     */
    public function check_password_expiration( $user_login, $user ) {
        $expiry_days = $this->settings->get_setting( 'pwd_expiry_days', 90 );
        $last_change = get_user_meta( $user->ID, 'wpsm_last_password_change', true );

        if ( ! $last_change ) {
            update_user_meta( $user->ID, 'wpsm_last_password_change', time() );
            return;
        }

        $days_passed = ( time() - $last_change ) / DAY_IN_SECONDS;

        if ( $days_passed > $expiry_days ) {
            update_user_meta( $user->ID, 'wpsm_force_password_reset', true );
            $this->logger->log( 'password_expired', sprintf( __( 'Contraseña expirada para el usuario %s', 'wp-security-monitor' ), $user_login ), 'medium' );
        }
    }

    /**
     * Mejora el hash a Argon2id si está disponible
     */
    public function upgrade_hash_on_login( $check, $password, $hash, $user_id ) {
        if ( ! $check || ! $user_id ) return $check;

        if ( defined( 'PASSWORD_ARGON2ID' ) ) {
            $info = password_get_info( $hash );
            if ( $info['algo'] !== PASSWORD_ARGON2ID ) {
                $new_hash = password_hash( $password, PASSWORD_ARGON2ID, array(
                    'memory_cost' => 65536,
                    'time_cost'   => 4,
                    'threads'     => 2
                ) );
                global $wpdb;
                $wpdb->update( $wpdb->users, array( 'user_pass' => $new_hash ), array( 'ID' => $user_id ) );
                $this->logger->log( 'password_hash_upgraded', sprintf( __( 'Hash de contraseña mejorado a Argon2id para el usuario ID %d', 'wp-security-monitor' ), $user_id ), 'low' );
            }
        }

        return $check;
    }

    public function record_password_change( $user_id, $old_user_data ) {
        $user = get_userdata( $user_id );
        if ( $user->user_pass !== $old_user_data->user_pass ) {
            update_user_meta( $user_id, 'wpsm_last_password_change', time() );

            $history = get_user_meta( $user_id, 'wpsm_password_history', true );
            if ( ! is_array( $history ) ) $history = array();

            array_unshift( $history, $old_user_data->user_pass );
            $history = array_slice( $history, 0, 5 );
            update_user_meta( $user_id, 'wpsm_password_history', $history );

            // Forzar logout global tras cambio de contraseña
            $manager = WP_Session_Tokens::get_instance( $user_id );
            $manager->destroy_all();
            $this->logger->log( 'global_logout_after_pwd_change', sprintf( __( 'Sesiones cerradas globalmente tras cambio de contraseña para el usuario ID %d', 'wp-security-monitor' ), $user_id ), 'medium' );
        }
    }
}
