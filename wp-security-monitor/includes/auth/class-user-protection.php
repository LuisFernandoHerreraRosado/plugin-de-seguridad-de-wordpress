<?php
/**
 * Protección de Usuarios y Acceso
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_User_Protection {
    private $logger;
    private $settings;

    public function __construct( $logger, $settings ) {
        $this->logger = $logger;
        $this->settings = $settings;
    }

    public function init() {
        if ( ! is_admin() ) {
            add_filter( 'rest_endpoints', array( $this, 'disable_user_endpoints' ) );
            add_action( 'template_redirect', array( $this, 'block_author_archives' ) );
        }

        add_filter( 'validate_username', array( $this, 'restrict_usernames' ), 10, 2 );
        add_filter( 'registration_errors', array( $this, 'block_disposable_emails' ), 10, 3 );
        add_action( 'set_user_role', array( $this, 'protect_role_elevation' ), 10, 3 );
        add_action( 'update_option_admin_email', array( $this, 'log_admin_email_change' ), 10, 2 );

        // Proteger registro abierto y rol por defecto
        add_filter( 'option_users_can_register', array( $this, 'enforce_registration_setting' ) );
        add_filter( 'option_default_role', array( $this, 'enforce_default_role_setting' ) );
    }

    public function disable_user_endpoints( $endpoints ) {
        if ( ! is_user_logged_in() ) {
            if ( isset( $endpoints['/wp/v2/users'] ) ) unset( $endpoints['/wp/v2/users'] );
            if ( isset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] ) ) unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
        }
        return $endpoints;
    }

    public function block_author_archives() {
        if ( is_author() ) {
            $this->logger->log( 'user_enumeration_attempt', sprintf( __( 'Intento de enumeración de autor bloqueado desde %s', 'wp-security-monitor' ), $_SERVER['REMOTE_ADDR'] ), 'medium' );
            wp_redirect( home_url() );
            exit;
        }
    }

    public function restrict_usernames( $valid, $username ) {
        $restricted = array( 'admin', 'administrator', 'webmaster', 'root', 'support' );
        if ( in_array( strtolower( $username ), $restricted ) ) {
            return false;
        }
        return $valid;
    }

    public function block_disposable_emails( $errors, $sanitized_user_login, $user_email ) {
        $disposable_domains = array( 'mailinator.com', 'guerrillamail.com', '10minutemail.com' );
        $domain = substr( strrchr( $user_email, "@" ), 1 );

        if ( in_array( $domain, $disposable_domains ) ) {
            $errors->add( 'disposable_email', __( 'Error: El dominio de correo electrónico no está permitido.', 'wp-security-monitor' ) );
            $this->logger->log( 'registration_blocked', sprintf( __( 'Registro bloqueado para %s (email desechable)', 'wp-security-monitor' ), $user_email ), 'medium' );
        }
        return $errors;
    }

    public function protect_role_elevation( $user_id, $role, $old_roles ) {
        if ( $role === 'administrator' && ! current_user_can( 'manage_options' ) ) {
            $this->logger->log( 'unauthorized_elevation_attempt', sprintf( __( 'Intento de elevación no autorizada para el usuario ID %d a administrador', 'wp-security-monitor' ), $user_id ), 'critical' );
        }
    }

    public function log_admin_email_change( $old_value, $new_value ) {
        $this->logger->log( 'admin_email_changed', sprintf( __( 'El email del administrador cambió de %s a %s', 'wp-security-monitor' ), $old_value, $new_value ), 'critical' );
    }

    /**
     * Asegura que la configuración de registro sea la deseada por seguridad si no se especifica lo contrario
     */
    public function enforce_registration_setting( $value ) {
        // En una implementación completa, esto vendría de un ajuste propio
        return $value;
    }

    /**
     * Previene que el rol por defecto sea algo peligroso (como administrador)
     */
    public function enforce_default_role_setting( $value ) {
        if ( $value === 'administrator' ) {
            $this->logger->log( 'insecure_default_role_blocked', __( 'Se intentó establecer el rol por defecto como administrador. Bloqueado por seguridad.', 'wp-security-monitor' ), 'critical' );
            return 'subscriber';
        }
        return $value;
    }
}
