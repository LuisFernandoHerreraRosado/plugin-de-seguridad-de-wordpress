<?php
/**
 * Monitoreo de Login y Usuarios
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Login_Monitor {
    private $logger;

    public function __construct( $logger ) {
        $this->logger = $logger;
    }

    public function init() {
        // Fallos de login
        add_action( 'wp_login_failed', array( $this, 'log_failed_login' ) );
        // Logins exitosos
        add_action( 'wp_login', array( $this, 'log_successful_login' ), 10, 2 );
        // Creación de usuarios
        add_action( 'user_register', array( $this, 'log_user_registration' ) );
        // Eliminación de usuarios
        add_action( 'delete_user', array( $this, 'log_user_deletion' ) );
        // Cambio de perfil (roles)
        add_action( 'set_user_role', array( $this, 'log_role_change' ), 10, 3 );
    }

    public function log_failed_login( $username ) {
        $this->logger->log(
            'login_failed',
            sprintf( __( 'Intento de login fallido para el usuario: %s', 'wp-security-monitor' ), $username ),
            'medium'
        );
    }

    public function log_successful_login( $user_login, $user ) {
        $this->logger->log(
            'login_success',
            sprintf( __( 'Usuario %s ha iniciado sesión correctamente.', 'wp-security-monitor' ), $user_login ),
            'low'
        );
    }

    public function log_user_registration( $user_id ) {
        $user = get_userdata( $user_id );
        $role = ! empty( $user->roles ) ? $user->roles[0] : __( 'sin rol', 'wp-security-monitor' );

        $severity = ( $role === 'administrator' ) ? 'critical' : 'medium';

        $this->logger->log(
            'user_created',
            sprintf( __( 'Nuevo usuario creado: %s con rol %s', 'wp-security-monitor' ), $user->user_login, $role ),
            $severity
        );
    }

    public function log_user_deletion( $user_id ) {
        $user = get_userdata( $user_id );
        $this->logger->log(
            'user_deleted',
            sprintf( __( 'Usuario eliminado: %s', 'wp-security-monitor' ), $user ? $user->user_login : 'ID ' . $user_id ),
            'medium'
        );
    }

    public function log_role_change( $user_id, $role, $old_roles ) {
        $user = get_userdata( $user_id );
        $old_role = ! empty( $old_roles ) ? $old_roles[0] : __( 'ninguno', 'wp-security-monitor' );

        $this->logger->log(
            'role_change',
            sprintf( __( 'El usuario %s cambió de rol %s a %s', 'wp-security-monitor' ), $user->user_login, $old_role, $role ),
            ( $role === 'administrator' ) ? 'critical' : 'medium'
        );
    }
}
