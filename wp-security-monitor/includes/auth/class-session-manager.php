<?php
/**
 * Gestión de Sesiones y Reseteo de Password
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Session_Manager {
    private $logger;

    public function __construct( $logger ) {
        $this->logger = $logger;
    }

    public function init() {
        add_action( 'init', array( $this, 'check_force_reset' ) );
    }

    /**
     * Obtiene todas las sesiones activas de un usuario
     */
    public function get_user_sessions( $user_id ) {
        $manager = WP_Session_Tokens::get_instance( $user_id );
        return $manager->get_all();
    }

    /**
     * Cierra una sesión específica por su verifier
     */
    public function destroy_session( $user_id, $verifier ) {
        $manager = WP_Session_Tokens::get_instance( $user_id );
        $manager->destroy( $verifier );

        $this->logger->log( 'session_destroyed', sprintf( __( 'Sesión cerrada para el usuario ID %d', 'wp-security-monitor' ), $user_id ), 'low' );
    }

    /**
     * Cierra todas las sesiones de un usuario excepto la actual
     */
    public function destroy_other_sessions( $user_id ) {
        $manager = WP_Session_Tokens::get_instance( $user_id );
        $manager->destroy_others( wp_get_session_token() );

        $this->logger->log( 'global_logout_others', sprintf( __( 'Todas las demás sesiones cerradas para el usuario ID %d', 'wp-security-monitor' ), $user_id ), 'medium' );
    }

    /**
     * Fuerza el reseteo de contraseña para un usuario
     */
    public function force_password_reset( $user_id ) {
        update_user_meta( $user_id, 'wpsm_force_password_reset', true );
        $this->logger->log( 'force_password_reset_triggered', sprintf( __( 'Reseteo forzado de contraseña para el usuario ID %d', 'wp-security-monitor' ), $user_id ), 'medium' );
    }

    /**
     * Verifica si el usuario actual debe resetear su contraseña
     */
    public function check_force_reset() {
        if ( is_user_logged_in() && ! is_admin() ) {
            $user_id = get_current_user_id();
            if ( get_user_meta( $user_id, 'wpsm_force_password_reset', true ) ) {
                // Redirigir a la página de perfil para cambiar password, o logout
                // Para este MVP, forzamos logout y alertamos
                delete_user_meta( $user_id, 'wpsm_force_password_reset' );
                wp_logout();
                wp_redirect( home_url( '/?password_reset_required=1' ) );
                exit;
            }
        }
    }
}
