<?php
/**
 * Proveedor 2FA: Magic Link (Passwordless)
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_2FA_Magic_Link {
    public function send_magic_link( $user ) {
        $token = wp_generate_password( 32, false );
        set_transient( 'wpsm_magic_link_' . $token, $user->ID, 900 );

        $link = add_query_arg( 'wpsm_magic_token', $token, home_url() );
        $message = sprintf( __( 'Haga clic en el siguiente enlace para iniciar sesión: %s', 'wp-security-monitor' ), $link );

        return wp_mail( $user->user_email, __( 'Su enlace de acceso mágico', 'wp-security-monitor' ), $message );
    }

    public function validate_token( $token ) {
        $user_id = get_transient( 'wpsm_magic_link_' . $token );
        if ( $user_id ) {
            delete_transient( 'wpsm_magic_link_' . $token );
            return $user_id;
        }
        return false;
    }
}
