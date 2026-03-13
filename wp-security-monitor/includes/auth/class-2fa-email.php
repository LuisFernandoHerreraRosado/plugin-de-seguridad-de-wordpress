<?php
/**
 * Proveedor 2FA: Email
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_2FA_Email {
    public function send_code( $user ) {
        $code = wp_generate_password( 6, false, false );
        set_transient( 'wpsm_2fa_email_code_' . $user->ID, $code, 600 );

        $message = sprintf( __( 'Su código de verificación de seguridad es: %s', 'wp-security-monitor' ), $code );
        return wp_mail( $user->user_email, __( 'Código de verificación', 'wp-security-monitor' ), $message );
    }

    public function validate_code( $user_id, $code ) {
        $saved_code = get_transient( 'wpsm_2fa_email_code_' . $user_id );
        return $saved_code && $saved_code === $code;
    }
}
