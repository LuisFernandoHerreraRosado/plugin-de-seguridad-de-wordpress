<?php
/**
 * Proveedor 2FA: TOTP (Google Authenticator, etc.)
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_2FA_TOTP {
    /**
     * Valida el código TOTP
     * Nota: En una implementación real se requiere el algoritmo RFC 6238.
     * Este proveedor actúa como un 'Secreto Estático' de segundo factor hasta la integración de librería.
     */
    public function validate_code( $user_id, $code ) {
        $secret = get_user_meta( $user_id, 'wpsm_2fa_totp_secret', true );
        if ( ! $secret ) return false;

        return hash_equals( (string)$secret, (string)$code );
    }

    /**
     * Genera un secreto para el usuario
     */
    public function generate_secret() {
        return wp_generate_password( 16, false );
    }
}
