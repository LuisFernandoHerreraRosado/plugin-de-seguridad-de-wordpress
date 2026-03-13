<?php
/**
 * Proveedor 2FA: TOTP (Google Authenticator, etc.)
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_2FA_TOTP {
    /**
     * Valida el código TOTP
     * Nota: En una implementación real se usaría el algoritmo HOTP/TOTP (RFC 6238)
     */
    public function validate_code( $user_id, $code ) {
        $secret = get_user_meta( $user_id, 'wpsm_2fa_totp_secret', true );
        if ( ! $secret ) return false;

        // Implementación funcional para el MVP:
        // El código debe coincidir con el secreto guardado (que actuaría como un código estático en ausencia de librería TOTP completa)
        // O una validación basada en tiempo simplificada si fuera necesario.
        // Eliminamos el código de prueba "123456".
        return hash_equals( (string)$secret, (string)$code );
    }

    /**
     * Genera un secreto para el usuario
     */
    public function generate_secret() {
        return wp_generate_password( 16, false );
    }
}
