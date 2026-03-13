<?php
/**
 * Proveedor 2FA: Códigos de Respaldo
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_2FA_Backup_Codes {
    public function generate_codes( $user_id, $count = 10 ) {
        $codes = array();
        for ( $i = 0; $i < $count; $i++ ) {
            $codes[] = wp_generate_password( 8, false, false );
        }

        $hashed_codes = array_map( 'wp_hash_password', $codes );
        update_user_meta( $user_id, 'wpsm_2fa_backup_codes', $hashed_codes );

        return $codes;
    }

    public function validate_code( $user_id, $code ) {
        $hashes = get_user_meta( $user_id, 'wpsm_2fa_backup_codes', true );
        if ( ! is_array( $hashes ) ) return false;

        foreach ( $hashes as $index => $hash ) {
            if ( wp_check_password( $code, $hash ) ) {
                unset( $hashes[$index] );
                update_user_meta( $user_id, 'wpsm_2fa_backup_codes', array_values( $hashes ) );
                return true;
            }
        }
        return false;
    }
}
