<?php
/**
 * Editor seguro para wp-config.php
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Config_Editor {
    private $config_path;

    public function __construct() {
        $this->config_path = ABSPATH . 'wp-config.php';
    }

    public function is_writable() {
        return is_writable( $this->config_path );
    }

    /**
     * Añade o actualiza una constante en wp-config.php
     */
    public function update_constant( $name, $value ) {
        if ( ! $this->is_writable() ) return false;

        $config = file_get_contents( $this->config_path );
        $value_str = is_bool( $value ) ? ( $value ? 'true' : 'false' ) : var_export( $value, true );

        // Backup
        file_put_contents( $this->config_path . '.bak', $config );

        $pattern = "/define\s*\(\s*['\"]" . preg_quote( $name ) . "['\"]\s*,\s*[^)]+\s*\)\s*;/i";
        $replacement = "define( '$name', $value_str );";

        if ( preg_match( $pattern, $config ) ) {
            $config = preg_replace( $pattern, $replacement, $config );
        } else {
            // Insertar antes del comentario de stop editing
            $stop_editing = "/* That's all, stop editing!";
            if ( strpos( $config, $stop_editing ) !== false ) {
                $config = str_replace( $stop_editing, $replacement . "\n" . $stop_editing, $config );
            } else {
                $config .= "\n" . $replacement;
            }
        }

        return file_put_contents( $this->config_path, $config );
    }
}
