<?php
/**
 * Integridad de Archivos
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_File_Integrity {
    private $table_name;

    public function __construct() {
        global $wpdb;
        $this->table_name = $wpdb->prefix . 'wpsm_file_integrity';
    }

    public function create_tables() {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $this->table_name (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            file_path text NOT NULL,
            file_hash varchar(64) NOT NULL,
            last_checked datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            status varchar(20) DEFAULT 'trusted' NOT NULL,
            PRIMARY KEY  (id)
        ) $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql );
    }

    public function get_monitored_files() {
        return array(
            ABSPATH . 'wp-config.php',
            ABSPATH . '.htaccess',
            ABSPATH . 'index.php',
            ABSPATH . 'wp-settings.php',
            ABSPATH . 'wp-login.php',
            ABSPATH . 'wp-load.php'
        );
    }

    public function scan_integrity() {
        $files = $this->get_monitored_files();
        $changes = array();

        foreach ( $files as $file ) {
            if ( ! file_exists( $file ) ) continue;

            $current_hash = hash_file( 'sha256', $file );
            $stored_data  = $this->get_stored_data( $file );

            if ( ! $stored_data ) {
                $this->save_hash( $file, $current_hash, 'trusted' );
            } elseif ( $stored_data->file_hash !== $current_hash ) {
                // Solo alertamos si no ha sido marcado como 'modified_trusted' por el usuario
                if ( $stored_data->status !== 'modified_trusted' ) {
                    $changes[] = $file;
                }
            }
        }

        return $changes;
    }

    private function get_stored_data( $file ) {
        global $wpdb;
        return $wpdb->get_row( $wpdb->prepare(
            "SELECT file_hash, status FROM $this->table_name WHERE file_path = %s",
            $file
        ) );
    }

    public function save_hash( $file, $hash, $status = 'trusted' ) {
        global $wpdb;
        $exists = $this->get_stored_data( $file );

        if ( $exists ) {
            $wpdb->update( $this->table_name,
                array( 'file_hash' => $hash, 'last_checked' => current_time( 'mysql' ), 'status' => $status ),
                array( 'file_path' => $file )
            );
        } else {
            $wpdb->insert( $this->table_name,
                array( 'file_path' => $file, 'file_hash' => $hash, 'last_checked' => current_time( 'mysql' ), 'status' => $status )
            );
        }
    }
}
