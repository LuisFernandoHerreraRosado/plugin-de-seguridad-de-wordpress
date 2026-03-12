<?php
/**
 * Sistema de Logs interno
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Logger {
    private $table_name;

    public function __construct() {
        global $wpdb;
        $this->table_name = $wpdb->prefix . 'wpsm_logs';
    }

    public function create_tables() {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $this->table_name (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            time datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            event_type varchar(50) NOT NULL,
            severity varchar(20) DEFAULT 'low' NOT NULL,
            message text NOT NULL,
            user_id bigint(20) DEFAULT 0,
            ip varchar(45) DEFAULT '',
            metadata text DEFAULT '',
            PRIMARY KEY  (id),
            KEY event_type (event_type),
            KEY severity (severity)
        ) $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql );
    }

    public function log( $type, $message, $severity = 'low', $metadata = '' ) {
        global $wpdb;

        $user_id = get_current_user_id();
        $ip = $this->get_ip();

        return $wpdb->insert(
            $this->table_name,
            array(
                'event_type' => sanitize_text_field( $type ),
                'message'    => wp_kses_post( $message ),
                'severity'   => sanitize_text_field( $severity ),
                'user_id'    => $user_id,
                'ip'         => $ip,
                'metadata'   => is_array( $metadata ) ? json_encode( $metadata ) : $metadata
            )
        );
    }

    private function get_ip() {
        if ( ! empty( $_SERVER['HTTP_CLIENT_IP'] ) ) {
            return $_SERVER['HTTP_CLIENT_IP'];
        } elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            return $_SERVER['HTTP_X_FORWARDED_FOR'];
        }
        return $_SERVER['REMOTE_ADDR'];
    }

    public function get_logs( $limit = 50, $offset = 0 ) {
        global $wpdb;
        return $wpdb->get_results( $wpdb->prepare(
            "SELECT * FROM $this->table_name ORDER BY time DESC LIMIT %d OFFSET %d",
            $limit, $offset
        ) );
    }

    public function purge_logs() {
        global $wpdb;
        return $wpdb->query( "TRUNCATE TABLE $this->table_name" );
    }
}
