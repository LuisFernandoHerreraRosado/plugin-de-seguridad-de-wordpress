<?php
/**
 * Tareas Programadas (WP-Cron)
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Cron {
    private $scanner;

    public function __construct( $scanner = null ) {
        $this->scanner = $scanner;
    }

    public function init() {
        add_action( 'wpsm_scheduled_scan', array( $this, 'execute_scan' ) );
        add_action( 'wpsm_scheduled_sync', array( $this, 'execute_sync' ) );
        add_action( 'wpsm_scheduled_backup', array( $this, 'execute_backup' ) );
    }

    public static function register_defaults() {
        if ( ! wp_next_scheduled( 'wpsm_scheduled_scan' ) ) {
            wp_schedule_event( time(), 'daily', 'wpsm_scheduled_scan' );
        }
        if ( ! wp_next_scheduled( 'wpsm_scheduled_sync' ) ) {
            wp_schedule_event( time(), 'hourly', 'wpsm_scheduled_sync' );
        }
    }

    public function execute_scan() {
        if ( $this->scanner ) {
            $this->scanner->run_scan();
        }
    }

    public function execute_sync() {
        $remote_sync = new WPSM_Remote_Sync( new WPSM_Logger() );
        $remote_sync->send_heartbeat();
    }

    public function execute_backup() {
        $logger = new WPSM_Logger();
        $settings = new WPSM_Settings();
        $manager = new WPSM_Backup_Manager( $logger, $settings );
        $manager->run_backup( 'full' );
    }

    public function update_schedule( $frequency ) {
        wp_clear_scheduled_hook( 'wpsm_scheduled_scan' );
        if ( $frequency !== 'none' ) {
            wp_schedule_event( time(), $frequency, 'wpsm_scheduled_scan' );
        }
    }
}
