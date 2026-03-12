<?php
/**
 * Fired when the plugin is uninstalled.
 */

// If uninstall not called from WordPress, then exit.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// Limpiar opciones
delete_option( 'wpsm_site_uuid' );
delete_option( 'wpsm_api_key' );
delete_option( 'wpsm_last_scan_results' );
delete_option( 'wpsm_last_scan_time' );
delete_option( 'wpsm_alert_email' );
delete_option( 'wpsm_scan_frequency' );

// Eliminar tablas personalizadas
global $wpdb;
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}wpsm_logs" );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}wpsm_file_integrity" );

// Limpiar cron
wp_clear_scheduled_hook( 'wpsm_scheduled_scan' );
wp_clear_scheduled_hook( 'wpsm_scheduled_sync' );
