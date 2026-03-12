<?php
/**
 * Sistema de Alertas
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Alerts {
    public function send_email_alert( $subject, $message ) {
        $to = get_option( 'wpsm_alert_email', get_option( 'admin_email' ) );
        $headers = array( 'Content-Type: text/html; charset=UTF-8' );

        $body = "<h2>" . __( 'WP Security Monitor Alert', 'wp-security-monitor' ) . "</h2>";
        $body .= "<p>" . wp_kses_post( $message ) . "</p>";
        $body .= "<p>---<br>" . __( 'Este es un correo automático de tu sitio WordPress.', 'wp-security-monitor' ) . "</p>";

        return wp_mail( $to, $subject, $body, $headers );
    }

    public function trigger_critical_alert( $event_type, $details ) {
        /* translators: %s: Site name */
        $subject = sprintf( __( '[WPSM] Alerta Crítica en %s', 'wp-security-monitor' ), get_bloginfo( 'name' ) );
        $this->send_email_alert( $subject, $details );

        // Hook para futuras integraciones (Slack, Telegram)
        do_action( 'wpsm_critical_alert_triggered', $event_type, $details );
    }
}
