<?php
/**
 * Motor de Escaneo de Salud y Seguridad
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Scanner {
    private $logger;
    private $integrity;

    public function __construct( $logger, $integrity ) {
        $this->logger = $logger;
        $this->integrity = $integrity;
    }

    public function run_scan() {
        $results = array(
            'critical' => array(),
            'warning'  => array(),
            'info'     => array()
        );

        // 1. Integridad de archivos
        $file_changes = $this->integrity->scan_integrity();
        if ( ! empty( $file_changes ) ) {
            foreach ( $file_changes as $file ) {
                $msg = sprintf( __( 'Cambio detectado en archivo sensible: %s', 'wp-security-monitor' ), basename( $file ) );
                $results['critical'][] = $msg;
                $this->logger->log( 'file_change', $msg, 'critical' );
            }
        }

        // 2. Estado de actualizaciones
        $updates = get_site_transient( 'update_core' );
        if ( isset( $updates->updates ) && ! empty( $updates->updates ) && $updates->updates[0]->response === 'upgrade' ) {
            $results['warning'][] = __( 'WordPress tiene una actualización disponible.', 'wp-security-monitor' );
        }

        $plugin_updates = get_site_transient( 'update_plugins' );
        if ( ! empty( $plugin_updates->response ) ) {
            $results['warning'][] = __( 'Hay plugins desactualizados.', 'wp-security-monitor' );
        }

        // 3. Debug mode
        if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
            $results['info'][] = __( 'El modo WP_DEBUG está activado.', 'wp-security-monitor' );
        }

        // 4. Archivos sospechosos en Uploads
        $this->scan_uploads( $results );

        // Guardar resultado del último escaneo
        update_option( 'wpsm_last_scan_results', $results );
        update_option( 'wpsm_last_scan_time', current_time( 'mysql' ) );

        return $results;
    }

    private function scan_uploads( &$results ) {
        $upload_dir = wp_upload_dir();
        $base_path = $upload_dir['basedir'];

        if ( is_dir( $base_path ) ) {
            // Optimización: Solo escaneamos archivos PHP en la raíz de uploads y primer nivel de subcarpetas
            // para evitar recorrer miles de imágenes si el sitio es grande.
            $it = new DirectoryIterator( $base_path );
            foreach ( $it as $fileinfo ) {
                if ( $fileinfo->isFile() && $fileinfo->getExtension() === 'php' ) {
                    $this->report_suspicious_php( $fileinfo->getFilename(), $results );
                }
                if ( $fileinfo->isDir() && ! $fileinfo->isDot() ) {
                    $sub_it = new DirectoryIterator( $fileinfo->getPathname() );
                    foreach ( $sub_it as $sub_file ) {
                        if ( $sub_file->isFile() && $sub_file->getExtension() === 'php' ) {
                            $this->report_suspicious_php( $sub_file->getFilename(), $results );
                        }
                    }
                }
            }
        }
    }

    private function report_suspicious_php( $filename, &$results ) {
        $msg = sprintf( __( 'Archivo PHP sospechoso en uploads: %s', 'wp-security-monitor' ), $filename );
        $results['critical'][] = $msg;
        $this->logger->log( 'suspicious_file', $msg, 'critical' );
    }

    public function get_security_score() {
        $results = get_option( 'wpsm_last_scan_results', array() );
        $score = 100;

        if ( ! empty( $results['critical'] ) ) $score -= count( $results['critical'] ) * 20;
        if ( ! empty( $results['warning'] ) )  $score -= count( $results['warning'] ) * 5;

        return max( 0, $score );
    }
}
