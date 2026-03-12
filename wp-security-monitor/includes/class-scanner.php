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
            'info'     => array(),
            'passed'   => array(),
            'recommendations' => array()
        );

        // 1. Integridad de archivos
        $file_changes = $this->integrity->scan_integrity();
        if ( ! empty( $file_changes ) ) {
            foreach ( $file_changes as $file ) {
                $msg = sprintf( __( 'Cambio detectado en archivo sensible: %s', 'wp-security-monitor' ), basename( $file ) );
                $results['critical'][] = $msg;
                $results['recommendations'][] = sprintf( __( 'Restaura el archivo %s desde una copia de seguridad confiable.', 'wp-security-monitor' ), basename( $file ) );
                $this->logger->log( 'file_change', $msg, 'critical' );
            }
        } else {
            $results['passed'][] = __( 'Archivos sensibles del core protegidos e íntegros.', 'wp-security-monitor' );
        }

        // 2. Estado de actualizaciones
        $updates = get_site_transient( 'update_core' );
        if ( isset( $updates->updates ) && ! empty( $updates->updates ) && $updates->updates[0]->response === 'upgrade' ) {
            $msg = __( 'WordPress tiene una actualización disponible.', 'wp-security-monitor' );
            $results['warning'][] = $msg;
            $results['recommendations'][] = __( 'Actualiza WordPress a la última versión estable.', 'wp-security-monitor' );
        } else {
            $results['passed'][] = __( 'WordPress está actualizado.', 'wp-security-monitor' );
        }

        $plugin_updates = get_site_transient( 'update_plugins' );
        if ( ! empty( $plugin_updates->response ) ) {
            $results['warning'][] = __( 'Hay plugins desactualizados.', 'wp-security-monitor' );
            $results['recommendations'][] = __( 'Actualiza todos tus plugins para evitar vulnerabilidades conocidas.', 'wp-security-monitor' );
        } else {
            $results['passed'][] = __( 'Todos los plugins están actualizados.', 'wp-security-monitor' );
        }

        // 3. SSL
        if ( is_ssl() ) {
            $results['passed'][] = __( 'El sitio utiliza una conexión segura (SSL).', 'wp-security-monitor' );
        } else {
            $results['warning'][] = __( 'El sitio no utiliza SSL.', 'wp-security-monitor' );
            $results['recommendations'][] = __( 'Instala un certificado SSL para cifrar el tráfico de tus usuarios.', 'wp-security-monitor' );
        }

        // 4. Usuario 'admin'
        if ( username_exists( 'admin' ) ) {
            $results['critical'][] = __( 'Se detectó el usuario predeterminado "admin".', 'wp-security-monitor' );
            $results['recommendations'][] = __( 'Crea un nuevo administrador con un nombre de usuario diferente y elimina el usuario "admin".', 'wp-security-monitor' );
        } else {
            $results['passed'][] = __( 'No se utiliza el usuario "admin" por defecto.', 'wp-security-monitor' );
        }

        // 5. Prefijo de base de datos
        global $wpdb;
        if ( $wpdb->prefix === 'wp_' ) {
            $results['info'][] = __( 'La base de datos utiliza el prefijo predeterminado "wp_".', 'wp-security-monitor' );
            $results['recommendations'][] = __( 'Cambia el prefijo de las tablas de la base de datos para dificultar ataques de inyección SQL.', 'wp-security-monitor' );
        } else {
            $results['passed'][] = __( 'El prefijo de la base de datos es personalizado.', 'wp-security-monitor' );
        }

        // 6. Debug mode
        if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
            $results['info'][] = __( 'El modo WP_DEBUG está activado.', 'wp-security-monitor' );
            $results['recommendations'][] = __( 'Desactiva WP_DEBUG en producción para no exponer rutas de archivos o errores internos.', 'wp-security-monitor' );
        } else {
            $results['passed'][] = __( 'El modo de depuración (WP_DEBUG) está desactivado.', 'wp-security-monitor' );
        }

        // 7. Archivos sospechosos en Uploads
        $this->scan_uploads( $results );
        if ( empty( $results['critical_uploads'] ) ) {
             $results['passed'][] = __( 'Carpeta de uploads libre de archivos PHP sospechosos.', 'wp-security-monitor' );
        }

        // Guardar resultado del último escaneo
        update_option( 'wpsm_last_scan_results', $results );
        update_option( 'wpsm_last_scan_time', current_time( 'mysql' ) );

        return $results;
    }

    private function scan_uploads( &$results ) {
        $upload_dir = wp_upload_dir();
        $base_path = $upload_dir['basedir'];
        $found_php = false;

        if ( is_dir( $base_path ) ) {
            // Re-implementando con RecursiveDirectoryIterator para profundidad 2 (uploads/year/month)
            $this->recursive_scan( $base_path, 0, 2, $found_php, $results );
        }

        if ( $found_php ) {
            $results['critical_uploads'] = true;
            $results['recommendations'][] = __( 'Elimina inmediatamente cualquier archivo PHP en la carpeta de uploads.', 'wp-security-monitor' );
        }
    }

    private function recursive_scan( $path, $depth, $max_depth, &$found_php, &$results ) {
        if ( $depth > $max_depth ) return;

        $it = new DirectoryIterator( $path );
        foreach ( $it as $fileinfo ) {
            if ( $fileinfo->isDot() ) continue;
            if ( $fileinfo->isFile() && $fileinfo->getExtension() === 'php' ) {
                $this->report_suspicious_php( $fileinfo->getFilename(), $results );
                $found_php = true;
            }
            if ( $fileinfo->isDir() ) {
                $this->recursive_scan( $fileinfo->getPathname(), $depth + 1, $max_depth, $found_php, $results );
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

        if ( ! empty( $results['critical'] ) ) $score -= count( $results['critical'] ) * 15;
        if ( ! empty( $results['warning'] ) )  $score -= count( $results['warning'] ) * 5;
        if ( ! empty( $results['info'] ) )     $score -= count( $results['info'] ) * 2;

        return max( 0, min( 100, $score ) );
    }
}
