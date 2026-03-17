<?php
/**
 * Gestión de Backups
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Backup_Manager {
    private $logger;
    private $settings;
    private $backup_dir;

    public function __construct( $logger, $settings ) {
        $this->logger = $logger;
        $this->settings = $settings;
        $upload_dir = wp_upload_dir();
        $this->backup_dir = $upload_dir['basedir'] . '/wpsm-backups';

        if ( ! file_exists( $this->backup_dir ) ) {
            wp_mkdir_p( $this->backup_dir );
            // Protege el directorio con un .htaccess
            file_put_contents( $this->backup_dir . '/.htaccess', "Deny from all" );
            file_put_contents( $this->backup_dir . '/index.php', "<?php // Silence is golden" );
        }
    }

    /**
     * Inicia el proceso de backup
     */
    public function run_backup( $type = 'full' ) {
        $db_file = false;
        $files_file = false;

        $this->logger->log( 'backup_started', sprintf( __( 'Backup de tipo %s iniciado.', 'wp-security-monitor' ), $type ), 'low' );

        if ( $type === 'db' || $type === 'full' ) {
            $db_file = $this->backup_database();
        }

        if ( $type === 'files' || $type === 'full' ) {
            $files_file = $this->backup_files();
        }

        if ( ( $type === 'db' && $db_file ) || ( $type === 'files' && $files_file ) || ( $type === 'full' && $db_file && $files_file ) ) {
            $this->add_to_history( $type, $db_file, $files_file );
            $this->logger->log( 'backup_completed', sprintf( __( 'Backup de tipo %s completado con éxito.', 'wp-security-monitor' ), $type ), 'medium' );
            return true;
        }

        $this->logger->log( 'backup_failed', sprintf( __( 'Backup de tipo %s falló.', 'wp-security-monitor' ), $type ), 'critical' );
        return false;
    }

    /**
     * Añade una entrada al historial
     */
    private function add_to_history( $type, $db_file, $files_file ) {
        $history = $this->get_history();
        $entry = array(
            'id'         => time(),
            'date'       => date( 'Y-m-d H:i:s' ),
            'type'       => $type,
            'db_file'    => $db_file ? basename( $db_file ) : null,
            'files_file' => $files_file ? basename( $files_file ) : null,
            'status'     => 'success'
        );

        array_unshift( $history, $entry );

        // Limitar historial a los últimos 10
        if ( count( $history ) > 10 ) {
            $old = array_pop( $history );
            // Aquí se podría eliminar el archivo físico si se desea
        }

        update_option( 'wpsm_backup_history', $history );
    }

    /**
     * Backup de Base de Datos
     */
    private function backup_database() {
        global $wpdb;
        $tables = $wpdb->get_col( "SHOW TABLES" );
        $sql = "-- WP Security Monitor SQL Dump\n";
        $sql .= "-- Generation Time: " . date( 'Y-m-d H:i:s' ) . "\n\n";

        foreach ( $tables as $table ) {
            $create_table = $wpdb->get_row( "SHOW CREATE TABLE $table", ARRAY_A );
            $sql .= "DROP TABLE IF EXISTS `$table`;\n";
            $sql .= $create_table['Create Table'] . ";\n\n";

            $rows = $wpdb->get_results( "SELECT * FROM $table", ARRAY_A );
            foreach ( $rows as $row ) {
                $fields = array_map( array( $wpdb, '_escape' ), array_values( $row ) );
                $sql .= "INSERT INTO `$table` VALUES ('" . implode( "','", $fields ) . "');\n";
            }
            $sql .= "\n";
        }

        $filename = 'db-backup-' . date( 'Y-m-d-His' ) . '.sql';
        $filepath = $this->backup_dir . '/' . $filename;

        if ( file_put_contents( $filepath, $sql ) ) {
            return $filepath;
        }

        return false;
    }

    /**
     * Backup de Archivos
     */
    private function backup_files() {
        if ( ! class_exists( 'ZipArchive' ) ) {
            return false;
        }

        $filename = 'file-backup-' . date( 'Y-m-d-His' ) . '.zip';
        $filepath = $this->backup_dir . '/' . $filename;
        $zip = new ZipArchive();

        if ( $zip->open( $filepath, ZipArchive::CREATE ) !== true ) {
            return false;
        }

        $root_path = ABSPATH;
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator( $root_path, RecursiveDirectoryIterator::SKIP_DOTS ),
            RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ( $files as $name => $file ) {
            if ( ! $file->isDir() ) {
                $file_real_path = $file->getRealPath();
                $relative_path  = substr( $file_real_path, strlen( $root_path ) );

                // Evitar incluir el directorio de backups en sí mismo
                if ( strpos( $file_real_path, $this->backup_dir ) === false ) {
                    $zip->addFile( $file_real_path, $relative_path );
                }
            }
        }

        $zip->close();
        return $filepath;
    }

    /**
     * Obtiene el historial de backups
     */
    public function get_history() {
        return get_option( 'wpsm_backup_history', array() );
    }

    /**
     * Evalúa riesgos del almacenamiento actual
     */
    public function assess_storage_risk() {
        $risks = array();

        // Verificar si el directorio es escribible
        if ( ! is_writable( $this->backup_dir ) ) {
            $risks[] = __( 'El directorio de backups no tiene permisos de escritura.', 'wp-security-monitor' );
        }

        // Verificar si es accesible públicamente
        $test_file = $this->backup_dir . '/test.txt';
        file_put_contents( $test_file, 'test' );
        $upload_dir = wp_upload_dir();
        $test_url = $upload_dir['baseurl'] . '/wpsm-backups/test.txt';

        $response = wp_remote_get( $test_url, array( 'timeout' => 5, 'sslverify' => false ) );
        if ( ! is_wp_error( $response ) && wp_remote_retrieve_response_code( $response ) === 200 ) {
            $risks[] = __( '¡Peligro! El directorio de backups es accesible públicamente desde la web.', 'wp-security-monitor' );
        }
        @unlink( $test_file );

        // Verificar si el almacenamiento es local (siempre local por ahora)
        if ( $this->settings->get_setting( 'storage_provider', 'local' ) === 'local' ) {
            $risks[] = __( 'Advertencia: Estás usando almacenamiento local. Se recomienda configurar una ubicación remota para mayor seguridad.', 'wp-security-monitor' );
        }

        return $risks;
    }

    /**
     * Backup preventivo antes de acciones críticas
     */
    public function preventive_backup() {
        if ( $this->settings->get_setting( 'preventive_backup', 'yes' ) === 'yes' ) {
            return $this->run_backup( 'db' ); // Por defecto solo DB por rapidez
        }
        return true;
    }
}
