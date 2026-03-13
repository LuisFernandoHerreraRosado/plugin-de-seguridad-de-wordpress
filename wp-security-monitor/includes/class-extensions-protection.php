<?php
/**
 * Protección de Extensiones (Plugins y Themes)
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Extensions_Protection {
    private $logger;
    private $settings;

    public function __construct( $logger, $settings ) {
        $this->logger = $logger;
        $this->settings = $settings;
    }

    public function init() {
        // Bloquear carga de archivos .zip
        if ( $this->settings->get_setting( 'block_zip_upload', 'no' ) === 'yes' ) {
            add_filter( 'wp_handle_upload_prefilter', array( $this, 'block_zip_uploads' ) );
        }

        // Restringir operaciones de plugins y themes
        if ( $this->settings->get_setting( 'restrict_ext_ops', 'no' ) === 'yes' ) {
            add_filter( 'user_has_cap', array( $this, 'restrict_capabilities' ), 10, 3 );
            add_filter( 'plugin_action_links', array( $this, 'remove_plugin_action_links' ), 10, 4 );
        }

        // Forzar método de escritura FTP si se requiere
        if ( $this->settings->get_setting( 'force_ftp', 'no' ) === 'yes' ) {
            add_filter( 'filesystem_method', array( $this, 'force_ftp_method' ) );
        }

        // Auditar el método de escritura actual
        add_action( 'admin_init', array( $this, 'audit_filesystem_method' ) );
    }

    /**
     * Bloquea la subida de archivos ZIP
     */
    public function block_zip_uploads( $file ) {
        if ( $file['type'] === 'application/zip' || pathinfo( $file['name'], PATHINFO_EXTENSION ) === 'zip' ) {
            $file['error'] = __( 'La subida de archivos ZIP está restringida por seguridad.', 'wp-security-monitor' );
            $this->logger->log( 'security_alert', sprintf( __( 'Intento de subida de archivo ZIP bloqueado: %s', 'wp-security-monitor' ), $file['name'] ), 'medium' );
        }
        return $file;
    }

    /**
     * Restringe capacidades para prevenir instalación/borrado desde el backend
     */
    public function restrict_capabilities( $allcaps, $caps, $args ) {
        $restricted_caps = array(
            'install_plugins', 'delete_plugins', 'update_plugins', 'activate_plugins', 'deactivate_plugins',
            'install_themes', 'delete_themes', 'update_themes', 'switch_themes'
        );

        foreach ( $caps as $cap ) {
            if ( in_array( $cap, $restricted_caps ) ) {
                $allcaps[$cap] = false;
            }
        }

        return $allcaps;
    }

    /**
     * Elimina enlaces de acción (Desactivar/Eliminar) en la lista de plugins
     */
    public function remove_plugin_action_links( $actions, $plugin_file, $plugin_data, $context ) {
        if ( isset( $actions['deactivate'] ) ) unset( $actions['deactivate'] );
        if ( isset( $actions['delete'] ) ) unset( $actions['delete'] );
        return $actions;
    }

    /**
     * Fuerza el método de escritura FTP
     */
    public function force_ftp_method( $method ) {
        return 'ftpext';
    }

    /**
     * Audita y loguea el método de escritura actual
     */
    public function audit_filesystem_method() {
        if ( ! function_exists( 'get_filesystem_method' ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        $method = get_filesystem_method();
        if ( $method === 'direct' && $this->settings->get_setting( 'force_ftp', 'no' ) === 'yes' ) {
            $this->logger->log( 'security_warning', __( 'El sistema está usando el método de escritura DIRECTO a pesar de la restricción FTP.', 'wp-security-monitor' ), 'high' );
        }
    }
}
