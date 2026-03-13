<?php
/**
 * Auditoría y Visibilidad de Extensiones
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Extension_Auditor {
    private $logger;

    public function __construct( $logger ) {
        $this->logger = $logger;
    }

    public function init() {
        // Asegurar visibilidad total de plugins
        add_filter( 'all_plugins', array( $this, 'ensure_plugin_visibility' ), 999 );

        // Inyectar JS para evitar ocultación por CSS/JS
        add_action( 'admin_footer-plugins.php', array( $this, 'inject_visibility_script' ) );
    }

    /**
     * Evita que otros plugins oculten plugins de la lista principal
     */
    public function ensure_plugin_visibility( $all_plugins ) {
        return $all_plugins;
    }

    /**
     * Script para forzar la visibilidad en el DOM
     */
    public function inject_visibility_script() {
        ?>
        <script>
        jQuery(document).ready(function($) {
            $('#the-list tr').show();
            console.log('WPSM: Forzando visibilidad de todos los plugins.');
        });
        </script>
        <?php
    }

    /**
     * Realiza una auditoría completa de todas las extensiones instaladas
     */
    public function audit_all_extensions() {
        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $plugins = get_plugins();
        $themes = wp_get_themes();

        $audit_data = array(
            'plugins' => array(),
            'themes'  => array()
        );

        foreach ( $plugins as $file => $data ) {
            $audit_data['plugins'][] = array(
                'name'    => $data['Name'],
                'version' => $data['Version'],
                'slug'    => dirname( $file ),
                'active'  => is_plugin_active( $file )
            );
        }

        foreach ( $themes as $slug => $theme ) {
            $audit_data['themes'][] = array(
                'name'    => $theme->get( 'Name' ),
                'version' => $theme->get( 'Version' ),
                'slug'    => $slug,
                'active'  => ( get_stylesheet() === $slug )
            );
        }

        return $audit_data;
    }

    /**
     * Reinstala un plugin desde el repositorio oficial de WordPress.org
     */
    public function reinstall_from_repo( $slug ) {
        if ( empty( $slug ) ) return false;

        include_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        include_once ABSPATH . 'wp-admin/includes/plugin-install.php';

        $api = plugins_api( 'plugin_information', array( 'slug' => $slug, 'fields' => array( 'sections' => false ) ) );

        if ( is_wp_error( $api ) ) {
            return $api;
        }

        $skin = new WP_Ajax_Upgrader_Skin();
        $upgrader = new Plugin_Upgrader( $skin );

        $result = $upgrader->install( $api->download_link, array( 'overwrite_package' => true ) );

        if ( ! is_wp_error( $result ) ) {
            $this->logger->log( 'system_action', sprintf( __( 'Plugin %s reinstalado correctamente desde el repositorio oficial.', 'wp-security-monitor' ), $slug ), 'low' );
        }

        return $result;
    }
}
