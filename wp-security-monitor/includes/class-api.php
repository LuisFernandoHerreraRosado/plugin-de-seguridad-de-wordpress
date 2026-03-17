<?php
/**
 * REST API del Plugin
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_API {
    private $namespace = 'wgsm/v1';
    private $logger;
    private $scanner;
    private $integrity;

    public function __construct( $logger, $scanner, $integrity ) {
        $this->logger = $logger;
        $this->scanner = $scanner;
        $this->integrity = $integrity;
    }

    public function init() {
        add_action( 'rest_api_init', array( $this, 'register_routes' ) );
    }

    public function register_routes() {
        register_rest_route( $this->namespace, '/status', array(
            'methods'  => 'GET',
            'callback' => array( $this, 'get_status' ),
            'permission_callback' => array( $this, 'check_permission' )
        ) );

        register_rest_route( $this->namespace, '/scan', array(
            'methods'  => 'POST',
            'callback' => array( $this, 'run_manual_scan' ),
            'permission_callback' => array( $this, 'check_permission' )
        ) );

        register_rest_route( $this->namespace, '/logs', array(
            'methods'  => 'GET',
            'callback' => array( $this, 'get_logs' ),
            'permission_callback' => array( $this, 'check_permission' )
        ) );


        register_rest_route( $this->namespace, '/sessions', array(
            'methods'  => 'GET',
            'callback' => array( $this, 'get_active_sessions' ),
            'permission_callback' => array( $this, 'check_permission' )
        ) );

        register_rest_route( $this->namespace, '/sessions/terminate', array(
            'methods'  => 'POST',
            'callback' => array( $this, 'terminate_session' ),
            'permission_callback' => array( $this, 'check_permission' )
        ) );

        register_rest_route( $this->namespace, '/extensions', array(
            'methods'  => 'GET',
            'callback' => array( $this, 'get_extensions' ),
            'permission_callback' => array( $this, 'check_permission' )
        ) );

        register_rest_route( $this->namespace, '/vulnerabilities', array(
            'methods'  => 'GET',
            'callback' => array( $this, 'get_vulnerabilities' ),
            'permission_callback' => array( $this, 'check_permission' )
        ) );

        register_rest_route( $this->namespace, '/extensions/reinstall', array(
            'methods'  => 'POST',
            'callback' => array( $this, 'reinstall_extension' ),
            'permission_callback' => array( $this, 'check_permission' )
        ) );

        // Nuevos endpoints para WordPress Core
        register_rest_route( $this->namespace, '/core/status', array(
            'methods'  => 'GET',
            'callback' => array( $this, 'get_core_status' ),
            'permission_callback' => array( $this, 'check_permission' )
        ) );

        register_rest_route( $this->namespace, '/database/prefix', array(
            'methods'  => 'GET',
            'callback' => array( $this, 'get_db_status' ),
            'permission_callback' => array( $this, 'check_permission' )
        ) );

        register_rest_route( $this->namespace, '/sensitive-data', array(
            'methods'  => 'GET',
            'callback' => array( $this, 'get_sensitive_settings' ),
            'permission_callback' => array( $this, 'check_permission' )
        ) );

        register_rest_route( $this->namespace, '/sensitive-data', array(
            'methods'  => 'POST',
            'callback' => array( $this, 'update_sensitive_settings' ),
            'permission_callback' => array( $this, 'check_permission' )
        ) );

        // Endpoints de Backups
        register_rest_route( $this->namespace, '/backups', array(
            'methods'  => 'GET',
            'callback' => array( $this, 'get_backups' ),
            'permission_callback' => array( $this, 'check_permission' )
        ) );

        register_rest_route( $this->namespace, '/backups/run', array(
            'methods'  => 'POST',
            'callback' => array( $this, 'run_backup' ),
            'permission_callback' => array( $this, 'check_permission' )
        ) );

        register_rest_route( $this->namespace, '/backups/config', array(
            'methods'  => 'GET',
            'callback' => array( $this, 'get_backup_config' ),
            'permission_callback' => array( $this, 'check_permission' )
        ) );

        register_rest_route( $this->namespace, '/backups/config', array(
            'methods'  => 'POST',
            'callback' => array( $this, 'update_backup_config' ),
            'permission_callback' => array( $this, 'check_permission' )
        ) );
    }

    public function check_permission( $request ) {
        $api_key = $request->get_header( 'X-WPSM-KEY' );
        $saved_key = get_option( 'wpsm_api_key' );

        if ( empty( $saved_key ) ) return false;

        return hash_equals( $saved_key, (string)$api_key );
    }

    public function get_status( $request ) {
        $identity = WPSM_Site_Identity::get_instance();
        return new WP_REST_Response( array(
            'site_info' => $identity->get_site_info(),
            'score'     => $this->scanner->get_security_score(),
            'last_scan' => get_option( 'wpsm_last_scan_time' ),
            'alerts'    => get_option( 'wpsm_last_scan_results' )
        ), 200 );
    }

    public function run_manual_scan( $request ) {
        $results = $this->scanner->run_scan();
        return new WP_REST_Response( array( 'success' => true, 'results' => $results ), 200 );
    }

    public function get_logs( $request ) {
        return new WP_REST_Response( $this->logger->get_logs( 20, 0 ), 200 );
    }


    public function get_active_sessions( $request ) {
        $user_id = $request->get_param( 'user_id' );
        if ( ! $user_id ) return new WP_Error( 'missing_user_id', 'User ID is required', array( 'status' => 400 ) );

        $manager = WP_Session_Tokens::get_instance( $user_id );
        return new WP_REST_Response( $manager->get_all(), 200 );
    }

    public function terminate_session( $request ) {
        $user_id = $request->get_param( 'user_id' );
        $verifier = $request->get_param( 'verifier' );

        if ( ! $user_id ) return new WP_Error( 'missing_user_id', 'User ID is required', array( 'status' => 400 ) );

        $manager = WP_Session_Tokens::get_instance( $user_id );

        if ( $verifier ) {
            $manager->destroy( $verifier );
        } else {
            $manager->destroy_all();
        }
        return new WP_REST_Response( array( 'success' => true ), 200 );
    }

    public function get_sensitive_settings( $request ) {
        $options = array(
            'wpsm_xmlrpc_status',
            'wpsm_xmlrpc_limit_multicall',
            'wpsm_author_base',
            'wpsm_disable_author_archives',
            'wpsm_anti_hotlink',
            'wpsm_anti_404_guessing',
            'wpsm_robots_blackhole',
            'wpsm_hide_wp_version',
            'wpsm_block_sensitive_files',
            'wpsm_disable_php_disclosure',
            'wpsm_disable_directory_listing'
        );

        $settings = array();
        foreach ( $options as $option ) {
            $settings[$option] = get_option( $option );
        }

        return new WP_REST_Response( $settings, 200 );
    }

    public function update_sensitive_settings( $request ) {
        $params = $request->get_params();
        $old_author_base = get_option( 'wpsm_author_base', 'profile' );

        $options = array(
            'wpsm_xmlrpc_status',
            'wpsm_xmlrpc_limit_multicall',
            'wpsm_author_base',
            'wpsm_disable_author_archives',
            'wpsm_anti_hotlink',
            'wpsm_anti_404_guessing',
            'wpsm_robots_blackhole',
            'wpsm_hide_wp_version',
            'wpsm_block_sensitive_files',
            'wpsm_disable_php_disclosure',
            'wpsm_disable_directory_listing'
        );

        foreach ( $options as $option ) {
            if ( isset( $params[$option] ) ) {
                $val = sanitize_text_field( $params[$option] );
                if ( $option === 'wpsm_author_base' ) {
                    $val = sanitize_title( $val );
                }
                update_option( $option, $val );
            }
        }

        $new_author_base = get_option( 'wpsm_author_base', 'profile' );
        if ( $old_author_base !== $new_author_base ) {
            flush_rewrite_rules();
        }

        return new WP_REST_Response( array( 'success' => true ), 200 );
    }


    public function get_extensions( $request ) {
        $auditor = new WPSM_Extension_Auditor( $this->logger );
        return new WP_REST_Response( $auditor->audit_all_extensions(), 200 );
    }

    public function get_vulnerabilities( $request ) {
        return new WP_REST_Response( get_option( 'wpsm_vulnerability_findings', array() ), 200 );
    }

    public function reinstall_extension( $request ) {
        $slug = $request->get_param( 'slug' );
        if ( ! $slug ) return new WP_Error( 'missing_slug', 'Slug is required', array( 'status' => 400 ) );

        $auditor = new WPSM_Extension_Auditor( $this->logger );
        $result = $auditor->reinstall_from_repo( $slug );

        if ( is_wp_error( $result ) ) {
            return $result;
        }

        return new WP_REST_Response( array( 'success' => true ), 200 );
    }

    /**
     * Obtiene el estado del core (versión, actualizaciones disponibles)
     */
    public function get_core_status( $request ) {
        $updates = get_site_transient( 'update_core' );
        return new WP_REST_Response( array(
            'version' => get_bloginfo( 'version' ),
            'updates' => $updates,
            'history' => get_option( 'wpsm_update_history', array() )
        ), 200 );
    }

    /**
     * Obtiene el estado de la base de datos (prefijo)
     */
    public function get_db_status( $request ) {
        $manager = new WPSM_DB_Prefix_Manager( $this->logger );
        return new WP_REST_Response( $manager->get_prefix_status(), 200 );
    }

    public function get_backups( $request ) {
        $settings = new WPSM_Settings();
        $manager = new WPSM_Backup_Manager( $this->logger, $settings );
        return new WP_REST_Response( $manager->get_history(), 200 );
    }

    public function run_backup( $request ) {
        $type = $request->get_param( 'type' ) ?: 'full';
        $settings = new WPSM_Settings();
        $manager = new WPSM_Backup_Manager( $this->logger, $settings );
        $result = $manager->run_backup( $type );

        if ( $result ) {
            return new WP_REST_Response( array( 'success' => true ), 200 );
        }
        return new WP_Error( 'backup_failed', 'Backup execution failed', array( 'status' => 500 ) );
    }

    public function get_backup_config( $request ) {
        $settings = new WPSM_Settings();
        return new WP_REST_Response( array(
            'backup_frequency'  => $settings->get_setting( 'backup_frequency', 'daily' ),
            'preventive_backup' => $settings->get_setting( 'preventive_backup', 'yes' ),
            'storage_provider'  => $settings->get_setting( 'storage_provider', 'local' )
        ), 200 );
    }

    public function update_backup_config( $request ) {
        $params = $request->get_params();
        $settings = new WPSM_Settings();
        $keys = array( 'backup_frequency', 'preventive_backup', 'storage_provider' );

        foreach ( $keys as $key ) {
            if ( isset( $params[$key] ) ) {
                $settings->update_setting( $key, sanitize_text_field( $params[$key] ) );
            }
        }

        return new WP_REST_Response( array( 'success' => true ), 200 );
    }

}
