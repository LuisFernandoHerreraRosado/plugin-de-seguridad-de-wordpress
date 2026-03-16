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
}
