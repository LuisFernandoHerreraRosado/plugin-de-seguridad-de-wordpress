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
}
