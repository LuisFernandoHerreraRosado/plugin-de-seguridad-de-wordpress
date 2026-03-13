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

        // Nuevos endpoints para extensiones
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

    /**
     * Obtiene auditoría completa de extensiones
     */
    public function get_extensions( $request ) {
        $auditor = new WPSM_Extension_Auditor( $this->logger );
        return new WP_REST_Response( $auditor->audit_all_extensions(), 200 );
    }

    /**
     * Obtiene hallazgos de vulnerabilidades
     */
    public function get_vulnerabilities( $request ) {
        return new WP_REST_Response( get_option( 'wpsm_vulnerability_findings', array() ), 200 );
    }

    /**
     * Reinstala una extensión remotamente
     */
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
}
