<?php
/**
 * Personalización de la URL de Login
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Custom_Login {
    private $settings;
    private $login_slug;

    public function __construct( $settings ) {
        $this->settings = $settings;
        $this->login_slug = $this->settings->get_setting( 'login_slug', '' );
    }

    public function init() {
        if ( empty( $this->login_slug ) ) {
            return;
        }

        add_action( 'init', array( $this, 'intercept_login_page' ), 1 );
        add_filter( 'site_url', array( $this, 'rewrite_login_urls' ), 10, 4 );
        add_filter( 'network_site_url', array( $this, 'rewrite_login_urls' ), 10, 3 );
        add_filter( 'wp_redirect', array( $this, 'filter_wp_redirect' ), 10, 2 );
        add_action( 'wp_loaded', array( $this, 'block_wp_login' ) );
    }

    /**
     * Intercepta el acceso al slug personalizado
     */
    public function intercept_login_page() {
        if ( empty( $this->login_slug ) ) return;

        $request_uri = $_SERVER['REQUEST_URI'];
        $path = untrailingslashit( strtok( $request_uri, '?' ) );
        $path = ltrim( $path, '/' );

        if ( $path === $this->login_slug ) {
            define( 'WPSM_INTERCEPTING_LOGIN', true );

            // Si es logout, procesar normalmente pero a través de wp-login.php
            status_header( 200 );
            require_once ABSPATH . 'wp-login.php';
            exit;
        }
    }

    /**
     * Bloquea el acceso directo a wp-login.php
     */
    public function block_wp_login() {
        if ( empty( $this->login_slug ) ) return;

        $script_name = basename( $_SERVER['SCRIPT_NAME'] );

        if ( $script_name === 'wp-login.php' && ! is_admin() ) {
            if ( ! defined( 'WPSM_INTERCEPTING_LOGIN' ) ) {
                // Permitir algunas acciones internas si es necesario,
                // pero generalmente queremos bloquear el acceso directo.
                wp_die( __( 'El acceso a esta página ha sido deshabilitado.', 'wp-security-monitor' ), 403 );
            }
        }
    }

    /**
     * Reescribe las URLs de login/logout/register para usar el slug
     */
    public function rewrite_login_urls( $url, $path, $scheme, $blog_id = null ) {
        if ( empty( $this->login_slug ) ) return $url;

        if ( strpos( $path, 'wp-login.php' ) !== false ) {
            $query = parse_url( $url, PHP_URL_QUERY );
            $new_url = home_url( '/' . $this->login_slug );

            if ( $query ) {
                $new_url = add_query_arg( array(), $new_url . '?' . $query );
            }

            return $new_url;
        }

        return $url;
    }

    /**
     * Asegura que los redirects automáticos de WP también usen el slug
     */
    public function filter_wp_redirect( $location, $status ) {
        if ( empty( $this->login_slug ) ) return $location;

        if ( strpos( $location, 'wp-login.php' ) !== false ) {
            return $this->rewrite_login_urls( $location, 'wp-login.php', null );
        }

        return $location;
    }
}
