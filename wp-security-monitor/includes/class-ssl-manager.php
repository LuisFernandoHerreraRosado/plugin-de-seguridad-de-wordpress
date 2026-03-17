<?php
/**
 * Módulo de Gestión de SSL y HTTPS
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_SSL_Manager {
    private $logger;
    private $settings;

    public function __construct( $logger, $settings ) {
        $this->logger = $logger;
        $this->settings = $settings;
    }

    public function init() {
        // Redirigir a HTTPS si está activado
        if ( $this->settings->get_setting( 'force_https', 'no' ) === 'yes' ) {
            add_action( 'template_redirect', array( $this, 'force_https_redirection' ), 1 );
        }

        // Corregir contenido mixto si está activado
        if ( $this->settings->get_setting( 'fix_mixed_content', 'no' ) === 'yes' ) {
            add_action( 'init', array( $this, 'start_mixed_content_fixer' ) );
        }
    }

    /**
     * Fuerza la redirección a HTTPS
     */
    public function force_https_redirection() {
        if ( ! is_ssl() ) {
            wp_redirect( 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'], 301 );
            exit;
        }
    }

    /**
     * Inicia el buffer para corregir contenido mixto
     */
    public function start_mixed_content_fixer() {
        ob_start( array( $this, 'fix_mixed_content_callback' ) );
    }

    /**
     * Callback para reemplazar enlaces http por https
     */
    public function fix_mixed_content_callback( $buffer ) {
        if ( ! is_ssl() ) {
            return $buffer;
        }

        $site_url = str_replace( array( 'http://', 'https://' ), '', get_site_url() );
        $pattern  = '/http:\/\/' . preg_quote( $site_url, '/' ) . '/i';
        $buffer   = preg_replace( $pattern, 'https://' . $site_url, $buffer );

        return $buffer;
    }

    /**
     * Obtiene el estado detallado del SSL
     */
    public function get_ssl_status() {
        $is_ssl = is_ssl();
        $site_url = get_site_url();
        $home_url = get_home_url();

        $status = array(
            'enabled'        => $is_ssl,
            'site_url_https' => ( strpos( $site_url, 'https://' ) === 0 ),
            'home_url_https' => ( strpos( $home_url, 'https://' ) === 0 ),
            'cert_info'      => $this->get_cert_info(),
            'warnings'       => array()
        );

        if ( ! $is_ssl ) {
            $status['warnings'][] = __( 'El sitio no está cargando sobre HTTPS.', 'wp-security-monitor' );
        }

        if ( ! $status['site_url_https'] || ! $status['home_url_https'] ) {
            $status['warnings'][] = __( 'Las URLs del sitio en los ajustes de WordPress no usan https://.', 'wp-security-monitor' );
        }

        return $status;
    }

    /**
     * Obtiene información del certificado (Arquitectura preparada)
     */
    private function get_cert_info() {
        $host = parse_url( get_site_url(), PHP_URL_HOST );
        $info = array(
            'issuer'  => 'Unknown',
            'expiry'  => 'Unknown',
            'valid'   => false,
            'message' => ''
        );

        if ( ! function_exists( 'openssl_x509_parse' ) ) {
            $info['message'] = __( 'La extensión OpenSSL no está disponible.', 'wp-security-monitor' );
            return $info;
        }

        try {
            $get = stream_context_create( array( "ssl" => array( "capture_peer_cert" => true ) ) );
            $read = @stream_socket_client( "ssl://" . $host . ":443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $get );

            if ( $read ) {
                $cont = stream_context_get_params( $read );
                $cert = openssl_x509_parse( $cont["options"]["ssl"]["peer_certificate"] );

                $info['issuer'] = $cert['issuer']['O'] ?? $cert['issuer']['CN'] ?? 'Unknown';
                $info['expiry'] = date( 'Y-m-d H:i:s', $cert['validTo_time_t'] );
                $info['valid']  = ( $cert['validTo_time_t'] > time() );
                $info['message'] = __( 'Certificado detectado correctamente.', 'wp-security-monitor' );
            } else {
                $info['message'] = __( 'No se pudo conectar para validar el certificado.', 'wp-security-monitor' );
            }
        } catch ( Exception $e ) {
            $info['message'] = $e->getMessage();
        }

        return $info;
    }
}
