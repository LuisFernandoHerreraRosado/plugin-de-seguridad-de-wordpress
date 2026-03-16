<?php
/**
 * Módulo Firewall
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Firewall {
    private $logger;
    private $settings;

    public function __construct( $logger, $settings ) {
        $this->logger = $logger;
        $this->settings = $settings;
    }

    public function init() {
        if ( $this->settings->get_setting( 'firewall_enable', 'no' ) !== 'yes' ) {
            return;
        }

        add_action( 'init', array( $this, 'inspect_request' ), 1 );
    }

    public function inspect_request() {
        if ( is_admin() && ! defined( 'DOING_AJAX' ) ) return;

        $this->check_user_agent();
        $this->check_referrer();
        $this->check_url_parameters();
        $this->check_suspicious_files();
        $this->check_custom_rules();
    }

    private function check_user_agent() {
        $ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '';
        if ( empty( $ua ) ) return;

        // Block malicious User Agents
        $bad_uas_str = $this->settings->get_setting( 'firewall_bad_uas', '' );
        $bad_uas = ! empty( $bad_uas_str ) ? array_map( 'trim', explode( "\n", $bad_uas_str ) ) : array();
        foreach ( $bad_uas as $bad_ua ) {
            if ( ! empty( $bad_ua ) && stripos( $ua, $bad_ua ) !== false ) {
                $this->block_request( __( 'User Agent bloqueado', 'wp-security-monitor' ), array( 'ua' => $ua ) );
            }
        }

        // Block AI Bots
        if ( $this->settings->get_setting( 'block_ai_bots', 'no' ) === 'yes' ) {
            $ai_bots = array( 'GPTBot', 'ChatGPT-User', 'Google-Extended', 'CCBot', 'Omgilibot', 'FacebookBot' );
            foreach ( $ai_bots as $bot ) {
                if ( stripos( $ua, $bot ) !== false ) {
                    $this->block_request( __( 'Bot de IA bloqueado', 'wp-security-monitor' ), array( 'ua' => $ua ) );
                }
            }
        }

        // Block Fake SEO Bots
        if ( $this->settings->get_setting( 'block_fake_seo_bots', 'no' ) === 'yes' ) {
            $seo_bots = array(
                'Googlebot'   => '/\.googlebot\.com$/i',
                'Bingbot'     => '/\.search\.msn\.com$/i',
                'Baiduspider' => '/\.baidu\.(com|jp)$/i',
                'YandexBot'   => '/\.yandex\.(com|net|ru)$/i',
            );
            $ip = $_SERVER['REMOTE_ADDR'];
            foreach ( $seo_bots as $bot => $domain_pattern ) {
                if ( stripos( $ua, $bot ) !== false ) {
                    // Cache DNS lookups to avoid performance hits
                    $transient_key = 'wpsm_rdns_' . md5( $ip );
                    $hostname = get_transient( $transient_key );

                    if ( false === $hostname ) {
                        $hostname = gethostbyaddr( $ip );
                        set_transient( $transient_key, $hostname, DAY_IN_SECONDS );
                    }

                    if ( ! preg_match( $domain_pattern, $hostname ) ) {
                        $this->block_request( sprintf( __( 'Falso bot SEO detectado: %s', 'wp-security-monitor' ), $bot ), array( 'ua' => $ua, 'ip' => $ip, 'hostname' => $hostname ) );
                    }
                }
            }
        }

    }

    private function check_custom_rules() {
        $request_uri = $_SERVER['REQUEST_URI'];
        $query_string = $_SERVER['QUERY_STRING'];
        $ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '';

        // Custom Rules/Signatures
        $custom_rules = get_option( 'wpsm_firewall_rules', array() );
        foreach ( $custom_rules as $rule ) {
            if ( empty( $rule['pattern'] ) || empty( $rule['enabled'] ) ) continue;

            $match = false;
            // Use @ to suppress errors in case of invalid regex
            $pattern = '/' . str_replace( '/', '\/', $rule['pattern'] ) . '/i';

            switch ( $rule['type'] ) {
                case 'url':
                    $match = @preg_match( $pattern, $request_uri );
                    break;
                case 'ua':
                    $match = @preg_match( $pattern, $ua );
                    break;
                case 'param':
                    $match = @preg_match( $pattern, $query_string );
                    break;
            }

            if ( $match ) {
                $this->block_request( sprintf( __( 'Regla personalizada: %s', 'wp-security-monitor' ), $rule['name'] ), array( 'rule_id' => $rule['id'] ) );
            }
        }
    }

    public function update_rules( $new_rules ) {
        return update_option( 'wpsm_firewall_rules', $new_rules );
    }

    private function check_referrer() {
        $referrer = isset( $_SERVER['HTTP_REFERER'] ) ? $_SERVER['HTTP_REFERER'] : '';
        if ( empty( $referrer ) ) return;

        $bad_referrers_str = $this->settings->get_setting( 'firewall_bad_referrers', '' );
        $bad_referrers = ! empty( $bad_referrers_str ) ? array_map( 'trim', explode( "\n", $bad_referrers_str ) ) : array();
        foreach ( $bad_referrers as $bad_ref ) {
            if ( ! empty( $bad_ref ) && stripos( $referrer, $bad_ref ) !== false ) {
                $this->block_request( __( 'Referer bloqueado', 'wp-security-monitor' ), array( 'referrer' => $referrer ) );
            }
        }
    }

    private function check_url_parameters() {
        $request_uri = $_SERVER['REQUEST_URI'];
        $query_string = $_SERVER['QUERY_STRING'];

        $malicious_patterns = array(
            'union select',
            'base64_decode',
            '<script',
            '../',
            'etc/passwd',
            'eval\(',
            'exec\(',
            'system\(',
            'passthru\(',
        );

        foreach ( $malicious_patterns as $pattern ) {
            if ( preg_match( '/' . str_replace( '/', '\/', $pattern ) . '/i', $request_uri ) ||
                 preg_match( '/' . str_replace( '/', '\/', $pattern ) . '/i', $query_string ) ) {
                $this->block_request( __( 'Patrón malicioso detectado en URL o parámetros', 'wp-security-monitor' ), array( 'pattern' => $pattern, 'url' => $request_uri ) );
            }
        }

        // Check POST data if present
        if ( ! empty( $_POST ) ) {
            $post_data = json_encode( $_POST );
            foreach ( $malicious_patterns as $pattern ) {
                if ( preg_match( '/' . str_replace( '/', '\/', $pattern ) . '/i', $post_data ) ) {
                    $this->block_request( __( 'Patrón malicioso detectado en datos POST', 'wp-security-monitor' ), array( 'pattern' => $pattern ) );
                }
            }
        }
    }

    private function check_suspicious_files() {
        $request_uri = $_SERVER['REQUEST_URI'];
        $path = parse_url( $request_uri, PHP_URL_PATH );

        if ( empty( $path ) ) return;

        // Block access to non-existent .php files that are often targeted by bots
        if ( strpos( $path, '.php' ) !== false ) {
            $abs_path = ABSPATH . ltrim( $path, '/' );
            if ( ! file_exists( $abs_path ) ) {
                $suspicious_files = array( 'wp-config', 'wp-login', 'xmlrpc', 'setup-config', 'install', 'phpinfo', 'shell', 'cmd' );
                foreach ( $suspicious_files as $file ) {
                    if ( strpos( $path, $file ) !== false ) {
                        $this->block_request( __( 'Acceso a archivo PHP sospechoso o inexistente', 'wp-security-monitor' ), array( 'path' => $path ) );
                    }
                }
            }
        }
    }

    public function block_request( $reason, $details = array() ) {
        $ip = $_SERVER['REMOTE_ADDR'];
        $this->logger->log( 'firewall_blocked', sprintf( __( 'Solicitud bloqueada por el Firewall: %s', 'wp-security-monitor' ), $reason ), 'high', array_merge( array( 'ip' => $ip ), $details ) );

        status_header( 403 );
        wp_die( sprintf( __( 'Acceso denegado por razones de seguridad: %s', 'wp-security-monitor' ), $reason ), 'Firewall Blocked', array( 'response' => 403 ) );
    }
}
