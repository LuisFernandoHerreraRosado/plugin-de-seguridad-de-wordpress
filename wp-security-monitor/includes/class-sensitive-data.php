<?php
/**
 * Módulo de Datos Sensibles
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Sensitive_Data {
    private $logger;

    public function __construct( $logger ) {
        $this->logger = $logger;
    }

    public function init() {
        // Inicializar hooks de protección
        $this->init_xmlrpc();
        $this->init_author_base();
        $this->init_request_protections();
        $this->init_disclosure_prevention();
    }

    private function init_xmlrpc() {
        $xmlrpc_status = get_option( 'wpsm_xmlrpc_status', 'enabled' );

        if ( $xmlrpc_status === 'disabled' ) {
            add_filter( 'xmlrpc_enabled', '__return_false' );
            add_filter( 'xmlrpc_methods', array( $this, 'block_xmlrpc_methods' ) );
        } elseif ( $xmlrpc_status === 'partial' ) {
            add_filter( 'xmlrpc_methods', array( $this, 'restrict_xmlrpc_methods' ) );
        }

        if ( get_option( 'wpsm_xmlrpc_limit_multicall', 'no' ) === 'yes' ) {
            add_filter( 'xmlrpc_methods', array( $this, 'limit_xmlrpc_multicall' ) );
        }
    }

    public function block_xmlrpc_methods( $methods ) {
        $this->logger->log( 'security', 'XML-RPC access blocked completely.', 'medium' );
        return array();
    }

    public function restrict_xmlrpc_methods( $methods ) {
        // Allow only non-authentication methods if needed, or specific ones.
        // For now, let's just log and keep basic ones.
        $this->logger->log( 'security', 'XML-RPC access restricted.', 'low' );
        unset( $methods['wp.getUsersBlogs'] );
        unset( $methods['wp.getPage'] );
        return $methods;
    }

    public function limit_xmlrpc_multicall( $methods ) {
        if ( isset( $methods['system.multicall'] ) ) {
            unset( $methods['system.multicall'] );
            $this->logger->log( 'security', 'XML-RPC system.multicall disabled.', 'low' );
        }
        return $methods;
    }

    private function init_author_base() {
        $new_base = get_option( 'wpsm_author_base', '' );
        if ( ! empty( $new_base ) ) {
            add_action( 'init', array( $this, 'change_author_base' ) );
        }

        if ( get_option( 'wpsm_disable_author_archives', 'no' ) === 'yes' ) {
            add_action( 'template_redirect', array( $this, 'disable_author_archives' ) );
        }
    }

    public function change_author_base() {
        global $wp_rewrite;
        $new_base = get_option( 'wpsm_author_base', 'profile' );
        $wp_rewrite->author_base = $new_base;
    }

    public function disable_author_archives() {
        if ( is_author() ) {
            global $wp_query;
            $wp_query->set_404();
            status_header( 404 );
            nocache_headers();
            $this->logger->log( 'security', 'Attempted access to author archive blocked.', 'low' );
        }
    }

    private function init_request_protections() {
        if ( get_option( 'wpsm_anti_hotlink', 'no' ) === 'yes' ) {
            add_action( 'init', array( $this, 'enable_anti_hotlink' ) );
        }

        if ( get_option( 'wpsm_anti_404_guessing', 'no' ) === 'yes' ) {
            add_action( 'template_redirect', array( $this, 'anti_404_guessing' ) );
        }

        if ( get_option( 'wpsm_robots_blackhole', 'no' ) === 'yes' ) {
            add_filter( 'robots_txt', array( $this, 'add_robots_blackhole' ), 10, 2 );
            add_action( 'init', array( $this, 'check_blackhole_access' ) );
        }
    }

    public function enable_anti_hotlink() {
        // This usually requires .htaccess, but we can attempt to block via PHP for specific requests
        // or just log that it should be enabled in server config.
        // For a generic implementation, we check the Referer header.
        if ( strpos( $_SERVER['REQUEST_URI'], '/wp-content/uploads/' ) !== false ) {
            $referer = isset( $_SERVER['HTTP_REFERER'] ) ? $_SERVER['HTTP_REFERER'] : '';
            if ( ! empty( $referer ) && strpos( $referer, get_home_url() ) === false ) {
                $this->logger->log( 'security', 'Hotlinking detected and potentially blocked.', 'low', array( 'referer' => $referer ) );
                // wp_die('Hotlinking not allowed'); // Be careful with this as it might break valid embeds
            }
        }
    }

    public function anti_404_guessing() {
        if ( is_404() ) {
            $ip = $_SERVER['REMOTE_ADDR'];
            $requested_url = $_SERVER['REQUEST_URI'];
            // Log 404 attempts to detect scanning
            $this->logger->log( 'security', "404 detected: $requested_url", 'low', array( 'ip' => $ip ) );
        }
    }

    public function add_robots_blackhole( $output, $public ) {
        $output .= "\nUser-agent: *\nDisallow: /?wpsm_blackhole=1\n";
        return $output;
    }

    public function check_blackhole_access() {
        if ( isset( $_GET['wpsm_blackhole'] ) ) {
            $ip = $_SERVER['REMOTE_ADDR'];
            $this->logger->log( 'security', "Bot trapped in blackhole!", 'high', array( 'ip' => $ip ) );
            wp_die( 'You have been blocked for violating robots.txt rules.' );
        }
    }

    private function init_disclosure_prevention() {
        if ( get_option( 'wpsm_hide_wp_version', 'no' ) === 'yes' ) {
            add_filter( 'the_generator', '__return_empty_string' );
            add_filter( 'script_loader_src', array( $this, 'remove_version_scripts' ), 15 );
            add_filter( 'style_loader_src', array( $this, 'remove_version_scripts' ), 15 );
        }

        if ( get_option( 'wpsm_block_sensitive_files', 'no' ) === 'yes' ) {
            add_action( 'init', array( $this, 'block_sensitive_files' ) );
        }

        if ( get_option( 'wpsm_disable_php_disclosure', 'no' ) === 'yes' ) {
            // PHP Easter egg (PHP disclosure) can be blocked by setting expose_php = Off in php.ini
            // But we can also try to hide headers if possible via PHP (limited)
            header_remove( 'X-Powered-By' );
            add_action( 'init', array( $this, 'block_php_easter_eggs' ) );
        }

        if ( get_option( 'wpsm_disable_directory_listing', 'no' ) === 'yes' ) {
            add_action( 'init', array( $this, 'block_directory_listing' ) );
        }
    }

    public function remove_version_scripts( $src ) {
        if ( strpos( $src, 'ver=' ) ) {
            $src = remove_query_arg( 'ver', $src );
        }
        return $src;
    }

    public function block_php_easter_eggs() {
        if ( ! empty( $_SERVER['QUERY_STRING'] ) ) {
            $easter_eggs = array(
                'PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000', // Credits
                'PHPE9568971-334E-11d4-A7DC-00C04F010301', // Logo
                'PHPE9568978-334E-11d4-A7DC-00C04F010301', // Zend Logo
                'PHPE956896F-334E-11d4-A7DC-00C04F010301'  // Version
            );

            foreach ( $easter_eggs as $egg ) {
                if ( strpos( $_SERVER['QUERY_STRING'], $egg ) !== false ) {
                    $this->logger->log( 'security', "PHP Easter Egg access blocked: $egg", 'medium' );
                    wp_die( 'Access Denied', 'Forbidden', array( 'response' => 403 ) );
                }
            }
        }
    }

    public function block_directory_listing() {
        if ( is_admin() ) return;

        $request_uri = $_SERVER['REQUEST_URI'];
        // Basic check for common directories that might not have an index file
        $directories = array( '/wp-content/', '/wp-content/uploads/', '/wp-content/plugins/', '/wp-content/themes/' );

        foreach ( $directories as $dir ) {
            if ( $request_uri === $dir ) {
                $this->logger->log( 'security', "Attempted directory listing blocked: $dir", 'medium' );
                wp_die( 'Access Denied', 'Forbidden', array( 'response' => 403 ) );
            }
        }
    }

    public function block_sensitive_files() {
        $request_uri = $_SERVER['REQUEST_URI'];
        $sensitive_files = array(
            'readme.html',
            'readme.txt',
            'license.txt',
            'wp-config-sample.php',
            'changelog.md',
            'composer.json',
            'package.json'
        );

        foreach ( $sensitive_files as $file ) {
            if ( strpos( strtolower( $request_uri ), $file ) !== false ) {
                $this->logger->log( 'security', "Blocked access to sensitive file: $file", 'medium' );
                wp_die( 'Access Denied', 'Forbidden', array( 'response' => 403 ) );
            }
        }
    }
}
