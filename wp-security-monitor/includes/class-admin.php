<?php
/**
 * Lógica de Administración
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Admin {
    private $scanner;
    private $logger;
    private $settings;

    public function __construct( $scanner, $logger, $settings ) {
        $this->scanner = $scanner;
        $this->logger = $logger;
        $this->settings = $settings;
    }

    public function init() {
        add_action( 'admin_menu', array( $this, 'add_menu_pages' ) );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
        add_action( 'admin_post_wpsm_save_settings', array( $this, 'save_settings' ) );

        add_action( 'admin_post_wpsm_save_auth_settings', array( $this, 'save_auth_settings' ) );
        add_action( 'admin_post_wpsm_save_ext_settings', array( $this, 'save_ext_settings' ) );
        add_action( 'admin_post_wpsm_save_core_settings', array( $this, 'save_core_settings' ) );
        add_action( 'admin_post_wpsm_change_db_prefix', array( $this, 'change_db_prefix' ) );

        add_action( 'admin_post_wpsm_save_sensitive_settings', array( $this, 'save_sensitive_settings' ) );
        add_action( 'admin_post_wpsm_save_ssl_settings', array( $this, 'save_ssl_settings' ) );

        add_action( 'admin_post_wpsm_manual_scan', array( $this, 'run_manual_scan' ) );
        add_action( 'admin_post_wpsm_purge_logs', array( $this, 'purge_logs' ) );
        add_action( 'admin_post_wpsm_generate_api_key', array( $this, 'generate_api_key' ) );
    }

    public function add_menu_pages() {
        add_menu_page(
            'Security Monitor',
            'WP Security',
            'manage_options',
            'wp-security-monitor',
            array( $this, 'render_dashboard' ),
            'dashicons-shield',
            80
        );

        add_submenu_page(
            'wp-security-monitor',
            __( 'Seguridad SSL / HTTPS', 'wp-security-monitor' ),
            'SSL / HTTPS',
            'manage_options',
            'wpsm-ssl',
            array( $this, 'render_ssl_page' )
        );

        add_submenu_page(
            'wp-security-monitor',
            'Dashboard',
            'Dashboard',
            'manage_options',
            'wp-security-monitor'
        );

        add_submenu_page(
            'wp-security-monitor',

            __( 'WordPress Core', 'wp-security-monitor' ),
            __( 'WordPress core', 'wp-security-monitor' ),
            'manage_options',
            'wpsm-core',
            array( $this, 'render_core_page' )
        );

        add_submenu_page(
            'wp-security-monitor',
            __( 'Usuarios y Acceso', 'wp-security-monitor' ),
            __( 'Usuarios', 'wp-security-monitor' ),
            'manage_options',
            'wpsm-auth',
            array( $this, 'render_auth_page' )
        );

        add_submenu_page(
            'wp-security-monitor',
            __( 'Plugins y Themes', 'wp-security-monitor' ),
            __( 'Plugins & Themes', 'wp-security-monitor' ),
            'manage_options',
            'wpsm-extensions',
            array( $this, 'render_extensions_page' )
        );

        add_submenu_page(
            'wp-security-monitor',
            'Datos Sensibles',
            'Datos Sensibles',
            'manage_options',
            'wpsm-sensitive-data',
            array( $this, 'render_sensitive_data' )
        );

        add_submenu_page(
            'wp-security-monitor',
            'Logs de Eventos',
            'Logs',
            'manage_options',
            'wpsm-logs',
            array( $this, 'render_logs' )
        );

        add_submenu_page(
            'wp-security-monitor',
            'Configuración',
            'Ajustes',
            'manage_options',
            'wpsm-settings',
            array( $this, 'render_settings' )
        );

        add_submenu_page(
            'wp-security-monitor',
            'Integración API',
            'API REST',
            'manage_options',
            'wpsm-api',
            array( $this, 'render_api_page' )
        );
    }

    public function enqueue_assets( $hook ) {
        if ( strpos( $hook, 'wp-security-monitor' ) === false && strpos( $hook, 'wpsm-' ) === false ) {
            return;
        }
        wp_enqueue_style( 'wpsm-admin-css', WPSM_URL . 'assets/css/style.css', array(), WPSM_VERSION );
        wp_enqueue_script( 'wpsm-admin-js', WPSM_URL . 'assets/js/script.js', array( 'jquery' ), WPSM_VERSION, true );
    }

    public function render_dashboard() {
        include WPSM_PATH . 'admin/admin-page.php';
    }

    public function render_sensitive_data() {
        include WPSM_PATH . 'admin/sensitive-data-page.php';
    }

    public function render_logs() {
        include WPSM_PATH . 'admin/logs-page.php';
    }

    public function render_settings() {
        include WPSM_PATH . 'admin/settings-page.php';
    }

    public function render_auth_page() {
        include WPSM_PATH . 'admin/auth-settings-page.php';
    }

    public function render_extensions_page() {
        include WPSM_PATH . 'admin/extensions-settings-page.php';
    }

    public function render_core_page() {
        include WPSM_PATH . 'admin/core-settings-page.php';
    }

    public function render_api_page() {
        include WPSM_PATH . 'admin/api-page.php';
    }

    public function render_ssl_page() {
        include WPSM_PATH . 'admin/ssl-settings-page.php';
    }

    public function save_settings() {
        check_admin_referer( 'wpsm_settings_action' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die( 'No autorizado' );

        if ( isset( $_POST['alert_email'] ) ) {
            $this->settings->update_setting( 'alert_email', sanitize_email( $_POST['alert_email'] ) );
        }

        if ( isset( $_POST['scan_frequency'] ) ) {
            $freq = sanitize_text_field( $_POST['scan_frequency'] );
            $this->settings->update_setting( 'scan_frequency', $freq );

            $cron = new WPSM_Cron();
            $cron->update_schedule( $freq );
        }

        wp_redirect( admin_url( 'admin.php?page=wpsm-settings&settings-updated=true' ) );
        exit;
    }

    public function save_auth_settings() {
        check_admin_referer( 'wpsm_auth_settings_action' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die( 'No autorizado' );

        $keys = array(
            'login_slug',
            'brute_force_enable',
            'max_retries',
            'lockout_duration',
            'geoip_enable',
            'geoip_mode',
            'allowed_countries',
            'two_factor_enable',
            'captcha_enable',
            'pwd_min_length',
            'pwd_expiry_days',
            'pwd_complexity'
        );

        foreach ( $keys as $key ) {
            if ( isset( $_POST[$key] ) ) {
                $this->settings->update_setting( $key, sanitize_text_field( $_POST[$key] ) );
            } else {
                if ( in_array( $key, array( 'brute_force_enable', 'geoip_enable', 'two_factor_enable', 'captcha_enable' ) ) ) {
                    $this->settings->update_setting( $key, 'no' );
                }
            }
        }

        wp_redirect( admin_url( 'admin.php?page=wpsm-auth&settings-updated=true' ) );
        exit;
    }

    public function save_ext_settings() {
        check_admin_referer( 'wpsm_ext_settings_action' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die( 'No autorizado' );

        $keys = array( 'block_zip_upload', 'restrict_ext_ops', 'force_ftp', 'vulnerability_scan' );

        foreach ( $keys as $key ) {
            if ( isset( $_POST[$key] ) ) {
                $this->settings->update_setting( $key, sanitize_text_field( $_POST[$key] ) );
            } else {
                $this->settings->update_setting( $key, 'no' );
            }
        }

        wp_redirect( admin_url( 'admin.php?page=wpsm-extensions&settings-updated=true' ) );
        exit;
    }

    public function save_core_settings() {
        check_admin_referer( 'wpsm_core_settings_action' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die( 'No autorizado' );

        $keys = array( 'auto_update_minor', 'auto_update_major', 'disable_file_edit', 'hide_db_errors', 'block_unfiltered_uploads', 'disable_debug' );

        foreach ( $keys as $key ) {
            if ( isset( $_POST[$key] ) ) {
                $this->settings->update_setting( $key, sanitize_text_field( $_POST[$key] ) );
            } else {
                $this->settings->update_setting( $key, 'no' );
            }
        }

        wp_redirect( admin_url( 'admin.php?page=wpsm-core&settings-updated=true' ) );
        exit;
    }

    public function change_db_prefix() {
        check_admin_referer( 'wpsm_change_prefix_action' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die( 'No autorizado' );

        $new_prefix = sanitize_text_field( $_POST['new_prefix'] );
        $manager = new WPSM_DB_Prefix_Manager( $this->logger );
        $result = $manager->change_prefix( $new_prefix );

        if ( is_wp_error( $result ) ) {
            wp_die( $result->get_error_message() );
        }

        wp_redirect( admin_url( 'admin.php?page=wpsm-core&prefix-changed=true' ) );
        exit;
    }

    public function run_manual_scan() {
        check_admin_referer( 'wpsm_manual_scan' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die( 'No autorizado' );

        $this->scanner->run_scan();

        wp_redirect( admin_url( 'admin.php?page=wp-security-monitor&scan-complete=true' ) );
        exit;
    }

    public function purge_logs() {
        check_admin_referer( 'wpsm_purge_logs' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die( __( 'No autorizado', 'wp-security-monitor' ) );

        $this->logger->purge_logs();

        wp_redirect( admin_url( 'admin.php?page=wpsm-logs&logs-purged=true' ) );
        exit;
    }

    public function generate_api_key() {
        check_admin_referer( 'wpsm_generate_key' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die( __( 'No autorizado', 'wp-security-monitor' ) );

        $new_key = wp_generate_password( 32, false );
        update_option( 'wpsm_api_key', $new_key );

        wp_redirect( admin_url( 'admin.php?page=wpsm-api&key-generated=true' ) );
        exit;
    }

    public function save_ssl_settings() {
        check_admin_referer( 'wpsm_ssl_settings_action' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die( 'No autorizado' );

        $keys = array( 'force_https', 'fix_mixed_content' );

        foreach ( $keys as $key ) {
            if ( isset( $_POST[$key] ) ) {
                $this->settings->update_setting( $key, sanitize_text_field( $_POST[$key] ) );
            } else {
                $this->settings->update_setting( $key, 'no' );
            }
        }

        wp_redirect( admin_url( 'admin.php?page=wpsm-ssl&settings-updated=true' ) );
        exit;
    }

    public function save_sensitive_settings() {
        check_admin_referer( 'wpsm_sensitive_settings_action' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die( 'No autorizado' );

        $old_author_base = get_option( 'wpsm_author_base', 'profile' );

        $options = array(
            'wpsm_xmlrpc_status'           => 'enabled',
            'wpsm_xmlrpc_limit_multicall'  => 'no',
            'wpsm_author_base'             => 'profile',
            'wpsm_disable_author_archives' => 'no',
            'wpsm_anti_hotlink'            => 'no',
            'wpsm_anti_404_guessing'       => 'no',
            'wpsm_robots_blackhole'        => 'no',
            'wpsm_hide_wp_version'         => 'no',
            'wpsm_block_sensitive_files'   => 'no',
            'wpsm_disable_php_disclosure'  => 'no',
            'wpsm_disable_directory_listing' => 'no'
        );

        foreach ( $options as $key => $default ) {
            if ( isset( $_POST[$key] ) ) {
                $val = sanitize_text_field( $_POST[$key] );
                if ( $key === 'wpsm_author_base' ) {
                    $val = sanitize_title( $val );
                }
                update_option( $key, $val );
            } else {
                update_option( $key, $default );
            }
        }

        $new_author_base = get_option( 'wpsm_author_base', 'profile' );
        if ( $old_author_base !== $new_author_base ) {
            flush_rewrite_rules();
        }

        wp_redirect( admin_url( 'admin.php?page=wpsm-sensitive-data&settings-updated=true' ) );
        exit;
    }
}
