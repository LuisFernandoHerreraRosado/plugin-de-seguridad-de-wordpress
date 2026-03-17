<?php
/**
 * Módulo Anti-Spam y Anti-Phishing
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Anti_Spam_Phishing {
    private $logger;
    private $settings;
    private $alerts;

    public function __construct( $logger, $settings, $alerts ) {
        $this->logger = $logger;
        $this->settings = $settings;
        $this->alerts = $alerts;
    }

    public function init() {
        if ( $this->settings->get_setting( 'disable_comments', 'no' ) === 'yes' ) {
            add_filter( 'comments_open', '__return_false', 20 );
            add_filter( 'pings_open', '__return_false', 20 );
            add_action( 'init', array( $this, 'disable_comments_support' ) );
        }

        if ( $this->settings->get_setting( 'spam_protection_enable', 'no' ) === 'yes' ) {
            $this->init_spam_protection();
        }

        if ( $this->settings->get_setting( 'phishing_protection_enable', 'no' ) === 'yes' ) {
            $this->init_phishing_protection();
        }
    }

    public function disable_comments_support() {
        // Close comments on existing posts
        add_filter( 'comments_array', '__return_empty_array', 20 );

        // Remove comments page in menu
        add_action( 'admin_menu', function () {
            remove_menu_page( 'edit-comments.php' );
        } );

        // Remove comments links from admin bar
        add_action( 'init', function () {
            if ( is_admin_bar_showing() ) {
                remove_action( 'admin_bar_menu', 'wp_admin_bar_comments_menu', 60 );
            }
        } );
    }

    private function init_spam_protection() {
        if ( $this->settings->get_setting( 'antispam_honeypot', 'yes' ) === 'yes' ) {
            // Comment honeypot
            add_action( 'comment_form', array( $this, 'render_honeypot_field' ) );
            add_filter( 'preprocess_comment', array( $this, 'validate_comment_honeypot' ) );

            // Registration honeypot
            add_action( 'register_form', array( $this, 'render_honeypot_field' ) );
            add_filter( 'registration_errors', array( $this, 'validate_registration_honeypot' ), 10, 3 );
        }

        if ( $this->settings->get_setting( 'antispam_time_check', 'yes' ) === 'yes' ) {
            add_action( 'comment_form', array( $this, 'render_time_field' ) );
            add_filter( 'preprocess_comment', array( $this, 'validate_time_check' ) );

            add_action( 'register_form', array( $this, 'render_time_field' ) );
            add_filter( 'registration_errors', array( $this, 'validate_registration_time_check' ), 10, 3 );
        }
    }

    public function render_time_field() {
        $field_id = 'wpsm_ts_' . md5( home_url() );
        echo '<input type="hidden" name="' . esc_attr( $field_id ) . '" value="' . time() . '">';
    }

    public function validate_time_check( $commentdata ) {
        $field_id = 'wpsm_ts_' . md5( home_url() );
        if ( isset( $_POST[$field_id] ) ) {
            $diff = time() - intval( $_POST[$field_id] );
            if ( $diff < 3 ) { // Less than 3 seconds is likely a bot
                $this->handle_spam_detected( 'comment_fast_submission' );
                wp_die( __( 'Enviado demasiado rápido. ¿Eres un bot?', 'wp-security-monitor' ) );
            }
        }
        return $commentdata;
    }

    public function validate_registration_time_check( $errors, $sanitized_user_login, $user_email ) {
        $field_id = 'wpsm_ts_' . md5( home_url() );
        if ( isset( $_POST[$field_id] ) ) {
            $diff = time() - intval( $_POST[$field_id] );
            if ( $diff < 3 ) {
                $this->handle_spam_detected( 'registration_fast_submission' );
                $errors->add( 'spam_fast', __( 'Error: Registro demasiado rápido.', 'wp-security-monitor' ) );
            }
        }
        return $errors;
    }

    public function render_honeypot_field() {
        $field_id = 'wpsm_hp_' . md5( home_url() );
        echo '<p class="wpsm-hp-container" style="display:none !important;">';
        echo '<label for="' . esc_attr( $field_id ) . '">' . __( 'Si eres humano, deja este campo vacío.', 'wp-security-monitor' ) . '</label>';
        echo '<input type="text" name="' . esc_attr( $field_id ) . '" id="' . esc_attr( $field_id ) . '" value="" autocomplete="off">';
        echo '</p>';
    }

    public function validate_comment_honeypot( $commentdata ) {
        $field_id = 'wpsm_hp_' . md5( home_url() );
        if ( ! empty( $_POST[$field_id] ) ) {
            $this->handle_spam_detected( 'comment_honeypot' );
            wp_die( __( 'Spam detectado (honeypot).', 'wp-security-monitor' ) );
        }
        return $commentdata;
    }

    public function validate_registration_honeypot( $errors, $sanitized_user_login, $user_email ) {
        $field_id = 'wpsm_hp_' . md5( home_url() );
        if ( ! empty( $_POST[$field_id] ) ) {
            $this->handle_spam_detected( 'registration_honeypot' );
            $errors->add( 'spam_detected', __( 'Error: Spam detectado.', 'wp-security-monitor' ) );
        }
        return $errors;
    }

    private function handle_spam_detected( $reason ) {
        $ip = $_SERVER['REMOTE_ADDR'];
        $message = sprintf( __( 'Spam bloqueado (%s) desde la IP %s', 'wp-security-monitor' ), $reason, $ip );

        $this->logger->log( 'spam_detected', $message, 'medium', array( 'reason' => $reason, 'ip' => $ip ) );

        // Trigger alert for critical spam patterns if needed
        if ( strpos( $reason, 'honeypot' ) !== false ) {
            $this->alerts->trigger_critical_alert( 'spam_honeypot', $message );
        }
    }

    private function init_phishing_protection() {
        // Foundation for future link scanning
        add_filter( 'comment_text', array( $this, 'scan_content_for_phishing' ), 10, 2 );
        add_filter( 'the_content', array( $this, 'scan_content_for_phishing' ), 10, 2 );

        // Hook for external integration
        do_action( 'wpsm_phishing_protection_loaded' );
    }

    /**
     * Placeholder architecture for phishing detection
     */
    public function scan_content_for_phishing( $content, $id = 0 ) {
        if ( empty( $content ) ) return $content;

        // Future logic:
        // 1. Extract URLs from content
        // 2. Check URLs against a phishing database or API
        // 3. Look for suspicious patterns (e.g., misspellings of popular domains)

        return apply_filters( 'wpsm_phishing_scanned_content', $content, $id );
    }

    /**
     * Placeholder for decoy page detection
     */
    public function detect_decoy_pages() {
        // Future logic:
        // 1. Identify suspicious pages that look like login pages but aren't
        // 2. Monitor for unusual traffic patterns to these pages
        do_action( 'wpsm_decoy_page_check' );
    }

    /**
     * Placeholder for fraudulent content analysis
     */
    public function analyze_fraudulent_content( $content ) {
        // Future logic:
        // 1. AI-based content analysis
        // 2. Keyword matching for common phishing scams
        return apply_filters( 'wpsm_fraudulent_content_analysis', $content );
    }
}
