<?php
/**
 * Módulo de Protección Anti-Spam y Anti-Phishing
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Spam_Protection {
    private $logger;
    private $settings;

    public function __construct( $logger, $settings ) {
        $this->logger = $logger;
        $this->settings = $settings;
    }

    public function init() {
        // Desactivar comentarios si está habilitado
        if ( $this->settings->get_setting( 'disable_comments', 'no' ) === 'yes' ) {
            add_filter( 'comments_open', '__return_false', 20, 2 );
            add_filter( 'pings_open', '__return_false', 20, 2 );
            add_action( 'admin_init', array( $this, 'disable_comments_admin' ) );
        }

        // Protección Anti-Spam
        if ( $this->settings->get_setting( 'spam_protection_enable', 'no' ) === 'yes' ) {
            // Honeypot
            add_action( 'comment_form_after_fields', array( $this, 'render_honeypot' ) );
            add_action( 'register_form', array( $this, 'render_honeypot' ) );

            add_filter( 'preprocess_comment', array( $this, 'verify_spam' ) );
            add_action( 'register_post', array( $this, 'verify_registration_spam' ), 10, 3 );

            // Time-based protection
            add_action( 'comment_form_after_fields', array( $this, 'add_timestamp' ) );
        }

        // Arquitectura para Phishing (Extensible)
        add_filter( 'wpsm_check_phishing', array( $this, 'check_links_in_content' ), 10, 2 );
    }

    public function disable_comments_admin() {
        global $pagenow;
        remove_menu_page( 'edit-comments.php' );
        if ( $pagenow === 'edit-comments.php' ) {
            wp_die( __( 'Los comentarios están desactivados.', 'wp-security-monitor' ), '', array( 'response' => 403 ) );
        }
    }

    public function render_honeypot() {
        $field_name = 'wpsm_hp_field_' . date('Ymd');
        echo '<p class="wpsm-hp-field" style="display:none !important;">';
        echo '<label for="' . $field_name . '">Leave this field empty</label>';
        echo '<input type="text" name="' . $field_name . '" id="' . $field_name . '" value="" tabindex="-1" autocomplete="off">';
        echo '</p>';
    }

    public function add_timestamp() {
        echo '<input type="hidden" name="wpsm_timestamp" value="' . time() . '">';
    }

    public function verify_spam( $commentdata ) {
        // No verificar para usuarios registrados si se desea
        if ( is_user_logged_in() ) return $commentdata;

        $field_name = 'wpsm_hp_field_' . date('Ymd');

        // Verificar Honeypot
        if ( ! empty( $_POST[$field_name] ) ) {
            $this->logger->log( 'spam_blocked', __( 'Comentario bloqueado por Honeypot.', 'wp-security-monitor' ), 'medium' );
            wp_die( __( 'Spam detectado.', 'wp-security-monitor' ) );
        }

        // Verificar Tiempo
        $min_time = (int) $this->settings->get_setting( 'spam_min_time', 5 );
        if ( isset( $_POST['wpsm_timestamp'] ) ) {
            $diff = time() - (int) $_POST['wpsm_timestamp'];
            if ( $diff < $min_time ) {
                $this->logger->log( 'spam_blocked', sprintf( __( 'Comentario bloqueado por rapidez excesiva (%d segundos).', 'wp-security-monitor' ), $diff ), 'medium' );
                wp_die( __( 'Por favor, tómate tu tiempo para comentar.', 'wp-security-monitor' ) );
            }
        }

        // Verificar Phishing / Enlaces sospechosos
        $content = $commentdata['comment_content'];
        $phishing_detected = apply_filters( 'wpsm_check_phishing', false, $content );
        if ( $phishing_detected ) {
            $this->logger->log( 'phishing_blocked', __( 'Contenido bloqueado por sospecha de phishing/enlaces maliciosos.', 'wp-security-monitor' ), 'high' );
            wp_die( __( 'Contenido no permitido por razones de seguridad.', 'wp-security-monitor' ) );
        }

        return $commentdata;
    }

    public function verify_registration_spam( $errors, $sanitized_user_login, $user_email ) {
        $field_name = 'wpsm_hp_field_' . date('Ymd');
        if ( ! empty( $_POST[$field_name] ) ) {
            $this->logger->log( 'spam_registration_blocked', __( 'Registro bloqueado por Honeypot.', 'wp-security-monitor' ), 'medium' );
            $errors->add( 'spam_error', __( '<strong>ERROR</strong>: Registro no permitido.', 'wp-security-monitor' ) );
        }
        return $errors;
    }

    /**
     * Detección básica de phishing (extensible)
     */
    public function check_links_in_content( $is_phishing, $content ) {
        if ( $is_phishing ) return true;

        $max_links = (int) $this->settings->get_setting( 'spam_max_links', 3 );
        $link_count = preg_match_all( '/<a\s+[^>]*href=["\']([^"\']*)["\'][^>]*>/i', $content, $matches );

        if ( $link_count > $max_links ) {
            return true;
        }

        // Placeholder para futuras reglas (ej: dominios conocidos de phishing, typosquatting)
        // logic here...

        return false;
    }
}
