<?php
/**
 * Base para integración de CAPTCHA
 */
if ( ! defined( 'ABSPATH' ) ) exit;

abstract class WPSM_Captcha_Base {
    protected $settings;

    public function __construct( $settings ) {
        $this->settings = $settings;
    }

    /**
     * Renderiza el CAPTCHA en el formulario
     */
    abstract public function render_field();

    /**
     * Valida la respuesta del CAPTCHA
     */
    abstract public function verify_response( $response );

    /**
     * Hook para añadir el captcha al formulario de login
     */
    public function register_hooks() {
        if ( $this->settings->get_setting( 'captcha_enable', 'no' ) === 'yes' ) {
            add_action( 'login_form', array( $this, 'render_field' ) );
            add_filter( 'authenticate', array( $this, 'check_captcha' ), 25, 3 );
        }
    }

    public function check_captcha( $user, $username, $password ) {
        if ( is_wp_error( $user ) ) return $user;
        if ( empty( $_POST ) ) return $user;

        $response = isset( $_POST['g-recaptcha-response'] ) ? $_POST['g-recaptcha-response'] : '';

        if ( ! $this->verify_response( $response ) ) {
            return new WP_Error( 'captcha_failed', __( 'Error: La validación del CAPTCHA ha fallado.', 'wp-security-monitor' ) );
        }

        return $user;
    }
}
