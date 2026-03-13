<?php
/**
 * Gestor de Autenticación de Dos Factores (2FA)
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_2FA_Manager {
    private $providers = array();
    private $settings;

    public function __construct( $settings ) {
        $this->settings = $settings;
    }

    public function init() {
        if ( $this->settings->get_setting( 'two_factor_enable', 'no' ) !== 'yes' ) {
            return;
        }

        // Interceptar el proceso de autenticación para requerir 2FA
        add_filter( 'authenticate', array( $this, 'enforce_2fa' ), 50, 3 );

        // Renderizar el campo de código en el formulario de login si es necesario
        add_action( 'login_form', array( $this, 'render_2fa_field' ) );

        // Soporte para Magic Link en el init
        add_action( 'init', array( $this, 'process_magic_link_auth' ) );
    }

    public function register_provider( $id, $class ) {
        $this->providers[$id] = $class;
    }

    /**
     * Enforce 2FA by intercepting the authentication result
     */
    public function enforce_2fa( $user, $username, $password ) {
        if ( is_wp_error( $user ) || ! $user instanceof WP_User ) {
            return $user;
        }

        $enabled_provider = get_user_meta( $user->ID, 'wpsm_2fa_enabled_provider', true );
        $extra_verify = get_user_meta( $user->ID, 'wpsm_extra_verification_required', true );

        if ( ! $enabled_provider && ! $extra_verify ) {
            return $user;
        }

        if ( ! $enabled_provider && $extra_verify ) {
            $enabled_provider = 'email';
        }

        if ( isset( $this->providers[$enabled_provider] ) ) {
            $provider = $this->providers[$enabled_provider];

            // Si es un Magic Link, enviamos y bloqueamos
            if ( $enabled_provider === 'magic_link' && ! isset( $_GET['wpsm_magic_token'] ) ) {
                $provider->send_magic_link( $user );
                return new WP_Error( '2fa_magic_sent', __( 'Se ha enviado un enlace mágico a su correo. Por favor, haga clic en él para acceder.', 'wp-security-monitor' ) );
            }

            // Si el código no está presente, disparamos el envío del código
            if ( ! isset( $_POST['wpsm_2fa_code'] ) && $enabled_provider !== 'magic_link' ) {
                if ( method_exists( $provider, 'send_code' ) ) {
                    $provider->send_code( $user );
                }

                return new WP_Error( '2fa_required', __( 'Se requiere verificación de dos factores. Introduzca el código enviado o generado.', 'wp-security-monitor' ) );
            }

            if ( $enabled_provider !== 'magic_link' ) {
                $code = sanitize_text_field( $_POST['wpsm_2fa_code'] );
                if ( ! $provider->validate_code( $user->ID, $code ) ) {
                    return new WP_Error( '2fa_invalid', __( 'Código de verificación de dos factores inválido.', 'wp-security-monitor' ) );
                }
            }

            // Si llegamos aquí, es válido
            delete_user_meta( $user->ID, 'wpsm_extra_verification_required' );
        }

        return $user;
    }

    public function process_magic_link_auth() {
        if ( isset( $_GET['wpsm_magic_token'] ) && isset( $this->providers['magic_link'] ) ) {
            $token = sanitize_text_field( $_GET['wpsm_magic_token'] );
            $user_id = $this->providers['magic_link']->validate_token( $token );

            if ( $user_id ) {
                wp_set_auth_cookie( $user_id );
                wp_redirect( admin_url() );
                exit;
            }
        }
    }

    public function render_2fa_field() {
        ?>
        <p>
            <label for="wpsm_2fa_code"><?php _e( 'Código de Seguridad (2FA)', 'wp-security-monitor' ); ?><br />
            <input type="text" name="wpsm_2fa_code" id="wpsm_2fa_code" class="input" value="" size="20" autocomplete="off" /></label>
        </p>
        <?php
    }
}
