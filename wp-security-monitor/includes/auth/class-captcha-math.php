<?php
/**
 * Implementación de CAPTCHA Matemático
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Captcha_Math extends WPSM_Captcha_Base {

    public function render_field() {
        $num1 = rand( 1, 10 );
        $num2 = rand( 1, 10 );
        set_transient( 'wpsm_captcha_ans_' . $_SERVER['REMOTE_ADDR'], $num1 + $num2, 300 );
        ?>
        <p>
            <label for="wpsm_captcha_answer"><?php echo sprintf( __( 'Seguridad: ¿Cuánto es %d + %d?', 'wp-security-monitor' ), $num1, $num2 ); ?><br />
            <input type="number" name="wpsm_captcha_answer" id="wpsm_captcha_answer" class="input" value="" size="20" required /></label>
        </p>
        <?php
    }

    public function verify_response( $response ) {
        $answer = isset( $_POST['wpsm_captcha_answer'] ) ? intval( $_POST['wpsm_captcha_answer'] ) : -1;
        $expected = get_transient( 'wpsm_captcha_ans_' . $_SERVER['REMOTE_ADDR'] );

        if ( $expected !== false && $answer === intval( $expected ) ) {
            delete_transient( 'wpsm_captcha_ans_' . $_SERVER['REMOTE_ADDR'] );
            return true;
        }

        return false;
    }

    public function register_hooks() {
        if ( $this->settings->get_setting( 'captcha_enable', 'no' ) === 'yes' ) {
            add_action( 'login_form', array( $this, 'render_field' ) );
            add_action( 'register_form', array( $this, 'render_field' ) );
            add_filter( 'authenticate', array( $this, 'check_captcha' ), 25, 3 );
            add_filter( 'registration_errors', array( $this, 'validate_registration_captcha' ), 10, 3 );
        }
    }

    public function check_captcha( $user, $username, $password ) {
        if ( is_wp_error( $user ) ) return $user;
        if ( empty( $_POST ) ) return $user;

        if ( ! $this->verify_response( '' ) ) {
            return new WP_Error( 'captcha_failed', __( 'Error: La respuesta del CAPTCHA es incorrecta.', 'wp-security-monitor' ) );
        }

        return $user;
    }

    public function validate_registration_captcha( $errors, $sanitized_user_login, $user_email ) {
        if ( ! $this->verify_response( '' ) ) {
            $errors->add( 'captcha_failed', __( 'Error: La respuesta del CAPTCHA es incorrecta.', 'wp-security-monitor' ) );
        }
        return $errors;
    }
}
