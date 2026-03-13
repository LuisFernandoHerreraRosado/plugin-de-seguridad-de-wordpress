<?php if ( ! defined( 'ABSPATH' ) ) exit; ?>
<div class="wrap">
    <h1><?php _e( 'Usuarios y Acceso', 'wp-security-monitor' ); ?></h1>

    <form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>">
        <?php wp_nonce_field( 'wpsm_auth_settings_action' ); ?>
        <input type="hidden" name="action" value="wpsm_save_auth_settings">

        <h2 class="title"><?php _e( 'Ruta de Login Personalizada', 'wp-security-monitor' ); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php _e( 'Slug de Login', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="login_slug" type="text" value="<?php echo esc_attr( $this->settings->get_setting( 'login_slug', '' ) ); ?>" class="regular-text">
                    <p class="description"><?php _e( 'Ejemplo: "mi-secreto". Deja vacío para usar wp-login.php.', 'wp-security-monitor' ); ?></p>
                </td>
            </tr>
        </table>

        <h2 class="title"><?php _e( 'Protección de Fuerza Bruta', 'wp-security-monitor' ); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php _e( 'Habilitar', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="brute_force_enable" type="checkbox" value="yes" <?php checked( $this->settings->get_setting( 'brute_force_enable', 'yes' ), 'yes' ); ?>>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php _e( 'Intentos Máximos', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="max_retries" type="number" value="<?php echo esc_attr( $this->settings->get_setting( 'max_retries', 5 ) ); ?>" class="small-text">
                </td>
            </tr>
            <tr>
                <th scope="row"><?php _e( 'Duración Bloqueo (min)', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="lockout_duration" type="number" value="<?php echo esc_attr( $this->settings->get_setting( 'lockout_duration', 30 ) ); ?>" class="small-text">
                </td>
            </tr>
        </table>

        <h2 class="title"><?php _e( 'Validación GeoIP', 'wp-security-monitor' ); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php _e( 'Habilitar GeoIP', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="geoip_enable" type="checkbox" value="yes" <?php checked( $this->settings->get_setting( 'geoip_enable', 'no' ), 'yes' ); ?>>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php _e( 'Países Permitidos', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="allowed_countries" type="text" value="<?php echo esc_attr( $this->settings->get_setting( 'allowed_countries', '' ) ); ?>" class="regular-text">
                    <p class="description"><?php _e( 'Códigos ISO separados por comas (ej: ES, US, MX). Deja vacío para permitir todos.', 'wp-security-monitor' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php _e( 'Modo', 'wp-security-monitor' ); ?></th>
                <td>
                    <select name="geoip_mode">
                        <option value="alert" <?php selected( $this->settings->get_setting( 'geoip_mode', 'alert' ), 'alert' ); ?>><?php _e( 'Solo Alerta', 'wp-security-monitor' ); ?></option>
                        <option value="block" <?php selected( $this->settings->get_setting( 'geoip_mode', 'alert' ), 'block' ); ?>><?php _e( 'Bloquear', 'wp-security-monitor' ); ?></option>
                        <option value="verify" <?php selected( $this->settings->get_setting( 'geoip_mode', 'alert' ), 'verify' ); ?>><?php _e( 'Verificación Extra', 'wp-security-monitor' ); ?></option>
                    </select>
                </td>
            </tr>
        </table>

        <h2 class="title"><?php _e( 'Autenticación de Dos Factores (2FA)', 'wp-security-monitor' ); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php _e( 'Habilitar 2FA', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="two_factor_enable" type="checkbox" value="yes" <?php checked( $this->settings->get_setting( 'two_factor_enable', 'no' ), 'yes' ); ?>>
                </td>
            </tr>
        </table>

        <h2 class="title"><?php _e( 'CAPTCHA', 'wp-security-monitor' ); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php _e( 'Habilitar CAPTCHA', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="captcha_enable" type="checkbox" value="yes" <?php checked( $this->settings->get_setting( 'captcha_enable', 'no' ), 'yes' ); ?>>
                </td>
            </tr>
        </table>

        <h2 class="title"><?php _e( 'Políticas de Contraseña', 'wp-security-monitor' ); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php _e( 'Longitud Mínima', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="pwd_min_length" type="number" value="<?php echo esc_attr( $this->settings->get_setting( 'pwd_min_length', 12 ) ); ?>" class="small-text">
                </td>
            </tr>
            <tr>
                <th scope="row"><?php _e( 'Expiración (días)', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="pwd_expiry_days" type="number" value="<?php echo esc_attr( $this->settings->get_setting( 'pwd_expiry_days', 90 ) ); ?>" class="small-text">
                </td>
            </tr>
            <tr>
                <th scope="row"><?php _e( 'Complejidad', 'wp-security-monitor' ); ?></th>
                <td>
                    <select name="pwd_complexity">
                        <option value="low" <?php selected( $this->settings->get_setting( 'pwd_complexity', 'high' ), 'low' ); ?>><?php _e( 'Baja (8+ chars)', 'wp-security-monitor' ); ?></option>
                        <option value="high" <?php selected( $this->settings->get_setting( 'pwd_complexity', 'high' ), 'high' ); ?>><?php _e( 'Alta (Mayús, Minús, Núm, Sím)', 'wp-security-monitor' ); ?></option>
                    </select>
                </td>
            </tr>
        </table>

        <?php submit_button( __( 'Guardar Ajustes de Usuarios', 'wp-security-monitor' ) ); ?>
    </form>
</div>
