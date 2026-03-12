<?php if ( ! defined( 'ABSPATH' ) ) exit; ?>
<div class="wrap">
    <h1><?php _e( 'Configuración de Seguridad', 'wp-security-monitor' ); ?></h1>

    <form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>">
        <?php wp_nonce_field( 'wpsm_settings_action' ); ?>
        <input type="hidden" name="action" value="wpsm_save_settings">

        <table class="form-table">
            <tr>
                <th scope="row"><?php _e( 'Email de Alertas', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="alert_email" type="email" value="<?php echo esc_attr( $this->settings->get_setting( 'alert_email', get_option( 'admin_email' ) ) ); ?>" class="regular-text">
                    <p class="description"><?php _e( 'Donde se enviarán las notificaciones críticas.', 'wp-security-monitor' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php _e( 'Frecuencia de Escaneo', 'wp-security-monitor' ); ?></th>
                <td>
                    <?php $freq = $this->settings->get_setting( 'scan_frequency', 'daily' ); ?>
                    <select name="scan_frequency">
                        <option value="none" <?php selected( $freq, 'none' ); ?>><?php _e( 'Desactivado', 'wp-security-monitor' ); ?></option>
                        <option value="hourly" <?php selected( $freq, 'hourly' ); ?>><?php _e( 'Cada hora', 'wp-security-monitor' ); ?></option>
                        <option value="twicedaily" <?php selected( $freq, 'twicedaily' ); ?>><?php _e( 'Dos veces al día', 'wp-security-monitor' ); ?></option>
                        <option value="daily" <?php selected( $freq, 'daily' ); ?>><?php _e( 'Diario', 'wp-security-monitor' ); ?></option>
                        <option value="weekly" <?php selected( $freq, 'weekly' ); ?>><?php _e( 'Semanal', 'wp-security-monitor' ); ?></option>
                    </select>
                </td>
            </tr>
        </table>

        <?php submit_button( __( 'Guardar Cambios', 'wp-security-monitor' ) ); ?>
    </form>
</div>
