<?php if ( ! defined( 'ABSPATH' ) ) exit; ?>
<div class="wrap">
    <h1><?php _e( 'Protección Anti-Spam y Anti-Phishing', 'wp-security-monitor' ); ?></h1>

    <form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>">
        <?php wp_nonce_field( 'wpsm_spam_settings_action' ); ?>
        <input type="hidden" name="action" value="wpsm_save_spam_settings">

        <h2 class="title"><?php _e( 'Gestión de Comentarios', 'wp-security-monitor' ); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php _e( 'Desactivar Comentarios Totalmente', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="disable_comments" type="checkbox" value="yes" <?php checked( $this->settings->get_setting( 'disable_comments', 'no' ), 'yes' ); ?>>
                    <p class="description"><?php _e( 'Cierra los comentarios en todo el sitio y oculta el menú de comentarios en el admin.', 'wp-security-monitor' ); ?></p>
                </td>
            </tr>
        </table>

        <h2 class="title"><?php _e( 'Protección Anti-Spam', 'wp-security-monitor' ); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php _e( 'Habilitar Protección Anti-Spam', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="spam_protection_enable" type="checkbox" value="yes" <?php checked( $this->settings->get_setting( 'spam_protection_enable', 'no' ), 'yes' ); ?>>
                    <p class="description"><?php _e( 'Activa Honeypot y protección por tiempo en comentarios y registros.', 'wp-security-monitor' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php _e( 'Tiempo Mínimo de Envío (segundos)', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="spam_min_time" type="number" value="<?php echo esc_attr( $this->settings->get_setting( 'spam_min_time', 5 ) ); ?>" class="small-text">
                    <p class="description"><?php _e( 'Evita envíos automáticos ultra-rápidos.', 'wp-security-monitor' ); ?></p>
                </td>
            </tr>
        </table>

        <h2 class="title"><?php _e( 'Prevención de Phishing y Enlaces', 'wp-security-monitor' ); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php _e( 'Límite de Enlaces en Comentarios', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="spam_max_links" type="number" value="<?php echo esc_attr( $this->settings->get_setting( 'spam_max_links', 3 ) ); ?>" class="small-text">
                    <p class="description"><?php _e( 'Bloquea comentarios que superen este número de enlaces (0 para no permitir ninguno).', 'wp-security-monitor' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php _e( 'Detección de Phishing (Próximamente)', 'wp-security-monitor' ); ?></th>
                <td>
                    <input type="checkbox" disabled>
                    <p class="description"><?php _e( 'Funcionalidad de escaneo de URLs contra listas negras de phishing en desarrollo.', 'wp-security-monitor' ); ?></p>
                </td>
            </tr>
        </table>

        <?php submit_button( __( 'Guardar Ajustes Anti-Spam', 'wp-security-monitor' ) ); ?>
    </form>
</div>
