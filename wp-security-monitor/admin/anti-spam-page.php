<?php if ( ! defined( 'ABSPATH' ) ) exit; ?>
<div class="wrap">
    <h1><?php _e( 'Anti-Spam & Anti-Phishing', 'wp-security-monitor' ); ?></h1>

    <form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>">
        <?php wp_nonce_field( 'wpsm_anti_spam_settings_action' ); ?>
        <input type="hidden" name="action" value="wpsm_save_anti_spam_settings">

        <h2 class="title"><?php _e( 'Protección Anti-Spam', 'wp-security-monitor' ); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php _e( 'Habilitar Protección', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="spam_protection_enable" type="checkbox" value="yes" <?php checked( $this->settings->get_setting( 'spam_protection_enable', 'no' ), 'yes' ); ?>>
                    <p class="description"><?php _e( 'Activa la protección global contra spam automatizado.', 'wp-security-monitor' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php _e( 'Desactivar Comentarios', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="disable_comments" type="checkbox" value="yes" <?php checked( $this->settings->get_setting( 'disable_comments', 'no' ), 'yes' ); ?>>
                    <p class="description"><?php _e( 'Cierra completamente la funcionalidad de comentarios en todo el sitio.', 'wp-security-monitor' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php _e( 'Habilitar Honeypot', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="antispam_honeypot" type="checkbox" value="yes" <?php checked( $this->settings->get_setting( 'antispam_honeypot', 'yes' ), 'yes' ); ?>>
                    <p class="description"><?php _e( 'Añade campos invisibles para atrapar bots en comentarios y registros.', 'wp-security-monitor' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php _e( 'Control de Tiempo', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="antispam_time_check" type="checkbox" value="yes" <?php checked( $this->settings->get_setting( 'antispam_time_check', 'yes' ), 'yes' ); ?>>
                    <p class="description"><?php _e( 'Bloquea envíos de formularios que se realicen demasiado rápido (bots).', 'wp-security-monitor' ); ?></p>
                </td>
            </tr>
        </table>

        <h2 class="title"><?php _e( 'Protección Anti-Phishing (Próximamente)', 'wp-security-monitor' ); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php _e( 'Habilitar Anti-Phishing', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="phishing_protection_enable" type="checkbox" value="yes" <?php checked( $this->settings->get_setting( 'phishing_protection_enable', 'no' ), 'yes' ); ?>>
                    <p class="description"><?php _e( 'Base preparada para detección de enlaces sospechosos y contenido fraudulento.', 'wp-security-monitor' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php _e( 'Detección de Enlaces', 'wp-security-monitor' ); ?></th>
                <td>
                    <span class="badge badge-info"><?php _e( 'En desarrollo', 'wp-security-monitor' ); ?></span>
                    <p class="description"><?php _e( 'Analizará enlaces en comentarios y contenido en busca de patrones de phishing.', 'wp-security-monitor' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php _e( 'Páginas Señuelo', 'wp-security-monitor' ); ?></th>
                <td>
                    <span class="badge badge-info"><?php _e( 'En desarrollo', 'wp-security-monitor' ); ?></span>
                    <p class="description"><?php _e( 'Identificación de páginas que intentan suplantar la identidad del sitio.', 'wp-security-monitor' ); ?></p>
                </td>
            </tr>
        </table>

        <?php submit_button( __( 'Guardar Ajustes Anti-Spam', 'wp-security-monitor' ) ); ?>
    </form>
</div>
