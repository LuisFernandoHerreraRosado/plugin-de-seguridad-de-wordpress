<?php if ( ! defined( 'ABSPATH' ) ) exit; ?>
<div class="wrap">
    <h1><?php _e( 'Plugins y Themes', 'wp-security-monitor' ); ?></h1>

    <form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>">
        <?php wp_nonce_field( 'wpsm_ext_settings_action' ); ?>
        <input type="hidden" name="action" value="wpsm_save_ext_settings">

        <h2 class="title"><?php _e( 'Restricciones de Carga y Acciones', 'wp-security-monitor' ); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php _e( 'Bloquear subida de .zip', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="block_zip_upload" type="checkbox" value="yes" <?php checked( $this->settings->get_setting( 'block_zip_upload', 'no' ), 'yes' ); ?>>
                    <p class="description"><?php _e( 'Evita que se instalen extensiones manualmente vía subida de archivos.', 'wp-security-monitor' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php _e( 'Restringir acciones en backend', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="restrict_ext_ops" type="checkbox" value="yes" <?php checked( $this->settings->get_setting( 'restrict_ext_ops', 'no' ), 'yes' ); ?>>
                    <p class="description"><?php _e( 'Deshabilita instalación, activación, desactivación y borrado desde el panel de WordPress.', 'wp-security-monitor' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php _e( 'Forzar método FTP', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="force_ftp" type="checkbox" value="yes" <?php checked( $this->settings->get_setting( 'force_ftp', 'no' ), 'yes' ); ?>>
                    <p class="description"><?php _e( 'Obliga al sistema a pedir credenciales FTP para cualquier modificación de archivos.', 'wp-security-monitor' ); ?></p>
                </td>
            </tr>
        </table>

        <h2 class="title"><?php _e( 'Monitor de Vulnerabilidades', 'wp-security-monitor' ); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php _e( 'Escaneo Automático', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="vulnerability_scan" type="checkbox" value="yes" <?php checked( $this->settings->get_setting( 'vulnerability_scan', 'yes' ), 'yes' ); ?>>
                    <p class="description"><?php _e( 'Busca vulnerabilidades conocidas en tus extensiones periódicamente.', 'wp-security-monitor' ); ?></p>
                </td>
            </tr>
        </table>

        <?php submit_button( __( 'Guardar Ajustes de Extensiones', 'wp-security-monitor' ) ); ?>
    </form>
</div>
