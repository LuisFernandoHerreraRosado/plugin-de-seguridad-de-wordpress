<?php if ( ! defined( 'ABSPATH' ) ) exit; ?>
<div class="wrap">
    <h1><?php _e( 'WordPress Core', 'wp-security-monitor' ); ?></h1>

    <form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>">
        <?php wp_nonce_field( 'wpsm_core_settings_action' ); ?>
        <input type="hidden" name="action" value="wpsm_save_core_settings">

        <h2 class="title"><?php _e( 'Actualizaciones Automáticas', 'wp-security-monitor' ); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php _e( 'Actualizaciones Menores', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="auto_update_minor" type="checkbox" value="yes" <?php checked( $this->settings->get_setting( 'auto_update_minor', 'yes' ), 'yes' ); ?>>
                    <p class="description"><?php _e( 'Recomendado. Instala parches de seguridad automáticamente.', 'wp-security-monitor' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php _e( 'Actualizaciones Mayores', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="auto_update_major" type="checkbox" value="yes" <?php checked( $this->settings->get_setting( 'auto_update_major', 'no' ), 'yes' ); ?>>
                    <p class="description"><?php _e( 'Habilita la instalación automática de versiones principales (ej: 6.4 a 6.5).', 'wp-security-monitor' ); ?></p>
                </td>
            </tr>
        </table>

        <h2 class="title"><?php _e( 'Protección y Hardening', 'wp-security-monitor' ); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php _e( 'Deshabilitar Editor de Archivos', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="disable_file_edit" type="checkbox" value="yes" <?php checked( $this->settings->get_setting( 'disable_file_edit', 'yes' ), 'yes' ); ?>>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php _e( 'Ocultar Errores DB', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="hide_db_errors" type="checkbox" value="yes" <?php checked( $this->settings->get_setting( 'hide_db_errors', 'yes' ), 'yes' ); ?>>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php _e( 'Bloquear Uploads no Filtrados', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="block_unfiltered_uploads" type="checkbox" value="yes" <?php checked( $this->settings->get_setting( 'block_unfiltered_uploads', 'yes' ), 'yes' ); ?>>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php _e( 'Desactivar Debug en Producción', 'wp-security-monitor' ); ?></th>
                <td>
                    <input name="disable_debug" type="checkbox" value="yes" <?php checked( $this->settings->get_setting( 'disable_debug', 'yes' ), 'yes' ); ?>>
                </td>
            </tr>
        </table>

        <?php submit_button( __( 'Guardar Ajustes del Core', 'wp-security-monitor' ) ); ?>
    </form>

    <h2 class="title"><?php _e( 'Gestión de Base de Datos', 'wp-security-monitor' ); ?></h2>
    <div class="card">
        <h3><?php _e( 'Cambiar Prefijo', 'wp-security-monitor' ); ?></h3>
        <p><?php _e( 'Tu prefijo actual es:', 'wp-security-monitor' ); ?> <code><?php global $wpdb; echo $wpdb->prefix; ?></code></p>
        <form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>" onsubmit="return confirm('¿Estás seguro? Se recomienda hacer un backup completo antes.');">
            <?php wp_nonce_field( 'wpsm_change_prefix_action' ); ?>
            <input type="hidden" name="action" value="wpsm_change_db_prefix">
            <input name="new_prefix" type="text" placeholder="nuevo_prefijo_" class="regular-text" required>
            <?php submit_button( __( 'Cambiar Prefijo Ahora', 'wp-security-monitor' ), 'secondary' ); ?>
        </form>
    </div>
</div>
