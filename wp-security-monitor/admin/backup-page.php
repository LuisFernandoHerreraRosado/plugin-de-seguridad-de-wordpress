<?php
/**
 * Template de la página de Backups
 */
if ( ! defined( 'ABSPATH' ) ) exit;

$history = $backup_mgr->get_history();
$risks = $backup_mgr->assess_storage_risk();
$current_freq = $this->settings->get_setting( 'backup_frequency', 'daily' );
$preventive = $this->settings->get_setting( 'preventive_backup', 'yes' );
$provider = $this->settings->get_setting( 'storage_provider', 'local' );

?>
<div class="wrap wpsm-admin">
    <h1><?php _e( 'Gestión de Backups', 'wp-security-monitor' ); ?></h1>

    <?php if ( isset( $_GET['settings-updated'] ) ) : ?>
        <div class="updated"><p><?php _e( 'Configuración actualizada.', 'wp-security-monitor' ); ?></p></div>
    <?php endif; ?>

    <?php if ( isset( $_GET['backup-success'] ) ) : ?>
        <div class="updated"><p><?php _e( 'Backup realizado con éxito.', 'wp-security-monitor' ); ?></p></div>
    <?php endif; ?>

    <?php if ( isset( $_GET['backup-error'] ) ) : ?>
        <div class="error"><p><?php _e( 'Error al realizar el backup. Consulta los logs para más detalles.', 'wp-security-monitor' ); ?></p></div>
    <?php endif; ?>

    <?php if ( ! empty( $risks ) ) : ?>
        <div class="notice notice-warning">
            <h3><?php _e( 'Advertencias de Almacenamiento', 'wp-security-monitor' ); ?></h3>
            <ul>
                <?php foreach ( $risks as $risk ) : ?>
                    <li><strong><?php echo esc_html( $risk ); ?></strong></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <div class="wpsm-dashboard-grid">
        <!-- Manual Backup -->
        <div class="wpsm-card">
            <h2><?php _e( 'Ejecución Manual', 'wp-security-monitor' ); ?></h2>
            <form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>">
                <?php wp_nonce_field( 'wpsm_run_backup' ); ?>
                <input type="hidden" name="action" value="wpsm_run_backup">
                <p>
                    <label><?php _e( 'Tipo de Backup:', 'wp-security-monitor' ); ?></label><br>
                    <select name="backup_type">
                        <option value="full"><?php _e( 'Completo (Archivos + DB)', 'wp-security-monitor' ); ?></option>
                        <option value="db"><?php _e( 'Solo Base de Datos', 'wp-security-monitor' ); ?></option>
                        <option value="files"><?php _e( 'Solo Archivos', 'wp-security-monitor' ); ?></option>
                    </select>
                </p>
                <input type="submit" class="button button-primary" value="<?php _e( 'Iniciar Backup Ahora', 'wp-security-monitor' ); ?>">
            </form>
        </div>

        <!-- Settings -->
        <div class="wpsm-card">
            <h2><?php _e( 'Configuración de Tareas', 'wp-security-monitor' ); ?></h2>
            <form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>">
                <?php wp_nonce_field( 'wpsm_backup_settings_action' ); ?>
                <input type="hidden" name="action" value="wpsm_save_backup_settings">

                <table class="form-table">
                    <tr>
                        <th><?php _e( 'Frecuencia Programada', 'wp-security-monitor' ); ?></th>
                        <td>
                            <select name="backup_frequency">
                                <option value="none" <?php selected( $current_freq, 'none' ); ?>><?php _e( 'Desactivado', 'wp-security-monitor' ); ?></option>
                                <option value="hourly" <?php selected( $current_freq, 'hourly' ); ?>><?php _e( 'Cada hora', 'wp-security-monitor' ); ?></option>
                                <option value="twicedaily" <?php selected( $current_freq, 'twicedaily' ); ?>><?php _e( 'Dos veces al día', 'wp-security-monitor' ); ?></option>
                                <option value="daily" <?php selected( $current_freq, 'daily' ); ?>><?php _e( 'Diario', 'wp-security-monitor' ); ?></option>
                                <option value="weekly" <?php selected( $current_freq, 'weekly' ); ?>><?php _e( 'Semanal', 'wp-security-monitor' ); ?></option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th><?php _e( 'Backup Preventivo', 'wp-security-monitor' ); ?></th>
                        <td>
                            <input type="checkbox" name="preventive_backup" value="yes" <?php checked( $preventive, 'yes' ); ?>>
                            <span class="description"><?php _e( 'Realizar backup de DB antes de actualizaciones o cambios críticos.', 'wp-security-monitor' ); ?></span>
                        </td>
                    </tr>
                    <tr>
                        <th><?php _e( 'Ubicación de Almacenamiento', 'wp-security-monitor' ); ?></th>
                        <td>
                            <select name="storage_provider">
                                <option value="local" <?php selected( $provider, 'local' ); ?>><?php _e( 'Local (Servidor actual)', 'wp-security-monitor' ); ?></option>
                                <option value="remote" disabled><?php _e( 'Remoto (Próximamente: S3, Dropbox, etc.)', 'wp-security-monitor' ); ?></option>
                            </select>
                        </td>
                    </tr>
                </table>
                <input type="submit" class="button button-secondary" value="<?php _e( 'Guardar Ajustes', 'wp-security-monitor' ); ?>">
            </form>
        </div>
    </div>

    <!-- History -->
    <div class="wpsm-card" style="margin-top: 20px;">
        <h2><?php _e( 'Historial de Backups', 'wp-security-monitor' ); ?></h2>
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th><?php _e( 'Fecha', 'wp-security-monitor' ); ?></th>
                    <th><?php _e( 'Tipo', 'wp-security-monitor' ); ?></th>
                    <th><?php _e( 'Archivos', 'wp-security-monitor' ); ?></th>
                    <th><?php _e( 'Estado', 'wp-security-monitor' ); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php if ( empty( $history ) ) : ?>
                    <tr><td colspan="4"><?php _e( 'No hay backups registrados.', 'wp-security-monitor' ); ?></td></tr>
                <?php else : ?>
                    <?php foreach ( $history as $item ) : ?>
                        <tr>
                            <td><?php echo esc_html( $item['date'] ); ?></td>
                            <td><?php echo esc_html( strtoupper( $item['type'] ) ); ?></td>
                            <td>
                                <?php if ( $item['db_file'] ) echo 'DB: ' . esc_html( $item['db_file'] ) . '<br>'; ?>
                                <?php if ( $item['files_file'] ) echo 'Files: ' . esc_html( $item['files_file'] ); ?>
                            </td>
                            <td><span class="dashicons dashicons-yes" style="color:green;"></span> <?php echo esc_html( $item['status'] ); ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>
