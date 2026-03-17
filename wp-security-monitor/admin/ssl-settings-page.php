<?php
/**
 * Template de Ajustes de SSL/HTTPS
 */
if ( ! defined( 'ABSPATH' ) ) exit;

$ssl_manager = new WPSM_SSL_Manager( new WPSM_Logger(), new WPSM_Settings() );
$ssl_status  = $ssl_manager->get_ssl_status();
?>

<div class="wrap wpsm-admin-wrap">
    <h1><?php _e( 'Configuración SSL y HTTPS', 'wp-security-monitor' ); ?></h1>

    <?php if ( isset( $_GET['settings-updated'] ) ) : ?>
        <div class="notice notice-success is-dismissible"><p><?php _e( 'Ajustes guardados.', 'wp-security-monitor' ); ?></p></div>
    <?php endif; ?>

    <div class="wpsm-dashboard-grid">
        <!-- Estado Actual -->
        <div class="wpsm-card">
            <h2><?php _e( 'Estado del SSL', 'wp-security-monitor' ); ?></h2>
            <div class="wpsm-status-badge <?php echo $ssl_status['enabled'] ? 'status-passed' : 'status-warning'; ?>">
                <?php echo $ssl_status['enabled'] ? __( 'HTTPS Activo', 'wp-security-monitor' ) : __( 'HTTPS Inactivo', 'wp-security-monitor' ); ?>
            </div>

            <table class="wp-list-table widefat fixed striped" style="margin-top: 20px;">
                <tbody>
                    <tr>
                        <td><strong><?php _e( 'WordPress Address (URL)', 'wp-security-monitor' ); ?></strong></td>
                        <td><?php echo get_site_url(); ?></td>
                    </tr>
                    <tr>
                        <td><strong><?php _e( 'Site Address (URL)', 'wp-security-monitor' ); ?></strong></td>
                        <td><?php echo get_home_url(); ?></td>
                    </tr>
                    <tr>
                        <td><strong><?php _e( 'Emisor del Certificado', 'wp-security-monitor' ); ?></strong></td>
                        <td><?php echo esc_html( $ssl_status['cert_info']['issuer'] ); ?></td>
                    </tr>
                    <tr>
                        <td><strong><?php _e( 'Fecha de Expiración', 'wp-security-monitor' ); ?></strong></td>
                        <td><?php echo esc_html( $ssl_status['cert_info']['expiry'] ); ?></td>
                    </tr>
                </tbody>
            </table>

            <?php if ( ! empty( $ssl_status['warnings'] ) ) : ?>
                <div class="wpsm-alerts-list" style="margin-top: 20px;">
                    <?php foreach ( $ssl_status['warnings'] as $warning ) : ?>
                        <div class="wpsm-alert-item alert-warning">
                            <span class="dashicons dashicons-warning"></span> <?php echo esc_html( $warning ); ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>

        <!-- Ajustes -->
        <div class="wpsm-card">
            <h2><?php _e( 'Ajustes de Seguridad SSL', 'wp-security-monitor' ); ?></h2>
            <form method="post" action="admin-post.php">
                <input type="hidden" name="action" value="wpsm_save_ssl_settings">
                <?php wp_nonce_field( 'wpsm_ssl_settings_action' ); ?>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e( 'Forzar Redirección HTTPS', 'wp-security-monitor' ); ?></th>
                        <td>
                            <label class="wpsm-switch">
                                <input type="checkbox" name="force_https" value="yes" <?php checked( get_option( 'wpsm_force_https' ), 'yes' ); ?>>
                                <span class="slider round"></span>
                            </label>
                            <p class="description"><?php _e( 'Redirige automáticamente todas las peticiones HTTP a HTTPS.', 'wp-security-monitor' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e( 'Corregir Contenido Mixto', 'wp-security-monitor' ); ?></th>
                        <td>
                            <label class="wpsm-switch">
                                <input type="checkbox" name="fix_mixed_content" value="yes" <?php checked( get_option( 'wpsm_fix_mixed_content' ), 'yes' ); ?>>
                                <span class="slider round"></span>
                            </label>
                            <p class="description"><?php _e( 'Reemplaza dinámicamente enlaces http por https en el contenido de salida para evitar advertencias del navegador.', 'wp-security-monitor' ); ?></p>
                        </td>
                    </tr>
                </table>

                <?php submit_button( __( 'Guardar Configuración SSL', 'wp-security-monitor' ) ); ?>
            </form>
        </div>
    </div>
</div>
