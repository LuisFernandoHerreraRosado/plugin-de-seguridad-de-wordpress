<?php
/**
 * Template para la página de Datos Sensibles
 */
if ( ! defined( 'ABSPATH' ) ) exit;
?>

<div class="wrap wpsm-admin-wrap">
    <h1><?php _e( 'Protección de Datos Sensibles', 'wp-security-monitor' ); ?></h1>
    <p><?php _e( 'Gestiona la exposición de endpoints, rutas y contenido sensible de tu sitio.', 'wp-security-monitor' ); ?></p>

    <?php if ( isset( $_GET['settings-updated'] ) ) : ?>
        <div class="notice notice-success is-dismissible">
            <p><?php _e( 'Configuración actualizada correctamente.', 'wp-security-monitor' ); ?></p>
        </div>
    <?php endif; ?>

    <form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>">
        <?php wp_nonce_field( 'wpsm_sensitive_settings_action' ); ?>
        <input type="hidden" name="action" value="wpsm_save_sensitive_settings">

        <div class="wpsm-settings-section">
            <h2>XML-RPC</h2>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e( 'Estado de XML-RPC', 'wp-security-monitor' ); ?></th>
                    <td>
                        <select name="wpsm_xmlrpc_status">
                            <option value="enabled" <?php selected( get_option( 'wpsm_xmlrpc_status' ), 'enabled' ); ?>><?php _e( 'Habilitado (Por defecto)', 'wp-security-monitor' ); ?></option>
                            <option value="disabled" <?php selected( get_option( 'wpsm_xmlrpc_status' ), 'disabled' ); ?>><?php _e( 'Deshabilitar completamente', 'wp-security-monitor' ); ?></option>
                            <option value="partial" <?php selected( get_option( 'wpsm_xmlrpc_status' ), 'partial' ); ?>><?php _e( 'Deshabilitar parcialmente (Solo métodos básicos)', 'wp-security-monitor' ); ?></option>
                        </select>
                        <p class="description"><?php _e( 'Atención: Deshabilitar XML-RPC puede afectar a aplicaciones móviles de WordPress o plugins Jetpack.', 'wp-security-monitor' ); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e( 'Limitar Multicall', 'wp-security-monitor' ); ?></th>
                    <td>
                        <input type="checkbox" name="wpsm_xmlrpc_limit_multicall" value="yes" <?php checked( get_option( 'wpsm_xmlrpc_limit_multicall' ), 'yes' ); ?>>
                        <?php _e( 'Desactivar system.multicall para prevenir ataques de fuerza bruta.', 'wp-security-monitor' ); ?>
                    </td>
                </tr>
            </table>
        </div>

        <div class="wpsm-settings-section">
            <h2><?php _e( 'Rutas de Autor', 'wp-security-monitor' ); ?></h2>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e( 'Base de URL de Autor', 'wp-security-monitor' ); ?></th>
                    <td>
                        <input type="text" name="wpsm_author_base" value="<?php echo esc_attr( get_option( 'wpsm_author_base', 'profile' ) ); ?>" class="regular-text">
                        <p class="description"><?php _e( 'Cambia "/author/" por algo más discreto como "/profile/".', 'wp-security-monitor' ); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e( 'Deshabilitar Archivos de Autor', 'wp-security-monitor' ); ?></th>
                    <td>
                        <input type="checkbox" name="wpsm_disable_author_archives" value="yes" <?php checked( get_option( 'wpsm_disable_author_archives' ), 'yes' ); ?>>
                        <?php _e( 'Bloquear acceso a las páginas de archivo de autor para evitar enumeración de usuarios.', 'wp-security-monitor' ); ?>
                    </td>
                </tr>
            </table>
        </div>

        <div class="wpsm-settings-section">
            <h2><?php _e( 'Protecciones de Contenido', 'wp-security-monitor' ); ?></h2>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e( 'Anti-Hotlink', 'wp-security-monitor' ); ?></th>
                    <td>
                        <input type="checkbox" name="wpsm_anti_hotlink" value="yes" <?php checked( get_option( 'wpsm_anti_hotlink' ), 'yes' ); ?>>
                        <?php _e( 'Detectar y registrar intentos de hotlinking de tus medios. Nota: Para un bloqueo efectivo se recomienda configuración a nivel de servidor.', 'wp-security-monitor' ); ?>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e( 'Anti 404 Guessing', 'wp-security-monitor' ); ?></th>
                    <td>
                        <input type="checkbox" name="wpsm_anti_404_guessing" value="yes" <?php checked( get_option( 'wpsm_anti_404_guessing' ), 'yes' ); ?>>
                        <?php _e( 'Registrar errores 404 para identificar escaneos de rutas inexistentes.', 'wp-security-monitor' ); ?>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e( 'Blackhole en robots.txt', 'wp-security-monitor' ); ?></th>
                    <td>
                        <input type="checkbox" name="wpsm_robots_blackhole" value="yes" <?php checked( get_option( 'wpsm_robots_blackhole' ), 'yes' ); ?>>
                        <?php _e( 'Añadir una trampa para bots maliciosos en robots.txt.', 'wp-security-monitor' ); ?>
                    </td>
                </tr>
            </table>
        </div>

        <div class="wpsm-settings-section">
            <h2><?php _e( 'Revelación de Información', 'wp-security-monitor' ); ?></h2>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e( 'Ocultar Versión de WordPress', 'wp-security-monitor' ); ?></th>
                    <td>
                        <input type="checkbox" name="wpsm_hide_wp_version" value="yes" <?php checked( get_option( 'wpsm_hide_wp_version' ), 'yes' ); ?>>
                        <?php _e( 'Eliminar la etiqueta generator y versiones en scripts/styles.', 'wp-security-monitor' ); ?>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e( 'Proteger Archivos Sensibles', 'wp-security-monitor' ); ?></th>
                    <td>
                        <input type="checkbox" name="wpsm_block_sensitive_files" value="yes" <?php checked( get_option( 'wpsm_block_sensitive_files' ), 'yes' ); ?>>
                        <?php _e( 'Bloquear acceso a readme.txt, license.txt, changelog.md, etc.', 'wp-security-monitor' ); ?>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e( 'Bloquear PHP Disclosure', 'wp-security-monitor' ); ?></th>
                    <td>
                        <input type="checkbox" name="wpsm_disable_php_disclosure" value="yes" <?php checked( get_option( 'wpsm_disable_php_disclosure' ), 'yes' ); ?>>
                        <?php _e( 'Intentar ocultar cabeceras X-Powered-By y evitar PHP Easter Eggs.', 'wp-security-monitor' ); ?>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e( 'Desactivar Directory Listing', 'wp-security-monitor' ); ?></th>
                    <td>
                        <input type="checkbox" name="wpsm_disable_directory_listing" value="yes" <?php checked( get_option( 'wpsm_disable_directory_listing' ), 'yes' ); ?>>
                        <?php _e( 'Prevenir que se listen los archivos dentro de directorios. Nota: Se recomienda configurar "Options -Indexes" en su servidor web.', 'wp-security-monitor' ); ?>
                    </td>
                </tr>
            </table>
        </div>

        <?php submit_button( __( 'Guardar Cambios', 'wp-security-monitor' ) ); ?>
    </form>
</div>
