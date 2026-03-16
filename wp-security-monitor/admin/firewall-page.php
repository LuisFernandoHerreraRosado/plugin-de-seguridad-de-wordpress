<?php
/**
 * Admin Page: Firewall y GeoIP
 */
if ( ! defined( 'ABSPATH' ) ) exit;

$settings = new WPSM_Settings();
?>

<div class="wrap wpsm-admin-wrap">
    <h1><?php _e( 'Firewall y GeoIP', 'wp-security-monitor' ); ?></h1>

    <form method="post" action="admin-post.php">
        <?php wp_nonce_field( 'wpsm_firewall_settings_action' ); ?>
        <input type="hidden" name="action" value="wpsm_save_firewall_settings">

        <div class="wpsm-card">
            <h2><?php _e( 'Configuración del Firewall', 'wp-security-monitor' ); ?></h2>
            <table class="form-table">
                <tr>
                    <th><?php _e( 'Activar Firewall', 'wp-security-monitor' ); ?></th>
                    <td>
                        <input type="checkbox" name="firewall_enable" value="yes" <?php checked( $settings->get_setting( 'firewall_enable' ), 'yes' ); ?>>
                    </td>
                </tr>
                <tr>
                    <th><?php _e( 'Bloquear Bots de IA', 'wp-security-monitor' ); ?></th>
                    <td>
                        <input type="checkbox" name="block_ai_bots" value="yes" <?php checked( $settings->get_setting( 'block_ai_bots' ), 'yes' ); ?>>
                        <p class="description"><?php _e( 'Bloquea GPTBot, ChatGPT-User, etc.', 'wp-security-monitor' ); ?></p>
                    </td>
                </tr>
                <tr>
                    <th><?php _e( 'Bloquear Falsos Bots SEO', 'wp-security-monitor' ); ?></th>
                    <td>
                        <input type="checkbox" name="block_fake_seo_bots" value="yes" <?php checked( $settings->get_setting( 'block_fake_seo_bots' ), 'yes' ); ?>>
                    </td>
                </tr>
                <tr>
                    <th><?php _e( 'User Agents Maliciosos', 'wp-security-monitor' ); ?></th>
                    <td>
                        <textarea name="firewall_bad_uas" rows="5" class="large-text"><?php echo esc_textarea( $settings->get_setting( 'firewall_bad_uas' ) ); ?></textarea>
                        <p class="description"><?php _e( 'Un patrón por línea.', 'wp-security-monitor' ); ?></p>
                    </td>
                </tr>
                <tr>
                    <th><?php _e( 'Bad Referrers', 'wp-security-monitor' ); ?></th>
                    <td>
                        <textarea name="firewall_bad_referrers" rows="5" class="large-text"><?php echo esc_textarea( $settings->get_setting( 'firewall_bad_referrers' ) ); ?></textarea>
                    </td>
                </tr>
            </table>
        </div>

        <div class="wpsm-card">
            <h2><?php _e( 'GeoIP Global', 'wp-security-monitor' ); ?></h2>
            <table class="form-table">
                <tr>
                    <th><?php _e( 'Activar GeoIP Global', 'wp-security-monitor' ); ?></th>
                    <td>
                        <input type="checkbox" name="geoip_enable" value="yes" <?php checked( $settings->get_setting( 'geoip_enable' ), 'yes' ); ?>>
                    </td>
                </tr>
                <tr>
                    <th><?php _e( 'Modo', 'wp-security-monitor' ); ?></th>
                    <td>
                        <select name="geoip_global_mode">
                            <option value="whitelist" <?php selected( $settings->get_setting( 'geoip_global_mode' ), 'whitelist' ); ?>><?php _e( 'Lista Blanca (Solo permitir)', 'wp-security-monitor' ); ?></option>
                            <option value="blacklist" <?php selected( $settings->get_setting( 'geoip_global_mode' ), 'blacklist' ); ?>><?php _e( 'Lista Negra (Bloquear)', 'wp-security-monitor' ); ?></option>
                        </select>
                    </td>
                </tr>
                <tr>
                    <th><?php _e( 'Países (ISO Codes)', 'wp-security-monitor' ); ?></th>
                    <td>
                        <input type="text" name="geoip_countries" value="<?php echo esc_attr( $settings->get_setting( 'geoip_countries' ) ); ?>" class="large-text">
                        <p class="description"><?php _e( 'Ej: US,ES,CN. Separados por comas.', 'wp-security-monitor' ); ?></p>
                    </td>
                </tr>
            </table>
        </div>

        <?php submit_button( __( 'Guardar Configuración de Firewall', 'wp-security-monitor' ) ); ?>
    </form>

    <div class="wpsm-card">
        <h2><?php _e( 'Reglas y Firmas Personalizadas', 'wp-security-monitor' ); ?></h2>
        <p><?php _e( 'Estas reglas se pueden actualizar remotamente desde el panel central.', 'wp-security-monitor' ); ?></p>
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th><?php _e( 'Nombre', 'wp-security-monitor' ); ?></th>
                    <th><?php _e( 'Tipo', 'wp-security-monitor' ); ?></th>
                    <th><?php _e( 'Patrón', 'wp-security-monitor' ); ?></th>
                    <th><?php _e( 'Estado', 'wp-security-monitor' ); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php
                $rules = get_option( 'wpsm_firewall_rules', array() );
                if ( empty( $rules ) ) :
                ?>
                    <tr>
                        <td colspan="4"><?php _e( 'No hay reglas personalizadas activas.', 'wp-security-monitor' ); ?></td>
                    </tr>
                <?php else : foreach ( $rules as $rule ) : ?>
                    <tr>
                        <td><?php echo esc_html( $rule['name'] ); ?></td>
                        <td><?php echo esc_html( $rule['type'] ); ?></td>
                        <td><code><?php echo esc_html( $rule['pattern'] ); ?></code></td>
                        <td><?php echo $rule['enabled'] ? __( 'Activa', 'wp-security-monitor' ) : __( 'Inactiva', 'wp-security-monitor' ); ?></td>
                    </tr>
                <?php endforeach; endif; ?>
            </tbody>
        </table>
    </div>
</div>
