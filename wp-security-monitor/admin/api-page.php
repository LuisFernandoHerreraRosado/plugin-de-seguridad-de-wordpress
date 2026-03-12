<?php if ( ! defined( 'ABSPATH' ) ) exit; ?>
<div class="wrap">
    <h1><?php _e( 'Integración con Dashboard Externo', 'wp-security-monitor' ); ?></h1>
    <p><?php _e( 'Utiliza estos datos para conectar este sitio con tu Dashboard Maestro.', 'wp-security-monitor' ); ?></p>

    <?php if ( isset( $_GET['key-generated'] ) ) : ?>
        <div class="updated"><p><?php _e( 'Nueva API Key generada.', 'wp-security-monitor' ); ?></p></div>
    <?php endif; ?>

    <div class="card">
        <h2><?php _e( 'Identidad del Sitio', 'wp-security-monitor' ); ?></h2>
        <p><strong>Site UUID:</strong> <code><?php echo WPSM_Site_Identity::get_instance()->get_uuid(); ?></code></p>
        <p><strong>REST Namespace:</strong> <code>wgsm/v1</code></p>
    </div>

    <div class="card">
        <h2><?php _e( 'Credenciales de API', 'wp-security-monitor' ); ?></h2>
        <?php
        $api_key = get_option( 'wpsm_api_key' );
        if ( ! $api_key ) : ?>
            <p><?php _e( 'No se ha generado una API Key aún.', 'wp-security-monitor' ); ?></p>
            <form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>">
                <?php wp_nonce_field( 'wpsm_generate_key' ); ?>
                <input type="hidden" name="action" value="wpsm_generate_api_key">
                <button type="submit" class="button button-primary"><?php _e( 'Generar API Key', 'wp-security-monitor' ); ?></button>
            </form>
        <?php else : ?>
            <p><strong><?php _e( 'Tu API Key:', 'wp-security-monitor' ); ?></strong> <code><?php echo esc_html( $api_key ); ?></code></p>
            <p class="description"><?php _e( 'Copia esta clave. Se debe enviar en el header X-WPSM-KEY.', 'wp-security-monitor' ); ?></p>
            <hr>
            <form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>">
                <?php wp_nonce_field( 'wpsm_generate_key' ); ?>
                <input type="hidden" name="action" value="wpsm_generate_api_key">
                <button type="submit" class="button"><?php _e( 'Regenerar API Key', 'wp-security-monitor' ); ?></button>
            </form>
        <?php endif; ?>
    </div>
</div>
