<?php if ( ! defined( 'ABSPATH' ) ) exit; ?>
<div class="wrap wpsm-admin-wrap">
    <h1><span class="dashicons dashicons-shield"></span> <?php _e( 'WP Security Monitor - Dashboard', 'wp-security-monitor' ); ?></h1>

    <?php if ( isset( $_GET['scan-complete'] ) ) : ?>
        <div class="updated"><p><?php _e( 'Escaneo completado con éxito.', 'wp-security-monitor' ); ?></p></div>
    <?php endif; ?>

    <div class="wpsm-dashboard-grid">
        <div class="wpsm-card wpsm-score-card">
            <?php
            $score = $this->scanner->get_security_score();
            $score_class = $score > 80 ? 'good' : ( $score > 50 ? 'warning' : 'danger' );
            ?>
            <h3><?php _e( 'Puntuación de Seguridad', 'wp-security-monitor' ); ?></h3>
            <div class="wpsm-score-circle <?php echo $score_class; ?>">
                <span><?php echo $score; ?></span>
            </div>
        </div>

        <div class="wpsm-card">
            <h3><?php _e( 'Resumen del Sitio', 'wp-security-monitor' ); ?></h3>
            <ul>
                <li><strong>URL:</strong> <?php echo get_site_url(); ?></li>
                <li><strong><?php _e( 'Versión WP:', 'wp-security-monitor' ); ?></strong> <?php echo get_bloginfo( 'version' ); ?></li>
                <li><strong><?php _e( 'Último escaneo:', 'wp-security-monitor' ); ?></strong> <?php echo get_option( 'wpsm_last_scan_time', __( 'Nunca', 'wp-security-monitor' ) ); ?></li>
            </ul>
            <form action="<?php echo admin_url( 'admin-post.php' ); ?>" method="post">
                <?php wp_nonce_field( 'wpsm_manual_scan' ); ?>
                <input type="hidden" name="action" value="wpsm_manual_scan">
                <button type="submit" class="button button-primary"><?php _e( 'Escanear Ahora', 'wp-security-monitor' ); ?></button>
            </form>
        </div>
    </div>

    <div class="wpsm-card wpsm-alerts-card">
        <h3><?php _e( 'Últimas Alertas', 'wp-security-monitor' ); ?></h3>
        <?php
        $results = get_option( 'wpsm_last_scan_results', array() );
        if ( empty( $results['critical'] ) && empty( $results['warning'] ) ) :
            echo '<p>' . __( 'No se han detectado problemas críticos recientemente.', 'wp-security-monitor' ) . '</p>';
        else :
            if ( ! empty( $results['critical'] ) ) : ?>
                <h4 class="critical-title"><?php _e( 'Críticas', 'wp-security-monitor' ); ?></h4>
                <ul>
                <?php foreach ( $results['critical'] as $alert ) : ?>
                    <li class="alert-item critical"><?php echo esc_html( $alert ); ?></li>
                <?php endforeach; ?>
                </ul>
            <?php endif;
        endif;
        ?>
    </div>
</div>
