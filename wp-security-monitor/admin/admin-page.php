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
            <p class="score-desc"><?php echo sprintf( __( 'Tu sitio tiene un nivel de seguridad del %d%%.', 'wp-security-monitor' ), $score ); ?></p>
        </div>

        <div class="wpsm-card">
            <h3><?php _e( 'Acciones de Control', 'wp-security-monitor' ); ?></h3>
            <p><?php _e( 'Realiza un escaneo manual para actualizar el estado de seguridad.', 'wp-security-monitor' ); ?></p>
            <form action="<?php echo admin_url( 'admin-post.php' ); ?>" method="post">
                <?php wp_nonce_field( 'wpsm_manual_scan' ); ?>
                <input type="hidden" name="action" value="wpsm_manual_scan">
                <button type="submit" class="button button-primary button-large"><?php _e( 'Escanear Ahora', 'wp-security-monitor' ); ?></button>
            </form>
            <p class="description"><?php _e( 'Último escaneo:', 'wp-security-monitor' ); ?> <?php echo get_option( 'wpsm_last_scan_time', __( 'Nunca', 'wp-security-monitor' ) ); ?></p>
        </div>
    </div>

    <div class="wpsm-sections-grid">
        <?php
        $results = get_option( 'wpsm_last_scan_results', array() );
        ?>

        <!-- Recomendaciones para el 100% -->
        <div class="wpsm-card wpsm-recommendations">
            <h3><span class="dashicons dashicons-lightbulb"></span> <?php _e( '¿Cómo llegar al 100%?', 'wp-security-monitor' ); ?></h3>
            <?php if ( ! empty( $results['recommendations'] ) ) : ?>
                <ul class="wpsm-rec-list">
                <?php foreach ( $results['recommendations'] as $rec ) : ?>
                    <li><span class="dashicons dashicons-arrow-right-alt"></span> <?php echo esc_html( $rec ); ?></li>
                <?php endforeach; ?>
                </ul>
            <?php else : ?>
                <p class="wpsm-success-msg"><?php _e( '¡Felicidades! Tu sitio cumple con todas nuestras recomendaciones actuales.', 'wp-security-monitor' ); ?></p>
            <?php endif; ?>
        </div>

        <!-- Puntos Correctos -->
        <div class="wpsm-card wpsm-passed">
            <h3><span class="dashicons dashicons-yes-alt"></span> <?php _e( 'Controles Superados', 'wp-security-monitor' ); ?></h3>
            <?php if ( ! empty( $results['passed'] ) ) : ?>
                <ul class="wpsm-passed-list">
                <?php foreach ( $results['passed'] as $pass ) : ?>
                    <li><span class="dashicons dashicons-yes"></span> <?php echo esc_html( $pass ); ?></li>
                <?php endforeach; ?>
                </ul>
            <?php else : ?>
                <p><?php _e( 'No hay información de controles superados. Realiza un escaneo.', 'wp-security-monitor' ); ?></p>
            <?php endif; ?>
        </div>
    </div>

    <div class="wpsm-card wpsm-alerts-details">
        <h3><span class="dashicons dashicons-warning"></span> <?php _e( 'Detalles de Problemas Detectados', 'wp-security-monitor' ); ?></h3>
        <?php if ( empty( $results['critical'] ) && empty( $results['warning'] ) && empty( $results['info'] ) ) : ?>
            <p><?php _e( 'No se han detectado problemas de seguridad.', 'wp-security-monitor' ); ?></p>
        <?php else : ?>
            <div class="wpsm-alerts-list">
                <?php if ( ! empty( $results['critical'] ) ) : ?>
                    <div class="alert-group critical">
                        <h4><?php _e( 'Problemas Críticos', 'wp-security-monitor' ); ?></h4>
                        <?php foreach ( $results['critical'] as $alert ) : ?>
                            <div class="alert-item"><?php echo esc_html( $alert ); ?></div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>

                <?php if ( ! empty( $results['warning'] ) ) : ?>
                    <div class="alert-group warning">
                        <h4><?php _e( 'Advertencias', 'wp-security-monitor' ); ?></h4>
                        <?php foreach ( $results['warning'] as $alert ) : ?>
                            <div class="alert-item"><?php echo esc_html( $alert ); ?></div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>
</div>

<style>
    .wpsm-sections-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px; }
    .wpsm-card h3 { border-bottom: 1px solid #eee; padding-bottom: 10px; margin-top: 0; }
    .wpsm-rec-list, .wpsm-passed-list { list-style: none; padding: 0; }
    .wpsm-rec-list li { background: #fff8e5; padding: 10px; border-left: 4px solid #ffb900; margin-bottom: 8px; }
    .wpsm-passed-list li { color: #2e7d32; padding: 5px 0; }
    .wpsm-passed-list .dashicons-yes { color: #46b450; margin-right: 5px; }
    .wpsm-success-msg { color: #46b450; font-weight: bold; font-size: 1.1em; }
    .score-desc { text-align: center; font-weight: bold; margin-top: 10px; }
    .alert-group h4 { margin-bottom: 10px; }
    .alert-group.critical h4 { color: #dc3232; }
    .alert-group.warning h4 { color: #ff8f00; }
    .alert-item { padding: 8px; border-bottom: 1px solid #f0f0f0; }
</style>
