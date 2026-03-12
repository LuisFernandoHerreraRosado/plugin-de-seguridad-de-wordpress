<?php if ( ! defined( 'ABSPATH' ) ) exit; ?>
<div class="wrap">
    <h1><?php _e( 'Logs de Eventos de Seguridad', 'wp-security-monitor' ); ?></h1>

    <div class="tablenav top">
        <form action="<?php echo admin_url( 'admin-post.php' ); ?>" method="post" style="display:inline;">
            <?php wp_nonce_field( 'wpsm_purge_logs' ); ?>
            <input type="hidden" name="action" value="wpsm_purge_logs">
            <button type="submit" class="button action"><?php _e( 'Limpiar todos los logs', 'wp-security-monitor' ); ?></button>
        </form>
    </div>

    <table class="wp-list-table widefat fixed striped">
        <thead>
            <tr>
                <th><?php _e( 'Fecha/Hora', 'wp-security-monitor' ); ?></th>
                <th><?php _e( 'Evento', 'wp-security-monitor' ); ?></th>
                <th><?php _e( 'Severidad', 'wp-security-monitor' ); ?></th>
                <th><?php _e( 'Usuario', 'wp-security-monitor' ); ?></th>
                <th><?php _e( 'IP', 'wp-security-monitor' ); ?></th>
                <th><?php _e( 'Mensaje', 'wp-security-monitor' ); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php
            $logs = $this->logger->get_logs( 50, 0 );
            if ( $logs ) :
                foreach ( $logs as $log ) : ?>
                    <tr>
                        <td><?php echo esc_html( $log->time ); ?></td>
                        <td><code><?php echo esc_html( $log->event_type ); ?></code></td>
                        <td><span class="wpsm-badge <?php echo esc_attr( $log->severity ); ?>"><?php echo esc_html( $log->severity ); ?></span></td>
                        <td><?php echo $log->user_id ? get_userdata( $log->user_id )->user_login : __( 'Sistema', 'wp-security-monitor' ); ?></td>
                        <td><?php echo esc_html( $log->ip ); ?></td>
                        <td><?php echo esc_html( $log->message ); ?></td>
                    </tr>
                <?php endforeach;
            else : ?>
                <tr><td colspan="6"><?php _e( 'No hay logs registrados.', 'wp-security-monitor' ); ?></td></tr>
            <?php endif; ?>
        </tbody>
    </table>
</div>
