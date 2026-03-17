<?php
/**
 * Lógica de Remediación y Corrección Automática
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Remediation {
    private $logger;
    private $scanner;

    public function __construct( $logger, $scanner ) {
        $this->logger = $logger;
        $this->scanner = $scanner;
    }

    /**
     * Ejecuta las correcciones solicitadas
     */
    public function fix_issues( $issue_ids ) {
        if ( empty( $issue_ids ) || ! is_array( $issue_ids ) ) return false;

        $results = get_option( 'wpsm_last_scan_results', array() );
        $vulnerabilities = get_option( 'wpsm_vulnerability_findings', array() );

        $executed_fixes = 0;

        foreach ( $issue_ids as $id ) {
            // Buscar en resultados de escaneo
            $found_issue = $this->find_issue_by_id( $id, $results );
            if ( $found_issue ) {
                if ( $this->apply_fix( $id, $found_issue ) ) {
                    $executed_fixes++;
                }
                continue;
            }

            // Buscar en vulnerabilidades
            $found_vuln = $this->find_vulnerability_by_id( $id, $vulnerabilities );
            if ( $found_vuln ) {
                if ( $this->apply_vulnerability_fix( $id, $found_vuln ) ) {
                    $executed_fixes++;
                }
            }
        }

        if ( $executed_fixes > 0 ) {
            // Re-escanear para actualizar estado
            $this->scanner->run_scan();
            // También re-escanear vulnerabilidades si se corrigió alguna
            $vuln_mon = new WPSM_Vulnerability_Monitor( $this->logger, new WPSM_Settings() );
            $vuln_mon->run_vulnerability_check();
        }

        return $executed_fixes;
    }

    private function find_issue_by_id( $id, $results ) {
        $groups = array( 'critical', 'warning', 'info' );
        foreach ( $groups as $group ) {
            if ( empty( $results[$group] ) ) continue;
            foreach ( $results[$group] as $issue ) {
                if ( is_array( $issue ) && $issue['id'] === $id ) {
                    return $issue;
                }
            }
        }
        return false;
    }

    private function find_vulnerability_by_id( $id, $vulnerabilities ) {
        foreach ( $vulnerabilities as $vuln ) {
            if ( $vuln['id'] === $id ) {
                return $vuln;
            }
        }
        return false;
    }

    private function apply_fix( $id, $issue ) {
        switch ( $id ) {
            case 'core_update':
                return $this->update_core();
            case 'plugin_updates':
                return $this->update_plugins();
            case 'debug_mode_enabled':
                return $this->disable_debug();
            default:
                if ( strpos( $id, 'suspicious_file_' ) === 0 ) {
                    return $this->delete_file( $issue['data']['path'] );
                }
                break;
        }
        return false;
    }

    private function apply_vulnerability_fix( $id, $vuln ) {
        $auditor = new WPSM_Extension_Auditor( $this->logger );
        $result = $auditor->reinstall_from_repo( $vuln['slug'] );
        return ! is_wp_error( $result );
    }

    private function update_core() {
        include_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        $skin = new WP_Ajax_Upgrader_Skin();
        $upgrader = new Core_Upgrader( $skin );
        $updates = get_site_transient( 'update_core' );
        if ( ! $updates || empty( $updates->updates ) ) return false;

        $result = $upgrader->upgrade( $updates->updates[0] );
        if ( ! is_wp_error( $result ) ) {
            $this->logger->log( 'system_action', __( 'WordPress core actualizado automáticamente.', 'wp-security-monitor' ), 'medium' );
            return true;
        }
        return false;
    }

    private function update_plugins() {
        include_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        $plugin_updates = get_site_transient( 'update_plugins' );
        if ( ! $plugin_updates || empty( $plugin_updates->response ) ) return false;

        $plugins = array_keys( $plugin_updates->response );
        $skin = new WP_Ajax_Upgrader_Skin();
        $upgrader = new Plugin_Upgrader( $skin );
        $result = $upgrader->bulk_upgrade( $plugins );

        if ( ! empty( $result ) ) {
            $this->logger->log( 'system_action', __( 'Plugins actualizados automáticamente.', 'wp-security-monitor' ), 'medium' );
            return true;
        }
        return false;
    }

    private function disable_debug() {
        $config_editor = new WPSM_Config_Editor();
        if ( $config_editor->update_constant( 'WP_DEBUG', false ) ) {
            $this->logger->log( 'system_action', __( 'WP_DEBUG desactivado automáticamente.', 'wp-security-monitor' ), 'low' );
            return true;
        }
        return false;
    }

    private function delete_file( $path ) {
        if ( file_exists( $path ) && is_file( $path ) ) {
            if ( @unlink( $path ) ) {
                $this->logger->log( 'system_action', sprintf( __( 'Archivo sospechoso eliminado: %s', 'wp-security-monitor' ), basename( $path ) ), 'critical' );
                return true;
            }
        }
        return false;
    }
}
