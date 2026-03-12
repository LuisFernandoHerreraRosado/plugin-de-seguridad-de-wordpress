<?php
/**
 * Identidad única del sitio
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class WPSM_Site_Identity {
    private static $instance = null;
    private $option_name = 'wpsm_site_uuid';

    public static function get_instance() {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function get_uuid() {
        $uuid = get_option( $this->option_name );
        if ( ! $uuid ) {
            $uuid = $this->generate_uuid();
            update_option( $this->option_name, $uuid );
        }
        return $uuid;
    }

    private function generate_uuid() {
        return sprintf( '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ),
            mt_rand( 0, 0xffff ),
            mt_rand( 0, 0x0fff ) | 0x4000,
            mt_rand( 0, 0x3fff ) | 0x8000,
            mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )
        );
    }

    public function get_site_info() {
        return array(
            'uuid'      => $this->get_uuid(),
            'url'       => get_site_url(),
            'name'      => get_bloginfo( 'name' ),
            'wp_version'=> get_bloginfo( 'version' ),
            'php_version'=> phpversion(),
            'plugin_v'  => WPSM_VERSION
        );
    }
}
