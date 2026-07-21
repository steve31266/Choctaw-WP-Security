<?php
/**
 * Minimal WordPress stubs for Sassh Findings unit tests (no full WP install).
 *
 * @package Choctaw_Wp_Security
 */

error_reporting( E_ALL );

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', rtrim( sys_get_temp_dir(), '/\\' ) . '/sassh-findings-test-root/' );
}

if ( ! is_dir( ABSPATH ) ) {
	mkdir( ABSPATH, 0777, true );
}

if ( ! function_exists( 'wp_normalize_path' ) ) {
	/**
	 * @param string $path Path.
	 * @return string
	 */
	function wp_normalize_path( $path ) {
		$path = str_replace( '\\', '/', (string) $path );
		$path = preg_replace( '#/+#', '/', $path );
		return $path;
	}
}

if ( ! function_exists( '__' ) ) {
	/**
	 * @param string $text Text.
	 * @return string
	 */
	function __( $text ) {
		return $text;
	}
}

if ( ! function_exists( 'is_multisite' ) ) {
	/**
	 * @return bool
	 */
	function is_multisite() {
		return ! empty( $GLOBALS['sassh_test_is_multisite'] );
	}
}

if ( ! function_exists( 'current_user_can' ) ) {
	/**
	 * @param string $cap Capability.
	 * @return bool
	 */
	function current_user_can( $cap ) {
		$caps = isset( $GLOBALS['sassh_test_caps'] ) && is_array( $GLOBALS['sassh_test_caps'] )
			? $GLOBALS['sassh_test_caps']
			: array();
		return ! empty( $caps[ $cap ] );
	}
}

$root = dirname( __DIR__, 2 );

require_once $root . '/coreguard/includes/class-sassh-capabilities.php';
require_once $root . '/coreguard/includes/class-sassh-object-path-normalizer.php';
require_once $root . '/coreguard/includes/class-sassh-object-type-registry.php';
require_once $root . '/coreguard/includes/class-sassh-option-key-normalizer.php';
require_once $root . '/coreguard/includes/class-sassh-findings-service.php';
require_once $root . '/coreguard/includes/class-sassh-cron-event-key-normalizer.php';
require_once $root . '/coreguard/includes/class-exposed-files-patterns.php';
require_once $root . '/coreguard/includes/class-options-scan-patterns.php';

if ( ! function_exists( 'wp_json_encode' ) ) {
	/**
	 * @param mixed $data Data.
	 * @return string|false
	 */
	function wp_json_encode( $data ) {
		return json_encode( $data );
	}
}

if ( ! class_exists( 'WP_Error' ) ) {
	/**
	 * Minimal WP_Error stub for unit tests.
	 */
	class WP_Error {
		/**
		 * @var string
		 */
		public $code;

		/**
		 * @var string
		 */
		public $message;

		/**
		 * @param string $code    Error code.
		 * @param string $message Message.
		 */
		public function __construct( $code = '', $message = '' ) {
			$this->code    = (string) $code;
			$this->message = (string) $message;
		}

		/**
		 * @return string
		 */
		public function get_error_message() {
			return $this->message;
		}
	}
}

if ( ! function_exists( 'is_wp_error' ) ) {
	/**
	 * @param mixed $thing Value.
	 * @return bool
	 */
	function is_wp_error( $thing ) {
		return $thing instanceof WP_Error;
	}
}

if ( ! function_exists( 'get_current_blog_id' ) ) {
	/**
	 * @return int
	 */
	function get_current_blog_id() {
		return isset( $GLOBALS['sassh_test_current_blog_id'] ) ? (int) $GLOBALS['sassh_test_current_blog_id'] : 1;
	}
}

if ( ! function_exists( 'get_main_site_id' ) ) {
	/**
	 * @return int
	 */
	function get_main_site_id() {
		return isset( $GLOBALS['sassh_test_main_site_id'] ) ? (int) $GLOBALS['sassh_test_main_site_id'] : 1;
	}
}

if ( ! function_exists( 'get_site' ) ) {
	/**
	 * @param int $blog_id Blog id.
	 * @return object|null
	 */
	function get_site( $blog_id ) {
		$sites = isset( $GLOBALS['sassh_test_sites'] ) && is_array( $GLOBALS['sassh_test_sites'] )
			? $GLOBALS['sassh_test_sites']
			: array();
		$blog_id = (int) $blog_id;

		return isset( $sites[ $blog_id ] ) ? $sites[ $blog_id ] : null;
	}
}
