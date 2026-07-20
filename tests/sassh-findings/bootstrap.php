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
require_once $root . '/coreguard/includes/class-sassh-findings-service.php';
require_once $root . '/coreguard/includes/class-exposed-files-patterns.php';
