<?php
/**
 * Provisional Sassh installation identity (network-wide on Multisite).
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Creates and returns a stable provisional installation_id.
 */
class Sassh_Installation_Identity {

	const OPTION_KEY = 'sassh_installation_id';

	/**
	 * Get or create the provisional installation id.
	 *
	 * @return string
	 */
	public static function get_id() {
		$existing = self::get_option();

		if ( is_string( $existing ) && '' !== $existing ) {
			return $existing;
		}

		$id = self::generate_id();
		self::update_option( $id );

		return $id;
	}

	/**
	 * Generate an opaque UUID-like identifier.
	 *
	 * @return string
	 */
	private static function generate_id() {
		if ( function_exists( 'wp_generate_uuid4' ) ) {
			return (string) wp_generate_uuid4();
		}

		return sprintf(
			'%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
			wp_rand( 0, 0xffff ),
			wp_rand( 0, 0xffff ),
			wp_rand( 0, 0xffff ),
			wp_rand( 0, 0x0fff ) | 0x4000,
			wp_rand( 0, 0x3fff ) | 0x8000,
			wp_rand( 0, 0xffff ),
			wp_rand( 0, 0xffff ),
			wp_rand( 0, 0xffff )
		);
	}

	/**
	 * Read network-aware option.
	 *
	 * @return mixed
	 */
	private static function get_option() {
		if ( is_multisite() ) {
			return get_network_option( null, self::OPTION_KEY, '' );
		}

		return get_option( self::OPTION_KEY, '' );
	}

	/**
	 * Write network-aware option.
	 *
	 * @param string $value Value.
	 * @return void
	 */
	private static function update_option( $value ) {
		if ( is_multisite() ) {
			update_network_option( null, self::OPTION_KEY, $value );
			return;
		}

		update_option( self::OPTION_KEY, $value, false );
	}
}
