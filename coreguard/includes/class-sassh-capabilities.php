<?php
/**
 * Centralized Sassh authorization.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Capability checks for Sassh network-wide security actions.
 */
class Sassh_Capabilities {

	/**
	 * Whether the current user may manage Sassh (reports, scans, findings).
	 *
	 * Single-site: manage_options.
	 * Multisite: Super Admin via manage_network_options (not ordinary subsite admins).
	 *
	 * @return bool
	 */
	public static function current_user_can_manage() {
		if ( is_multisite() ) {
			return current_user_can( 'manage_network_options' );
		}

		return current_user_can( 'manage_options' );
	}

	/**
	 * Send a JSON 403 if the current user cannot manage Sassh.
	 *
	 * @param string $message Error message.
	 * @return void
	 */
	public static function require_manage_or_json_error( $message = '' ) {
		if ( self::current_user_can_manage() ) {
			return;
		}

		if ( '' === $message ) {
			$message = __( 'You do not have permission to manage Sassh security findings.', 'choctaw-wp-security' );
		}

		wp_send_json_error(
			array(
				'message' => $message,
			),
			403
		);
	}
}
