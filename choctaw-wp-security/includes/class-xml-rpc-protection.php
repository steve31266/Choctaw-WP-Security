<?php
/**
 * XML-RPC protection module.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Blocks XML-RPC when the feature is enabled.
 *
 * Preserves the behavior of the legacy Disable XML-RPC plugin.
 */
class Choctaw_Wp_Security_Xml_Rpc_Protection {

	const BLOCKED_MESSAGE = 'XML-RPC is disabled.';

	/**
	 * Block direct XML-RPC requests as early as possible during plugin load.
	 *
	 * Called from the main plugin file before WordPress finishes bootstrapping
	 * other modules so xmlrpc.php exits before unnecessary code runs.
	 *
	 * @return void
	 */
	public static function block_xmlrpc_request_if_needed() {
		if ( ! Choctaw_Wp_Security_Utils::is_enabled( 'xmlrpc_blocking_enabled' ) ) {
			return;
		}

		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			status_header( 403 );
			header( 'Content-Type: text/plain; charset=utf-8' );
			exit( self::BLOCKED_MESSAGE );
		}
	}

	/**
	 * Register module hooks.
	 *
	 * @return void
	 */
	public function register_hooks() {
		if ( ! Choctaw_Wp_Security_Utils::is_enabled( 'xmlrpc_blocking_enabled' ) ) {
			return;
		}

		add_filter( 'xmlrpc_enabled', array( $this, 'disable_xmlrpc' ) );
		add_filter( 'wp_headers', array( $this, 'remove_pingback_header' ) );
		add_filter( 'xmlrpc_methods', array( $this, 'disable_xmlrpc_methods' ) );
	}

	/**
	 * Disable XML-RPC via core filter.
	 *
	 * @param bool $enabled Whether XML-RPC is enabled.
	 * @return bool
	 */
	public function disable_xmlrpc( $enabled ) {
		unset( $enabled );

		return false;
	}

	/**
	 * Remove the X-Pingback response header.
	 *
	 * @param array<string, string> $headers Response headers.
	 * @return array<string, string>
	 */
	public function remove_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );

		return $headers;
	}

	/**
	 * Remove all XML-RPC methods.
	 *
	 * @param array<string, mixed> $methods Registered XML-RPC methods.
	 * @return array<string, mixed>
	 */
	public function disable_xmlrpc_methods( $methods ) {
		unset( $methods );

		return array();
	}
}
