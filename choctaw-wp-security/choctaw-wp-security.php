<?php
/**
 * Plugin Name:       Choctaw WP Security
 * Plugin URI:        https://github.com/choctaw/wp-security
 * Description:       XML-RPC protection and configurable login rate limiting for WordPress.
 * Version:           1.0.1
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            Choctaw
 * License:           GPL-3.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-3.0.html
 * Text Domain:       choctaw-wp-security
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

define( 'CHOCTAW_WP_SECURITY_VERSION', '1.0.0' );
define( 'CHOCTAW_WP_SECURITY_FILE', __FILE__ );
define( 'CHOCTAW_WP_SECURITY_PATH', plugin_dir_path( __FILE__ ) );
define( 'CHOCTAW_WP_SECURITY_URL', plugin_dir_url( __FILE__ ) );

require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-utils.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-plugin.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-settings.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-xml-rpc-protection.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-login-rate-limiter.php';

// Block xmlrpc.php as early as possible, matching legacy plugin behavior.
Choctaw_Wp_Security_Xml_Rpc_Protection::block_xmlrpc_request_if_needed();

/**
 * Initialize the plugin after WordPress loads other plugins.
 *
 * @return void
 */
function choctaw_wp_security_bootstrap() {
	Choctaw_Wp_Security_Plugin::instance()->init();
}
add_action( 'plugins_loaded', 'choctaw_wp_security_bootstrap' );

/**
 * Set default options on activation.
 *
 * @return void
 */
function choctaw_wp_security_activate() {
	$existing = get_option( Choctaw_Wp_Security_Utils::OPTION_KEY, null );

	if ( ! is_array( $existing ) ) {
		add_option( Choctaw_Wp_Security_Utils::OPTION_KEY, Choctaw_Wp_Security_Utils::default_options() );
	}
}
register_activation_hook( __FILE__, 'choctaw_wp_security_activate' );
