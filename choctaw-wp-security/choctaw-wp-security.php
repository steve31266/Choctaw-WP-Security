<?php
/**
 * Plugin Name:       Choctaw WP Security
 * Plugin URI:        https://github.com/steve31266/Choctaw-WP-Security
 * Description:       XML-RPC protection, login rate limiting, uploads PHP lockdown, username discovery blocking, core checksum scanning, known vulnerability scanning, wp_options scan, wp_posts scan, and other tools.
 * Version:           1.9.1
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            Choctaw Websites
 * License:           GPL-3.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-3.0.html
 * Text Domain:       choctaw-wp-security
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

define( 'CHOCTAW_WP_SECURITY_VERSION', '1.9.1' );
define( 'CHOCTAW_WP_SECURITY_FILE', __FILE__ );
define( 'CHOCTAW_WP_SECURITY_PATH', plugin_dir_path( __FILE__ ) );
define( 'CHOCTAW_WP_SECURITY_URL', plugin_dir_url( __FILE__ ) );

require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-utils.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-plugin.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-settings.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-xml-rpc-protection.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-login-rate-limiter.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-uploads-php-lockdown.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-username-discovery-protection.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-core-checksum-scanner.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-component-vulnerability-scanner.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-options-scan-patterns.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-options-table-discovery.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-options-table-scanner.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-posts-scan-patterns.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-posts-table-discovery.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-posts-table-scanner.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-users-table-discovery.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-users-table-reader.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-user-activity-reader.php';

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
 * Add a Settings link to the plugin row actions.
 *
 * @param array<string, string> $links Existing plugin action links.
 * @return array<string, string>
 */
function choctaw_wp_security_plugin_action_links( $links ) {
	$settings_link = sprintf(
		'<a href="%s">%s</a>',
		esc_url( admin_url( 'options-general.php?page=choctaw-wp-security' ) ),
		esc_html__( 'Settings', 'choctaw-wp-security' )
	);

	if ( isset( $links['deactivate'] ) ) {
		$updated_links = array();

		foreach ( $links as $key => $link ) {
			$updated_links[ $key ] = $link;

			if ( 'deactivate' === $key ) {
				$updated_links['settings'] = $settings_link;
			}
		}

		return $updated_links;
	}

	$links['settings'] = $settings_link;

	return $links;
}
add_filter( 'plugin_action_links_' . plugin_basename( CHOCTAW_WP_SECURITY_FILE ), 'choctaw_wp_security_plugin_action_links' );

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

	$lockdown = new Choctaw_Wp_Security_Uploads_Php_Lockdown();
	$lockdown->apply_policy();
}
register_activation_hook( __FILE__, 'choctaw_wp_security_activate' );
