<?php
/**
 * Plugin Name:       Sassh Security
 * Plugin URI:        https://github.com/steve31266/Choctaw-WP-Security
 * Description:       Cleans core files from malware infections, makes it extremely difficult for hackers and malware to get in, scans your website for infected files and database records.
 * Version:           1.9.3.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            Sashtastic, LLC
 * License:           GPL-3.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-3.0.html
 * Text Domain:       choctaw-wp-security
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

define( 'CHOCTAW_WP_SECURITY_VERSION', '1.9.3.0' );
define( 'CHOCTAW_WP_SECURITY_FILE', __FILE__ );
define( 'CHOCTAW_WP_SECURITY_PATH', plugin_dir_path( __FILE__ ) );
define( 'CHOCTAW_WP_SECURITY_URL', plugin_dir_url( __FILE__ ) );

require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-utils.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-finding-status-store.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-sassh-capabilities.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-sassh-installation-identity.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-sassh-object-path-normalizer.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-sassh-object-type-registry.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-sassh-findings-schema.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-sassh-findings-service.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-plugin.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-directory-browsing-scanner.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-admin-help-content.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-admin-help.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-settings.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-xml-rpc-protection.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-login-rate-limiter.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-uploads-php-lockdown.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-uploads-folder-scanner.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-mu-plugins-scanner.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-exposed-files-patterns.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-exposed-files-scanner.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-username-discovery-protection.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-core-checksum-scanner.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-component-vulnerability-scanner.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-options-scan-patterns.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-options-table-discovery.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-options-table-scanner.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-scheduled-tasks-patterns.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-scheduled-tasks-scanner.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-scheduled-tasks-presenter.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-posts-scan-patterns.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-posts-table-discovery.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-posts-table-scanner.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-users-table-discovery.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-users-table-reader.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-user-activity-reader.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-user-usermeta-reader.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-user-file-activity-scanner.php';
require_once CHOCTAW_WP_SECURITY_PATH . 'includes/class-table-prefix-discovery.php';

// Block xmlrpc.php as early as possible, matching legacy plugin behavior.
Choctaw_Wp_Security_Xml_Rpc_Protection::block_xmlrpc_request_if_needed();

/**
 * Initialize the plugin after WordPress loads other plugins.
 *
 * @return void
 */
function choctaw_wp_security_bootstrap() {
	Sassh_Findings_Schema::maybe_upgrade();
	Choctaw_Wp_Security_Plugin::instance()->init();
}
add_action( 'plugins_loaded', 'choctaw_wp_security_bootstrap' );

/**
 * Add a Settings link to the plugin row actions.
 *
 * On Multisite, Sassh Settings live under Network Admin only.
 *
 * @param array<string, string> $links Existing plugin action links.
 * @return array<string, string>
 */
function choctaw_wp_security_plugin_action_links( $links ) {
	if ( ! Sassh_Capabilities::current_user_can_manage() ) {
		return $links;
	}

	$settings_url = is_multisite()
		? network_admin_url( 'admin.php?page=sassh-settings' )
		: admin_url( 'admin.php?page=sassh-settings' );

	$settings_link = sprintf(
		'<a href="%s">%s</a>',
		esc_url( $settings_url ),
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
add_filter( 'network_admin_plugin_action_links_' . plugin_basename( CHOCTAW_WP_SECURITY_FILE ), 'choctaw_wp_security_plugin_action_links' );

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

	Sassh_Findings_Schema::maybe_upgrade();

	$lockdown = new Choctaw_Wp_Security_Uploads_Php_Lockdown();
	$lockdown->apply_policy();
}
register_activation_hook( __FILE__, 'choctaw_wp_security_activate' );
