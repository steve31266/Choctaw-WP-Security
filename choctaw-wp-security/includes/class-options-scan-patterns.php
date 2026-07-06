<?php
/**
 * Pattern lists and thresholds for the wp_options database scan.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Constants used by the wp_options table scanner.
 */
class Choctaw_Wp_Security_Options_Scan_Patterns {

	const BASELINE_OPTION_KEY       = 'choctaw_wp_security_options_baseline';
	const SCAN_TIME_BUDGET          = 30;
	const AUTOLOAD_SIZE_THRESHOLD   = 102400;
	const AUTOLOAD_TOP_LIMIT        = 20;
	const FINDINGS_DISPLAY_LIMIT    = 50;
	const EXCERPT_LENGTH            = 120;
	const LARGE_AUTOLOAD_PREVIEW_LENGTH = 200;

	/**
	 * Report section keys in display order.
	 *
	 * @var array<int, string>
	 */
	public static $section_keys = array(
		'site_url_security',
		'active_plugins',
		'cron_events',
		'large_autoload',
		'php_execution_patterns',
		'malware_option_names',
		'scripts_non_widget',
		'baseline_diff',
	);

	/**
	 * Critical option names checked for external URL domains.
	 *
	 * @var array<int, string>
	 */
	public static $critical_option_keys = array(
		'siteurl',
		'home',
		'cron',
		'active_plugins',
		'template',
		'stylesheet',
		'rewrite_rules',
	);

	/**
	 * PHP tag patterns.
	 *
	 * @var array<int, string>
	 */
	public static $php_tag_patterns = array(
		'<?php',
		'<?=',
	);

	/**
	 * PHP execution and obfuscation patterns.
	 *
	 * @var array<int, string>
	 */
	public static $execution_patterns = array(
		'eval(',
		'base64_decode(',
		'gzinflate(',
		'gzuncompress(',
		'str_rot13(',
		'shell_exec(',
		'passthru(',
		'system(',
		'assert(',
		'create_function(',
	);

	/**
	 * HTML injection patterns for non-widget options.
	 *
	 * @var array<int, string>
	 */
	public static $script_patterns = array(
		'<script',
		'<iframe',
	);

	/**
	 * Option names commonly created by malware families.
	 *
	 * @var array<int, string>
	 */
	public static $malware_option_names = array(
		'wp_temp',
		'rss_cache',
		'class_generic_support',
		'widget_custom_js',
		'wp_update_data',
		'cron_update',
		'wp_check_cache',
		'wp_custom_filters',
	);

	/**
	 * Option name prefixes excluded from script/iframe scans.
	 *
	 * @var array<int, string>
	 */
	public static $widget_theme_prefixes = array(
		'widget_',
		'theme_mods_',
	);

	/**
	 * Section metadata for admin rendering.
	 *
	 * @return array<string, array<string, string>>
	 */
	public static function get_section_meta() {
		return array(
			'site_url_security'        => array(
				'title'    => __( 'Site URL & Security Settings', 'choctaw-wp-security' ),
				'guidance' => __( 'Unexpected site URLs or weakened security settings can indicate a compromise. Verify each finding against your expected configuration.', 'choctaw-wp-security' ),
			),
			'active_plugins'           => array(
				'title'    => __( 'Active Plugin Consistency', 'choctaw-wp-security' ),
				'guidance' => __( 'Active plugins should exist on disk under wp-content/plugins. Missing files or unusual paths may indicate tampering with the active_plugins option.', 'choctaw-wp-security' ),
			),
			'cron_events'              => array(
				'title'    => __( 'Cron Events', 'choctaw-wp-security' ),
				'guidance' => __( 'WordPress stores scheduled tasks in the cron option. Unknown hooks or suspicious serialized content deserve investigation.', 'choctaw-wp-security' ),
			),
			'large_autoload'           => array(
				'title'    => __( 'Large Autoload Options', 'choctaw-wp-security' ),
				'guidance' => __( 'Autoloaded options load on every request. Unusually large autoload rows are sometimes used to hide malicious payloads.', 'choctaw-wp-security' ),
			),
			'php_execution_patterns'   => array(
				'title'    => __( 'PHP & Execution Patterns', 'choctaw-wp-security' ),
				'guidance' => __( 'PHP tags and execution functions rarely belong in wp_options values. Review each match in context before taking action.', 'choctaw-wp-security' ),
			),
			'malware_option_names'     => array(
				'title'    => __( 'Known-Malware Option Names', 'choctaw-wp-security' ),
				'guidance' => __( 'These option names have been observed in known malware families. Confirm whether each row is legitimate on your site.', 'choctaw-wp-security' ),
			),
			'scripts_non_widget'       => array(
				'title'    => __( 'Scripts in Non-Widget Options', 'choctaw-wp-security' ),
				'guidance' => __( 'Script or iframe tags outside widget and theme_mods options are uncommon and may indicate injected content.', 'choctaw-wp-security' ),
			),
			'baseline_diff'            => array(
				'title'    => __( 'Changed Options Since Last Scan', 'choctaw-wp-security' ),
				'guidance' => __( 'Compares the current wp_options table against the snapshot from your previous scan. New or changed rows may be routine plugin updates or signs of tampering.', 'choctaw-wp-security' ),
			),
		);
	}
}
