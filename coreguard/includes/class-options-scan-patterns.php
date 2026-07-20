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
	const FINDINGS_DISPLAY_LIMIT    = 20;
	const EXCERPT_LENGTH            = 60;
	const LARGE_AUTOLOAD_PREVIEW_LENGTH = 60;
	const FULL_VALUE_MAX_LENGTH     = 16384;

	/**
	 * Report section keys in display order.
	 *
	 * @var array<int, string>
	 */
	public static $section_keys = array(
		'site_url_security',
		'active_plugins',
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
		'phar://',
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

	/**
	 * Short category labels for the unified options report.
	 *
	 * @return array<string, string>
	 */
	public static function get_category_labels() {
		return array(
			'site_url_security'      => __( 'Site URL', 'choctaw-wp-security' ),
			'active_plugins'         => __( 'Plugin', 'choctaw-wp-security' ),
			'large_autoload'         => __( 'Autoload', 'choctaw-wp-security' ),
			'php_execution_patterns' => __( 'Execution', 'choctaw-wp-security' ),
			'malware_option_names'   => __( 'Malware Names', 'choctaw-wp-security' ),
			'scripts_non_widget'     => __( 'Scripts', 'choctaw-wp-security' ),
			'baseline_diff'          => __( 'Changed', 'choctaw-wp-security' ),
		);
	}

	/**
	 * Map legacy severity + section to the shared Risk vocabulary.
	 *
	 * @param string $severity    Legacy severity: critical, warning, info.
	 * @param string $section_key Section key.
	 * @return string Risk key: critical, suspicious, safe, info.
	 */
	public static function map_severity_to_risk( $severity, $section_key ) {
		$severity    = (string) $severity;
		$section_key = (string) $section_key;

		if ( 'critical' === $severity ) {
			return 'critical';
		}

		if ( 'warning' === $severity ) {
			return 'suspicious';
		}

		// Small autoload inventory is recognized/benign — Safe (hidden unless checkbox on).
		if ( 'large_autoload' === $section_key && 'info' === $severity ) {
			return 'safe';
		}

		return 'info';
	}

	/**
	 * Preliminary Why / How guidance for the options detail panel.
	 *
	 * Keys are category (section) keys. Each entry may define risk-specific
	 * copy under why/how, plus a default fallback.
	 *
	 * @return array<string, array{why: array<string, string>, how: array<string, string>}>
	 */
	public static function get_detail_guidance() {
		return array(
			'site_url_security'      => array(
				'why' => array(
					'critical'   => __( 'A core site URL or security-related option does not match the expected configuration. Attackers often change siteurl/home or weaken security settings to redirect traffic or keep a foothold.', 'choctaw-wp-security' ),
					'suspicious' => __( 'A site URL or security setting looks unusual compared with a typical WordPress install. It may be intentional, but it is worth confirming against your known-good configuration.', 'choctaw-wp-security' ),
					'default'    => __( 'This option affects how WordPress identifies the site or enforces security-related behavior. Unexpected values here are a common compromise indicator.', 'choctaw-wp-security' ),
				),
				'how' => array(
					'critical'   => __( 'Compare the stored value with your real site URL and expected security settings. If it was changed without authorization, restore the correct value from a clean backup or wp-config/known settings, then investigate how it was modified (admin users, file changes, other infected options).', 'choctaw-wp-security' ),
					'suspicious' => __( 'Verify the value against your production domain and intended security configuration. Document intentional customizations; otherwise restore the expected value and review recent admin activity.', 'choctaw-wp-security' ),
					'default'    => __( 'Confirm the value is intentional. If not, restore the expected setting and continue reviewing other Critical or Suspicious findings on this report.', 'choctaw-wp-security' ),
				),
			),
			'active_plugins'         => array(
				'why' => array(
					'critical'   => __( 'The active_plugins list references a plugin path that is missing, unexpected, or inconsistent with files on disk. Malware sometimes injects fake plugin entries or removes legitimate ones to hide activity.', 'choctaw-wp-security' ),
					'suspicious' => __( 'An active plugin entry looks inconsistent with the plugins directory. That can happen after incomplete installs or migrations, but it can also indicate tampering with active_plugins.', 'choctaw-wp-security' ),
					'default'    => __( 'WordPress stores the list of active plugins in wp_options. Findings here mean the stored list does not line up cleanly with plugins present on disk.', 'choctaw-wp-security' ),
				),
				'how' => array(
					'critical'   => __( 'Open Plugins in wp-admin and compare with the files under wp-content/plugins. Remove unknown entries from active_plugins only after confirming they are not needed, restore missing legitimate plugins from a clean copy, and scan for other database or file indicators.', 'choctaw-wp-security' ),
					'suspicious' => __( 'Confirm whether the plugin should be active. Reinstall or deactivate as appropriate, then rescan. If the entry is unknown, treat it as suspicious until proven otherwise.', 'choctaw-wp-security' ),
					'default'    => __( 'Reconcile the active_plugins option with the plugins folder. Prefer reinstalling trusted plugins over manually editing serialized data unless you are comfortable doing so.', 'choctaw-wp-security' ),
				),
			),
			'large_autoload'         => array(
				'why' => array(
					'critical'   => __( 'This autoloaded option is unusually large. Oversized autoload rows load on every request and are sometimes used to hide malicious payloads in plain sight.', 'choctaw-wp-security' ),
					'suspicious' => __( 'This autoloaded option exceeds the size threshold used by this scan. Large autoload data can hurt performance and occasionally conceals injected content.', 'choctaw-wp-security' ),
					'safe'       => __( 'This row is part of the autoload inventory below the alert threshold. It is shown so you can review what WordPress loads on every request, not because it matched a malware pattern.', 'choctaw-wp-security' ),
					'default'    => __( 'Autoloaded options are fetched on every page load. Size and content here matter for both performance and security review.', 'choctaw-wp-security' ),
				),
				'how' => array(
					'critical'   => __( 'Inspect the Option Value for encoded or unexpected content. Identify which plugin or theme owns the option name. If the value is not legitimate, remove or truncate it using a trusted cleanup method, disable autoload if appropriate, and investigate the source.', 'choctaw-wp-security' ),
					'suspicious' => __( 'Review the value and owning plugin/theme. If the size is expected (cache, settings export), you can leave it; otherwise reduce autoload usage or clean the value and rescan.', 'choctaw-wp-security' ),
					'safe'       => __( 'No immediate action is required unless the option name or value looks unfamiliar. Use this inventory when hunting for unexpected autoload growth over time.', 'choctaw-wp-security' ),
					'default'    => __( 'Confirm the option is expected for an active plugin or theme. Large or unfamiliar autoload rows deserve a closer look at the Option Value.', 'choctaw-wp-security' ),
				),
			),
			'php_execution_patterns' => array(
				'why' => array(
					'critical'   => __( 'The option value contains PHP tags or execution-related functions (such as eval or base64_decode). Legitimate options almost never store executable PHP like this.', 'choctaw-wp-security' ),
					'suspicious' => __( 'Patterns associated with PHP execution or obfuscation were found in this option value. They can appear in rare legitimate cases, but they are a strong malware signal in wp_options.', 'choctaw-wp-security' ),
					'default'    => __( 'This finding matched PHP or code-execution patterns inside an options row. That is uncommon for normal WordPress configuration data.', 'choctaw-wp-security' ),
				),
				'how' => array(
					'critical'   => __( 'Treat this as high priority. Copy the Option Value for evidence, then remove or restore the option from a clean backup. Do not “test” suspicious PHP by executing it. Follow up with a broader malware scan of files and other database tables.', 'choctaw-wp-security' ),
					'suspicious' => __( 'Read the Option Value in context. If the content is not clearly owned by a trusted plugin feature, remove or restore the row and investigate related admin/user activity.', 'choctaw-wp-security' ),
					'default'    => __( 'Verify whether a trusted plugin intentionally stores this content. If not, clean the option and continue investigating other Execution or Malware Names findings.', 'choctaw-wp-security' ),
				),
			),
			'malware_option_names'   => array(
				'why' => array(
					'critical'   => __( 'This option name matches a name previously observed in known malware families. Attackers often reuse distinctive option keys for persistence.', 'choctaw-wp-security' ),
					'suspicious' => __( 'The option name resembles names used by known malware. It may be a coincidence, but name matches deserve verification.', 'choctaw-wp-security' ),
					'default'    => __( 'This option name is on the scanner’s known-malware name list. Appearance here means the name matched, not that compromise is already proven.', 'choctaw-wp-security' ),
				),
				'how' => array(
					'critical'   => __( 'Inspect the Option Value. If the row is not required by a trusted plugin you recognize, delete it with a trusted database/admin tool after taking a backup. Then search for related backdoors in files and other options.', 'choctaw-wp-security' ),
					'suspicious' => __( 'Confirm whether an installed plugin created the option. If ownership is unclear, back up and remove the row, then rescan.', 'choctaw-wp-security' ),
					'default'    => __( 'Identify the owner of the option name. Keep it only when a trusted component clearly needs it; otherwise remove it and rescan.', 'choctaw-wp-security' ),
				),
			),
			'scripts_non_widget'     => array(
				'why' => array(
					'critical'   => __( 'Script or iframe markup was found in an option that is not a normal widget or theme_mods location. Injected scripts in options are a common way to load drive-by content site-wide.', 'choctaw-wp-security' ),
					'suspicious' => __( 'HTML script or iframe tags appeared outside the usual widget/theme option prefixes. Some plugins store markup intentionally, but unexpected locations are worth reviewing.', 'choctaw-wp-security' ),
					'default'    => __( 'This option matched script/iframe patterns outside widget_ and theme_mods_ prefixes, which is uncommon for ordinary settings.', 'choctaw-wp-security' ),
				),
				'how' => array(
					'critical'   => __( 'Examine the Option Value for injected third-party scripts. Remove unauthorized markup, restore from backup if needed, and check posts/widgets/theme settings for the same payload.', 'choctaw-wp-security' ),
					'suspicious' => __( 'Confirm the owning plugin or feature. If the markup is unexpected, clean the value and rescan wp_options and wp_posts for related injections.', 'choctaw-wp-security' ),
					'default'    => __( 'Validate that the script/iframe content is intentional. Remove anything you do not recognize, then rescan.', 'choctaw-wp-security' ),
				),
			),
			'baseline_diff'          => array(
				'why' => array(
					'critical'   => __( 'This option changed in a way that looks high risk compared with your previous scan baseline. Sudden changes to sensitive options can indicate tampering.', 'choctaw-wp-security' ),
					'suspicious' => __( 'This option is new or changed since the last baseline snapshot. Changes are often routine (plugin updates), but unexpected ones should be explained.', 'choctaw-wp-security' ),
					'default'    => __( 'The Changed category compares the current options table with your saved baseline from a previous scan of this same table.', 'choctaw-wp-security' ),
				),
				'how' => array(
					'critical'   => __( 'Determine whether an admin, plugin update, or migration explains the change. If not, restore the prior value from backup and investigate further. After cleanup, use Reset Baseline so future diffs stay meaningful.', 'choctaw-wp-security' ),
					'suspicious' => __( 'Review the Option Value and recent site changes. Accept expected changes; investigate unfamiliar ones. Reset the baseline after intentional bulk updates so noise does not hide later tampering.', 'choctaw-wp-security' ),
					'default'    => __( 'Ask whether this change was expected. Keep unexpected changes on your investigation list, and reset the baseline once the table reflects a known-good state.', 'choctaw-wp-security' ),
				),
			),
		);
	}

	/**
	 * Resolve Why / How copy for a finding category and risk.
	 *
	 * @param string $category Category / section key.
	 * @param string $risk     Risk key.
	 * @return array{why: string, how: string}
	 */
	public static function resolve_detail_guidance( $category, $risk ) {
		$guidance = self::get_detail_guidance();
		$category = (string) $category;
		$risk     = (string) $risk;
		$entry    = isset( $guidance[ $category ] ) && is_array( $guidance[ $category ] ) ? $guidance[ $category ] : array();
		$why_map  = isset( $entry['why'] ) && is_array( $entry['why'] ) ? $entry['why'] : array();
		$how_map  = isset( $entry['how'] ) && is_array( $entry['how'] ) ? $entry['how'] : array();

		$why = '';
		if ( isset( $why_map[ $risk ] ) ) {
			$why = (string) $why_map[ $risk ];
		} elseif ( isset( $why_map['default'] ) ) {
			$why = (string) $why_map['default'];
		}

		$how = '';
		if ( isset( $how_map[ $risk ] ) ) {
			$how = (string) $how_map[ $risk ];
		} elseif ( isset( $how_map['default'] ) ) {
			$how = (string) $how_map['default'];
		}

		if ( '' === $why ) {
			$why = __( 'This option matched one of the wp_options security checks. Review the Detail and Option Value to understand why it was flagged.', 'choctaw-wp-security' );
		}

		if ( '' === $how ) {
			$how = __( 'Confirm whether the value is expected for your site. If it is not, restore or remove it using a trusted backup or admin workflow, then rescan. Sassh reports findings only — it does not modify options automatically.', 'choctaw-wp-security' );
		}

		return array(
			'why' => $why,
			'how' => $how,
		);
	}
}
