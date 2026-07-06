<?php
/**
 * Pattern lists and thresholds for the wp_posts database scan.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Constants used by the wp_posts table scanner.
 */
class Choctaw_Wp_Security_Posts_Scan_Patterns {

	const BASELINE_OPTION_KEY           = 'choctaw_wp_security_posts_baseline';
	const SCAN_TIME_BUDGET              = 30;
	const CONTENT_SIZE_THRESHOLD        = 102400;
	const LARGE_CONTENT_TOP_LIMIT       = 20;
	const EXCERPT_LENGTH                = 120;
	const LARGE_CONTENT_PREVIEW_LENGTH  = 200;

	/**
	 * Report section keys in display order.
	 *
	 * @var array<int, string>
	 */
	public static $section_keys = array(
		'php_execution_patterns',
		'script_iframe_injection',
		'high_confidence_scripts',
		'seo_spam_titles',
		'large_post_content',
		'baseline_diff',
	);

	/**
	 * Post types excluded from content scans.
	 *
	 * @var array<int, string>
	 */
	public static $excluded_post_types = array(
		'revision',
		'nav_menu_item',
		'attachment',
		'customize_changeset',
		'oembed_cache',
	);

	/**
	 * Post statuses excluded from content scans.
	 *
	 * @var array<int, string>
	 */
	public static $excluded_post_statuses = array(
		'auto-draft',
		'inherit',
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
		'error_reporting(0)',
	);

	/**
	 * Generic HTML injection patterns.
	 *
	 * @var array<int, string>
	 */
	public static $script_patterns = array(
		'<script',
		'<iframe',
	);

	/**
	 * Higher-confidence script injection patterns.
	 *
	 * @var array<int, string>
	 */
	public static $high_confidence_script_patterns = array(
		'<iframe src="http',
		'<script src="http',
		'document.write',
		'eval(unescape',
	);

	/**
	 * SEO spam keywords checked against published post titles.
	 *
	 * @var array<int, string>
	 */
	public static $seo_spam_keywords = array(
		'viagra',
		'casino',
		'loan',
		'pharma',
	);

	/**
	 * Section metadata for admin rendering.
	 *
	 * @return array<string, array<string, string>>
	 */
	public static function get_section_meta() {
		return array(
			'php_execution_patterns'   => array(
				'title'    => __( 'PHP & Execution Patterns', 'choctaw-wp-security' ),
				'guidance' => __( 'PHP tags and execution functions rarely belong in post content. Review each match in the editor before taking action.', 'choctaw-wp-security' ),
			),
			'script_iframe_injection'  => array(
				'title'    => __( 'Script & Iframe Injection', 'choctaw-wp-security' ),
				'guidance' => __( 'Script or iframe tags in post content may be legitimate embeds. Malicious injections are often hidden at the top or bottom of the content.', 'choctaw-wp-security' ),
			),
			'high_confidence_scripts'  => array(
				'title'    => __( 'High-Confidence Script Patterns', 'choctaw-wp-security' ),
				'guidance' => __( 'These patterns are more commonly associated with malicious injections than generic script tags. Verify each match in context.', 'choctaw-wp-security' ),
			),
			'seo_spam_titles'          => array(
				'title'    => __( 'SEO Spam Titles', 'choctaw-wp-security' ),
				'guidance' => __( 'Published posts with spam-related titles may indicate an SEO injection attack. Trash suspicious posts instead of deleting them outright.', 'choctaw-wp-security' ),
			),
			'large_post_content'       => array(
				'title'    => __( 'Large Post Content', 'choctaw-wp-security' ),
				'guidance' => __( 'Reports published posts with content of 100 KB or larger (up to 20 rows). Smaller posts are omitted because they are usually normal. Unusually large content can hide malicious payloads.', 'choctaw-wp-security' ),
			),
			'baseline_diff'            => array(
				'title'    => __( 'Changed Posts Since Last Scan', 'choctaw-wp-security' ),
				'guidance' => __( 'Compares the current wp_posts table against the snapshot from your previous scan. New or changed rows may be routine updates or signs of tampering.', 'choctaw-wp-security' ),
			),
		);
	}
}
