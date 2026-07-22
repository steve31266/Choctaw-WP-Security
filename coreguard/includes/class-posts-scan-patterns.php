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
	const LARGE_CONTENT_TOP_LIMIT       = 20; // Legacy display hint only; not used for Findings coverage.
	const LARGE_CONTENT_BATCH_SIZE      = 50;
	const EXCERPT_LENGTH                = 60;
	const LARGE_CONTENT_PREVIEW_LENGTH  = 60;
	const MATCHED_SNIPPET_LENGTH        = 16384;

	/**
	 * Report section keys in display order.
	 *
	 * @var array<int, string>
	 */
	public static $section_keys = array(
		'php_execution_patterns',
		'scripts',
		'seo_spam_titles',
		'large_post_content',
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
	 * High-specificity execution/obfuscation patterns (single hit → Warning for posts).
	 *
	 * @return array<int, string>
	 */
	public static function high_specificity_execution_patterns() {
		return array(
			'eval(',
			'base64_decode(',
			'gzinflate(',
			'gzuncompress(',
			'str_rot13(',
			'create_function(',
			'phar://',
			'error_reporting(0)',
		);
	}

	/**
	 * Lower-specificity execution-like patterns (single hit → Suspicious for posts).
	 *
	 * @return array<int, string>
	 */
	public static function low_specificity_execution_patterns() {
		return array(
			'shell_exec(',
			'passthru(',
			'system(',
			'assert(',
		);
	}

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
			'scripts'                  => array(
				'title'    => __( 'Script & Iframe Injection', 'choctaw-wp-security' ),
				'guidance' => __( 'Script or iframe tags in post content may be legitimate embeds. Higher-confidence patterns (remote script/iframe sources, document.write, eval unescape) are prioritized when both match the same post.', 'choctaw-wp-security' ),
			),
			'seo_spam_titles'          => array(
				'title'    => __( 'SEO Spam Titles', 'choctaw-wp-security' ),
				'guidance' => __( 'Published posts with spam-related titles may indicate an SEO injection attack. Trash suspicious posts instead of deleting them outright.', 'choctaw-wp-security' ),
			),
			'large_post_content'       => array(
				'title'    => __( 'Large Post Content', 'choctaw-wp-security' ),
				'guidance' => __( 'Reports posts with content of 100 KB or larger. Smaller posts are omitted because they are usually normal. Unusually large content can hide malicious payloads.', 'choctaw-wp-security' ),
			),
		);
	}

	/**
	 * Short category labels for the unified posts report.
	 *
	 * @return array<string, string>
	 */
	public static function get_category_labels() {
		return array(
			'php_execution_patterns' => __( 'PHP Tags', 'choctaw-wp-security' ),
			'scripts'                => __( 'Scripts', 'choctaw-wp-security' ),
			'seo_spam_titles'        => __( 'SEO Spam', 'choctaw-wp-security' ),
			'large_post_content'     => __( 'Large', 'choctaw-wp-security' ),
		);
	}

	/**
	 * Map legacy severity + section to the shared Risk vocabulary.
	 *
	 * @param string $severity    Legacy severity: critical, warning, info.
	 * @param string $section_key Section key.
	 * @return string Risk key: critical, suspicious, safe, info.
	 */
	public static function map_severity_to_risk( $severity, $section_key = '' ) {
		unset( $section_key );
		$severity = (string) $severity;

		if ( 'critical' === $severity ) {
			return 'critical';
		}

		if ( 'warning' === $severity ) {
			return 'suspicious';
		}

		return 'info';
	}

	/**
	 * Preliminary Why / How guidance for the posts detail panel.
	 *
	 * @return array<string, array{why: array<string, string>, how: array<string, string>}>
	 */
	public static function get_detail_guidance() {
		return array(
			'php_execution_patterns' => array(
				'why' => array(
					'critical'   => __( 'This post’s content contains PHP tags or execution-related functions. Legitimate posts almost never store executable PHP in post_content.', 'choctaw-wp-security' ),
					'suspicious' => __( 'Patterns associated with PHP execution or obfuscation were found in this post. They are a strong malware signal even when the rest of the content looks normal.', 'choctaw-wp-security' ),
					'default'    => __( 'This finding matched PHP or code-execution patterns inside post content, which is uncommon for ordinary WordPress posts or pages.', 'choctaw-wp-security' ),
				),
				'how' => array(
					'critical'   => __( 'Open the post in the editor (or review the Matched Snippet). Remove the malicious markup, or trash/restore the post from a clean backup. Do not execute suspicious code. Check the author account and scan related posts for the same payload.', 'choctaw-wp-security' ),
					'suspicious' => __( 'Inspect the Matched Snippet in context. If the content is not clearly intentional, clean or trash the post and review other PHP Tags findings from the same author.', 'choctaw-wp-security' ),
					'default'    => __( 'Confirm whether a trusted workflow inserted this content. If not, clean the post and continue investigating other Critical or Suspicious findings.', 'choctaw-wp-security' ),
				),
			),
			'scripts'                => array(
				'why' => array(
					'critical'   => __( 'High-confidence script or iframe injection patterns were found in this post (for example remote script/iframe sources, document.write, or eval/unescape). That often indicates injected drive-by content.', 'choctaw-wp-security' ),
					'suspicious' => __( 'Script or iframe markup appears in this post. Some embeds are legitimate, but unexpected scripts—especially from unknown hosts—are a common compromise indicator.', 'choctaw-wp-security' ),
					'default'    => __( 'This post matched script/iframe patterns used to detect injected HTML in post content.', 'choctaw-wp-security' ),
				),
				'how' => array(
					'critical'   => __( 'Review the Matched Snippet and remove unauthorized scripts/iframes. Prefer restoring from a clean revision or backup when the post is heavily altered. Then search other posts for the same injection and review the author user.', 'choctaw-wp-security' ),
					'suspicious' => __( 'Confirm the embed is intentional (trusted video/map/widget). Remove anything you do not recognize, update the post, and rescan.', 'choctaw-wp-security' ),
					'default'    => __( 'Validate the script/iframe against your expected content. Clean unexpected markup, then rescan wp_posts.', 'choctaw-wp-security' ),
				),
			),
			'seo_spam_titles'        => array(
				'why' => array(
					'critical'   => __( 'A published post title matches spam-related keywords commonly used in SEO injection attacks. Compromised sites often publish or retitle posts to push pharmaceutical, casino, or loan spam.', 'choctaw-wp-security' ),
					'suspicious' => __( 'This published title contains terms associated with SEO spam. It may be a false positive for niche content, but it deserves a quick authenticity check.', 'choctaw-wp-security' ),
					'default'    => __( 'Published post titles are checked against a short list of spam-oriented keywords that frequently appear after content injection attacks.', 'choctaw-wp-security' ),
				),
				'how' => array(
					'critical'   => __( 'Open the post, confirm it is not legitimate content for your site, then trash it (prefer trash over permanent delete while investigating). Review the author account, recent posts by that user, and other SEO Spam findings.', 'choctaw-wp-security' ),
					'suspicious' => __( 'Verify the title and body are intentional. If the post is spam, trash it and check for more posts from the same author or with similar titles.', 'choctaw-wp-security' ),
					'default'    => __( 'Confirm authorship and intent. Trash unexpected spam posts and continue reviewing related findings.', 'choctaw-wp-security' ),
				),
			),
			'large_post_content'     => array(
				'why' => array(
					'critical'   => __( 'This published post is unusually large. Oversized post_content can hide malicious payloads while still rendering enough normal text to look legitimate.', 'choctaw-wp-security' ),
					'suspicious' => __( 'This published post meets the large-content threshold used by this scan. Size alone is not proof of compromise, but large posts are a useful place to look for hidden injections.', 'choctaw-wp-security' ),
					'default'    => __( 'This category lists published posts at or above the large-content size threshold so you can review unusually big content rows.', 'choctaw-wp-security' ),
				),
				'how' => array(
					'critical'   => __( 'Inspect the Matched Snippet and full post in the editor for encoded or unexpected blocks at the end of the content. Remove injected material or restore from a clean revision, then investigate how the content grew.', 'choctaw-wp-security' ),
					'suspicious' => __( 'Confirm whether the size is expected (long guide, imported content). If not, search the content for hidden scripts or PHP and clean as needed.', 'choctaw-wp-security' ),
					'default'    => __( 'Skim the post for unexpected trailing content. No action is required when the size matches a known long-form page.', 'choctaw-wp-security' ),
				),
			),
			'baseline_diff'          => array(
				'why' => array(
					'critical'   => __( 'This post changed in a high-risk way compared with your previous scan baseline. Sudden content changes can indicate tampering or spam injection.', 'choctaw-wp-security' ),
					'suspicious' => __( 'This post is new or changed since the last baseline snapshot. Many changes are routine edits; unexplained ones should be reviewed.', 'choctaw-wp-security' ),
					'default'    => __( 'The Changed category compares the current wp_posts table with your saved baseline from a previous scan of this same table.', 'choctaw-wp-security' ),
				),
				'how' => array(
					'critical'   => __( 'Compare the current post with a known-good revision or backup. Revert unauthorized edits, review the author, and check related Changed findings. After cleanup, use Reset Baseline so future diffs stay useful.', 'choctaw-wp-security' ),
					'suspicious' => __( 'Confirm whether an editor, import, or plugin explains the change. Investigate unfamiliar updates, then reset the baseline after intentional bulk changes.', 'choctaw-wp-security' ),
					'default'    => __( 'Ask whether this change was expected. Keep unexpected diffs on your investigation list, and reset the baseline once the table reflects a known-good state.', 'choctaw-wp-security' ),
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
			$why = __( 'This post matched one of the wp_posts security checks. Review the Detail and Matched Snippet to understand why it was flagged.', 'choctaw-wp-security' );
		}

		if ( '' === $how ) {
			$how = __( 'Confirm whether the post content is expected. If it is not, clean or trash it using the editor or a trusted backup, then rescan. Sassh reports findings only — it does not modify posts automatically.', 'choctaw-wp-security' );
		}

		return array(
			'why' => $why,
			'how' => $how,
		);
	}
}
