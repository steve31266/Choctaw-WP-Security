<?php
/**
 * Patterns, weights, and thresholds for the WP-Cron scanner.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Tunable detection configuration for WP-Cron scheduled task analysis.
 */
class Choctaw_Wp_Security_Scheduled_Tasks_Patterns {

	/**
	 * Unusual frequency threshold in seconds (5 minutes).
	 *
	 * @var int
	 */
	const UNUSUAL_FREQUENCY_SECONDS = 300;

	/**
	 * Stale task threshold in seconds (24 hours).
	 *
	 * @var int
	 */
	const STALE_TASK_SECONDS = DAY_IN_SECONDS;

	/**
	 * Duplicate threshold for the same hook name.
	 *
	 * @var int
	 */
	const DUPLICATE_HOOK_THRESHOLD = 5;

	/**
	 * Duplicate threshold for the same hook + args hash.
	 *
	 * @var int
	 */
	const DUPLICATE_HOOK_ARGS_THRESHOLD = 3;

	/**
	 * Risk band: review max score (inclusive).
	 *
	 * @var int
	 */
	const RISK_REVIEW_MAX = 39;

	/**
	 * Risk band: suspicious max score (inclusive).
	 *
	 * @var int
	 */
	const RISK_SUSPICIOUS_MAX = 79;

	/**
	 * Known WordPress core cron hooks.
	 *
	 * @return array<int, string>
	 */
	public static function get_core_hooks() {
		return array(
			'delete_expired_transients',
			'do_pings',
			'importer_scheduled_cleanup',
			'recovery_mode_clean_expired_keys',
			'upgrader_scheduled_cleanup',
			'wp_delete_temp_updater_backup',
			'wp_delete_temp_updater_backups',
			'wp_https_detection',
			'wp_privacy_delete_old_export_files',
			'wp_scheduled_auto_draft_delete',
			'wp_scheduled_delete',
			'wp_site_health_scheduled_check',
			'wp_update_https_detection_errors',
			'wp_update_user_counts',
			'wp_version_check',
			'wp_update_plugins',
			'wp_update_themes',
		);
	}

	/**
	 * Point weights for rules and signals.
	 *
	 * @return array<string, int>
	 */
	public static function get_weights() {
		return array(
			'unknown_hook'           => 25,
			'unregistered_handler'   => 25,
			'missing_source'         => 20,
			'unusual_frequency'      => 15,
			'stale_task'             => 10,
			'duplicate_task'         => 15,
			'suspicious_hook_name'   => 30,
			'external_url'           => 20,
			'ip_address'             => 15,
			'base64_payload'         => 40,
			'php_fragment'           => 50,
			'js_fragment'            => 35,
			'shell_fragment'         => 50,
			'eval_family'            => 100,
		);
	}

	/**
	 * Strong payload signals used for confidence.
	 *
	 * @return array<int, string>
	 */
	public static function get_strong_signals() {
		return array(
			'eval_family',
			'php_fragment',
			'base64_payload',
			'shell_fragment',
		);
	}

	/**
	 * Review rule IDs that contribute to confidence (excludes recognized_*).
	 *
	 * @return array<int, string>
	 */
	public static function get_review_rule_ids() {
		return array(
			'unknown_hook',
			'unregistered_handler',
			'missing_source',
			'unusual_frequency',
			'stale_task',
			'duplicate_task',
			'suspicious_hook_name',
			'suspicious_arguments',
		);
	}

	/**
	 * Suspicious terms for hook-name heuristics.
	 *
	 * @return array<int, string>
	 */
	public static function get_suspicious_hook_terms() {
		return array(
			'eval',
			'shell',
			'base64',
			'gzinflate',
			'passthru',
			'assert',
			'wp_temp',
			'bypass',
			'backdoor',
			'redirect',
			'inject',
			'payload',
			'c99',
			'r57',
			'webshell',
		);
	}

	/**
	 * Category labels keyed by rule ID.
	 *
	 * @return array<string, string>
	 */
	public static function get_category_labels() {
		return array(
			'recognized_core'          => __( 'Recognized Core', 'choctaw-wp-security' ),
			'recognized_plugin_theme'  => __( 'Recognized Plugin / Theme', 'choctaw-wp-security' ),
			'unknown_hook'             => __( 'Unknown Hook', 'choctaw-wp-security' ),
			'unregistered_handler'     => __( 'Unregistered Handler', 'choctaw-wp-security' ),
			'missing_source'           => __( 'Missing Source', 'choctaw-wp-security' ),
			'unusual_frequency'        => __( 'Unusual Frequency', 'choctaw-wp-security' ),
			'stale_task'               => __( 'Stale Task', 'choctaw-wp-security' ),
			'duplicate_task'           => __( 'Duplicate Task', 'choctaw-wp-security' ),
			'suspicious_hook_name'     => __( 'Suspicious Hook Name', 'choctaw-wp-security' ),
			'suspicious_arguments'     => __( 'Suspicious Arguments', 'choctaw-wp-security' ),
		);
	}

	/**
	 * Derive risk level from score.
	 *
	 * @param int  $score         Weighted score.
	 * @param bool $is_recognized Recognized-only inventory finding.
	 * @return string
	 */
	public static function risk_from_score( $score, $is_recognized = false ) {
		$score = (int) $score;

		if ( $is_recognized || $score <= 0 ) {
			return 'info';
		}

		if ( $score <= self::RISK_REVIEW_MAX ) {
			return 'review';
		}

		if ( $score <= self::RISK_SUSPICIOUS_MAX ) {
			return 'suspicious';
		}

		return 'critical';
	}
}
