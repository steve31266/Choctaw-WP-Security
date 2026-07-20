<?php
/**
 * Sassh Findings service — persistence, finalize, dismissals, related findings.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Shared Findings System service.
 */
class Sassh_Findings_Service {

	const SCANNER_UPLOADS            = 'uploads-folder';
	const RULE_PHP_UPLOADS           = 'php-file-in-uploads';
	const SCANNER_MU_PLUGINS         = 'mu-plugins';
	const RULE_PHP_MU_PLUGINS        = 'php-like-file-in-mu-plugins';
	const SCANNER_VERIFY_CHECKSUMS   = 'verify-checksums';
	const RULE_CORE_FILE_MODIFIED    = 'core-file-modified';
	const RULE_CORE_FILE_MISSING     = 'core-file-missing';
	const RULE_CORE_FILE_UNKNOWN     = 'core-file-unknown';
	const SCANNER_EXPOSED_FILES      = 'exposed-files';
	const SCANNER_DATABASE_SCAN      = 'database-scan';
	const FINGERPRINT_MISSING        = 'sha256:missing';
	const FINGERPRINT_DIRECTORY      = 'sha256:directory';

	const RULE_HOME_SITEURL_MISMATCH           = 'home-siteurl-mismatch';
	const RULE_HOME_CONSTANT_MISMATCH          = 'home-constant-mismatch';
	const RULE_SITEURL_CONSTANT_MISMATCH       = 'siteurl-constant-mismatch';
	const RULE_HOME_EXTERNAL_HOST              = 'home-external-host';
	const RULE_SITEURL_EXTERNAL_HOST           = 'siteurl-external-host';
	const RULE_USERS_CAN_REGISTER_ENABLED      = 'users-can-register-enabled';
	const RULE_DEFAULT_ROLE_ADMINISTRATOR      = 'default-role-administrator';
	const RULE_ADMIN_EMAIL_INVALID             = 'admin-email-invalid';
	const RULE_CRITICAL_OPTION_EXTERNAL_URL    = 'critical-option-external-url';
	const RULE_ACTIVE_PLUGINS_INVALID          = 'active-plugins-invalid';
	const RULE_ACTIVE_PLUGIN_SUSPICIOUS_PATH   = 'active-plugin-suspicious-path';
	const RULE_ACTIVE_PLUGIN_MISSING           = 'active-plugin-missing';
	const RULE_LARGE_AUTOLOAD_OPTION           = 'large-autoload-option';
	const RULE_PHP_EXECUTION_PATTERNS_MATCH    = 'php-execution-patterns-match';
	const RULE_MALWARE_OPTION_NAME             = 'malware-option-name';
	const RULE_SCRIPTS_NON_WIDGET_MATCH        = 'scripts-non-widget-match';

	/**
	 * Risk severity order (low to high).
	 *
	 * @var array<string, int>
	 */
	private static $risk_rank = array(
		'safe'       => 0,
		'info'       => 1,
		'suspicious' => 2,
		'warning'    => 3,
		'critical'   => 4,
	);

	/**
	 * Identity keys observed during the current execution (memory).
	 *
	 * @var array<int, array<string, true>>
	 */
	private $observed_identity_keys = array();

	/**
	 * Begin a scanner execution.
	 *
	 * @param string               $scanner_id Scanner id.
	 * @param array<string, mixed> $attrs      scope_key, run_type, run_source, scan_run_id, meta.
	 * @return int Execution id.
	 */
	public function begin_scanner_execution( $scanner_id, array $attrs = array() ) {
		global $wpdb;

		Sassh_Findings_Schema::maybe_upgrade();

		$table = Sassh_Findings_Schema::table( 'sassh_scanner_executions' );
		$now   = current_time( 'mysql', true );

		$wpdb->insert(
			$table,
			array(
				'scanner_id'        => (string) $scanner_id,
				'scan_run_id'       => isset( $attrs['scan_run_id'] ) ? (string) $attrs['scan_run_id'] : null,
				'run_type'          => isset( $attrs['run_type'] ) ? (string) $attrs['run_type'] : 'individual',
				'run_source'        => isset( $attrs['run_source'] ) ? (string) $attrs['run_source'] : 'wordpress_admin',
				'scope_key'         => isset( $attrs['scope_key'] ) ? (string) $attrs['scope_key'] : '',
				'started_at'        => $now,
				'completed_at'      => null,
				'completion_status' => 'running',
				'meta'              => isset( $attrs['meta'] ) ? wp_json_encode( $attrs['meta'] ) : null,
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);

		$execution_id = (int) $wpdb->insert_id;
		$this->observed_identity_keys[ $execution_id ] = array();

		return $execution_id;
	}

	/**
	 * Record observations for an open execution.
	 *
	 * @param int                  $execution_id Execution id.
	 * @param array<int, array<string, mixed>> $observations Observations.
	 * @return void
	 */
	public function record_observations( $execution_id, array $observations ) {
		$execution = $this->get_execution( $execution_id );

		if ( ! $execution || 'running' !== $execution['completion_status'] ) {
			return;
		}

		foreach ( $observations as $observation ) {
			if ( ! is_array( $observation ) ) {
				continue;
			}
			$this->upsert_observation( $execution_id, $execution, $observation );
		}
	}

	/**
	 * Finalize execution: absence processing, events, then success — or fail.
	 *
	 * @param int    $execution_id Execution id.
	 * @param string $desired_status success|failed|partial|interrupted — success only applied after finalize steps.
	 * @return bool True if marked success.
	 */
	public function finalize_scanner_execution( $execution_id, $desired_status = 'success' ) {
		global $wpdb;

		$execution = $this->get_execution( $execution_id );

		if ( ! $execution || 'running' !== $execution['completion_status'] ) {
			return false;
		}

		$now   = current_time( 'mysql', true );
		$table = Sassh_Findings_Schema::table( 'sassh_scanner_executions' );

		if ( 'success' !== $desired_status ) {
			$wpdb->update(
				$table,
				array(
					'completed_at'      => $now,
					'completion_status' => $desired_status,
				),
				array( 'id' => $execution_id ),
				array( '%s', '%s' ),
				array( '%d' )
			);
			return false;
		}

		try {
			$this->mark_absent_within_scope( $execution_id, $execution );
		} catch ( Exception $e ) {
			$wpdb->update(
				$table,
				array(
					'completed_at'      => $now,
					'completion_status' => 'failed',
				),
				array( 'id' => $execution_id ),
				array( '%s', '%s' ),
				array( '%d' )
			);
			return false;
		}

		$wpdb->update(
			$table,
			array(
				'completed_at'      => $now,
				'completion_status' => 'success',
			),
			array( 'id' => $execution_id ),
			array( '%s', '%s' ),
			array( '%d' )
		);

		return true;
	}

	/**
	 * Dismiss a finding for the reviewed finding fingerprint.
	 *
	 * @param string               $finding_id           Finding id.
	 * @param string               $reviewed_fingerprint Finding content fingerprint.
	 * @param array<string, mixed> $actor                actor_type, actor_identifier, action_source, reason.
	 * @return array<string, mixed>|\WP_Error
	 */
	public function dismiss( $finding_id, $reviewed_fingerprint, array $actor = array() ) {
		global $wpdb;

		Sassh_Findings_Schema::maybe_upgrade();

		$finding = $this->get_finding( $finding_id );

		if ( ! $finding ) {
			return new WP_Error( 'sassh_finding_not_found', __( 'Finding not found.', 'choctaw-wp-security' ) );
		}

		if ( 'needs_review' !== $finding['sassh_classification'] ) {
			return new WP_Error( 'sassh_not_dismissible', __( 'This finding cannot be dismissed.', 'choctaw-wp-security' ) );
		}

		$reviewed_fingerprint = self::normalize_fingerprint( $reviewed_fingerprint );
		$current_fingerprint  = self::normalize_fingerprint( $finding['content_fingerprint'] );

		if ( '' === $reviewed_fingerprint || $reviewed_fingerprint !== $current_fingerprint ) {
			return new WP_Error( 'sassh_stale_fingerprint', __( 'This finding changed and must be reviewed again.', 'choctaw-wp-security' ) );
		}

		$valid = $this->get_valid_dismissal( $finding_id );

		if ( $valid ) {
			return $this->enrich_finding_row( $finding );
		}

		$now   = current_time( 'mysql', true );
		$table = Sassh_Findings_Schema::table( 'sassh_dismissal_decisions' );

		$wpdb->insert(
			$table,
			array(
				'finding_id'           => $finding_id,
				'reviewed_fingerprint' => $reviewed_fingerprint,
				'dismissed_at'         => $now,
				'actor_type'           => isset( $actor['actor_type'] ) ? (string) $actor['actor_type'] : 'wordpress_user',
				'actor_identifier'     => isset( $actor['actor_identifier'] ) ? (string) $actor['actor_identifier'] : (string) get_current_user_id(),
				'action_source'        => isset( $actor['action_source'] ) ? (string) $actor['action_source'] : 'wordpress_admin',
				'reason'               => isset( $actor['reason'] ) ? (string) $actor['reason'] : null,
				'invalidated_at'       => null,
				'invalidation_reason'  => null,
				'created_at'           => $now,
				'updated_at'           => $now,
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);

		return $this->enrich_finding_row( $this->get_finding( $finding_id ) );
	}

	/**
	 * Undo the currently valid dismissal.
	 *
	 * @param string               $finding_id Finding id.
	 * @param array<string, mixed> $actor      Actor context.
	 * @return array<string, mixed>|\WP_Error
	 */
	public function undismiss( $finding_id, array $actor = array() ) {
		global $wpdb;

		$finding = $this->get_finding( $finding_id );

		if ( ! $finding ) {
			return new WP_Error( 'sassh_finding_not_found', __( 'Finding not found.', 'choctaw-wp-security' ) );
		}

		$valid = $this->get_valid_dismissal( $finding_id );

		if ( ! $valid ) {
			return $this->enrich_finding_row( $finding );
		}

		$now   = current_time( 'mysql', true );
		$table = Sassh_Findings_Schema::table( 'sassh_dismissal_decisions' );

		$wpdb->update(
			$table,
			array(
				'invalidated_at'      => $now,
				'invalidation_reason' => 'undismissed',
				'updated_at'          => $now,
			),
			array( 'dismissal_id' => (int) $valid['dismissal_id'] ),
			array( '%s', '%s', '%s' ),
			array( '%d' )
		);

		$this->record_event(
			$finding_id,
			'dismissal_invalidated',
			'valid',
			'undismissed',
			null,
			null,
			array( 'reason' => 'undismissed' )
		);

		return $this->enrich_finding_row( $this->get_finding( $finding_id ) );
	}

	/**
	 * Get one finding row (raw).
	 *
	 * @param string $finding_id Finding id.
	 * @return array<string, mixed>|null
	 */
	public function get_finding( $finding_id ) {
		global $wpdb;

		Sassh_Findings_Schema::maybe_upgrade();

		$table = Sassh_Findings_Schema::table( 'sassh_findings' );
		$row   = $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$table} WHERE finding_id = %s", $finding_id ),
			ARRAY_A
		);

		return is_array( $row ) ? $row : null;
	}

	/**
	 * Get one finding with effective status / labels applied.
	 *
	 * @param string $finding_id Finding id.
	 * @return array<string, mixed>|null
	 */
	public function get_enriched_finding( $finding_id ) {
		return $this->enrich_finding_row( $this->get_finding( $finding_id ) );
	}

	/**
	 * List findings for a scanner.
	 *
	 * @param array<string, mixed> $filters scanner_id, detection_state, etc.
	 * @return array<int, array<string, mixed>>
	 */
	public function list_findings( array $filters = array() ) {
		global $wpdb;

		Sassh_Findings_Schema::maybe_upgrade();

		$table = Sassh_Findings_Schema::table( 'sassh_findings' );
		$where = array( '1=1' );
		$args  = array();

		if ( ! empty( $filters['scanner_id'] ) ) {
			$where[] = 'scanner_id = %s';
			$args[]  = (string) $filters['scanner_id'];
		}

		if ( ! empty( $filters['detection_state'] ) ) {
			$where[] = 'detection_state = %s';
			$args[]  = (string) $filters['detection_state'];
		}

		$sql = "SELECT * FROM {$table} WHERE " . implode( ' AND ', $where ) . ' ORDER BY last_seen_at DESC';

		if ( ! empty( $args ) ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			$rows = $wpdb->get_results( $wpdb->prepare( $sql, $args ), ARRAY_A );
		} else {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			$rows = $wpdb->get_results( $sql, ARRAY_A );
		}

		if ( ! is_array( $rows ) ) {
			return array();
		}

		$out = array();

		foreach ( $rows as $row ) {
			$out[] = $this->enrich_finding_row( $row );
		}

		return $out;
	}

	/**
	 * Related findings by object correlation (excludes current; cap 10).
	 *
	 * @param string $finding_id Finding id.
	 * @return array<int, array<string, mixed>>
	 */
	public function list_related_findings( $finding_id ) {
		global $wpdb;

		$finding = $this->get_finding( $finding_id );

		if ( ! $finding ) {
			return array();
		}

		$table = Sassh_Findings_Schema::table( 'sassh_findings' );
		$rows  = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE object_correlation_key = %s AND finding_id != %s",
				$finding['object_correlation_key'],
				$finding_id
			),
			ARRAY_A
		);

		if ( ! is_array( $rows ) ) {
			return array();
		}

		$object_fp = (string) $finding['object_fingerprint'];
		$enriched  = array();

		foreach ( $rows as $row ) {
			$item = $this->enrich_finding_row( $row );
			$other_fp = (string) $row['object_fingerprint'];

			if ( '' === $object_fp || '' === $other_fp ) {
				$comparison = 'unknown';
			} elseif ( $object_fp === $other_fp ) {
				$comparison = 'same';
			} else {
				$comparison = 'different';
			}

			$item['object_fingerprint_comparison'] = $comparison;
			$enriched[] = $item;
		}

		usort(
			$enriched,
			static function ( $a, $b ) {
				$order = array( 'same' => 0, 'different' => 1, 'unknown' => 2 );
				$ca    = isset( $order[ $a['object_fingerprint_comparison'] ] ) ? $order[ $a['object_fingerprint_comparison'] ] : 9;
				$cb    = isset( $order[ $b['object_fingerprint_comparison'] ] ) ? $order[ $b['object_fingerprint_comparison'] ] : 9;

				if ( $ca !== $cb ) {
					return $ca - $cb;
				}

				$active_a = ( 'active' === $a['detection_state'] ) ? 0 : 1;
				$active_b = ( 'active' === $b['detection_state'] ) ? 0 : 1;

				if ( $active_a !== $active_b ) {
					return $active_a - $active_b;
				}

				return strcmp( (string) $b['last_seen_at'], (string) $a['last_seen_at'] );
			}
		);

		return array_slice( $enriched, 0, 10 );
	}

	/**
	 * Build Uploads scope key from uploads basedir.
	 *
	 * @param string $basedir Absolute uploads basedir.
	 * @return string
	 */
	public static function uploads_scope_key( $basedir ) {
		$normalized = Sassh_Object_Path_Normalizer::normalize_in_root( $basedir );

		if ( '' === $normalized ) {
			$normalized = 'wp-content/uploads';
		}

		return 'uploads:' . $normalized;
	}

	/**
	 * Build MU-Plugins scope key from mu-plugins directory.
	 *
	 * @param string $dir Absolute mu-plugins directory.
	 * @return string
	 */
	public static function mu_plugins_scope_key( $dir ) {
		$normalized = Sassh_Object_Path_Normalizer::normalize_in_root( $dir );

		if ( '' === $normalized ) {
			$normalized = 'wp-content/mu-plugins';
		}

		return 'mu-plugins:' . $normalized;
	}

	/**
	 * Stable Verify Checksums scope (WordPress core tree vs official checksums).
	 *
	 * @return string
	 */
	public static function verify_checksums_scope_key() {
		return 'verify-checksums:wordpress-core';
	}

	/**
	 * Stable Exposed Files scope (non-recursive WordPress document root).
	 *
	 * @return string
	 */
	public static function exposed_files_scope_key() {
		return 'exposed-files:wordpress-root';
	}

	/**
	 * Scope key for a database-scan options table.
	 *
	 * @param string $options_table Options table name.
	 * @return string
	 */
	public static function database_scan_scope_key( $options_table ) {
		return 'database-scan:' . (string) $options_table;
	}

	/**
	 * SHA-256 fingerprint for an arbitrary string payload.
	 *
	 * @param string $value Raw bytes/string.
	 * @return string sha256:hex
	 */
	public static function content_fingerprint_from_string( $value ) {
		return 'sha256:' . hash( 'sha256', (string) $value );
	}

	/**
	 * Rule-based risk_level for database-scan (Phase 3.3). No legacy warning→suspicious collapse.
	 *
	 * @param string               $rule_id  Rule id.
	 * @param array<string, mixed> $evidence Optional evidence (matched_patterns, plugin_path, …).
	 * @return string
	 */
	public static function database_scan_risk_level( $rule_id, array $evidence = array() ) {
		$rule_id = (string) $rule_id;

		switch ( $rule_id ) {
			case self::RULE_HOME_SITEURL_MISMATCH:
			case self::RULE_HOME_CONSTANT_MISMATCH:
			case self::RULE_SITEURL_CONSTANT_MISMATCH:
			case self::RULE_USERS_CAN_REGISTER_ENABLED:
			case self::RULE_ADMIN_EMAIL_INVALID:
			case self::RULE_ACTIVE_PLUGINS_INVALID:
			case self::RULE_ACTIVE_PLUGIN_MISSING:
			case self::RULE_LARGE_AUTOLOAD_OPTION:
				return 'suspicious';

			case self::RULE_HOME_EXTERNAL_HOST:
			case self::RULE_SITEURL_EXTERNAL_HOST:
			case self::RULE_DEFAULT_ROLE_ADMINISTRATOR:
			case self::RULE_CRITICAL_OPTION_EXTERNAL_URL:
			case self::RULE_SCRIPTS_NON_WIDGET_MATCH:
			case self::RULE_MALWARE_OPTION_NAME:
				return 'warning';

			case self::RULE_ACTIVE_PLUGIN_SUSPICIOUS_PATH:
				return self::active_plugin_path_risk_level(
					isset( $evidence['plugin_path'] ) ? (string) $evidence['plugin_path'] : ''
				);

			case self::RULE_PHP_EXECUTION_PATTERNS_MATCH:
				$matched = isset( $evidence['matched_patterns'] ) && is_array( $evidence['matched_patterns'] )
					? $evidence['matched_patterns']
					: array();
				$tag_patterns = isset( $evidence['php_tag_patterns'] ) && is_array( $evidence['php_tag_patterns'] )
					? $evidence['php_tag_patterns']
					: array();
				$execution_patterns = isset( $evidence['execution_patterns'] ) && is_array( $evidence['execution_patterns'] )
					? $evidence['execution_patterns']
					: array();

				return self::php_execution_risk_from_matches( $matched, $tag_patterns, $execution_patterns );

			default:
				return 'suspicious';
		}
	}

	/**
	 * Risk for active-plugin path outside plugins dir.
	 *
	 * Critical only when the path itself shows strong malware evidence.
	 *
	 * @param string $plugin_path Plugin path entry.
	 * @return string
	 */
	public static function active_plugin_path_risk_level( $plugin_path ) {
		$path = (string) $plugin_path;

		if ( '' === $path ) {
			return 'warning';
		}

		$lower = strtolower( $path );

		if (
			false !== strpos( $lower, 'phar://' )
			|| preg_match( '#^[a-z][a-z0-9+.-]*://#i', $path )
			|| false !== strpos( $path, "\0" )
			|| false !== strpos( $path, '../' )
			|| false !== strpos( $path, '..\\' )
		) {
			return 'critical';
		}

		return 'warning';
	}

	/**
	 * PHP execution pattern risk from the complete matched evidence set.
	 *
	 * Tag alone → warning. Single execution/obfuscation pattern alone → warning.
	 * Critical only for documented strong combinations (tag+execution, multiple
	 * complementary execution patterns, or 2+ shell-execution patterns).
	 *
	 * @param array<int, string> $matched_patterns    All patterns matched in the value.
	 * @param array<int, string> $php_tag_patterns    Known PHP tag patterns.
	 * @param array<int, string> $execution_patterns  Known execution/obfuscation patterns.
	 * @return string
	 */
	public static function php_execution_risk_from_matches( array $matched_patterns, array $php_tag_patterns, array $execution_patterns ) {
		$matched = array();

		foreach ( $matched_patterns as $pattern ) {
			$pattern = (string) $pattern;
			if ( '' !== $pattern ) {
				$matched[ $pattern ] = $pattern;
			}
		}

		$matched = array_values( $matched );

		if ( empty( $matched ) ) {
			return 'warning';
		}

		$tag_hits = array();
		$exec_hits = array();

		foreach ( $matched as $pattern ) {
			foreach ( $php_tag_patterns as $tag ) {
				if ( 0 === strcasecmp( (string) $tag, $pattern ) ) {
					$tag_hits[ $pattern ] = $pattern;
				}
			}
			foreach ( $execution_patterns as $exec ) {
				if ( 0 === strcasecmp( (string) $exec, $pattern ) ) {
					$exec_hits[ $pattern ] = $pattern;
				}
			}
		}

		$tag_count  = count( $tag_hits );
		$exec_count = count( $exec_hits );

		// Tag + execution/obfuscation.
		if ( $tag_count > 0 && $exec_count > 0 ) {
			return 'critical';
		}

		// Multiple complementary execution/obfuscation patterns.
		if ( $exec_count >= 2 ) {
			return 'critical';
		}

		// Especially strong shell-execution combination (2+ shell family).
		$shell_family = array( 'shell_exec(', 'passthru(', 'system(' );
		$shell_hits   = 0;

		foreach ( $exec_hits as $pattern ) {
			foreach ( $shell_family as $shell ) {
				if ( 0 === strcasecmp( $shell, $pattern ) ) {
					++$shell_hits;
					break;
				}
			}
		}

		if ( $shell_hits >= 2 ) {
			return 'critical';
		}

		// Tag alone, or a single execution/obfuscation pattern alone.
		return 'warning';
	}

	/**
	 * Map an Exposed Files pattern id to a kebab-case Sassh rule_id.
	 *
	 * @param string $pattern Pattern id (snake_case).
	 * @return string
	 */
	public static function exposed_files_rule_id( $pattern ) {
		$pattern = (string) $pattern;

		if ( '' === $pattern ) {
			return '';
		}

		return str_replace( '_', '-', $pattern );
	}

	/**
	 * Merge keys into an open execution's JSON meta.
	 *
	 * @param int                  $execution_id Execution id.
	 * @param array<string, mixed> $meta_patch   Keys to merge.
	 * @return void
	 */
	public function update_execution_meta( $execution_id, array $meta_patch ) {
		global $wpdb;

		$execution = $this->get_execution( $execution_id );

		if ( ! $execution ) {
			return;
		}

		$existing = array();

		if ( ! empty( $execution['meta'] ) && is_string( $execution['meta'] ) ) {
			$decoded = json_decode( $execution['meta'], true );
			if ( is_array( $decoded ) ) {
				$existing = $decoded;
			}
		}

		$table = Sassh_Findings_Schema::table( 'sassh_scanner_executions' );

		$wpdb->update(
			$table,
			array(
				'meta' => wp_json_encode( array_merge( $existing, $meta_patch ) ),
			),
			array( 'id' => (int) $execution_id ),
			array( '%s' ),
			array( '%d' )
		);
	}

	/**
	 * Whether reappearance after not_detected must invalidate a still-valid dismissal.
	 *
	 * Sentinel fingerprints (sha256:missing) cannot distinguish absence episodes.
	 *
	 * @param string $rule_id    Rule id.
	 * @param string $content_fp Finding content fingerprint.
	 * @return bool
	 */
	public static function should_invalidate_dismissal_on_reappearance( $rule_id, $content_fp ) {
		return self::FINGERPRINT_MISSING === (string) $content_fp
			|| self::RULE_CORE_FILE_MISSING === (string) $rule_id;
	}

	/**
	 * Default classification for a risk level.
	 *
	 * @param string $risk_level Risk level.
	 * @return string
	 */
	public static function default_classification( $risk_level ) {
		$risk_level = (string) $risk_level;

		if ( in_array( $risk_level, array( 'info', 'safe' ), true ) ) {
			return 'no_action_needed';
		}

		return 'needs_review';
	}

	/**
	 * Effective status label.
	 *
	 * @param string $status Status key.
	 * @return string
	 */
	public static function status_label( $status ) {
		switch ( (string) $status ) {
			case 'dismissed':
				return __( 'Dismissed', 'choctaw-wp-security' );
			case 'no_action_needed':
				return __( 'Review Not Needed', 'choctaw-wp-security' );
			default:
				return __( 'Needs Review', 'choctaw-wp-security' );
		}
	}

	/**
	 * Hash file contents as sha256:hex.
	 *
	 * @param string $absolute_path Absolute path.
	 * @return string
	 */
	public static function file_content_fingerprint( $absolute_path ) {
		if ( ! is_readable( $absolute_path ) ) {
			return 'sha256:missing';
		}

		$hash = hash_file( 'sha256', $absolute_path );

		if ( ! is_string( $hash ) || '' === $hash ) {
			return 'sha256:unreadable';
		}

		return 'sha256:' . $hash;
	}

	/**
	 * Canonical tuple hash.
	 *
	 * @param array<int, string> $parts Parts.
	 * @return string
	 */
	public static function hash_tuple( array $parts ) {
		$encoded = '';

		foreach ( $parts as $part ) {
			$part     = (string) $part;
			$encoded .= strlen( $part ) . ':' . $part . '|';
		}

		return hash( 'sha256', $encoded );
	}

	/**
	 * Guess blog_id from uploads-relative path (Multisite sites/N/).
	 *
	 * @param string $object_key Normalized object key.
	 * @return int|null
	 */
	public static function blog_id_from_uploads_path( $object_key ) {
		if ( preg_match( '#^wp-content/uploads/sites/(\d+)/#', (string) $object_key, $matches ) ) {
			return (int) $matches[1];
		}

		return null;
	}

	/**
	 * Upsert one observation.
	 *
	 * @param int                  $execution_id Execution id.
	 * @param array<string, mixed> $execution    Execution row.
	 * @param array<string, mixed> $observation  Observation.
	 * @return void
	 */
	private function upsert_observation( $execution_id, array $execution, array $observation ) {
		global $wpdb;

		$installation_id = Sassh_Installation_Identity::get_id();
		$scanner_id      = isset( $observation['scanner_id'] ) ? (string) $observation['scanner_id'] : (string) $execution['scanner_id'];
		$rule_id         = isset( $observation['rule_id'] ) ? (string) $observation['rule_id'] : '';
		$object_type     = isset( $observation['object_type'] ) ? (string) $observation['object_type'] : '';
		$object_key      = isset( $observation['object_key'] ) ? (string) $observation['object_key'] : '';
		$blog_id         = array_key_exists( 'blog_id', $observation ) ? $observation['blog_id'] : null;
		$blog_part       = ( null === $blog_id || '' === $blog_id ) ? '' : (string) (int) $blog_id;

		$identity_key = self::hash_tuple(
			array(
				$installation_id,
				$scanner_id,
				$rule_id,
				$object_type,
				$blog_part,
				$object_key,
			)
		);

		$correlation_parts = array( $installation_id, $object_type );

		if ( '' !== $blog_part ) {
			$correlation_parts[] = $blog_part;
		}

		$correlation_parts[]   = $object_key;
		$object_correlation_key = self::hash_tuple( $correlation_parts );

		$risk_level    = isset( $observation['risk_level'] ) ? (string) $observation['risk_level'] : 'info';
		$classification = isset( $observation['sassh_classification'] )
			? (string) $observation['sassh_classification']
			: self::default_classification( $risk_level );
		$content_fp = isset( $observation['content_fingerprint'] ) ? (string) $observation['content_fingerprint'] : '';
		$object_fp  = isset( $observation['object_fingerprint'] ) ? (string) $observation['object_fingerprint'] : '';
		$scope_key  = (string) $execution['scope_key'];
		$now        = current_time( 'mysql', true );
		$table      = Sassh_Findings_Schema::table( 'sassh_findings' );

		$existing = $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$table} WHERE identity_key = %s", $identity_key ),
			ARRAY_A
		);

		$this->observed_identity_keys[ $execution_id ][ $identity_key ] = true;

		$title       = isset( $observation['title'] ) ? (string) $observation['title'] : $object_key;
		$description = isset( $observation['description'] ) ? (string) $observation['description'] : '';
		$metadata    = isset( $observation['metadata'] ) && is_array( $observation['metadata'] ) ? $observation['metadata'] : array();
		$meta_json   = wp_json_encode( $metadata );

		if ( ! $existing ) {
			$finding_id = 'ssf_' . bin2hex( random_bytes( 12 ) );

			$wpdb->insert(
				$table,
				array(
					'finding_id'                 => $finding_id,
					'installation_id'            => $installation_id,
					'blog_id'                    => ( null === $blog_id || '' === $blog_id ) ? null : (int) $blog_id,
					'scanner_id'                 => $scanner_id,
					'rule_id'                    => $rule_id,
					'object_type'                => $object_type,
					'object_key'                 => $object_key,
					'object_correlation_key'     => $object_correlation_key,
					'identity_key'               => $identity_key,
					'title'                      => $title,
					'description'                => $description,
					'risk_level'                 => $risk_level,
					'sassh_classification'       => $classification,
					'content_fingerprint'        => $content_fp,
					'object_fingerprint'         => $object_fp,
					'rule_fingerprint'           => isset( $observation['rule_fingerprint'] ) ? (string) $observation['rule_fingerprint'] : null,
					'first_seen_at'              => $now,
					'last_seen_at'               => $now,
					'last_scanner_execution_id'  => $execution_id,
					'last_scan_run_id'           => $execution['scan_run_id'],
					'last_scope_key'             => $scope_key,
					'detection_state'            => 'active',
					'metadata'                   => $meta_json,
					'created_at'                 => $now,
					'updated_at'                 => $now,
				)
			);

			$this->record_event( $finding_id, 'created', null, 'active', $execution_id, $execution['scan_run_id'], null );
			return;
		}

		$finding_id     = (string) $existing['finding_id'];
		$prev_fp        = (string) $existing['content_fingerprint'];
		$prev_risk      = (string) $existing['risk_level'];
		$prev_class     = (string) $existing['sassh_classification'];
		$prev_detection = (string) $existing['detection_state'];

		$wpdb->update(
			$table,
			array(
				'title'                     => $title,
				'description'               => $description,
				'risk_level'                => $risk_level,
				'sassh_classification'      => $classification,
				'content_fingerprint'       => $content_fp,
				'object_fingerprint'        => $object_fp,
				'last_seen_at'              => $now,
				'last_scanner_execution_id' => $execution_id,
				'last_scan_run_id'          => $execution['scan_run_id'],
				'last_scope_key'            => $scope_key,
				'detection_state'           => 'active',
				'metadata'                  => $meta_json,
				'updated_at'                => $now,
				'blog_id'                   => ( null === $blog_id || '' === $blog_id ) ? null : (int) $blog_id,
			),
			array( 'finding_id' => $finding_id )
		);

		if ( 'not_detected' === $prev_detection ) {
			$this->record_event( $finding_id, 'reappeared', $prev_detection, 'active', $execution_id, $execution['scan_run_id'], null );

			// Sentinel fingerprints (e.g. missing files) cannot distinguish episodes; reopen review.
			if ( self::should_invalidate_dismissal_on_reappearance( $rule_id, $content_fp ) ) {
				$this->invalidate_dismissal( $finding_id, 'reappeared_after_absence', $execution_id, $execution['scan_run_id'] );
			}
		}

		if ( self::normalize_fingerprint( $prev_fp ) !== self::normalize_fingerprint( $content_fp ) ) {
			$this->record_event( $finding_id, 'fingerprint_changed', $prev_fp, $content_fp, $execution_id, $execution['scan_run_id'], null );
			$this->invalidate_dismissal( $finding_id, 'fingerprint_changed', $execution_id, $execution['scan_run_id'] );
		}

		if ( $prev_risk !== $risk_level ) {
			$this->record_event( $finding_id, 'risk_changed', $prev_risk, $risk_level, $execution_id, $execution['scan_run_id'], null );

			if ( $this->risk_increased( $prev_risk, $risk_level ) ) {
				$this->invalidate_dismissal( $finding_id, 'risk_increased', $execution_id, $execution['scan_run_id'] );
			}
		}

		if ( $prev_class !== $classification ) {
			$this->record_event( $finding_id, 'classification_changed', $prev_class, $classification, $execution_id, $execution['scan_run_id'], null );

			if ( 'needs_review' === $prev_class && 'no_action_needed' === $classification ) {
				$this->invalidate_dismissal( $finding_id, 'classification_changed', $execution_id, $execution['scan_run_id'] );
			}
		}
	}

	/**
	 * Mark missing findings not_detected within execution scope.
	 *
	 * @param int                  $execution_id Execution id.
	 * @param array<string, mixed> $execution    Execution row.
	 * @return void
	 */
	private function mark_absent_within_scope( $execution_id, array $execution ) {
		global $wpdb;

		$scanner_id = (string) $execution['scanner_id'];
		$scope_key  = (string) $execution['scope_key'];
		$observed   = isset( $this->observed_identity_keys[ $execution_id ] )
			? array_keys( $this->observed_identity_keys[ $execution_id ] )
			: array();

		$table = Sassh_Findings_Schema::table( 'sassh_findings' );
		$now   = current_time( 'mysql', true );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT finding_id, identity_key FROM {$table}
				WHERE scanner_id = %s AND detection_state = %s AND last_scope_key = %s",
				$scanner_id,
				'active',
				$scope_key
			),
			ARRAY_A
		);

		if ( ! is_array( $rows ) ) {
			return;
		}

		$observed_lookup = array_fill_keys( $observed, true );

		foreach ( $rows as $row ) {
			$identity = (string) $row['identity_key'];

			if ( isset( $observed_lookup[ $identity ] ) ) {
				continue;
			}

			$finding_id = (string) $row['finding_id'];

			$wpdb->update(
				$table,
				array(
					'detection_state' => 'not_detected',
					'updated_at'      => $now,
				),
				array( 'finding_id' => $finding_id ),
				array( '%s', '%s' ),
				array( '%s' )
			);

			$this->record_event(
				$finding_id,
				'marked_not_detected',
				'active',
				'not_detected',
				$execution_id,
				$execution['scan_run_id'],
				array( 'scope_key' => $scope_key )
			);
		}
	}

	/**
	 * Invalidate current dismissal if present.
	 *
	 * @param string     $finding_id   Finding id.
	 * @param string     $reason       Reason.
	 * @param int|null   $execution_id Execution id.
	 * @param string|null $scan_run_id Scan run id.
	 * @return void
	 */
	private function invalidate_dismissal( $finding_id, $reason, $execution_id = null, $scan_run_id = null ) {
		global $wpdb;

		$valid = $this->get_valid_dismissal( $finding_id );

		if ( ! $valid ) {
			return;
		}

		$now   = current_time( 'mysql', true );
		$table = Sassh_Findings_Schema::table( 'sassh_dismissal_decisions' );

		$wpdb->update(
			$table,
			array(
				'invalidated_at'      => $now,
				'invalidation_reason' => $reason,
				'updated_at'          => $now,
			),
			array( 'dismissal_id' => (int) $valid['dismissal_id'] ),
			array( '%s', '%s', '%s' ),
			array( '%d' )
		);

		$this->record_event( $finding_id, 'dismissal_invalidated', 'valid', $reason, $execution_id, $scan_run_id, array( 'reason' => $reason ) );
	}

	/**
	 * @param string $finding_id Finding id.
	 * @return array<string, mixed>|null
	 */
	private function get_valid_dismissal( $finding_id ) {
		global $wpdb;

		$table = Sassh_Findings_Schema::table( 'sassh_dismissal_decisions' );

		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE finding_id = %s AND invalidated_at IS NULL ORDER BY dismissal_id DESC LIMIT 1",
				$finding_id
			),
			ARRAY_A
		);

		return is_array( $row ) ? $row : null;
	}

	/**
	 * @param int $execution_id Execution id.
	 * @return array<string, mixed>|null
	 */
	private function get_execution( $execution_id ) {
		global $wpdb;

		$table = Sassh_Findings_Schema::table( 'sassh_scanner_executions' );
		$row   = $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d", $execution_id ),
			ARRAY_A
		);

		return is_array( $row ) ? $row : null;
	}

	/**
	 * @param string      $finding_id   Finding id.
	 * @param string      $event_type   Event type.
	 * @param mixed       $previous     Previous value.
	 * @param mixed       $current      Current value.
	 * @param int|null    $execution_id Execution id.
	 * @param string|null $scan_run_id  Scan run id.
	 * @param array|null  $metadata     Metadata.
	 * @return void
	 */
	private function record_event( $finding_id, $event_type, $previous, $current, $execution_id, $scan_run_id, $metadata ) {
		global $wpdb;

		$table = Sassh_Findings_Schema::table( 'sassh_finding_events' );

		$wpdb->insert(
			$table,
			array(
				'finding_id'            => $finding_id,
				'scanner_execution_id'  => $execution_id,
				'scan_run_id'           => $scan_run_id,
				'event_type'            => $event_type,
				'previous_value'        => is_string( $previous ) || null === $previous ? $previous : wp_json_encode( $previous ),
				'current_value'         => is_string( $current ) || null === $current ? $current : wp_json_encode( $current ),
				'occurred_at'           => current_time( 'mysql', true ),
				'metadata'              => null === $metadata ? null : wp_json_encode( $metadata ),
			)
		);
	}

	/**
	 * @param string $from Previous risk.
	 * @param string $to   New risk.
	 * @return bool
	 */
	private function risk_increased( $from, $to ) {
		$from_rank = isset( self::$risk_rank[ $from ] ) ? self::$risk_rank[ $from ] : -1;
		$to_rank   = isset( self::$risk_rank[ $to ] ) ? self::$risk_rank[ $to ] : -1;

		return $to_rank > $from_rank;
	}

	/**
	 * Enrich finding with effective_status and labels.
	 *
	 * @param array<string, mixed>|null $row Finding row.
	 * @return array<string, mixed>|null
	 */
	private function enrich_finding_row( $row ) {
		if ( ! is_array( $row ) ) {
			return null;
		}

		$classification = (string) $row['sassh_classification'];
		$effective      = $classification;

		if ( 'needs_review' === $classification ) {
			$dismissal = $this->get_valid_dismissal( (string) $row['finding_id'] );

			if (
				$dismissal
				&& self::normalize_fingerprint( $dismissal['reviewed_fingerprint'] )
					=== self::normalize_fingerprint( $row['content_fingerprint'] )
			) {
				$effective = 'dismissed';
				$row['dismissal'] = array(
					'dismissed_at'         => $dismissal['dismissed_at'],
					'reviewed_fingerprint' => $dismissal['reviewed_fingerprint'],
					'action_source'        => $dismissal['action_source'],
				);
			}
		}

		$row['effective_status'] = $effective;
		$row['status']           = $effective;
		$row['status_label']     = self::status_label( $effective );
		$row['risk']             = $row['risk_level'];
		$row['risk_label']       = $this->risk_label( (string) $row['risk_level'] );

		if ( ! empty( $row['metadata'] ) && is_string( $row['metadata'] ) ) {
			$decoded = json_decode( $row['metadata'], true );
			if ( is_array( $decoded ) ) {
				$row['metadata_decoded'] = $decoded;
				foreach ( $decoded as $key => $value ) {
					if ( ! isset( $row[ $key ] ) ) {
						$row[ $key ] = $value;
					}
				}
			}
		}

		return $row;
	}

	/**
	 * @param string $risk Risk level.
	 * @return string
	 */
	private function risk_label( $risk ) {
		$map = array(
			'critical'   => __( 'Critical', 'choctaw-wp-security' ),
			'warning'    => __( 'Warning', 'choctaw-wp-security' ),
			'suspicious' => __( 'Suspicious', 'choctaw-wp-security' ),
			'info'       => __( 'Info', 'choctaw-wp-security' ),
			'safe'       => __( 'Safe', 'choctaw-wp-security' ),
		);

		return isset( $map[ $risk ] ) ? $map[ $risk ] : $risk;
	}

	/**
	 * Normalize a fingerprint string for equality checks.
	 *
	 * @param mixed $fingerprint Raw fingerprint.
	 * @return string
	 */
	public static function normalize_fingerprint( $fingerprint ) {
		return trim( (string) $fingerprint );
	}
}
