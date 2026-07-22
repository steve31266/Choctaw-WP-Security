<?php
/**
 * Sassh Findings service — object-level Findings + categories (Phase 3.4.5).
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
	const SCANNER_SCHEDULED_TASKS    = 'scheduled-tasks';
	const SCANNER_COMPONENT_SCAN     = 'component-scan';
	const SCANNER_DIRECTORY_BROWSING = 'directory-browsing';
	const RULE_UNRECOGNIZED_COMPONENT = 'unrecognized-component';
	const FINGERPRINT_MISSING        = 'sha256:missing';
	const FINGERPRINT_DIRECTORY      = 'sha256:directory';

	const RULE_UNKNOWN_HOOK            = 'unknown-hook';
	const RULE_UNREGISTERED_HANDLER    = 'unregistered-handler';
	const RULE_MISSING_SOURCE          = 'missing-source';
	const RULE_UNUSUAL_FREQUENCY       = 'unusual-frequency';
	const RULE_STALE_TASK              = 'stale-task';
	const RULE_DUPLICATE_TASK          = 'duplicate-task';
	const RULE_SUSPICIOUS_HOOK_NAME    = 'suspicious-hook-name';
	const RULE_SUSPICIOUS_ARGUMENTS    = 'suspicious-arguments';

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
	 * Finding identity keys observed during the current execution.
	 *
	 * @var array<int, array<string, true>>
	 */
	private $observed_identity_keys = array();

	/**
	 * Category keys (identity_key + "\0" + rule_id) confirmed during the current execution.
	 *
	 * @var array<int, array<string, true>>
	 */
	private $observed_category_keys = array();

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
		$this->observed_category_keys[ $execution_id ] = array();

		return $execution_id;
	}

	/**
	 * Record observations for an open execution (object-level; coalesces categories).
	 *
	 * @param int                              $execution_id Execution id.
	 * @param array<int, array<string, mixed>> $observations Observations.
	 * @return void
	 */
	public function record_observations( $execution_id, array $observations ) {
		$execution = $this->get_execution( $execution_id );

		if ( ! $execution || 'running' !== $execution['completion_status'] ) {
			return;
		}

		$grouped = array();

		foreach ( $observations as $observation ) {
			if ( ! is_array( $observation ) ) {
				continue;
			}
			$normalized = $this->normalize_object_observation( $observation, $execution );
			if ( null === $normalized ) {
				continue;
			}
			$key = $normalized['_identity_key'];
			if ( ! isset( $grouped[ $key ] ) ) {
				$grouped[ $key ] = $normalized;
				continue;
			}
			// Merge categories by rule_id (later observation wins).
			foreach ( $normalized['categories'] as $rule_id => $cat ) {
				$grouped[ $key ]['categories'][ $rule_id ] = $cat;
			}
			if ( '' !== (string) $normalized['object_fingerprint'] ) {
				$grouped[ $key ]['object_fingerprint'] = $normalized['object_fingerprint'];
			}
			if ( '' !== (string) $normalized['title'] ) {
				$grouped[ $key ]['title'] = $normalized['title'];
			}
			if ( '' !== (string) $normalized['description'] ) {
				$grouped[ $key ]['description'] = $normalized['description'];
			}
			if ( ! empty( $normalized['metadata'] ) && is_array( $normalized['metadata'] ) ) {
				$grouped[ $key ]['metadata'] = array_merge( $grouped[ $key ]['metadata'], $normalized['metadata'] );
			}
		}

		foreach ( $grouped as $observation ) {
			$this->upsert_object_observation( $execution_id, $execution, $observation );
		}
	}

	/**
	 * Finalize execution.
	 *
	 * @param int    $execution_id   Execution id.
	 * @param string $desired_status success|failed|partial|interrupted.
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
			$this->reconcile_categories_on_success( $execution_id, $execution );
			$this->mark_absent_within_scope( $execution_id, $execution );
			$this->apply_success_dismissal_reconciliation( $execution_id, $execution );
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
	 * Dismiss a finding for the current review fingerprint.
	 *
	 * @param string               $finding_id           Finding id.
	 * @param string               $reviewed_fingerprint Finding review fingerprint.
	 * @param array<string, mixed> $actor                Actor context.
	 * @return array<string, mixed>|\WP_Error
	 */
	public function dismiss( $finding_id, $reviewed_fingerprint, array $actor = array() ) {
		global $wpdb;

		Sassh_Findings_Schema::maybe_upgrade();

		$finding = $this->get_finding( $finding_id );

		if ( ! $finding ) {
			return new WP_Error( 'sassh_finding_not_found', __( 'Finding not found.', 'choctaw-wp-security' ) );
		}

		if ( ! self::can_dismiss( $finding ) ) {
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
		$finding = $this->get_finding( $finding_id );

		if ( ! $finding ) {
			return new WP_Error( 'sassh_finding_not_found', __( 'Finding not found.', 'choctaw-wp-security' ) );
		}

		$valid = $this->get_valid_dismissal( $finding_id );

		if ( ! $valid ) {
			return $this->enrich_finding_row( $finding );
		}

		$this->invalidate_dismissal( $finding_id, 'undismissed', null, null );

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
	 * Get one finding with effective status / labels / categories applied.
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
			$item     = $this->enrich_finding_row( $row );
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
	 * Scope key for WP-Cron / scheduled-tasks (options-table bounded).
	 *
	 * @param string $options_table Options table name.
	 * @return string
	 */
	public static function scheduled_tasks_scope_key( $options_table ) {
		return 'scheduled-tasks:' . (string) $options_table;
	}

	/**
	 * Scope key for Vulnerabilities / component-scan (installation-wide).
	 *
	 * @return string
	 */
	public static function component_scan_scope_key() {
		return 'component-scan:installation';
	}

	/**
	 * Scope key for Directory Browsing (fixed wordpress-root target set).
	 *
	 * @return string
	 */
	public static function directory_browsing_scope_key() {
		return 'directory-browsing:wordpress-root';
	}

	/**
	 * Risk for a directory-browsing rule_id (Phase 3.6 D4).
	 *
	 * @param string $rule_id Rule id.
	 * @return string
	 */
	public static function directory_browsing_risk_level( $rule_id ) {
		return Sassh_Directory_Exposure_Key_Normalizer::risk_level_for_rule( $rule_id );
	}

	/**
	 * Risk for a known-vulnerability category from CVSS severity code (Phase 3.5 Q4 A).
	 *
	 * @param string $severity_code n|l|m|h|c|unknown.
	 * @return string
	 */
	public static function component_scan_risk_level_for_vuln( $severity_code ) {
		$code = Sassh_Component_Key_Normalizer::normalize_severity_code( $severity_code );

		if ( 'c' === $code || 'h' === $code ) {
			return 'warning';
		}

		return 'suspicious';
	}

	/**
	 * Risk for unrecognized-component (Phase 3.5 Q4b A).
	 *
	 * @return string
	 */
	public static function component_scan_risk_level_for_unrecognized() {
		return 'suspicious';
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
	 * Higher of two risk levels (canonical severity order).
	 *
	 * @param string $a Risk level.
	 * @param string $b Risk level.
	 * @return string
	 */
	public static function stronger_risk_level( $a, $b ) {
		$a = (string) $a;
		$b = (string) $b;
		$ra = isset( self::$risk_rank[ $a ] ) ? self::$risk_rank[ $a ] : -1;
		$rb = isset( self::$risk_rank[ $b ] ) ? self::$risk_rank[ $b ] : -1;

		return $ra >= $rb ? $a : $b;
	}

	/**
	 * Rule-based risk_level for scheduled-tasks (Phase 3.4).
	 *
	 * @param string               $rule_id  Rule id.
	 * @param array<string, mixed> $evidence Optional evidence (signals, …).
	 * @return string
	 */
	public static function scheduled_tasks_risk_level( $rule_id, array $evidence = array() ) {
		$rule_id = (string) $rule_id;

		switch ( $rule_id ) {
			case self::RULE_UNKNOWN_HOOK:
			case self::RULE_UNREGISTERED_HANDLER:
			case self::RULE_MISSING_SOURCE:
			case self::RULE_UNUSUAL_FREQUENCY:
			case self::RULE_STALE_TASK:
			case self::RULE_DUPLICATE_TASK:
				return 'suspicious';

			case self::RULE_SUSPICIOUS_HOOK_NAME:
				return 'warning';

			case self::RULE_SUSPICIOUS_ARGUMENTS:
				$signals = isset( $evidence['signals'] ) && is_array( $evidence['signals'] )
					? $evidence['signals']
					: array();

				return self::suspicious_arguments_risk_from_signals( $signals );

			default:
				return 'suspicious';
		}
	}

	/**
	 * Risk for suspicious-arguments from the complete signal set.
	 *
	 * @param array<int, string> $signals Signal ids.
	 * @return string
	 */
	public static function suspicious_arguments_risk_from_signals( array $signals ) {
		$set = array();

		foreach ( $signals as $signal ) {
			$signal = (string) $signal;
			if ( '' !== $signal ) {
				$set[ $signal ] = $signal;
			}
		}

		$has_eval   = isset( $set['eval_family'] );
		$has_php    = isset( $set['php_fragment'] );
		$has_shell  = isset( $set['shell_fragment'] );
		$has_b64    = isset( $set['base64_payload'] );
		$has_js     = isset( $set['js_fragment'] );
		$has_url_ip = isset( $set['external_url'] ) || isset( $set['ip_address'] );

		// Documented Critical combinations only.
		if ( $has_eval && ( $has_b64 || $has_php || $has_shell ) ) {
			return 'critical';
		}

		if ( $has_php && $has_shell ) {
			return 'critical';
		}

		if ( $has_eval || $has_php || $has_shell || $has_b64 || $has_js ) {
			return 'warning';
		}

		if ( $has_url_ip ) {
			return 'suspicious';
		}

		return 'suspicious';
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
	 * Whether a finding (or classification key) is eligible for dismissal.
	 *
	 * Canonical rule: only CoreGuard classification `needs_review` may be dismissed.
	 * Review Not Needed (`no_action_needed`) is never dismissible.
	 *
	 * @param array<string, mixed>|string $finding_or_classification Finding row or classification key.
	 * @return bool
	 */
	public static function can_dismiss( $finding_or_classification ) {
		if ( is_array( $finding_or_classification ) ) {
			if ( isset( $finding_or_classification['sassh_classification'] ) && '' !== (string) $finding_or_classification['sassh_classification'] ) {
				return 'needs_review' === (string) $finding_or_classification['sassh_classification'];
			}

			// Fall back for report DTOs that expose only effective status / risk.
			if ( isset( $finding_or_classification['effective_status'] ) && 'dismissed' === (string) $finding_or_classification['effective_status'] ) {
				return true;
			}
			if ( isset( $finding_or_classification['status'] ) && 'dismissed' === (string) $finding_or_classification['status'] ) {
				return true;
			}
			if ( isset( $finding_or_classification['effective_status'] ) ) {
				return 'needs_review' === (string) $finding_or_classification['effective_status'];
			}
			if ( isset( $finding_or_classification['status'] ) ) {
				return 'needs_review' === (string) $finding_or_classification['status'];
			}
			if ( isset( $finding_or_classification['risk_level'] ) || isset( $finding_or_classification['risk'] ) ) {
				$risk = isset( $finding_or_classification['risk_level'] )
					? (string) $finding_or_classification['risk_level']
					: (string) $finding_or_classification['risk'];
				return 'needs_review' === self::default_classification( $risk );
			}

			return false;
		}

		return 'needs_review' === (string) $finding_or_classification;
	}

	/**
	 * Shared dismiss-control UI state for Findings detail panels.
	 *
	 * - active: Needs Review — show dismiss checkbox + Submit.
	 * - dismissed: show checked dismiss control for restore/undismiss.
	 * - not_dismissible: Review Not Needed — muted explanation only (no active controls).
	 *
	 * @param array<string, mixed> $finding Finding row or report DTO.
	 * @return string active|dismissed|not_dismissible
	 */
	public static function dismissal_control_state( array $finding ) {
		$effective = '';
		if ( isset( $finding['effective_status'] ) && '' !== (string) $finding['effective_status'] ) {
			$effective = (string) $finding['effective_status'];
		} elseif ( isset( $finding['status'] ) && '' !== (string) $finding['status'] ) {
			$effective = (string) $finding['status'];
		}

		if ( 'dismissed' === $effective ) {
			return 'dismissed';
		}

		if ( self::can_dismiss( $finding ) && 'no_action_needed' !== $effective ) {
			return 'active';
		}

		return 'not_dismissible';
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

	/**
	 * Normalize an observation to object + categories map keyed by rule_id.
	 *
	 * @param array<string, mixed> $observation Observation.
	 * @param array<string, mixed> $execution   Execution row.
	 * @return array<string, mixed>|null
	 */
	private function normalize_object_observation( array $observation, array $execution ) {
		$installation_id = Sassh_Installation_Identity::get_id();
		$scanner_id      = isset( $observation['scanner_id'] ) ? (string) $observation['scanner_id'] : (string) $execution['scanner_id'];
		$object_type     = isset( $observation['object_type'] ) ? (string) $observation['object_type'] : '';
		$object_key      = isset( $observation['object_key'] ) ? (string) $observation['object_key'] : '';
		$blog_id         = array_key_exists( 'blog_id', $observation ) ? $observation['blog_id'] : null;
		$blog_part       = ( null === $blog_id || '' === $blog_id ) ? '' : (string) (int) $blog_id;

		if ( '' === $object_type || '' === $object_key ) {
			return null;
		}

		$identity_key = self::hash_tuple(
			array(
				$installation_id,
				$scanner_id,
				$object_type,
				$blog_part,
				$object_key,
			)
		);

		$correlation_parts = array( $installation_id, $object_type );
		if ( '' !== $blog_part ) {
			$correlation_parts[] = $blog_part;
		}
		$correlation_parts[]    = $object_key;
		$object_correlation_key = self::hash_tuple( $correlation_parts );

		$categories = array();

		if ( isset( $observation['categories'] ) && is_array( $observation['categories'] ) ) {
			foreach ( $observation['categories'] as $cat ) {
				if ( ! is_array( $cat ) ) {
					continue;
				}
				$rule_id = isset( $cat['rule_id'] ) ? (string) $cat['rule_id'] : '';
				if ( '' === $rule_id ) {
					continue;
				}
				$risk = isset( $cat['risk_level'] ) ? (string) $cat['risk_level'] : 'info';
				$fp   = isset( $cat['category_fingerprint'] ) ? (string) $cat['category_fingerprint'] : '';
				if ( '' === $fp && isset( $cat['content_fingerprint'] ) ) {
					$fp = (string) $cat['content_fingerprint'];
				}
				$categories[ $rule_id ] = array(
					'rule_id'                 => $rule_id,
					'risk_level'              => $risk,
					'sassh_classification'    => isset( $cat['sassh_classification'] )
						? (string) $cat['sassh_classification']
						: self::default_classification( $risk ),
					'category_fingerprint'    => $fp,
					'title'                   => isset( $cat['title'] ) ? (string) $cat['title'] : $rule_id,
					'metadata'                => isset( $cat['metadata'] ) && is_array( $cat['metadata'] ) ? $cat['metadata'] : array(),
					'guidance_contributions'  => isset( $cat['guidance_contributions'] ) && is_array( $cat['guidance_contributions'] )
						? $cat['guidance_contributions']
						: array(),
				);
			}
		} elseif ( ! empty( $observation['rule_id'] ) ) {
			$rule_id = (string) $observation['rule_id'];
			$risk    = isset( $observation['risk_level'] ) ? (string) $observation['risk_level'] : 'info';
			$fp      = isset( $observation['content_fingerprint'] ) ? (string) $observation['content_fingerprint'] : '';
			$meta    = isset( $observation['metadata'] ) && is_array( $observation['metadata'] ) ? $observation['metadata'] : array();
			$categories[ $rule_id ] = array(
				'rule_id'                => $rule_id,
				'risk_level'             => $risk,
				'sassh_classification'   => isset( $observation['sassh_classification'] )
					? (string) $observation['sassh_classification']
					: self::default_classification( $risk ),
				'category_fingerprint'   => $fp,
				'title'                  => isset( $observation['title'] ) ? (string) $observation['title'] : $rule_id,
				'metadata'               => $meta,
				'guidance_contributions' => isset( $observation['guidance_contributions'] ) && is_array( $observation['guidance_contributions'] )
					? $observation['guidance_contributions']
					: array(),
			);
		}

		if ( empty( $categories ) ) {
			return null;
		}

		return array(
			'_identity_key'           => $identity_key,
			'_object_correlation_key' => $object_correlation_key,
			'_installation_id'        => $installation_id,
			'_blog_part'              => $blog_part,
			'scanner_id'              => $scanner_id,
			'object_type'             => $object_type,
			'object_key'              => $object_key,
			'blog_id'                 => $blog_id,
			'object_fingerprint'      => isset( $observation['object_fingerprint'] ) ? (string) $observation['object_fingerprint'] : '',
			'title'                   => isset( $observation['title'] ) ? (string) $observation['title'] : $object_key,
			'description'             => isset( $observation['description'] ) ? (string) $observation['description'] : '',
			'metadata'                => isset( $observation['metadata'] ) && is_array( $observation['metadata'] ) ? $observation['metadata'] : array(),
			'categories'              => $categories,
		);
	}

	/**
	 * Upsert one object-level observation with categories (positive path).
	 *
	 * @param int                  $execution_id Execution id.
	 * @param array<string, mixed> $execution    Execution row.
	 * @param array<string, mixed> $observation  Normalized observation.
	 * @return void
	 */
	private function upsert_object_observation( $execution_id, array $execution, array $observation ) {
		global $wpdb;

		$identity_key           = (string) $observation['_identity_key'];
		$object_correlation_key = (string) $observation['_object_correlation_key'];
		$installation_id        = (string) $observation['_installation_id'];
		$scanner_id             = (string) $observation['scanner_id'];
		$object_type            = (string) $observation['object_type'];
		$object_key             = (string) $observation['object_key'];
		$blog_id                = $observation['blog_id'];
		$object_fp              = (string) $observation['object_fingerprint'];
		$title                  = (string) $observation['title'];
		$description            = (string) $observation['description'];
		$metadata               = is_array( $observation['metadata'] ) ? $observation['metadata'] : array();
		$scope_key              = (string) $execution['scope_key'];
		$now                    = current_time( 'mysql', true );
		$table                  = Sassh_Findings_Schema::table( 'sassh_findings' );

		$existing = $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$table} WHERE identity_key = %s", $identity_key ),
			ARRAY_A
		);

		$this->observed_identity_keys[ $execution_id ][ $identity_key ] = true;

		$is_new = ! $existing;
		if ( $is_new ) {
			$finding_id = 'ssf_' . bin2hex( random_bytes( 12 ) );
			$wpdb->insert(
				$table,
				array(
					'finding_id'                => $finding_id,
					'installation_id'           => $installation_id,
					'blog_id'                   => ( null === $blog_id || '' === $blog_id ) ? null : (int) $blog_id,
					'scanner_id'                => $scanner_id,
					'object_type'               => $object_type,
					'object_key'                => $object_key,
					'object_correlation_key'    => $object_correlation_key,
					'identity_key'              => $identity_key,
					'title'                     => $title,
					'description'               => $description,
					'risk_level'                => 'info',
					'sassh_classification'      => 'needs_review',
					'content_fingerprint'       => '',
					'object_fingerprint'        => $object_fp,
					'first_seen_at'             => $now,
					'last_seen_at'              => $now,
					'last_scanner_execution_id' => $execution_id,
					'last_scan_run_id'          => $execution['scan_run_id'],
					'last_scope_key'            => $scope_key,
					'detection_state'           => 'active',
					'metadata'                  => wp_json_encode( $metadata ),
					'created_at'                => $now,
					'updated_at'                => $now,
				)
			);
			$this->record_event( $finding_id, 'created', null, 'active', $execution_id, $execution['scan_run_id'], null );
			$existing = $this->get_finding( $finding_id );
		} else {
			$finding_id     = (string) $existing['finding_id'];
			$prev_detection = (string) $existing['detection_state'];
			$prev_object_fp = (string) $existing['object_fingerprint'];

			$wpdb->update(
				$table,
				array(
					'title'                     => $title,
					'description'               => $description,
					'object_fingerprint'        => '' !== $object_fp ? $object_fp : $prev_object_fp,
					'last_seen_at'              => $now,
					'last_scanner_execution_id' => $execution_id,
					'last_scan_run_id'          => $execution['scan_run_id'],
					'last_scope_key'            => $scope_key,
					'detection_state'           => 'active',
					'metadata'                  => wp_json_encode( $metadata ),
					'updated_at'                => $now,
					'blog_id'                   => ( null === $blog_id || '' === $blog_id ) ? null : (int) $blog_id,
				),
				array( 'finding_id' => $finding_id )
			);

			if ( 'not_detected' === $prev_detection ) {
				$this->record_event( $finding_id, 'reappeared', $prev_detection, 'active', $execution_id, $execution['scan_run_id'], null );
			}

			if ( '' !== $object_fp && self::normalize_fingerprint( $prev_object_fp ) !== self::normalize_fingerprint( $object_fp ) ) {
				$this->invalidate_dismissal( $finding_id, 'object_fingerprint_changed', $execution_id, $execution['scan_run_id'] );
			}

			$existing = $this->get_finding( $finding_id );
		}

		$prev_risk  = (string) $existing['risk_level'];
		$strengthen = false;

		foreach ( $observation['categories'] as $rule_id => $cat ) {
			$cat_key = $identity_key . "\0" . $rule_id;
			$this->observed_category_keys[ $execution_id ][ $cat_key ] = true;

			$result = $this->upsert_category( $finding_id, $cat, $execution_id, $execution['scan_run_id'], $now );
			if ( ! empty( $result['strengthen'] ) ) {
				$strengthen = true;
			}
			if ( ! empty( $result['new_category'] ) ) {
				$strengthen = true;
				$this->invalidate_dismissal( $finding_id, 'category_added', $execution_id, $execution['scan_run_id'] );
			}
			if ( ! empty( $result['material_non_weakening'] ) ) {
				$strengthen = true;
				$this->invalidate_dismissal( $finding_id, 'category_fingerprint_changed', $execution_id, $execution['scan_run_id'] );
			}
		}

		// Reappearance with missing-style evidence reopens.
		if ( ! $is_new && 'not_detected' === ( isset( $prev_detection ) ? $prev_detection : '' ) ) {
			$active_cats = $this->get_categories_for_finding( $finding_id, 'active' );
			foreach ( $active_cats as $ac ) {
				if ( self::should_invalidate_dismissal_on_reappearance( $ac['rule_id'], $ac['category_fingerprint'] ) ) {
					$this->invalidate_dismissal( $finding_id, 'reappeared_after_absence', $execution_id, $execution['scan_run_id'] );
					break;
				}
			}
		}

		$this->recompute_finding_aggregates( $finding_id, $execution_id, $execution['scan_run_id'], true );

		$updated = $this->get_finding( $finding_id );
		if ( $updated && $this->risk_increased( $prev_risk, (string) $updated['risk_level'] ) ) {
			$this->invalidate_dismissal( $finding_id, 'risk_increased', $execution_id, $execution['scan_run_id'] );
		}

		unset( $strengthen );
	}

	/**
	 * Upsert one category row.
	 *
	 * @param string               $finding_id   Finding id.
	 * @param array<string, mixed> $cat          Category payload.
	 * @param int                  $execution_id Execution id.
	 * @param string|null          $scan_run_id  Scan run id.
	 * @param string               $now          Timestamp.
	 * @return array<string, bool>
	 */
	private function upsert_category( $finding_id, array $cat, $execution_id, $scan_run_id, $now ) {
		global $wpdb;

		$table   = Sassh_Findings_Schema::table( 'sassh_finding_categories' );
		$rule_id = (string) $cat['rule_id'];
		$out     = array(
			'new_category'            => false,
			'material_non_weakening'  => false,
			'strengthen'              => false,
		);

		$existing = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE finding_id = %s AND rule_id = %s",
				$finding_id,
				$rule_id
			),
			ARRAY_A
		);

		$risk  = (string) $cat['risk_level'];
		$class = (string) $cat['sassh_classification'];
		$fp    = (string) $cat['category_fingerprint'];
		$title = (string) $cat['title'];
		$meta  = is_array( $cat['metadata'] ) ? $cat['metadata'] : array();
		if ( ! empty( $cat['guidance_contributions'] ) ) {
			$meta['guidance_contributions'] = $cat['guidance_contributions'];
		}

		if ( ! $existing ) {
			$category_id = 'ssc_' . bin2hex( random_bytes( 12 ) );
			$wpdb->insert(
				$table,
				array(
					'category_id'               => $category_id,
					'finding_id'                => $finding_id,
					'rule_id'                   => $rule_id,
					'risk_level'                => $risk,
					'sassh_classification'      => $class,
					'category_fingerprint'      => $fp,
					'title'                     => $title,
					'detection_state'           => 'active',
					'first_seen_at'             => $now,
					'last_seen_at'              => $now,
					'last_scanner_execution_id' => $execution_id,
					'metadata'                  => wp_json_encode( $meta ),
					'created_at'                => $now,
					'updated_at'                => $now,
				)
			);
			$this->record_event(
				$finding_id,
				'category_added',
				null,
				$rule_id,
				$execution_id,
				$scan_run_id,
				array( 'rule_id' => $rule_id, 'category_id' => $category_id )
			);
			$out['new_category'] = true;
			$out['strengthen']   = true;
			return $out;
		}

		$prev_fp   = (string) $existing['category_fingerprint'];
		$prev_risk = (string) $existing['risk_level'];
		$prev_det  = (string) $existing['detection_state'];

		$wpdb->update(
			$table,
			array(
				'risk_level'                => $risk,
				'sassh_classification'      => $class,
				'category_fingerprint'      => $fp,
				'title'                     => $title,
				'detection_state'           => 'active',
				'last_seen_at'              => $now,
				'last_scanner_execution_id' => $execution_id,
				'metadata'                  => wp_json_encode( $meta ),
				'updated_at'                => $now,
			),
			array( 'category_id' => (string) $existing['category_id'] )
		);

		if ( 'not_detected' === $prev_det ) {
			$this->record_event(
				$finding_id,
				'category_added',
				'not_detected',
				'active',
				$execution_id,
				$scan_run_id,
				array( 'rule_id' => $rule_id, 'reactivated' => true )
			);
			$out['new_category'] = true;
			$out['strengthen']   = true;
		}

		if ( self::normalize_fingerprint( $prev_fp ) !== self::normalize_fingerprint( $fp ) ) {
			$this->record_event(
				$finding_id,
				'category_fingerprint_changed',
				$prev_fp,
				$fp,
				$execution_id,
				$scan_run_id,
				array( 'rule_id' => $rule_id )
			);
			if ( $this->risk_increased( $prev_risk, $risk ) || ! $this->risk_decreased( $prev_risk, $risk ) ) {
				// Fingerprint changed without a risk decrease → treat as material non-weakening (or same risk material change).
				if ( ! $this->risk_decreased( $prev_risk, $risk ) ) {
					$out['material_non_weakening'] = true;
					$out['strengthen']             = true;
				}
			}
		}

		if ( $this->risk_increased( $prev_risk, $risk ) ) {
			$out['strengthen'] = true;
		}

		return $out;
	}

	/**
	 * Recompute finding aggregates from active categories.
	 *
	 * @param string      $finding_id     Finding id.
	 * @param int|null    $execution_id   Execution id.
	 * @param string|null $scan_run_id    Scan run id.
	 * @param bool        $ratchet_only   If true, never lower risk/classification.
	 * @return void
	 */
	private function recompute_finding_aggregates( $finding_id, $execution_id = null, $scan_run_id = null, $ratchet_only = false ) {
		global $wpdb;

		$finding = $this->get_finding( $finding_id );
		if ( ! $finding ) {
			return;
		}

		$active = $this->get_categories_for_finding( $finding_id, 'active' );
		$prev_risk  = (string) $finding['risk_level'];
		$prev_class = (string) $finding['sassh_classification'];
		$prev_fp    = (string) $finding['content_fingerprint'];

		if ( empty( $active ) ) {
			$risk  = $prev_risk;
			$class = $prev_class;
			if ( ! $ratchet_only ) {
				$risk  = 'info';
				$class = 'no_action_needed';
			}
		} else {
			$risk  = 'safe';
			$class = 'no_action_needed';
			foreach ( $active as $cat ) {
				$risk = self::stronger_risk_level( $risk, (string) $cat['risk_level'] );
				if ( 'needs_review' === (string) $cat['sassh_classification'] ) {
					$class = 'needs_review';
				}
			}
			if ( $ratchet_only ) {
				$risk = self::stronger_risk_level( $prev_risk, $risk );
				if ( 'needs_review' === $prev_class ) {
					$class = 'needs_review';
				}
			}
		}

		$review_fp = self::compute_review_fingerprint(
			(string) $finding['object_fingerprint'],
			$risk,
			$active
		);

		$table = Sassh_Findings_Schema::table( 'sassh_findings' );
		$wpdb->update(
			$table,
			array(
				'risk_level'           => $risk,
				'sassh_classification' => $class,
				'content_fingerprint'  => $review_fp,
				'updated_at'           => current_time( 'mysql', true ),
			),
			array( 'finding_id' => $finding_id )
		);

		if ( $prev_risk !== $risk ) {
			$this->record_event( $finding_id, 'risk_changed', $prev_risk, $risk, $execution_id, $scan_run_id, null );
		}
		if ( $prev_class !== $class ) {
			$this->record_event( $finding_id, 'classification_changed', $prev_class, $class, $execution_id, $scan_run_id, null );
		}
		if ( self::normalize_fingerprint( $prev_fp ) !== self::normalize_fingerprint( $review_fp ) ) {
			$this->record_event( $finding_id, 'fingerprint_changed', $prev_fp, $review_fp, $execution_id, $scan_run_id, null );
		}
	}

	/**
	 * Compute Finding review fingerprint (dismissal version).
	 *
	 * @param string                    $object_fp Object fingerprint.
	 * @param string                    $risk      Aggregate risk.
	 * @param array<int, array<string, mixed>> $active_categories Active categories.
	 * @return string
	 */
	public static function compute_review_fingerprint( $object_fp, $risk, array $active_categories ) {
		$parts = array();
		foreach ( $active_categories as $cat ) {
			$parts[] = (string) $cat['rule_id'] . '=' . self::normalize_fingerprint( $cat['category_fingerprint'] );
		}
		sort( $parts, SORT_STRING );

		return 'sha256:' . self::hash_tuple(
			array_merge(
				array( (string) $object_fp, (string) $risk ),
				$parts
			)
		);
	}

	/**
	 * Categories for a finding.
	 *
	 * @param string      $finding_id Finding id.
	 * @param string|null $state      Optional detection_state filter.
	 * @return array<int, array<string, mixed>>
	 */
	public function get_categories_for_finding( $finding_id, $state = null ) {
		global $wpdb;

		$table = Sassh_Findings_Schema::table( 'sassh_finding_categories' );

		if ( null === $state ) {
			$rows = $wpdb->get_results(
				$wpdb->prepare( "SELECT * FROM {$table} WHERE finding_id = %s ORDER BY rule_id ASC", $finding_id ),
				ARRAY_A
			);
		} else {
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT * FROM {$table} WHERE finding_id = %s AND detection_state = %s ORDER BY rule_id ASC",
					$finding_id,
					$state
				),
				ARRAY_A
			);
		}

		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Select primary category from active rows.
	 *
	 * @param array<int, array<string, mixed>> $categories Categories.
	 * @return array<string, mixed>|null
	 */
	public static function select_primary_category( array $categories ) {
		$best = null;
		foreach ( $categories as $cat ) {
			if ( 'active' !== (string) ( isset( $cat['detection_state'] ) ? $cat['detection_state'] : 'active' ) ) {
				continue;
			}
			if ( null === $best ) {
				$best = $cat;
				continue;
			}
			$br = isset( self::$risk_rank[ $best['risk_level'] ] ) ? self::$risk_rank[ $best['risk_level'] ] : -1;
			$cr = isset( self::$risk_rank[ $cat['risk_level'] ] ) ? self::$risk_rank[ $cat['risk_level'] ] : -1;
			if ( $cr > $br ) {
				$best = $cat;
				continue;
			}
			if ( $cr < $br ) {
				continue;
			}
			$bc = ( 'needs_review' === (string) $best['sassh_classification'] ) ? 1 : 0;
			$cc = ( 'needs_review' === (string) $cat['sassh_classification'] ) ? 1 : 0;
			if ( $cc > $bc ) {
				$best = $cat;
				continue;
			}
			if ( $cc < $bc ) {
				continue;
			}
			if ( strcmp( (string) $cat['rule_id'], (string) $best['rule_id'] ) < 0 ) {
				$best = $cat;
			}
		}
		return $best;
	}

	/**
	 * On success: clear unobserved categories; absent findings with no active cats.
	 *
	 * @param int                  $execution_id Execution id.
	 * @param array<string, mixed> $execution    Execution row.
	 * @return void
	 */
	private function reconcile_categories_on_success( $execution_id, array $execution ) {
		global $wpdb;

		$confirmed = isset( $this->observed_category_keys[ $execution_id ] )
			? $this->observed_category_keys[ $execution_id ]
			: array();
		$observed_identities = isset( $this->observed_identity_keys[ $execution_id ] )
			? $this->observed_identity_keys[ $execution_id ]
			: array();

		$findings_table = Sassh_Findings_Schema::table( 'sassh_findings' );
		$cat_table      = Sassh_Findings_Schema::table( 'sassh_finding_categories' );
		$scanner_id     = (string) $execution['scanner_id'];
		$scope_key      = (string) $execution['scope_key'];
		$now            = current_time( 'mysql', true );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$findings = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$findings_table}
				WHERE scanner_id = %s AND detection_state = %s AND last_scope_key = %s",
				$scanner_id,
				'active',
				$scope_key
			),
			ARRAY_A
		);

		if ( ! is_array( $findings ) ) {
			return;
		}

		foreach ( $findings as $finding ) {
			$finding_id   = (string) $finding['finding_id'];
			$identity_key = (string) $finding['identity_key'];

			if ( ! isset( $observed_identities[ $identity_key ] ) ) {
				continue; // Handled by mark_absent_within_scope.
			}

			$cats = $this->get_categories_for_finding( $finding_id, 'active' );
			foreach ( $cats as $cat ) {
				$cat_key = $identity_key . "\0" . $cat['rule_id'];
				if ( isset( $confirmed[ $cat_key ] ) ) {
					continue;
				}
				$wpdb->update(
					$cat_table,
					array(
						'detection_state' => 'not_detected',
						'updated_at'      => $now,
					),
					array( 'category_id' => (string) $cat['category_id'] )
				);
				$this->record_event(
					$finding_id,
					'category_cleared',
					'active',
					'not_detected',
					$execution_id,
					$execution['scan_run_id'],
					array( 'rule_id' => $cat['rule_id'] )
				);
			}

			$remaining = $this->get_categories_for_finding( $finding_id, 'active' );
			if ( empty( $remaining ) ) {
				$wpdb->update(
					$findings_table,
					array(
						'detection_state' => 'not_detected',
						'updated_at'      => $now,
					),
					array( 'finding_id' => $finding_id )
				);
				$this->record_event(
					$finding_id,
					'marked_not_detected',
					'active',
					'not_detected',
					$execution_id,
					$execution['scan_run_id'],
					array( 'reason' => 'no_active_categories' )
				);
			} else {
				$this->recompute_finding_aggregates( $finding_id, $execution_id, $execution['scan_run_id'], false );
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
			? $this->observed_identity_keys[ $execution_id ]
			: array();

		$table = Sassh_Findings_Schema::table( 'sassh_findings' );
		$now   = current_time( 'mysql', true );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT finding_id, identity_key, detection_state FROM {$table}
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

		foreach ( $rows as $row ) {
			$identity = (string) $row['identity_key'];
			if ( isset( $observed[ $identity ] ) ) {
				continue;
			}

			$finding_id = (string) $row['finding_id'];
			$wpdb->update(
				$table,
				array(
					'detection_state' => 'not_detected',
					'updated_at'      => $now,
				),
				array( 'finding_id' => $finding_id )
			);

			// Clear active categories on fully absent object.
			$cat_table = Sassh_Findings_Schema::table( 'sassh_finding_categories' );
			$active_cats = $this->get_categories_for_finding( $finding_id, 'active' );
			foreach ( $active_cats as $cat ) {
				$wpdb->update(
					$cat_table,
					array(
						'detection_state' => 'not_detected',
						'updated_at'      => $now,
					),
					array( 'category_id' => (string) $cat['category_id'] )
				);
				$this->record_event(
					$finding_id,
					'category_cleared',
					'active',
					'not_detected',
					$execution_id,
					$execution['scan_run_id'],
					array( 'rule_id' => $cat['rule_id'], 'reason' => 'finding_absent' )
				);
			}

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
	 * After success reconcile: carry-forward or keep dismissals.
	 *
	 * @param int                  $execution_id Execution id.
	 * @param array<string, mixed> $execution    Execution row.
	 * @return void
	 */
	private function apply_success_dismissal_reconciliation( $execution_id, array $execution ) {
		global $wpdb;

		$observed = isset( $this->observed_identity_keys[ $execution_id ] )
			? $this->observed_identity_keys[ $execution_id ]
			: array();

		if ( empty( $observed ) ) {
			return;
		}

		$table = Sassh_Findings_Schema::table( 'sassh_findings' );
		foreach ( array_keys( $observed ) as $identity_key ) {
			$finding = $wpdb->get_row(
				$wpdb->prepare( "SELECT * FROM {$table} WHERE identity_key = %s", $identity_key ),
				ARRAY_A
			);
			if ( ! is_array( $finding ) || 'active' !== $finding['detection_state'] ) {
				continue;
			}

			$finding_id = (string) $finding['finding_id'];
			$valid      = $this->get_valid_dismissal( $finding_id );
			if ( ! $valid ) {
				continue;
			}

			// Strengthening already invalidated during record. Remaining = same or weakening.
			$current_fp = self::normalize_fingerprint( $finding['content_fingerprint'] );
			$reviewed   = self::normalize_fingerprint( $valid['reviewed_fingerprint'] );

			if ( $current_fp === $reviewed ) {
				continue;
			}

			// Carry forward onto weaker/cleared-category review fingerprint.
			$now = current_time( 'mysql', true );
			$dtable = Sassh_Findings_Schema::table( 'sassh_dismissal_decisions' );
			$wpdb->update(
				$dtable,
				array(
					'reviewed_fingerprint' => $current_fp,
					'updated_at'           => $now,
				),
				array( 'dismissal_id' => (int) $valid['dismissal_id'] )
			);
			$this->record_event(
				$finding_id,
				'dismissal_carried_forward',
				$reviewed,
				$current_fp,
				$execution_id,
				$execution['scan_run_id'],
				array( 'reason' => 'weakening_or_category_removal' )
			);
		}
	}

	/**
	 * Invalidate current dismissal if present.
	 *
	 * @param string      $finding_id   Finding id.
	 * @param string      $reason       Reason.
	 * @param int|null    $execution_id Execution id.
	 * @param string|null $scan_run_id  Scan run id.
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
				'finding_id'           => $finding_id,
				'scanner_execution_id' => $execution_id,
				'scan_run_id'          => $scan_run_id,
				'event_type'           => $event_type,
				'previous_value'       => is_string( $previous ) || null === $previous ? $previous : wp_json_encode( $previous ),
				'current_value'        => is_string( $current ) || null === $current ? $current : wp_json_encode( $current ),
				'occurred_at'          => current_time( 'mysql', true ),
				'metadata'             => null === $metadata ? null : wp_json_encode( $metadata ),
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
	 * @param string $from Previous risk.
	 * @param string $to   New risk.
	 * @return bool
	 */
	private function risk_decreased( $from, $to ) {
		$from_rank = isset( self::$risk_rank[ $from ] ) ? self::$risk_rank[ $from ] : -1;
		$to_rank   = isset( self::$risk_rank[ $to ] ) ? self::$risk_rank[ $to ] : -1;

		return $to_rank < $from_rank;
	}

	/**
	 * Enrich finding with effective_status, categories, guidance, labels.
	 *
	 * @param array<string, mixed>|null $row Finding row.
	 * @return array<string, mixed>|null
	 */
	private function enrich_finding_row( $row ) {
		if ( ! is_array( $row ) ) {
			return null;
		}

		$finding_id = (string) $row['finding_id'];
		$all_cats   = $this->get_categories_for_finding( $finding_id );
		$active     = array();
		$cleared    = array();

		foreach ( $all_cats as $cat ) {
			$decoded = array();
			if ( ! empty( $cat['metadata'] ) && is_string( $cat['metadata'] ) ) {
				$tmp = json_decode( $cat['metadata'], true );
				if ( is_array( $tmp ) ) {
					$decoded = $tmp;
				}
			}
			$item = array(
				'category_id'            => $cat['category_id'],
				'rule_id'                => $cat['rule_id'],
				'risk_level'             => $cat['risk_level'],
				'risk'                   => $cat['risk_level'],
				'sassh_classification'   => $cat['sassh_classification'],
				'category_fingerprint'   => $cat['category_fingerprint'],
				'title'                  => $cat['title'],
				'detection_state'        => $cat['detection_state'],
				'first_seen_at'          => $cat['first_seen_at'],
				'last_seen_at'           => $cat['last_seen_at'],
				'metadata'               => $decoded,
				'category_label'         => isset( $decoded['category_label'] ) ? $decoded['category_label'] : $cat['title'],
			);
			foreach ( $decoded as $k => $v ) {
				if ( ! isset( $item[ $k ] ) ) {
					$item[ $k ] = $v;
				}
			}
			if ( 'active' === $cat['detection_state'] ) {
				$active[] = $item;
			} else {
				$cleared[] = $item;
			}
		}

		$primary = self::select_primary_category( $active );
		$row['categories']            = $active;
		$row['previously_detected']   = $cleared;
		$row['extra_rule_count']      = max( 0, count( $active ) - 1 );
		$row['primary_rule_id']       = $primary ? (string) $primary['rule_id'] : '';
		$row['category_label']        = $primary
			? ( isset( $primary['category_label'] ) ? (string) $primary['category_label'] : (string) $primary['title'] )
			: '';
		if ( $row['extra_rule_count'] > 0 && '' !== $row['category_label'] ) {
			$row['category_label_display'] = $row['category_label'] . ' +' . $row['extra_rule_count'];
		} else {
			$row['category_label_display'] = $row['category_label'];
		}

		$classification = (string) $row['sassh_classification'];
		$effective      = $classification;

		if ( 'needs_review' === $classification ) {
			$dismissal = $this->get_valid_dismissal( $finding_id );
			if ( $dismissal ) {
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
		$row['can_dismiss']      = self::can_dismiss( $row );
		$row['dismissal_control_state'] = self::dismissal_control_state( $row );
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

		// Prefer composed guidance; fall back to legacy metadata strings.
		if ( class_exists( 'Sassh_Finding_Guidance_Composer' ) ) {
			$guidance = Sassh_Finding_Guidance_Composer::compose( $active, (string) $row['scanner_id'] );
			$row['guidance'] = $guidance;
			if ( ! empty( $guidance['why'] ) ) {
				$row['why_seeing_this'] = array_map(
					static function ( $item ) {
						return is_array( $item ) && isset( $item['text'] ) ? $item['text'] : (string) $item;
					},
					$guidance['why']
				);
			}
			if ( ! empty( $guidance['how_to_proceed'] ) ) {
				$row['how_to_proceed'] = array_map(
					static function ( $item ) {
						return is_array( $item ) && isset( $item['text'] ) ? $item['text'] : (string) $item;
					},
					$guidance['how_to_proceed']
				);
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
