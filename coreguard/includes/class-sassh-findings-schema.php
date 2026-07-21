<?php
/**
 * Sassh Findings database schema (network-wide via base_prefix).
 *
 * Schema v2: object-level Findings + sassh_finding_categories (Phase 3.4.5).
 * Upgrade from v1 is a destructive reset of Sassh Findings tables only.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Creates and upgrades Sassh Findings tables.
 */
class Sassh_Findings_Schema {

	const SCHEMA_VERSION     = 2;
	const SCHEMA_VERSION_KEY = 'sassh_findings_schema_version';

	/**
	 * Exact Findings table suffixes (base_prefix + suffix).
	 *
	 * @return array<int, string>
	 */
	public static function findings_table_suffixes() {
		return array(
			'sassh_scanner_executions',
			'sassh_findings',
			'sassh_finding_categories',
			'sassh_dismissal_decisions',
			'sassh_finding_events',
		);
	}

	/**
	 * Ensure schema is at current version.
	 *
	 * @return void
	 */
	public static function maybe_upgrade() {
		$current = (int) self::get_network_option( self::SCHEMA_VERSION_KEY, 0 );

		if ( $current >= self::SCHEMA_VERSION ) {
			return;
		}

		if ( $current > 0 && $current < self::SCHEMA_VERSION ) {
			self::reset_findings_tables();
			self::clear_v1_report_caches();
		}

		self::install();

		if ( ! self::validate_v2_schema() ) {
			return;
		}

		self::update_network_option( self::SCHEMA_VERSION_KEY, self::SCHEMA_VERSION );
		Sassh_Installation_Identity::get_id();
	}

	/**
	 * Drop only Sassh Findings tables (idempotent). Retains sassh_installation_id.
	 *
	 * @return void
	 */
	public static function reset_findings_tables() {
		global $wpdb;

		foreach ( self::findings_table_suffixes() as $suffix ) {
			$table = self::table( $suffix );
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
		}

		// Allow retry: do not mark version current until validate succeeds.
		self::update_network_option( self::SCHEMA_VERSION_KEY, 0 );
	}

	/**
	 * Clear cached Findings-backed report DTOs that may still be v1-shaped.
	 *
	 * @return void
	 */
	public static function clear_v1_report_caches() {
		global $wpdb;

		$like_patterns = array(
			'%choctaw_wp_security%exposed_files%result%',
			'%choctaw_wp_security%uploads_folder%result%',
			'%choctaw_wp_security%mu_plugins%result%',
			'%choctaw_wp_security%core_checksum%result%',
			'%choctaw_wp_security%database_scan%result%',
			'%choctaw_wp_security%scheduled_tasks%result%',
			'%cws_%result%',
		);

		foreach ( $like_patterns as $like ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
					'_transient_' . $like,
					'_transient_timeout_' . $like
				)
			);

			if ( is_multisite() && ! empty( $wpdb->sitemeta ) ) {
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$wpdb->query(
					$wpdb->prepare(
						"DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s OR meta_key LIKE %s",
						'_site_transient_' . $like,
						'_site_transient_timeout_' . $like
					)
				);
			}
		}

		// User-meta last-run payloads used by admin report tabs.
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query(
			"DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE '%choctaw_wp_security%result%' OR meta_key LIKE '%cws_%scan%result%'"
		);

		/**
		 * Fires after Sassh Findings v1 report caches are cleared (schema reset).
		 *
		 * @since 1.9.3.5
		 */
		do_action( 'sassh_findings_v1_caches_cleared' );
	}

	/**
	 * Install or recreate v2 tables.
	 *
	 * @return void
	 */
	public static function install() {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset = $wpdb->get_charset_collate();
		$base    = $wpdb->base_prefix;

		$executions  = $base . 'sassh_scanner_executions';
		$findings    = $base . 'sassh_findings';
		$categories  = $base . 'sassh_finding_categories';
		$dismissals  = $base . 'sassh_dismissal_decisions';
		$events      = $base . 'sassh_finding_events';

		$sql = array();

		$sql[] = "CREATE TABLE {$executions} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			scanner_id varchar(64) NOT NULL DEFAULT '',
			scan_run_id varchar(64) DEFAULT NULL,
			run_type varchar(32) NOT NULL DEFAULT 'individual',
			run_source varchar(32) NOT NULL DEFAULT 'wordpress_admin',
			scope_key varchar(255) NOT NULL DEFAULT '',
			started_at datetime NOT NULL,
			completed_at datetime DEFAULT NULL,
			completion_status varchar(32) NOT NULL DEFAULT 'running',
			meta longtext NULL,
			PRIMARY KEY  (id),
			KEY scanner_status (scanner_id, completion_status),
			KEY scope_key (scope_key)
		) {$charset};";

		// Object-level Finding: identity excludes rule_id (Phase 3.4.5).
		$sql[] = "CREATE TABLE {$findings} (
			finding_id varchar(64) NOT NULL,
			installation_id varchar(64) NOT NULL DEFAULT '',
			blog_id bigint(20) DEFAULT NULL,
			scanner_id varchar(64) NOT NULL DEFAULT '',
			object_type varchar(64) NOT NULL DEFAULT '',
			object_key text NOT NULL,
			object_correlation_key varchar(64) NOT NULL DEFAULT '',
			identity_key varchar(64) NOT NULL DEFAULT '',
			title text NULL,
			description longtext NULL,
			risk_level varchar(32) NOT NULL DEFAULT 'info',
			sassh_classification varchar(32) NOT NULL DEFAULT 'needs_review',
			content_fingerprint varchar(128) NOT NULL DEFAULT '',
			object_fingerprint varchar(128) NOT NULL DEFAULT '',
			first_seen_at datetime NOT NULL,
			last_seen_at datetime NOT NULL,
			last_scanner_execution_id bigint(20) unsigned DEFAULT NULL,
			last_scan_run_id varchar(64) DEFAULT NULL,
			last_scope_key varchar(255) NOT NULL DEFAULT '',
			detection_state varchar(32) NOT NULL DEFAULT 'active',
			metadata longtext NULL,
			created_at datetime NOT NULL,
			updated_at datetime NOT NULL,
			PRIMARY KEY  (finding_id),
			UNIQUE KEY identity_key (identity_key),
			KEY object_correlation_key (object_correlation_key),
			KEY scanner_detection (scanner_id, detection_state),
			KEY risk_level (risk_level),
			KEY last_seen_at (last_seen_at)
		) {$charset};";

		$sql[] = "CREATE TABLE {$categories} (
			category_id varchar(64) NOT NULL,
			finding_id varchar(64) NOT NULL DEFAULT '',
			rule_id varchar(128) NOT NULL DEFAULT '',
			risk_level varchar(32) NOT NULL DEFAULT 'info',
			sassh_classification varchar(32) NOT NULL DEFAULT 'needs_review',
			category_fingerprint varchar(128) NOT NULL DEFAULT '',
			title text NULL,
			detection_state varchar(32) NOT NULL DEFAULT 'active',
			first_seen_at datetime NOT NULL,
			last_seen_at datetime NOT NULL,
			last_scanner_execution_id bigint(20) unsigned DEFAULT NULL,
			metadata longtext NULL,
			created_at datetime NOT NULL,
			updated_at datetime NOT NULL,
			PRIMARY KEY  (category_id),
			UNIQUE KEY finding_rule (finding_id, rule_id),
			KEY finding_id (finding_id),
			KEY rule_id (rule_id),
			KEY detection_state (detection_state)
		) {$charset};";

		$sql[] = "CREATE TABLE {$dismissals} (
			dismissal_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			finding_id varchar(64) NOT NULL DEFAULT '',
			reviewed_fingerprint varchar(128) NOT NULL DEFAULT '',
			dismissed_at datetime NOT NULL,
			actor_type varchar(32) NOT NULL DEFAULT '',
			actor_identifier varchar(191) NOT NULL DEFAULT '',
			action_source varchar(64) NOT NULL DEFAULT '',
			reason text NULL,
			invalidated_at datetime DEFAULT NULL,
			invalidation_reason varchar(191) DEFAULT NULL,
			created_at datetime NOT NULL,
			updated_at datetime NOT NULL,
			PRIMARY KEY  (dismissal_id),
			KEY finding_id (finding_id),
			KEY finding_valid (finding_id, invalidated_at)
		) {$charset};";

		$sql[] = "CREATE TABLE {$events} (
			event_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			finding_id varchar(64) NOT NULL DEFAULT '',
			scanner_execution_id bigint(20) unsigned DEFAULT NULL,
			scan_run_id varchar(64) DEFAULT NULL,
			event_type varchar(64) NOT NULL DEFAULT '',
			previous_value longtext NULL,
			current_value longtext NULL,
			occurred_at datetime NOT NULL,
			metadata longtext NULL,
			PRIMARY KEY  (event_id),
			KEY finding_id (finding_id),
			KEY event_type (event_type),
			KEY occurred_at (occurred_at)
		) {$charset};";

		foreach ( $sql as $statement ) {
			dbDelta( $statement );
		}
	}

	/**
	 * Validate v2 tables exist with required columns before bumping version.
	 *
	 * @return bool
	 */
	public static function validate_v2_schema() {
		global $wpdb;

		$findings = self::table( 'sassh_findings' );
		$cats     = self::table( 'sassh_finding_categories' );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$findings_ok = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $findings ) ) === $findings;
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$cats_ok = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $cats ) ) === $cats;

		if ( ! $findings_ok || ! $cats_ok ) {
			return false;
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$finding_cols = $wpdb->get_col( "DESCRIBE {$findings}", 0 );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$cat_cols = $wpdb->get_col( "DESCRIBE {$cats}", 0 );

		if ( ! is_array( $finding_cols ) || ! is_array( $cat_cols ) ) {
			return false;
		}

		// v2 findings must not require rule_id; must have identity_key.
		if ( in_array( 'rule_id', $finding_cols, true ) ) {
			return false;
		}

		foreach ( array( 'finding_id', 'identity_key', 'object_type', 'object_key', 'content_fingerprint' ) as $col ) {
			if ( ! in_array( $col, $finding_cols, true ) ) {
				return false;
			}
		}

		foreach ( array( 'category_id', 'finding_id', 'rule_id', 'category_fingerprint', 'detection_state' ) as $col ) {
			if ( ! in_array( $col, $cat_cols, true ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Table name helpers.
	 *
	 * @param string $suffix Table suffix without prefix (e.g. sassh_findings).
	 * @return string
	 */
	public static function table( $suffix ) {
		global $wpdb;

		return $wpdb->base_prefix . $suffix;
	}

	/**
	 * @param string $key     Option key.
	 * @param mixed  $default Default.
	 * @return mixed
	 */
	private static function get_network_option( $key, $default = null ) {
		if ( is_multisite() ) {
			return get_network_option( null, $key, $default );
		}

		return get_option( $key, $default );
	}

	/**
	 * @param string $key   Option key.
	 * @param mixed  $value Value.
	 * @return void
	 */
	private static function update_network_option( $key, $value ) {
		if ( is_multisite() ) {
			update_network_option( null, $key, $value );
			return;
		}

		update_option( $key, $value, false );
	}
}
