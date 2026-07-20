<?php
/**
 * Sassh Findings database schema (network-wide via base_prefix).
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Creates and upgrades Sassh Findings tables.
 */
class Sassh_Findings_Schema {

	const SCHEMA_VERSION      = 1;
	const SCHEMA_VERSION_KEY  = 'sassh_findings_schema_version';

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

		self::install();
		self::update_network_option( self::SCHEMA_VERSION_KEY, self::SCHEMA_VERSION );
		Sassh_Installation_Identity::get_id();
	}

	/**
	 * Install or upgrade tables.
	 *
	 * @return void
	 */
	public static function install() {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset = $wpdb->get_charset_collate();
		$base    = $wpdb->base_prefix;

		$executions = $base . 'sassh_scanner_executions';
		$findings   = $base . 'sassh_findings';
		$dismissals = $base . 'sassh_dismissal_decisions';
		$events     = $base . 'sassh_finding_events';

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

		$sql[] = "CREATE TABLE {$findings} (
			finding_id varchar(64) NOT NULL,
			installation_id varchar(64) NOT NULL DEFAULT '',
			blog_id bigint(20) DEFAULT NULL,
			scanner_id varchar(64) NOT NULL DEFAULT '',
			rule_id varchar(128) NOT NULL DEFAULT '',
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
			rule_fingerprint varchar(128) DEFAULT NULL,
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
