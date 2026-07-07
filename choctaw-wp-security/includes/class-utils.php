<?php
/**
 * Shared helpers for Choctaw WP Security.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Utility methods used across plugin modules.
 */
class Choctaw_Wp_Security_Utils {

	const OPTION_KEY         = 'choctaw_wp_security_options';
	const LOCKOUT_LOG_KEY    = 'choctaw_wp_security_lockout_log';
	const LOCKOUT_LOG_LIMIT  = 20;
	const REPORT_PAGE_SIZE   = 20;
	const REPORT_RESULT_TTL  = 43200;
	const USER_META_DATABASE_SCAN_RESULT = 'cws_database_scan_result';
	const USER_META_CORE_CHECKSUM_RESULT = 'cws_core_checksum_result';
	const USER_META_EXPOSED_FOLDERS_RESULT = 'cws_exposed_folders_result';
	const USER_META_USERS_TABLE_RESULT = 'cws_users_table_result';
	const USER_META_POSTS_SCAN_RESULT = 'cws_posts_scan_result';
	const USER_META_COMPONENT_SCAN_RESULT = 'cws_component_scan_result';
	const EMPTY_USERNAME_KEY = '__empty__';

	/**
	 * Default plugin options.
	 *
	 * @return array<string, mixed>
	 */
	public static function default_options() {
		return array(
			'xmlrpc_blocking_enabled'    => true,
			'login_rate_limit_enabled'   => true,
			'uploads_php_lockdown_enabled' => true,
			'block_user_rest_api_enabled' => true,
			'block_author_query_enabled' => true,
			'block_author_archives_enabled' => true,
			'normalize_login_errors_enabled' => true,
			'allowed_failed_attempts'    => 5,
			'failure_window_minutes'    => 15,
			'lockout_duration_minutes'  => 30,
			'database_scan_options_table' => '',
			'database_scan_users_table' => '',
			'database_scan_posts_table' => '',
		);
	}

	/**
	 * Retrieve merged plugin options.
	 *
	 * @return array<string, mixed>
	 */
	public static function get_options() {
		$stored = get_option( self::OPTION_KEY, array() );

		if ( ! is_array( $stored ) ) {
			$stored = array();
		}

		return wp_parse_args( $stored, self::default_options() );
	}

	/**
	 * Determine whether a boolean option is enabled.
	 *
	 * @param string $key Option key.
	 * @return bool
	 */
	public static function is_enabled( $key ) {
		$options = self::get_options();

		return ! empty( $options[ $key ] );
	}

	/**
	 * Resolve the client IP address conservatively.
	 *
	 * Defaults to REMOTE_ADDR and does not trust X-Forwarded-For unless
	 * explicit trusted-proxy support is added later.
	 *
	 * @return string
	 */
	public static function get_client_ip() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? wp_unslash( $_SERVER['REMOTE_ADDR'] ) : '';

		/*
		 * Future trusted reverse-proxy support (Cloudflare, load balancers, etc.)
		 * could be implemented here with an explicit allowlist of proxy IPs and
		 * a configurable header such as HTTP_CF_CONNECTING_IP or HTTP_X_FORWARDED_FOR.
		 *
		 * Example:
		 * if ( self::is_trusted_proxy( $ip ) && ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
		 *     $ip = wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] );
		 * }
		 */

		$ip = sanitize_text_field( (string) $ip );

		if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return $ip;
		}

		return '0.0.0.0';
	}

	/**
	 * Normalize attempted usernames for stable transient keys.
	 *
	 * @param mixed $username Raw username value.
	 * @return string
	 */
	public static function normalize_username( $username ) {
		$username = sanitize_user( (string) $username, true );
		$username = strtolower( trim( $username ) );

		if ( '' === $username ) {
			return self::EMPTY_USERNAME_KEY;
		}

		return $username;
	}

	/**
	 * Build a transient key for IP-only failure tracking.
	 *
	 * @param string $ip Client IP address.
	 * @return string
	 */
	public static function failure_key_ip( $ip ) {
		return 'cws_fail_ip_' . md5( $ip );
	}

	/**
	 * Build a transient key for IP-only lockouts.
	 *
	 * @param string $ip Client IP address.
	 * @return string
	 */
	public static function lockout_key_ip( $ip ) {
		return 'cws_lock_ip_' . md5( $ip );
	}

	/**
	 * Build a transient key for IP-plus-username failure tracking.
	 *
	 * @param string $ip       Client IP address.
	 * @param string $username Normalized username.
	 * @return string
	 */
	public static function failure_key_ip_user( $ip, $username ) {
		return 'cws_fail_ipu_' . md5( $ip . '|' . $username );
	}

	/**
	 * Build a transient key for IP-plus-username lockouts.
	 *
	 * @param string $ip       Client IP address.
	 * @param string $username Normalized username.
	 * @return string
	 */
	public static function lockout_key_ip_user( $ip, $username ) {
		return 'cws_lock_ipu_' . md5( $ip . '|' . $username );
	}

	/**
	 * Convert minutes to seconds for transient expiration.
	 *
	 * @param int $minutes Minutes value.
	 * @return int
	 */
	public static function minutes_to_seconds( $minutes ) {
		return max( 1, (int) $minutes ) * MINUTE_IN_SECONDS;
	}

	/**
	 * Append a lockout event to the recent log option.
	 *
	 * @param string $ip               Client IP address.
	 * @param string $username         Attempted username.
	 * @param int    $lockout_duration Lockout duration in seconds.
	 * @return void
	 */
	public static function log_lockout_event( $ip, $username, $lockout_duration, $scope = '' ) {
		$events = get_option( self::LOCKOUT_LOG_KEY, array() );

		if ( ! is_array( $events ) ) {
			$events = array();
		}

		array_unshift(
			$events,
			array(
				'timestamp'        => time(),
				'ip'               => $ip,
				'username'         => $username,
				'scope'            => $scope,
				'lockout_duration' => (int) $lockout_duration,
			)
		);

		$events = array_slice( $events, 0, self::LOCKOUT_LOG_LIMIT );

		update_option( self::LOCKOUT_LOG_KEY, $events, false );
	}

	/**
	 * Retrieve recent lockout events.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function get_lockout_log() {
		$events = get_option( self::LOCKOUT_LOG_KEY, array() );

		return is_array( $events ) ? $events : array();
	}

	/**
	 * Get the persisted database scan options table selection.
	 *
	 * @return string
	 */
	public static function get_database_scan_options_table() {
		$options = self::get_options();
		$table   = isset( $options['database_scan_options_table'] ) ? (string) $options['database_scan_options_table'] : '';

		if ( preg_match( '/^[A-Za-z0-9_]+$/', $table ) ) {
			return $table;
		}

		return '';
	}

	/**
	 * Persist the selected database scan options table.
	 *
	 * @param string $table_name Validated options table name.
	 * @return bool
	 */
	public static function save_database_scan_options_table( $table_name ) {
		$options = self::get_options();

		$options['database_scan_options_table'] = (string) $table_name;

		return update_option( self::OPTION_KEY, $options );
	}

	/**
	 * Get the persisted database scan users table selection.
	 *
	 * @return string
	 */
	public static function get_database_scan_users_table() {
		$options = self::get_options();
		$table   = isset( $options['database_scan_users_table'] ) ? (string) $options['database_scan_users_table'] : '';

		if ( preg_match( '/^[A-Za-z0-9_]+$/', $table ) ) {
			return $table;
		}

		return '';
	}

	/**
	 * Persist the selected database scan users table.
	 *
	 * @param string $table_name Validated users table name.
	 * @return bool
	 */
	public static function save_database_scan_users_table( $table_name ) {
		$options = self::get_options();

		$options['database_scan_users_table'] = (string) $table_name;

		return update_option( self::OPTION_KEY, $options );
	}

	/**
	 * Get the persisted database scan posts table selection.
	 *
	 * @return string
	 */
	public static function get_database_scan_posts_table() {
		$options = self::get_options();
		$table   = isset( $options['database_scan_posts_table'] ) ? (string) $options['database_scan_posts_table'] : '';

		if ( preg_match( '/^[A-Za-z0-9_]+$/', $table ) ) {
			return $table;
		}

		return '';
	}

	/**
	 * Persist the selected database scan posts table.
	 *
	 * @param string $table_name Validated posts table name.
	 * @return bool
	 */
	public static function save_database_scan_posts_table( $table_name ) {
		$options = self::get_options();

		$options['database_scan_posts_table'] = (string) $table_name;

		return update_option( self::OPTION_KEY, $options );
	}
}
