<?php
/**
 * Shared helpers for CoreGuard.
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
	const FINDING_STATUSES_KEY = 'choctaw_wp_security_finding_statuses';
	const LOCKOUT_LOG_LIMIT  = 20;
	const REPORT_PAGE_SIZE   = 20;
	const REPORT_RESULT_TTL  = 43200;
	const USER_META_DATABASE_SCAN_RESULT = 'cws_database_scan_result';
	const USER_META_CORE_CHECKSUM_RESULT = 'cws_core_checksum_result';
	const USER_META_EXPOSED_FOLDERS_RESULT = 'cws_exposed_folders_result';
	const USER_META_USERS_TABLE_RESULT = 'cws_users_table_result';
	const USER_META_POSTS_SCAN_RESULT = 'cws_posts_scan_result';
	const USER_META_COMPONENT_SCAN_RESULT = 'cws_component_scan_result';
	const USER_META_SCHEDULED_TASKS_RESULT = 'cws_scheduled_tasks_result';
	const USER_META_UPLOADS_FOLDER_RESULT = 'cws_uploads_folder_result';
	const USER_META_MU_PLUGINS_RESULT = 'cws_mu_plugins_result';
	const USER_META_EXPOSED_FILES_RESULT = 'cws_exposed_files_result';
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
			'database_scan_table_prefix' => '',
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
	 * Get the persisted database scan table-prefix override.
	 *
	 * Empty string means Auto (use the WordPress-configured prefix).
	 *
	 * @return string
	 */
	public static function get_database_scan_table_prefix() {
		$options = self::get_options();
		$prefix  = isset( $options['database_scan_table_prefix'] ) ? (string) $options['database_scan_table_prefix'] : '';

		if ( '' === $prefix ) {
			return '';
		}

		if ( preg_match( '/^[A-Za-z0-9_]+$/', $prefix ) ) {
			return $prefix;
		}

		return '';
	}

	/**
	 * Persist the database scan table-prefix override.
	 *
	 * Pass an empty string to clear the override and return to Auto.
	 *
	 * @param string $prefix Validated table prefix or empty for auto.
	 * @return bool
	 */
	public static function save_database_scan_table_prefix( $prefix ) {
		$options = self::get_options();

		$options['database_scan_table_prefix'] = (string) $prefix;

		return update_option( self::OPTION_KEY, $options );
	}

	/**
	 * Inline SVG mark for risk badges and report chrome.
	 *
	 * Uses fill="currentColor" so CSS risk colors apply like Dashicons.
	 *
	 * @return string
	 */
	public static function get_coreguard_mark_html() {
		$svg_path = CHOCTAW_WP_SECURITY_PATH . 'assets/images/coreguard-20.svg';

		if ( ! is_readable( $svg_path ) ) {
			return '<span class="dashicons dashicons-shield" aria-hidden="true"></span>';
		}

		$svg = file_get_contents( $svg_path );

		if ( false === $svg || '' === $svg ) {
			return '<span class="dashicons dashicons-shield" aria-hidden="true"></span>';
		}

		$svg = preg_replace( '/<\?xml[^>]*\?>\s*/', '', $svg );
		$svg = preg_replace( '/fill="#(?:ffffff|FFFFFF|000000|000|black)"/', 'fill="currentColor"', $svg );
		$svg = preg_replace( '/\bwidth="20"/', 'width="24"', $svg );
		$svg = preg_replace( '/\bheight="20"/', 'height="24"', $svg );
		$svg = preg_replace(
			'/<svg\b/',
			'<svg class="cws-coreguard-mark" aria-hidden="true" focusable="false"',
			$svg,
			1
		);
		$svg = preg_replace( '/\s+/', ' ', trim( $svg ) );

		return $svg;
	}

	/**
	 * Echo the CoreGuard mark SVG.
	 *
	 * @return void
	 */
	public static function render_coreguard_mark() {
		// Trusted local plugin SVG with fill="currentColor".
		echo self::get_coreguard_mark_html(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}

	/**
	 * Character limit for report Contents / value preview textareas.
	 */
	const REPORT_CONTENTS_CHAR_LIMIT = 16384;

	/**
	 * Format octal permission bits for Info panels (e.g. 644).
	 *
	 * @param string $path Absolute path.
	 * @return string
	 */
	public static function format_file_permissions( $path ) {
		$path = (string) $path;

		if ( '' === $path || ! file_exists( $path ) ) {
			return '';
		}

		$perms = @fileperms( $path );
		if ( false === $perms ) {
			return '';
		}

		return sprintf( '%o', $perms & 0777 );
	}

	/**
	 * Format file owner name or UID for Info panels.
	 *
	 * @param string $path Absolute path.
	 * @return string
	 */
	public static function format_file_owner( $path ) {
		$path = (string) $path;

		if ( '' === $path || ! file_exists( $path ) ) {
			return '';
		}

		$uid = @fileowner( $path );
		if ( false === $uid ) {
			return '';
		}

		if ( function_exists( 'posix_getpwuid' ) ) {
			$info = @posix_getpwuid( (int) $uid );
			if ( is_array( $info ) && ! empty( $info['name'] ) ) {
				return (string) $info['name'];
			}
		}

		return (string) (int) $uid;
	}

	/**
	 * Format a filemtime value for Info panels.
	 *
	 * @param int|false $modified Unix timestamp or false.
	 * @return string
	 */
	public static function format_file_modified_label( $modified ) {
		if ( false === $modified || ! $modified ) {
			return '';
		}

		return wp_date(
			sprintf( '%s %s', get_option( 'date_format' ), get_option( 'time_format' ) ),
			(int) $modified
		);
	}

	/**
	 * Read up to REPORT_CONTENTS_CHAR_LIMIT characters from a file.
	 *
	 * @param string   $path  Absolute path.
	 * @param int|null $limit Optional override limit.
	 * @return string
	 */
	public static function read_file_contents_preview( $path, $limit = null ) {
		$result = self::read_file_contents_preview_result( $path, $limit );
		return $result['contents'];
	}

	/**
	 * Read a file preview and report whether it was truncated.
	 *
	 * @param string   $path  Absolute path.
	 * @param int|null $limit Optional override limit.
	 * @return array{contents:string,truncated:bool}
	 */
	public static function read_file_contents_preview_result( $path, $limit = null ) {
		$path  = (string) $path;
		$limit = null === $limit ? self::REPORT_CONTENTS_CHAR_LIMIT : max( 1, (int) $limit );

		if ( '' === $path || ! is_readable( $path ) || is_dir( $path ) ) {
			return array(
				'contents'  => '',
				'truncated' => false,
			);
		}

		$handle = fopen( $path, 'rb' );
		if ( false === $handle ) {
			return array(
				'contents'  => '',
				'truncated' => false,
			);
		}

		$chunk = fread( $handle, $limit + 1 );
		fclose( $handle );

		if ( false === $chunk || '' === $chunk ) {
			return array(
				'contents'  => '',
				'truncated' => false,
			);
		}

		$truncated = strlen( $chunk ) > $limit;
		$contents  = $truncated ? substr( $chunk, 0, $limit ) : $chunk;

		if ( function_exists( 'mb_substr' ) ) {
			$contents = mb_substr( $contents, 0, $limit );
		}

		return array(
			'contents'  => $contents,
			'truncated' => $truncated,
		);
	}

	/**
	 * Build shared Info + Contents fields for a filesystem path.
	 *
	 * Missing or unreadable files return empty strings for each field.
	 *
	 * @param string $path Absolute path.
	 * @return array{size:int,size_label:string,modified:int,modified_label:string,permissions:string,owner:string,contents:string,contents_truncated:bool}
	 */
	public static function get_file_preview_meta( $path ) {
		$path     = (string) $path;
		$exists   = '' !== $path && file_exists( $path ) && is_file( $path );
		$size     = $exists ? (int) filesize( $path ) : 0;
		$modified = $exists ? filemtime( $path ) : false;
		$preview  = self::read_file_contents_preview_result( $path );

		return array(
			'size'               => $size,
			'size_label'         => $exists ? size_format( $size ) : '',
			'modified'           => false === $modified ? 0 : (int) $modified,
			'modified_label'     => self::format_file_modified_label( $modified ),
			'permissions'        => self::format_file_permissions( $path ),
			'owner'              => self::format_file_owner( $path ),
			'contents'           => $preview['contents'],
			'contents_truncated' => ! empty( $preview['truncated'] ),
		);
	}

	/**
	 * Truncate a string for report Contents textareas.
	 *
	 * @param string   $value Raw value.
	 * @param int|null $limit Optional override limit.
	 * @return string
	 */
	public static function truncate_report_contents( $value, $limit = null ) {
		$result = self::truncate_report_contents_result( $value, $limit );
		return $result['contents'];
	}

	/**
	 * Truncate a string and report whether truncation occurred.
	 *
	 * @param string   $value Raw value.
	 * @param int|null $limit Optional override limit.
	 * @return array{contents:string,truncated:bool}
	 */
	public static function truncate_report_contents_result( $value, $limit = null ) {
		$value = (string) $value;
		$limit = null === $limit ? self::REPORT_CONTENTS_CHAR_LIMIT : max( 1, (int) $limit );

		if ( function_exists( 'mb_strlen' ) && function_exists( 'mb_substr' ) ) {
			if ( mb_strlen( $value ) <= $limit ) {
				return array(
					'contents'  => $value,
					'truncated' => false,
				);
			}

			return array(
				'contents'  => mb_substr( $value, 0, $limit ),
				'truncated' => true,
			);
		}

		if ( strlen( $value ) <= $limit ) {
			return array(
				'contents'  => $value,
				'truncated' => false,
			);
		}

		return array(
			'contents'  => substr( $value, 0, $limit ),
			'truncated' => true,
		);
	}

	/**
	 * Footer label when Contents were shown in full.
	 *
	 * @param string $noun File, Arguments, Snippet, Option Value, etc.
	 * @return string
	 */
	public static function report_contents_end_label( $noun = '' ) {
		$noun = trim( (string) $noun );
		if ( '' === $noun ) {
			$noun = __( 'File', 'choctaw-wp-security' );
		}

		return sprintf(
			/* translators: %s: content noun (File, Arguments, Snippet, Option Value) */
			__( '---End of %s', 'choctaw-wp-security' ),
			$noun
		);
	}

	/**
	 * Footer label when Contents were truncated to the report limit.
	 *
	 * @return string
	 */
	public static function report_contents_truncated_label() {
		return __( '---Contents truncated, first 16K displayed.', 'choctaw-wp-security' );
	}

	/**
	 * Append the end-of / truncated marker inside Contents textarea text.
	 *
	 * @param string $contents  Preview contents.
	 * @param bool   $truncated Whether contents were truncated.
	 * @param string $noun      Content noun (File, Arguments, Snippet, Option Value).
	 * @return string
	 */
	public static function with_report_contents_footer( $contents, $truncated, $noun = '' ) {
		$label = $truncated
			? self::report_contents_truncated_label()
			: self::report_contents_end_label( $noun );

		return (string) $contents . "\n\n" . $label;
	}
}
