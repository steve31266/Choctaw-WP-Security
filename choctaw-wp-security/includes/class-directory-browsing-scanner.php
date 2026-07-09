<?php
/**
 * Server-level directory browsing detection.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Detects directory browsing status using .htaccess analysis and HTTP tests.
 */
class Choctaw_Wp_Security_Directory_Browsing_Scanner {

	const STATUS_ON      = 'on';
	const STATUS_OFF     = 'off';
	const STATUS_UNKNOWN = 'unknown';

	const METHOD_HTACCESS       = 'htaccess';
	const METHOD_DIRECTORY_TEST = 'directory_test';

	const SERVER_APACHE    = 'apache';
	const SERVER_LITESPEED = 'litespeed';
	const SERVER_NGINX     = 'nginx';
	const SERVER_UNKNOWN   = 'unknown';

	const HTTP_TIMEOUT = 10;

	const UNKNOWN_HTACCESS_NOT_FOUND    = 'not_found';
	const UNKNOWN_HTACCESS_UNREADABLE   = 'unreadable';
	const UNKNOWN_HTACCESS_INCONCLUSIVE = 'inconclusive';

	const UNKNOWN_DIRECTORY_NO_TARGETS = 'no_test_targets';
	const UNKNOWN_DIRECTORY_HTTP_FAILED = 'http_failed';
	const UNKNOWN_DIRECTORY_INCONCLUSIVE = 'inconclusive';

	/**
	 * Run server-level directory browsing checks.
	 *
	 * @param array<int, string> $plugin_folders Display paths for plugin folders missing index files.
	 * @param array<int, string> $theme_folders  Display paths for theme folders missing index files.
	 * @return array<string, mixed>
	 */
	public function scan( array $plugin_folders, array $theme_folders ) {
		$server_type = $this->get_server_type();
		$rows        = array();

		if ( self::SERVER_NGINX !== $server_type ) {
			$rows[] = $this->scan_htaccess( $server_type );
		}

		$rows[] = $this->scan_directory_test( $server_type, $plugin_folders, $theme_folders );

		$rows = $this->mark_conflicting_rows( $rows );

		return array(
			'server_type' => $server_type,
			'rows'        => $rows,
		);
	}

	/**
	 * Detect the web server type from SERVER_SOFTWARE.
	 *
	 * @return string One of the SERVER_* constants.
	 */
	public function get_server_type() {
		$software = isset( $_SERVER['SERVER_SOFTWARE'] )
			? strtolower( (string) wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) )
			: '';

		if ( '' === $software ) {
			return self::SERVER_UNKNOWN;
		}

		if (
			false !== strpos( $software, 'litespeed' )
			|| false !== strpos( $software, 'openlitespeed' )
		) {
			return self::SERVER_LITESPEED;
		}

		if ( false !== strpos( $software, 'nginx' ) ) {
			return self::SERVER_NGINX;
		}

		if ( false !== strpos( $software, 'apache' ) ) {
			return self::SERVER_APACHE;
		}

		return self::SERVER_UNKNOWN;
	}

	/**
	 * Analyze the site root .htaccess file for directory index options.
	 *
	 * @param string $server_type Detected server type.
	 * @return array<string, mixed>
	 */
	private function scan_htaccess( $server_type ) {
		$row = array(
			'method'          => self::METHOD_HTACCESS,
			'status'          => self::STATUS_UNKNOWN,
			'server_type'     => $server_type,
			'unknown_reason'  => self::UNKNOWN_HTACCESS_INCONCLUSIVE,
			'test_urls'       => array(),
			'conflict'        => false,
		);

		$path = trailingslashit( ABSPATH ) . '.htaccess';

		if ( ! file_exists( $path ) ) {
			$row['unknown_reason'] = self::UNKNOWN_HTACCESS_NOT_FOUND;
			return $row;
		}

		if ( ! is_readable( $path ) ) {
			$row['unknown_reason'] = self::UNKNOWN_HTACCESS_UNREADABLE;
			return $row;
		}

		$content = file_get_contents( $path );

		if ( false === $content || '' === trim( $content ) ) {
			$row['unknown_reason'] = self::UNKNOWN_HTACCESS_NOT_FOUND;
			return $row;
		}

		$indexes_state = $this->parse_htaccess_indexes_state( $content );

		if ( 'off' === $indexes_state ) {
			$row['status'] = self::STATUS_OFF;
			unset( $row['unknown_reason'] );
		} elseif ( 'on' === $indexes_state ) {
			$row['status'] = self::STATUS_ON;
			unset( $row['unknown_reason'] );
		}

		return $row;
	}

	/**
	 * Parse .htaccess content for Options +/-Indexes directives.
	 *
	 * @param string $content .htaccess file contents.
	 * @return string|null off, on, or null when inconclusive.
	 */
	private function parse_htaccess_indexes_state( $content ) {
		$lines = preg_split( '/\R/', (string) $content );

		if ( ! is_array( $lines ) ) {
			return null;
		}

		$indexes_enabled  = null;
		$indexes_disabled = false;

		foreach ( $lines as $line ) {
			$line = trim( (string) $line );

			if ( '' === $line || 0 === strpos( $line, '#' ) ) {
				continue;
			}

			if ( ! preg_match( '/^\s*Options\b(.+)$/i', $line, $matches ) ) {
				continue;
			}

			$tokens = preg_split( '/\s+/', trim( (string) $matches[1] ) );

			if ( ! is_array( $tokens ) ) {
				continue;
			}

			foreach ( $tokens as $token ) {
				$token = trim( (string) $token );

				if ( '' === $token || 0 === strpos( $token, '#' ) ) {
					continue;
				}

				if ( preg_match( '/^([+-]?)Indexes$/i', $token, $option_match ) ) {
					$sign = strtolower( (string) $option_match[1] );

					if ( '-' === $sign ) {
						$indexes_disabled = true;
					} elseif ( '+' === $sign || '' === $sign ) {
						$indexes_enabled = true;
					}
				} elseif ( preg_match( '/^([+-]?)All$/i', $token, $all_match ) ) {
					$sign = strtolower( (string) $all_match[1] );

					if ( '-' === $sign ) {
						$indexes_disabled = true;
					} elseif ( '+' === $sign || '' === $sign ) {
						$indexes_enabled = true;
					}
				}
			}
		}

		if ( $indexes_disabled && ! $indexes_enabled ) {
			return 'off';
		}

		if ( $indexes_enabled && ! $indexes_disabled ) {
			return 'on';
		}

		if ( $indexes_disabled && $indexes_enabled ) {
			return null;
		}

		return null;
	}

	/**
	 * Request public folder URLs and inspect responses for directory listings.
	 *
	 * @param string               $server_type     Detected server type.
	 * @param array<int, string>   $plugin_folders  Plugin folders missing index files.
	 * @param array<int, string>   $theme_folders   Theme folders missing index files.
	 * @return array<string, mixed>
	 */
	private function scan_directory_test( $server_type, array $plugin_folders, array $theme_folders ) {
		$row = array(
			'method'         => self::METHOD_DIRECTORY_TEST,
			'status'         => self::STATUS_UNKNOWN,
			'server_type'    => $server_type,
			'unknown_reason' => self::UNKNOWN_DIRECTORY_NO_TARGETS,
			'test_urls'      => array(),
			'conflict'       => false,
		);

		$test_paths = $this->select_directory_test_paths( $plugin_folders, $theme_folders );

		if ( empty( $test_paths ) ) {
			return $row;
		}

		$results = array();

		foreach ( $test_paths as $display_path ) {
			$url = trailingslashit( site_url( ltrim( (string) $display_path, '/' ) ) );

			$row['test_urls'][] = $url;
			$results[]          = $this->request_directory_listing_state( $url );
		}

		$listings_found   = 0;
		$non_listings     = 0;
		$failed_requests  = 0;
		$inconclusive     = 0;

		foreach ( $results as $result ) {
			if ( 'listing' === $result ) {
				++$listings_found;
			} elseif ( 'non_listing' === $result ) {
				++$non_listings;
			} elseif ( 'failed' === $result ) {
				++$failed_requests;
			} else {
				++$inconclusive;
			}
		}

		if ( $listings_found > 0 ) {
			$row['status'] = self::STATUS_ON;
			unset( $row['unknown_reason'] );
			return $row;
		}

		if ( $non_listings > 0 && 0 === $failed_requests && 0 === $inconclusive ) {
			$row['status'] = self::STATUS_OFF;
			unset( $row['unknown_reason'] );
			return $row;
		}

		if ( $non_listings > 0 && ( $failed_requests > 0 || $inconclusive > 0 ) ) {
			$row['unknown_reason'] = self::UNKNOWN_DIRECTORY_INCONCLUSIVE;
			return $row;
		}

		if ( $failed_requests > 0 && 0 === $non_listings && 0 === $listings_found ) {
			$row['unknown_reason'] = self::UNKNOWN_DIRECTORY_HTTP_FAILED;
			return $row;
		}

		$row['unknown_reason'] = self::UNKNOWN_DIRECTORY_INCONCLUSIVE;

		return $row;
	}

	/**
	 * Choose up to one plugin folder and one theme folder for HTTP testing.
	 *
	 * @param array<int, string> $plugin_folders Plugin folders missing index files.
	 * @param array<int, string> $theme_folders  Theme folders missing index files.
	 * @return array<int, string>
	 */
	private function select_directory_test_paths( array $plugin_folders, array $theme_folders ) {
		$paths = array();

		if ( ! empty( $plugin_folders[0] ) ) {
			$paths[] = (string) $plugin_folders[0];
		}

		if ( ! empty( $theme_folders[0] ) ) {
			$paths[] = (string) $theme_folders[0];
		}

		return $paths;
	}

	/**
	 * Request a folder URL and classify the response.
	 *
	 * @param string $url Public folder URL.
	 * @return string listing, non_listing, failed, or inconclusive.
	 */
	private function request_directory_listing_state( $url ) {
		$response = wp_remote_get(
			$url,
			array(
				'timeout'     => self::HTTP_TIMEOUT,
				'redirection' => 2,
				'headers'     => array(
					'Accept' => 'text/html,application/xhtml+xml',
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return 'failed';
		}

		$status_code = (int) wp_remote_retrieve_response_code( $response );
		$body        = (string) wp_remote_retrieve_body( $response );

		if ( $this->response_body_looks_like_directory_listing( $body ) ) {
			return 'listing';
		}

		if ( in_array( $status_code, array( 403, 404, 410 ), true ) ) {
			return 'non_listing';
		}

		if ( $status_code >= 200 && $status_code < 300 && '' === trim( $body ) ) {
			return 'non_listing';
		}

		if ( $status_code >= 200 && $status_code < 300 ) {
			return 'non_listing';
		}

		if ( $status_code >= 500 ) {
			return 'failed';
		}

		return 'inconclusive';
	}

	/**
	 * Determine whether an HTTP response body resembles a directory listing page.
	 *
	 * @param string $body Response body.
	 * @return bool
	 */
	private function response_body_looks_like_directory_listing( $body ) {
		if ( '' === trim( (string) $body ) ) {
			return false;
		}

		$markers = array(
			'Index of /',
			'Index of ',
			'<title>Index of',
			'Parent Directory',
			'Directory Listing',
		);

		foreach ( $markers as $marker ) {
			if ( false !== stripos( (string) $body, $marker ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Flag rows when .htaccess and directory test disagree on on/off.
	 *
	 * @param array<int, array<string, mixed>> $rows Scan rows.
	 * @return array<int, array<string, mixed>>
	 */
	private function mark_conflicting_rows( array $rows ) {
		$htaccess_status = null;
		$directory_status = null;

		foreach ( $rows as $row ) {
			if ( self::METHOD_HTACCESS === $row['method'] ) {
				$htaccess_status = $row['status'];
			}

			if ( self::METHOD_DIRECTORY_TEST === $row['method'] ) {
				$directory_status = $row['status'];
			}
		}

		if (
			null === $htaccess_status
			|| null === $directory_status
			|| self::STATUS_UNKNOWN === $htaccess_status
			|| self::STATUS_UNKNOWN === $directory_status
			|| $htaccess_status === $directory_status
		) {
			return $rows;
		}

		foreach ( $rows as $index => $row ) {
			$rows[ $index ]['conflict'] = true;
		}

		return $rows;
	}
}
