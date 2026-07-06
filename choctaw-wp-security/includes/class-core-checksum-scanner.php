<?php
/**
 * WordPress core checksum verification scanner.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Compares installed WordPress core files against official checksums.
 */
class Choctaw_Wp_Security_Core_Checksum_Scanner {

	const UNKNOWN_DISPLAY_LIMIT = 50;
	const SCAN_TIME_BUDGET      = 25;

	/**
	 * Basenames excluded from unknown-file reporting at the WordPress root.
	 *
	 * @var array<int, string>
	 */
	private static $excluded_root_basenames = array(
		'wp-config.php',
		'.htaccess',
		'.user.ini',
		'php.ini',
		'robots.txt',
		'sitemap.xml',
		'favicon.ico',
	);

	/**
	 * Run a core checksum scan.
	 *
	 * @return array<string, mixed>
	 */
	public function scan() {
		global $wp_version;

		$version = isset( $wp_version ) ? (string) $wp_version : '';
		$locale  = get_locale();

		if ( '' === $locale ) {
			$locale = 'en_US';
		}

		$result = array(
			'success'            => false,
			'version'            => $version,
			'locale'             => $locale,
			'checked'            => 0,
			'modified'           => array(),
			'missing'            => array(),
			'unknown'            => array(),
			'errors'             => array(),
			'unknown_total'      => 0,
			'unknown_truncated'  => 0,
			'scan_incomplete'    => false,
		);

		if ( '' === $version ) {
			$result['errors'][] = __( 'Unable to determine the installed WordPress version.', 'choctaw-wp-security' );
			return $result;
		}

		$checksums = $this->get_checksums( $version, $locale );

		if ( false === $checksums ) {
			$result['errors'][] = sprintf(
				/* translators: 1: WordPress version, 2: locale */
				__( 'Unable to retrieve official checksums for WordPress %1$s (%2$s).', 'choctaw-wp-security' ),
				$version,
				$locale
			);
			return $result;
		}

		$start_time   = microtime( true );
		$time_budget  = $this->get_scan_time_budget();
		$checksum_set = array_fill_keys( array_keys( $checksums ), true );

		foreach ( $checksums as $relative_path => $expected_hash ) {
			if ( $this->scan_timed_out( $start_time, $time_budget ) ) {
				$result['scan_incomplete'] = true;
				$result['errors'][]        = __( 'Scan timed out before all checksums could be verified.', 'choctaw-wp-security' );
				return $this->finalize_result( $result );
			}

			if ( $this->should_skip_checksum_path( $relative_path ) ) {
				continue;
			}

			$absolute_path = $this->absolute_path_for_relative( $relative_path );

			if ( ! is_file( $absolute_path ) ) {
				$result['missing'][] = $relative_path;
				continue;
			}

			$result['checked']++;

			$file_hash = @md5_file( $absolute_path );

			if ( false === $file_hash ) {
				$result['errors'][] = sprintf(
					/* translators: %s: relative file path */
					__( 'Unable to read file: %s', 'choctaw-wp-security' ),
					$relative_path
				);
				continue;
			}

			if ( ! hash_equals( (string) $expected_hash, $file_hash ) ) {
				$result['modified'][] = $relative_path;
			}
		}

		$unknown_files = $this->find_unknown_files( $checksum_set, $start_time, $time_budget, $result['scan_incomplete'] );

		if ( $result['scan_incomplete'] && empty( $result['errors'] ) ) {
			$result['errors'][] = __( 'Scan timed out before all directories could be scanned for unknown files.', 'choctaw-wp-security' );
		}

		$result['unknown_total'] = count( $unknown_files );

		if ( $result['unknown_total'] > self::UNKNOWN_DISPLAY_LIMIT ) {
			$result['unknown_truncated'] = $result['unknown_total'] - self::UNKNOWN_DISPLAY_LIMIT;
			$unknown_files               = array_slice( $unknown_files, 0, self::UNKNOWN_DISPLAY_LIMIT );
		}

		$result['unknown'] = $unknown_files;

		return $this->finalize_result( $result );
	}

	/**
	 * Retrieve official checksums for a WordPress version and locale.
	 *
	 * @param string $version WordPress version.
	 * @param string $locale  WordPress locale.
	 * @return array<string, string>|false
	 */
	private function get_checksums( $version, $locale ) {
		if ( ! function_exists( 'get_core_checksums' ) ) {
			$update_file = ABSPATH . 'wp-admin/includes/update.php';

			if ( is_readable( $update_file ) ) {
				require_once $update_file;
			}
		}

		if ( ! function_exists( 'get_core_checksums' ) ) {
			return false;
		}

		$checksums = get_core_checksums( $version, $locale );

		if ( ! is_array( $checksums ) || empty( $checksums ) ) {
			if ( 'en_US' !== $locale ) {
				$checksums = get_core_checksums( $version, 'en_US' );
			}
		}

		if ( ! is_array( $checksums ) || empty( $checksums ) ) {
			return false;
		}

		return $checksums;
	}

	/**
	 * Determine whether a checksum path should be skipped.
	 *
	 * @param string $relative_path Relative file path.
	 * @return bool
	 */
	private function should_skip_checksum_path( $relative_path ) {
		$relative_path = wp_normalize_path( $relative_path );

		if ( 0 === strpos( $relative_path, 'wp-content/' ) ) {
			return true;
		}

		$basename = basename( $relative_path );

		return in_array( $basename, self::$excluded_root_basenames, true );
	}

	/**
	 * Build an absolute path from a WordPress-relative path.
	 *
	 * @param string $relative_path Relative file path.
	 * @return string
	 */
	private function absolute_path_for_relative( $relative_path ) {
		return wp_normalize_path( ABSPATH . ltrim( wp_normalize_path( $relative_path ), '/' ) );
	}

	/**
	 * Find files present on disk that are not in the official checksum list.
	 *
	 * @param array<string, bool> $checksum_set  Known checksum paths.
	 * @param float               $start_time      Scan start time.
	 * @param int                 $time_budget     Allowed scan duration in seconds.
	 * @param bool                $scan_incomplete Whether the scan was marked incomplete.
	 * @return array<int, string>
	 */
	private function find_unknown_files( $checksum_set, $start_time, $time_budget, &$scan_incomplete ) {
		$unknown = array();

		$this->collect_unknown_root_files( $checksum_set, $unknown, $start_time, $time_budget, $scan_incomplete );

		if ( ! $scan_incomplete ) {
			$this->collect_unknown_directory_files( 'wp-admin', $checksum_set, $unknown, $start_time, $time_budget, $scan_incomplete );
		}

		if ( ! $scan_incomplete ) {
			$this->collect_unknown_directory_files( 'wp-includes', $checksum_set, $unknown, $start_time, $time_budget, $scan_incomplete );
		}

		sort( $unknown );

		return $unknown;
	}

	/**
	 * Collect unknown files directly under ABSPATH.
	 *
	 * @param array<string, bool> $checksum_set    Known checksum paths.
	 * @param array<int, string>  $unknown         Unknown file list.
	 * @param float               $start_time      Scan start time.
	 * @param int                 $time_budget     Allowed scan duration in seconds.
	 * @param bool                $scan_incomplete Whether the scan was marked incomplete.
	 * @return void
	 */
	private function collect_unknown_root_files( $checksum_set, &$unknown, $start_time, $time_budget, &$scan_incomplete ) {
		$root = wp_normalize_path( ABSPATH );

		if ( ! is_dir( $root ) || ! is_readable( $root ) ) {
			return;
		}

		$entries = @scandir( $root );

		if ( ! is_array( $entries ) ) {
			return;
		}

		foreach ( $entries as $entry ) {
			if ( $this->scan_timed_out( $start_time, $time_budget ) ) {
				$scan_incomplete = true;
				return;
			}

			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}

			if ( in_array( $entry, array( 'wp-content', 'wp-admin', 'wp-includes' ), true ) ) {
				continue;
			}

			if ( in_array( $entry, self::$excluded_root_basenames, true ) ) {
				continue;
			}

			$absolute_path = wp_normalize_path( $root . $entry );

			if ( ! is_file( $absolute_path ) ) {
				continue;
			}

			$relative_path = $this->relative_path_for_absolute( $absolute_path );

			if ( ! isset( $checksum_set[ $relative_path ] ) ) {
				$unknown[] = $relative_path;
			}
		}
	}

	/**
	 * Collect unknown files under a core directory.
	 *
	 * @param string              $directory       Directory relative to ABSPATH.
	 * @param array<string, bool> $checksum_set    Known checksum paths.
	 * @param array<int, string>  $unknown         Unknown file list.
	 * @param float               $start_time      Scan start time.
	 * @param int                 $time_budget     Allowed scan duration in seconds.
	 * @param bool                $scan_incomplete Whether the scan was marked incomplete.
	 * @return void
	 */
	private function collect_unknown_directory_files( $directory, $checksum_set, &$unknown, $start_time, $time_budget, &$scan_incomplete ) {
		$directory_path = wp_normalize_path( trailingslashit( ABSPATH ) . $directory );

		if ( ! is_dir( $directory_path ) || ! is_readable( $directory_path ) ) {
			return;
		}

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $directory_path, FilesystemIterator::SKIP_DOTS )
			);

			foreach ( $iterator as $file ) {
				if ( $this->scan_timed_out( $start_time, $time_budget ) ) {
					$scan_incomplete = true;
					return;
				}

				if ( ! $file->isFile() ) {
					continue;
				}

				$absolute_path = wp_normalize_path( $file->getPathname() );
				$relative_path = $this->relative_path_for_absolute( $absolute_path );

				if ( 0 === strpos( $relative_path, 'wp-content/' ) ) {
					continue;
				}

				if ( ! isset( $checksum_set[ $relative_path ] ) ) {
					$unknown[] = $relative_path;
				}
			}
		} catch ( Exception $exception ) {
			return;
		}
	}

	/**
	 * Convert an absolute path to a WordPress-relative path.
	 *
	 * @param string $absolute_path Absolute file path.
	 * @return string
	 */
	private function relative_path_for_absolute( $absolute_path ) {
		$absolute_path = wp_normalize_path( $absolute_path );
		$root          = trailingslashit( wp_normalize_path( ABSPATH ) );

		if ( 0 === strpos( $absolute_path, $root ) ) {
			return ltrim( substr( $absolute_path, strlen( $root ) ), '/' );
		}

		return $absolute_path;
	}

	/**
	 * Determine the allowed scan duration.
	 *
	 * @return int
	 */
	private function get_scan_time_budget() {
		$max_execution_time = (int) ini_get( 'max_execution_time' );

		if ( $max_execution_time <= 0 ) {
			return self::SCAN_TIME_BUDGET;
		}

		return max( 5, min( self::SCAN_TIME_BUDGET, $max_execution_time - 5 ) );
	}

	/**
	 * Check whether the scan has exceeded its time budget.
	 *
	 * @param float $start_time  Scan start time.
	 * @param int   $time_budget Allowed scan duration in seconds.
	 * @return bool
	 */
	private function scan_timed_out( $start_time, $time_budget ) {
		return ( microtime( true ) - $start_time ) >= $time_budget;
	}

	/**
	 * Finalize scan success state and sort issue lists.
	 *
	 * @param array<string, mixed> $result Scan result.
	 * @return array<string, mixed>
	 */
	private function finalize_result( $result ) {
		sort( $result['modified'] );
		sort( $result['missing'] );

		$has_issues = ! empty( $result['modified'] )
			|| ! empty( $result['missing'] )
			|| ! empty( $result['unknown'] )
			|| ! empty( $result['errors'] )
			|| ! empty( $result['scan_incomplete'] );

		$result['success'] = ! $has_issues;

		return $result;
	}
}
