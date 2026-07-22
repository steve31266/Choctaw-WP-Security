<?php
/**
 * WordPress core checksum verification scanner (Sassh Findings producer).
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Compares installed WordPress core files against official checksums.
 */
class Choctaw_Wp_Security_Core_Checksum_Scanner {

	const SCAN_TIME_BUDGET = 25;
	const SCANNER_ID       = 'verify-checksums';
	const RULE_MODIFIED    = 'core-file-modified';
	const RULE_MISSING     = 'core-file-missing';
	const RULE_UNKNOWN     = 'core-file-unknown';

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
	 * Run a core checksum scan and persist via Sassh Findings.
	 *
	 * @return array<string, mixed>
	 */
	public function scan() {
		global $wp_version;

		Sassh_Findings_Schema::maybe_upgrade();

		$version           = isset( $wp_version ) ? (string) $wp_version : '';
		$locale_requested  = get_locale();
		if ( '' === $locale_requested ) {
			$locale_requested = 'en_US';
		}

		$scope_key = Sassh_Findings_Service::verify_checksums_scope_key();
		$service   = new Sassh_Findings_Service();

		$execution_id = $service->begin_scanner_execution(
			self::SCANNER_ID,
			array(
				'scope_key'  => $scope_key,
				'run_type'   => 'individual',
				'run_source' => 'wordpress_admin',
				'meta'       => array(
					'version'          => $version,
					'locale_requested' => $locale_requested,
				),
			)
		);

		$errors = array();

		if ( '' === $version ) {
			$errors[] = __( 'Unable to determine the installed WordPress version.', 'choctaw-wp-security' );
			$service->finalize_scanner_execution( $execution_id, 'failed' );

			return $this->build_report_from_findings(
				$service,
				$execution_id,
				array(
					'completion_status'  => 'failed',
					'version'            => $version,
					'locale_requested'   => $locale_requested,
					'locale_effective'   => '',
					'checked'            => 0,
					'errors'             => $errors,
					'scan_incomplete'    => false,
				)
			);
		}

		$checksum_result = $this->get_checksums( $version, $locale_requested );

		if ( false === $checksum_result ) {
			$errors[] = sprintf(
				/* translators: 1: WordPress version, 2: locale */
				__( 'Unable to retrieve official checksums for WordPress %1$s (%2$s).', 'choctaw-wp-security' ),
				$version,
				$locale_requested
			);
			$service->update_execution_meta(
				$execution_id,
				array(
					'locale_effective' => '',
				)
			);
			$service->finalize_scanner_execution( $execution_id, 'failed' );

			return $this->build_report_from_findings(
				$service,
				$execution_id,
				array(
					'completion_status' => 'failed',
					'version'           => $version,
					'locale_requested'  => $locale_requested,
					'locale_effective'  => '',
					'checked'           => 0,
					'errors'            => $errors,
					'scan_incomplete'   => false,
				)
			);
		}

		$checksums         = $checksum_result['checksums'];
		$locale_effective  = $checksum_result['locale_effective'];

		$service->update_execution_meta(
			$execution_id,
			array(
				'locale_effective' => $locale_effective,
			)
		);

		$start_time        = microtime( true );
		$time_budget       = $this->get_scan_time_budget();
		$scan_incomplete   = false;
		$coverage_failure  = false;
		$checked           = 0;
		$observations      = array();
		$checksum_set      = array_fill_keys( array_keys( $checksums ), true );

		foreach ( $checksums as $relative_path => $expected_hash ) {
			if ( $this->scan_timed_out( $start_time, $time_budget ) ) {
				$scan_incomplete = true;
				$errors[]        = __( 'Scan timed out before all checksums could be verified.', 'choctaw-wp-security' );
				break;
			}

			if ( $this->should_skip_checksum_path( $relative_path ) ) {
				continue;
			}

			$absolute_path = $this->absolute_path_for_relative( $relative_path );
			$object_key    = Sassh_Object_Path_Normalizer::normalize_in_root( $relative_path );

			if ( '' === $object_key ) {
				$coverage_failure = true;
				$errors[]         = sprintf(
					/* translators: %s: relative file path */
					__( 'Unable to normalize core path: %s', 'choctaw-wp-security' ),
					$relative_path
				);
				continue;
			}

			if ( ! is_file( $absolute_path ) ) {
				$observation = $this->build_missing_observation( $object_key, $relative_path, $version, $locale_requested, $locale_effective );

				if ( null !== $observation ) {
					$observations[] = $observation;
				}
				continue;
			}

			++$checked;

			$digests = $this->hash_file_consistently( $absolute_path );

			if ( null === $digests ) {
				$coverage_failure = true;
				$errors[]         = sprintf(
					/* translators: %s: relative file path */
					__( 'Unable to read file: %s', 'choctaw-wp-security' ),
					$relative_path
				);
				continue;
			}

			if ( ! empty( $digests['changed_during_read'] ) ) {
				$coverage_failure = true;
				$errors[]         = sprintf(
					/* translators: %s: relative file path */
					__( 'File changed while being verified: %s', 'choctaw-wp-security' ),
					$relative_path
				);
				continue;
			}

			if ( ! hash_equals( (string) $expected_hash, $digests['md5'] ) ) {
				$observation = $this->build_file_observation(
					self::RULE_MODIFIED,
					'modified',
					$object_key,
					$relative_path,
					$absolute_path,
					$digests['sha256'],
					$version,
					$locale_requested,
					$locale_effective
				);

				if ( null !== $observation ) {
					$observations[] = $observation;
				} else {
					$coverage_failure = true;
				}
			}
		}

		if ( ! $scan_incomplete ) {
			$unknown_result = $this->find_unknown_files( $checksum_set, $start_time, $time_budget );

			if ( ! empty( $unknown_result['scan_incomplete'] ) ) {
				$scan_incomplete = true;
				$errors[]        = __( 'Scan timed out before all directories could be scanned for unknown files.', 'choctaw-wp-security' );
			}

			if ( ! empty( $unknown_result['coverage_failure'] ) ) {
				$coverage_failure = true;
				foreach ( $unknown_result['errors'] as $error_message ) {
					$errors[] = $error_message;
				}
			}

			foreach ( $unknown_result['paths'] as $relative_path ) {
				$absolute_path = $this->absolute_path_for_relative( $relative_path );
				$object_key    = Sassh_Object_Path_Normalizer::normalize_in_root( $relative_path );

				if ( '' === $object_key ) {
					$coverage_failure = true;
					continue;
				}

				$digests = $this->hash_file_consistently( $absolute_path );

				if ( null === $digests || ! empty( $digests['changed_during_read'] ) ) {
					$coverage_failure = true;
					$errors[]         = sprintf(
						/* translators: %s: relative file path */
						__( 'Unable to fingerprint unknown file: %s', 'choctaw-wp-security' ),
						$relative_path
					);
					continue;
				}

				$observation = $this->build_file_observation(
					self::RULE_UNKNOWN,
					'unknown',
					$object_key,
					$relative_path,
					$absolute_path,
					$digests['sha256'],
					$version,
					$locale_requested,
					$locale_effective
				);

				if ( null !== $observation ) {
					$observations[] = $observation;
				} else {
					$coverage_failure = true;
				}
			}
		}

		$service->record_observations( $execution_id, $observations );

		$desired_status = 'success';
		if ( $scan_incomplete ) {
			$desired_status = 'partial';
		} elseif ( $coverage_failure ) {
			$desired_status = 'partial';
		}

		$ok = $service->finalize_scanner_execution( $execution_id, $desired_status );

		return $this->build_report_from_findings(
			$service,
			$execution_id,
			array(
				'completion_status' => $ok ? 'success' : $desired_status,
				'version'           => $version,
				'locale_requested'  => $locale_requested,
				'locale_effective'  => $locale_effective,
				'checked'           => $checked,
				'errors'            => array_values( array_unique( $errors ) ),
				'scan_incomplete'   => $scan_incomplete || $coverage_failure || ! $ok,
			)
		);
	}

	/**
	 * Verify checksum status for specific WordPress-relative paths.
	 *
	 * Uses the same WordPress.org checksum source and md5 comparison as scan().
	 * Not a Findings producer (File Changes helper).
	 *
	 * @param array<int, string> $relative_paths Relative file paths.
	 * @return array<string, mixed>
	 */
	public function verify_paths( array $relative_paths ) {
		global $wp_version;

		$version = isset( $wp_version ) ? (string) $wp_version : '';
		$locale  = get_locale();

		if ( '' === $locale ) {
			$locale = 'en_US';
		}

		$result = array(
			'version' => $version,
			'locale'  => $locale,
			'paths'   => array(),
			'errors'  => array(),
		);

		if ( '' === $version ) {
			$result['errors'][] = __( 'Unable to determine the installed WordPress version.', 'choctaw-wp-security' );
		}

		$checksum_result = false;

		if ( '' !== $version ) {
			$checksum_result = $this->get_checksums( $version, $locale );
		}

		if ( false === $checksum_result ) {
			if ( empty( $result['errors'] ) ) {
				$result['errors'][] = sprintf(
					/* translators: 1: WordPress version, 2: locale */
					__( 'Unable to retrieve official checksums for WordPress %1$s (%2$s).', 'choctaw-wp-security' ),
					$version,
					$locale
				);
			}

			foreach ( $relative_paths as $relative_path ) {
				$result['paths'][ wp_normalize_path( (string) $relative_path ) ] = 'unavailable';
			}

			return $result;
		}

		$checksums                = $checksum_result['checksums'];
		$result['locale']         = $checksum_result['locale_effective'];
		$result['locale_requested'] = $locale;
		$result['locale_effective'] = $checksum_result['locale_effective'];

		foreach ( $relative_paths as $relative_path ) {
			$relative_path = wp_normalize_path( (string) $relative_path );

			if ( $this->should_skip_checksum_path( $relative_path ) ) {
				$result['paths'][ $relative_path ] = 'not_applicable';
				continue;
			}

			if ( ! isset( $checksums[ $relative_path ] ) ) {
				$result['paths'][ $relative_path ] = 'not_applicable';
				continue;
			}

			$absolute_path = $this->absolute_path_for_relative( $relative_path );

			if ( ! is_file( $absolute_path ) ) {
				$result['paths'][ $relative_path ] = 'missing';
				continue;
			}

			$digests = $this->hash_file_consistently( $absolute_path );

			if ( null === $digests || ! empty( $digests['changed_during_read'] ) ) {
				$result['paths'][ $relative_path ] = 'unavailable';
				continue;
			}

			$result['paths'][ $relative_path ] = hash_equals( (string) $checksums[ $relative_path ], $digests['md5'] ) ? 'verified' : 'failed';
		}

		return $result;
	}

	/**
	 * Category labels for UI filters.
	 *
	 * @return array<string, string>
	 */
	public static function get_category_labels() {
		return array(
			'modified' => __( 'Modified Files', 'choctaw-wp-security' ),
			'missing'  => __( 'Missing Files', 'choctaw-wp-security' ),
			'unknown'  => __( 'Not Part of Core', 'choctaw-wp-security' ),
		);
	}

	/**
	 * Retrieve official checksums and the locale that supplied them.
	 *
	 * @param string $version WordPress version.
	 * @param string $locale  Requested locale.
	 * @return array{checksums: array<string, string>, locale_effective: string}|false
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

		$locale_effective = (string) $locale;
		$checksums        = get_core_checksums( $version, $locale_effective );

		if ( ! is_array( $checksums ) || empty( $checksums ) ) {
			if ( 'en_US' !== $locale_effective ) {
				$checksums        = get_core_checksums( $version, 'en_US' );
				$locale_effective = 'en_US';
			}
		}

		if ( ! is_array( $checksums ) || empty( $checksums ) ) {
			return false;
		}

		return array(
			'checksums'        => $checksums,
			'locale_effective' => $locale_effective,
		);
	}

	/**
	 * Read file once and derive MD5 + SHA-256; detect mid-read change via second MD5.
	 *
	 * @param string $absolute_path Absolute path.
	 * @return array{md5: string, sha256: string, changed_during_read: bool}|null
	 */
	private function hash_file_consistently( $absolute_path ) {
		if ( ! is_readable( $absolute_path ) ) {
			return null;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- intentional single-read for consistent digests.
		$contents = @file_get_contents( $absolute_path );

		if ( false === $contents ) {
			return null;
		}

		$md5    = md5( $contents );
		$sha256 = hash( 'sha256', $contents );

		if ( ! is_string( $md5 ) || ! is_string( $sha256 ) || '' === $md5 || '' === $sha256 ) {
			return null;
		}

		$md5_again = @md5_file( $absolute_path );
		$changed   = ( false === $md5_again ) || ! hash_equals( $md5, (string) $md5_again );

		return array(
			'md5'                 => $md5,
			'sha256'              => 'sha256:' . $sha256,
			'changed_during_read' => $changed,
		);
	}

	/**
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
	 * @param string $relative_path Relative file path.
	 * @return string
	 */
	private function absolute_path_for_relative( $relative_path ) {
		return wp_normalize_path( ABSPATH . ltrim( wp_normalize_path( $relative_path ), '/' ) );
	}

	/**
	 * @param array<string, bool> $checksum_set Known checksum paths.
	 * @param float               $start_time   Scan start time.
	 * @param int                 $time_budget  Allowed scan duration in seconds.
	 * @return array{paths: array<int, string>, scan_incomplete: bool, coverage_failure: bool, errors: array<int, string>}
	 */
	private function find_unknown_files( $checksum_set, $start_time, $time_budget ) {
		$unknown           = array();
		$scan_incomplete   = false;
		$coverage_failure  = false;
		$errors            = array();

		$this->collect_unknown_root_files( $checksum_set, $unknown, $start_time, $time_budget, $scan_incomplete, $coverage_failure, $errors );

		if ( ! $scan_incomplete ) {
			$this->collect_unknown_directory_files( 'wp-admin', $checksum_set, $unknown, $start_time, $time_budget, $scan_incomplete, $coverage_failure, $errors );
		}

		if ( ! $scan_incomplete ) {
			$this->collect_unknown_directory_files( 'wp-includes', $checksum_set, $unknown, $start_time, $time_budget, $scan_incomplete, $coverage_failure, $errors );
		}

		sort( $unknown );

		return array(
			'paths'            => $unknown,
			'scan_incomplete'  => $scan_incomplete,
			'coverage_failure' => $coverage_failure,
			'errors'           => $errors,
		);
	}

	/**
	 * @param array<string, bool> $checksum_set     Known checksum paths.
	 * @param array<int, string>  $unknown          Unknown file list.
	 * @param float               $start_time       Scan start time.
	 * @param int                 $time_budget      Allowed scan duration.
	 * @param bool                $scan_incomplete  Incomplete flag.
	 * @param bool                $coverage_failure Coverage failure flag.
	 * @param array<int, string>  $errors           Errors.
	 * @return void
	 */
	private function collect_unknown_root_files( $checksum_set, &$unknown, $start_time, $time_budget, &$scan_incomplete, &$coverage_failure, &$errors ) {
		$root = wp_normalize_path( ABSPATH );

		if ( ! is_dir( $root ) ) {
			$coverage_failure = true;
			$errors[]         = __( 'WordPress root is not a readable directory.', 'choctaw-wp-security' );
			return;
		}

		if ( ! is_readable( $root ) ) {
			$coverage_failure = true;
			$errors[]         = __( 'WordPress root directory is not readable.', 'choctaw-wp-security' );
			return;
		}

		$entries = @scandir( $root );

		if ( ! is_array( $entries ) ) {
			$coverage_failure = true;
			$errors[]         = __( 'Unable to list WordPress root directory.', 'choctaw-wp-security' );
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
	 * @param string              $directory        Directory relative to ABSPATH.
	 * @param array<string, bool> $checksum_set     Known checksum paths.
	 * @param array<int, string>  $unknown          Unknown file list.
	 * @param float               $start_time       Scan start time.
	 * @param int                 $time_budget      Allowed scan duration.
	 * @param bool                $scan_incomplete  Incomplete flag.
	 * @param bool                $coverage_failure Coverage failure flag.
	 * @param array<int, string>  $errors           Errors.
	 * @return void
	 */
	private function collect_unknown_directory_files( $directory, $checksum_set, &$unknown, $start_time, $time_budget, &$scan_incomplete, &$coverage_failure, &$errors ) {
		$directory_path = wp_normalize_path( trailingslashit( ABSPATH ) . $directory );

		if ( ! is_dir( $directory_path ) ) {
			$coverage_failure = true;
			$errors[]         = sprintf(
				/* translators: %s: directory name */
				__( 'Core directory missing or not a directory: %s', 'choctaw-wp-security' ),
				$directory
			);
			return;
		}

		if ( ! is_readable( $directory_path ) ) {
			$coverage_failure = true;
			$errors[]         = sprintf(
				/* translators: %s: directory name */
				__( 'Core directory is not readable: %s', 'choctaw-wp-security' ),
				$directory
			);
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
			$coverage_failure = true;
			$errors[]         = sprintf(
				/* translators: %s: directory name */
				__( 'Unable to traverse core directory: %s', 'choctaw-wp-security' ),
				$directory
			);
		}
	}

	/**
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
	 * @param float $start_time  Scan start time.
	 * @param int   $time_budget Allowed scan duration in seconds.
	 * @return bool
	 */
	private function scan_timed_out( $start_time, $time_budget ) {
		return ( microtime( true ) - $start_time ) >= $time_budget;
	}

	/**
	 * @param string $object_key        Normalized object key.
	 * @param string $relative_path     Display path.
	 * @param string $version           WP version.
	 * @param string $locale_requested  Requested locale.
	 * @param string $locale_effective  Effective checksum locale.
	 * @return array<string, mixed>|null
	 */
	private function build_missing_observation( $object_key, $relative_path, $version, $locale_requested, $locale_effective ) {
		$labels = self::get_category_labels();
		$fp     = Sassh_Findings_Service::FINGERPRINT_MISSING;

		return array(
			'scanner_id'           => self::SCANNER_ID,
			'rule_id'              => self::RULE_MISSING,
			'object_type'          => Sassh_Object_Type_Registry::TYPE_FILE,
			'object_key'           => $object_key,
			'blog_id'              => null,
			'risk_level'           => 'critical',
			'sassh_classification' => 'needs_review',
			'content_fingerprint'  => $fp,
			'object_fingerprint'   => $fp,
			'title'                => $relative_path,
			'description'          => __( 'Official WordPress core verification reports that this file is missing.', 'choctaw-wp-security' ),
			'metadata'             => array(
				'path'              => $relative_path,
				'category'          => 'missing',
				'category_label'    => $labels['missing'],
				'size'              => 0,
				'size_label'        => '',
				'modified'          => 0,
				'modified_label'    => '',
				'permissions'       => '',
				'owner'             => '',
				'contents'          => '',
				'contents_truncated'  => false,
				'why_seeing_this'   => __( 'Official WordPress core verification reports that this file is missing. It is highly unlikely it was deleted by a plugin or theme.', 'choctaw-wp-security' ),
				'how_to_proceed'    => __( 'Restore the missing core file from a clean WordPress package matching your installed version, or reinstall/update WordPress core.', 'choctaw-wp-security' ),
				'wp_version'        => $version,
				'locale_requested'  => $locale_requested,
				'locale_effective'  => $locale_effective,
			),
		);
	}

	/**
	 * @param string $rule_id           Rule id.
	 * @param string $category          Category key.
	 * @param string $object_key        Normalized key.
	 * @param string $relative_path     Relative path.
	 * @param string $absolute_path     Absolute path.
	 * @param string $sha256_fingerprint sha256:hex fingerprint.
	 * @param string $version           WP version.
	 * @param string $locale_requested  Requested locale.
	 * @param string $locale_effective  Effective locale.
	 * @return array<string, mixed>|null
	 */
	private function build_file_observation( $rule_id, $category, $object_key, $relative_path, $absolute_path, $sha256_fingerprint, $version, $locale_requested, $locale_effective ) {
		$labels = self::get_category_labels();
		$meta   = Choctaw_Wp_Security_Utils::get_file_preview_meta( $absolute_path );

		if ( 'modified' === $category ) {
			$risk        = 'critical';
			$description = __( 'This file does not match the official WordPress core checksum.', 'choctaw-wp-security' );
			$why         = __( 'This file does not match the official WordPress core checksum, indicating that it was modified by something. Because plugins and themes do not modify core files, this was highly likely the result of an attacker.', 'choctaw-wp-security' );
			$how         = __( 'Replace the modified file with a clean copy from WordPress.org for your installed version, then investigate how it was changed.', 'choctaw-wp-security' );
		} else {
			$risk        = 'suspicious';
			$description = __( 'This file is present under WordPress core paths but is not part of the official checksum list.', 'choctaw-wp-security' );
			$why         = __( 'Official WordPress core verification reports that it does not recognize this file.', 'choctaw-wp-security' );
			$how         = __( 'Identify whether the file belongs to intentional customization or malware. Remove unexpected files from core directories.', 'choctaw-wp-security' );
		}

		return array(
			'scanner_id'           => self::SCANNER_ID,
			'rule_id'              => $rule_id,
			'object_type'          => Sassh_Object_Type_Registry::TYPE_FILE,
			'object_key'           => $object_key,
			'blog_id'              => null,
			'risk_level'           => $risk,
			'sassh_classification' => 'needs_review',
			'content_fingerprint'  => $sha256_fingerprint,
			'object_fingerprint'   => $sha256_fingerprint,
			'title'                => $relative_path,
			'description'          => $description,
			'metadata'             => array(
				'path'              => $relative_path,
				'absolute_path'     => $absolute_path,
				'category'          => $category,
				'category_label'    => isset( $labels[ $category ] ) ? $labels[ $category ] : $category,
				'size'              => $meta['size'],
				'size_label'        => $meta['size_label'],
				'modified'          => $meta['modified'],
				'modified_label'    => $meta['modified_label'],
				'permissions'       => isset( $meta['permissions'] ) ? $meta['permissions'] : '',
				'owner'             => isset( $meta['owner'] ) ? $meta['owner'] : '',
				'contents'          => $meta['contents'],
				'contents_truncated'  => ! empty( $meta['contents_truncated'] ),
				'why_seeing_this'   => $why,
				'how_to_proceed'    => $how,
				'wp_version'        => $version,
				'locale_requested'  => $locale_requested,
				'locale_effective'  => $locale_effective,
			),
		);
	}

	/**
	 * Build UI report payload from persisted findings.
	 *
	 * @param Sassh_Findings_Service $service      Service.
	 * @param int                    $execution_id Execution id.
	 * @param array<string, mixed>   $run_meta     Run summary fields.
	 * @return array<string, mixed>
	 */
	private function build_report_from_findings( Sassh_Findings_Service $service, $execution_id, array $run_meta ) {
		$completion = isset( $run_meta['completion_status'] ) ? (string) $run_meta['completion_status'] : 'failed';
		$coverage_ok = ( 'success' === $completion );
		$rows        = $service->list_findings(
			array(
				'scanner_id'      => self::SCANNER_ID,
				'detection_state' => 'active',
			)
		);

		$findings  = array();
		$critical  = 0;
		$suspicious = 0;
		$confirmed = 0;

		foreach ( $rows as $row ) {
			$confirmed_this_run = isset( $row['last_scanner_execution_id'] )
				&& (int) $row['last_scanner_execution_id'] === (int) $execution_id;

			if ( $confirmed_this_run ) {
				++$confirmed;
			}

			$risk = isset( $row['risk_level'] ) ? (string) $row['risk_level'] : 'info';
			if ( 'critical' === $risk ) {
				++$critical;
			} elseif ( 'suspicious' === $risk ) {
				++$suspicious;
			}

			$findings[] = array(
				'id'                  => $row['finding_id'],
				'finding_id'          => $row['finding_id'],
				'fingerprint'         => $row['content_fingerprint'],
				'content_fingerprint' => $row['content_fingerprint'],
				'object_fingerprint'  => $row['object_fingerprint'],
				'path'                => isset( $row['path'] ) ? $row['path'] : $row['object_key'],
				'risk'                => $risk,
				'risk_level'          => $risk,
				'risk_label'          => isset( $row['risk_label'] ) ? $row['risk_label'] : $risk,
				'status'              => $row['effective_status'],
				'status_label'        => $row['status_label'],
				'effective_status'    => $row['effective_status'],
				'can_dismiss'         => ! empty( $row['can_dismiss'] ),
				'dismissal_control_state' => isset( $row['dismissal_control_state'] ) ? $row['dismissal_control_state'] : Sassh_Findings_Service::dismissal_control_state( $row ),
				'category'            => isset( $row['category'] ) ? $row['category'] : '',
				'category_label'      => isset( $row['category_label'] ) ? $row['category_label'] : '',
				'size'                => isset( $row['size'] ) ? $row['size'] : 0,
				'size_label'          => isset( $row['size_label'] ) ? $row['size_label'] : '',
				'modified'            => isset( $row['modified'] ) ? $row['modified'] : 0,
				'modified_label'      => isset( $row['modified_label'] ) ? $row['modified_label'] : '',
				'permissions'         => isset( $row['permissions'] ) ? $row['permissions'] : '',
				'owner'               => isset( $row['owner'] ) ? $row['owner'] : '',
				'contents'            => isset( $row['contents'] ) ? $row['contents'] : '',
				'contents_truncated'    => ! empty( $row['contents_truncated'] ),
				'why_seeing_this'     => isset( $row['why_seeing_this'] ) ? $row['why_seeing_this'] : '',
				'how_to_proceed'      => isset( $row['how_to_proceed'] ) ? $row['how_to_proceed'] : '',
				'first_seen_at'       => $row['first_seen_at'],
				'last_seen_at'        => $row['last_seen_at'],
				'detection_state'     => $row['detection_state'],
				'confirmed_this_run'  => $confirmed_this_run,
				'categories'          => ( isset( $row['categories'] ) && is_array( $row['categories'] ) ) ? $row['categories'] : array(),
				'category_label_display' => isset( $row['category_label_display'] ) ? $row['category_label_display'] : ( isset( $row['category_label'] ) ? $row['category_label'] : '' ),
				'extra_rule_count'    => isset( $row['extra_rule_count'] ) ? (int) $row['extra_rule_count'] : 0,
				'guidance'            => ( isset( $row['guidance'] ) && is_array( $row['guidance'] ) ) ? $row['guidance'] : array(),
			);
		}

		$count = count( $findings );

		return array(
			'success'             => $coverage_ok && 0 === $critical && 0 === $suspicious,
			'coverage_complete'   => $coverage_ok,
			'absence_reconciled'  => $coverage_ok,
			'completion_status'   => $completion,
			'scan_incomplete'     => ! empty( $run_meta['scan_incomplete'] ) || ! $coverage_ok,
			'version'             => isset( $run_meta['version'] ) ? (string) $run_meta['version'] : '',
			'locale'              => isset( $run_meta['locale_effective'] ) ? (string) $run_meta['locale_effective'] : '',
			'locale_requested'    => isset( $run_meta['locale_requested'] ) ? (string) $run_meta['locale_requested'] : '',
			'locale_effective'    => isset( $run_meta['locale_effective'] ) ? (string) $run_meta['locale_effective'] : '',
			'checked'             => isset( $run_meta['checked'] ) ? (int) $run_meta['checked'] : 0,
			'errors'              => isset( $run_meta['errors'] ) && is_array( $run_meta['errors'] ) ? $run_meta['errors'] : array(),
			'findings'            => $findings,
			'confirmed_this_run'  => $confirmed,
			'prior_findings_only' => ! $coverage_ok && $count > 0 && 0 === $confirmed,
			'summary'             => array(
				'critical'   => $critical,
				'warning'    => 0,
				'suspicious' => $suspicious,
				'alert'      => 0,
				'safe'       => 0,
				'info'       => 0,
				'total'      => $count,
				'flagged'    => $count,
			),
			'scanned_at'          => time(),
			'execution_id'        => $execution_id,
			'findings_backend'    => 'sassh',
		);
	}
}
