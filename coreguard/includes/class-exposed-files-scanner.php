<?php
/**
 * Exposed files scanner for the WordPress document root (Sassh Findings producer).
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Non-recursively scans ABSPATH for sensitive leftover files and directories.
 */
class Choctaw_Wp_Security_Exposed_Files_Scanner {

	const CONTENTS_CHAR_LIMIT = 16384;
	const FILE_LIMIT          = 200;
	const SCANNER_ID          = 'exposed-files';

	/**
	 * Scan the WordPress root for exposed sensitive files and persist via Sassh Findings.
	 *
	 * @return array<string, mixed>
	 */
	public function scan() {
		Sassh_Findings_Schema::maybe_upgrade();

		$scope_key    = Sassh_Findings_Service::exposed_files_scope_key();
		$service      = new Sassh_Findings_Service();
		$execution_id = $service->begin_scanner_execution(
			self::SCANNER_ID,
			array(
				'scope_key'  => $scope_key,
				'run_type'   => 'individual',
				'run_source' => 'wordpress_admin',
			)
		);

		$root = wp_normalize_path( ABSPATH );

		if ( '' === $root || ! is_dir( $root ) || ! is_readable( $root ) ) {
			$service->finalize_scanner_execution( $execution_id, 'failed' );

			return $this->build_report_from_findings(
				$service,
				$execution_id,
				array(
					'completion_status' => 'failed',
					'scan_incomplete'   => true,
					'errors'            => array(
						__( 'WordPress root is not a readable directory.', 'choctaw-wp-security' ),
					),
				)
			);
		}

		$entries = $this->list_root_entries( $root );

		if ( null === $entries ) {
			$service->finalize_scanner_execution( $execution_id, 'failed' );

			return $this->build_report_from_findings(
				$service,
				$execution_id,
				array(
					'completion_status' => 'failed',
					'scan_incomplete'   => true,
					'errors'            => array(
						__( 'Unable to list WordPress root directory.', 'choctaw-wp-security' ),
					),
				)
			);
		}

		$observations   = array();
		$hash_failures  = 0;
		$limit_exceeded = false;
		$match_count    = 0;

		foreach ( $entries as $entry ) {
			$match = $this->match_entry( $entry );

			if ( null === $match ) {
				continue;
			}

			if ( $match_count >= self::FILE_LIMIT ) {
				$limit_exceeded = true;
				break;
			}

			$observation = $this->build_observation( $entry, $match );

			if ( null === $observation ) {
				++$hash_failures;
				continue;
			}

			$observations[] = $observation;
			++$match_count;
		}

		$service->record_observations( $execution_id, $observations );

		if ( $limit_exceeded || $hash_failures > 0 ) {
			$service->finalize_scanner_execution( $execution_id, 'partial' );

			$errors = array();

			if ( $limit_exceeded ) {
				$errors[] = sprintf(
					/* translators: %d: maximum findings recorded per scan */
					__( 'Scan stopped after recording %d exposed-file findings. Previously detected findings were not cleared.', 'choctaw-wp-security' ),
					self::FILE_LIMIT
				);
			}

			if ( $hash_failures > 0 ) {
				$errors[] = __( 'One or more matched files could not be fingerprinted.', 'choctaw-wp-security' );
			}

			return $this->build_report_from_findings(
				$service,
				$execution_id,
				array(
					'completion_status' => 'partial',
					'scan_incomplete'   => true,
					'errors'            => $errors,
				)
			);
		}

		$ok = $service->finalize_scanner_execution( $execution_id, 'success' );

		return $this->build_report_from_findings(
			$service,
			$execution_id,
			array(
				'completion_status' => $ok ? 'success' : 'failed',
				'scan_incomplete'   => ! $ok,
				'errors'            => array(),
			)
		);
	}

	/**
	 * Category labels for UI filters.
	 *
	 * @return array<string, string>
	 */
	public static function get_category_labels() {
		return Choctaw_Wp_Security_Exposed_Files_Patterns::get_category_labels();
	}

	/**
	 * List files and directories directly under ABSPATH.
	 *
	 * @param string $root Normalized ABSPATH.
	 * @return array<int, array{name: string, path: string, is_dir: bool}>|null Null when scandir fails.
	 */
	private function list_root_entries( $root ) {
		$names = @scandir( $root );

		if ( ! is_array( $names ) ) {
			return null;
		}

		$entries = array();

		foreach ( $names as $name ) {
			if ( '.' === $name || '..' === $name ) {
				continue;
			}

			$path = wp_normalize_path( trailingslashit( $root ) . $name );

			$entries[] = array(
				'name'   => $name,
				'path'   => $path,
				'is_dir' => is_dir( $path ),
			);
		}

		usort(
			$entries,
			static function ( $left, $right ) {
				return strcasecmp( (string) $left['name'], (string) $right['name'] );
			}
		);

		return $entries;
	}

	/**
	 * Match one root entry against Exposed Files patterns.
	 *
	 * @param array{name: string, path: string, is_dir: bool} $entry Entry metadata.
	 * @return array{pattern: string, category: string, risk: string}|null
	 */
	private function match_entry( array $entry ) {
		$name   = (string) $entry['name'];
		$path   = (string) $entry['path'];
		$is_dir = ! empty( $entry['is_dir'] );
		$size   = ( ! $is_dir && file_exists( $path ) ) ? (int) @filesize( $path ) : 0;

		$needs_snippet = $this->needs_content_snippet( $name, $is_dir );
		$snippet       = $needs_snippet ? $this->read_truncated_contents( $path ) : '';

		return Choctaw_Wp_Security_Exposed_Files_Patterns::match_entry( $name, $is_dir, $size, $snippet );
	}

	/**
	 * Whether a content snippet is needed before matching.
	 *
	 * @param string $name   Basename.
	 * @param bool   $is_dir Whether directory.
	 * @return bool
	 */
	private function needs_content_snippet( $name, $is_dir ) {
		if ( $is_dir ) {
			return false;
		}

		$exact = Choctaw_Wp_Security_Exposed_Files_Patterns::get_exact_file_patterns();
		if ( isset( $exact[ $name ] ) && 'diag_script' === $exact[ $name ] ) {
			return true;
		}

		return (bool) preg_match( '/\.php$/i', $name );
	}

	/**
	 * Build a Findings observation for one matched entry.
	 *
	 * @param array{name: string, path: string, is_dir: bool}               $entry Entry metadata.
	 * @param array{pattern: string, category: string, risk: string} $match Match result.
	 * @return array<string, mixed>|null Null when fingerprint cannot be computed.
	 */
	private function build_observation( array $entry, array $match ) {
		$path     = (string) $entry['path'];
		$name     = (string) $entry['name'];
		$is_dir   = ! empty( $entry['is_dir'] );
		$object_key = Sassh_Object_Path_Normalizer::normalize_in_root( $path );

		if ( '' === $object_key ) {
			$object_key = Sassh_Object_Path_Normalizer::normalize_in_root( $name );
		}

		if ( '' === $object_key ) {
			return null;
		}

		if ( $is_dir ) {
			$fingerprint = Sassh_Findings_Service::FINGERPRINT_DIRECTORY;
		} else {
			if ( ! is_readable( $path ) ) {
				return null;
			}

			$fingerprint = Sassh_Findings_Service::file_content_fingerprint( $path );

			if (
				Sassh_Findings_Service::FINGERPRINT_MISSING === $fingerprint
				|| 'sha256:unreadable' === $fingerprint
			) {
				return null;
			}
		}

		$risk_level    = (string) $match['risk'];
		$classification = Sassh_Findings_Service::default_classification( $risk_level );
		$labels        = self::get_category_labels();
		$guidance      = Choctaw_Wp_Security_Exposed_Files_Patterns::get_guidance( $match['pattern'] );
		$rule_id       = Choctaw_Wp_Security_Exposed_Files_Patterns::rule_id_for_pattern( $match['pattern'] );
		$category      = (string) $match['category'];
		$size          = ( ! $is_dir && file_exists( $path ) ) ? (int) @filesize( $path ) : 0;
		$modified      = file_exists( $path ) ? @filemtime( $path ) : false;

		$contents           = '';
		$contents_truncated = false;

		if ( $is_dir ) {
			$contents = __( 'Directory — contents not listed.', 'choctaw-wp-security' );
		} elseif ( $this->is_text_previewable( $name, $match['pattern'] ) ) {
			$preview            = Choctaw_Wp_Security_Utils::read_file_contents_preview_result( $path, self::CONTENTS_CHAR_LIMIT );
			$contents           = $preview['contents'];
			$contents_truncated = ! empty( $preview['truncated'] );
		} else {
			$contents = __( 'Binary archive — contents not displayed.', 'choctaw-wp-security' );
		}

		return array(
			'scanner_id'           => self::SCANNER_ID,
			'rule_id'              => $rule_id,
			'object_type'          => Sassh_Object_Type_Registry::TYPE_FILE,
			'object_key'           => $object_key,
			'blog_id'              => null,
			'risk_level'           => $risk_level,
			'sassh_classification' => $classification,
			'content_fingerprint'  => $fingerprint,
			'object_fingerprint'   => $fingerprint,
			'title'                => $name,
			'description'          => sprintf(
				/* translators: %s: pattern / rule id */
				__( 'Exposed sensitive file matched pattern %s.', 'choctaw-wp-security' ),
				$rule_id
			),
			'metadata'             => array(
				'filename'          => $name,
				'path'              => $name,
				'absolute_path'     => $path,
				'is_directory'      => $is_dir,
				'pattern'           => (string) $match['pattern'],
				'rule_id'           => $rule_id,
				'category'          => $category,
				'category_label'    => isset( $labels[ $category ] ) ? $labels[ $category ] : $category,
				'size'              => $is_dir ? 0 : $size,
				'size_label'        => $is_dir ? '—' : size_format( $size ),
				'modified'          => false === $modified ? 0 : (int) $modified,
				'modified_label'    => $this->format_modified_label( $modified ),
				'permissions'       => $this->format_permissions( $path ),
				'owner'             => $this->format_owner( $path ),
				'contents'          => $contents,
				'contents_truncated'  => $contents_truncated,
				'why_seeing_this'   => $guidance['why'],
				'how_to_proceed'    => $guidance['how'],
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
		$completion  = isset( $run_meta['completion_status'] ) ? (string) $run_meta['completion_status'] : 'failed';
		$coverage_ok = ( 'success' === $completion );
		$rows        = $service->list_findings(
			array(
				'scanner_id'      => self::SCANNER_ID,
				'detection_state' => 'active',
			)
		);

		$findings   = array();
		$critical   = 0;
		$warning    = 0;
		$suspicious = 0;
		$info       = 0;
		$confirmed  = 0;

		foreach ( $rows as $row ) {
			$confirmed_this_run = isset( $row['last_scanner_execution_id'] )
				&& (int) $row['last_scanner_execution_id'] === (int) $execution_id;

			if ( $confirmed_this_run ) {
				++$confirmed;
			}

			$risk = isset( $row['risk_level'] ) ? (string) $row['risk_level'] : 'info';

			if ( 'critical' === $risk ) {
				++$critical;
			} elseif ( 'warning' === $risk ) {
				++$warning;
			} elseif ( 'suspicious' === $risk ) {
				++$suspicious;
			} elseif ( 'info' === $risk ) {
				++$info;
			}

			$filename = isset( $row['filename'] ) ? (string) $row['filename'] : (string) $row['object_key'];

			$findings[] = array(
				'id'                  => $row['finding_id'],
				'finding_id'          => $row['finding_id'],
				'fingerprint'         => $row['content_fingerprint'],
				'content_fingerprint' => $row['content_fingerprint'],
				'object_fingerprint'  => $row['object_fingerprint'],
				'filename'            => $filename,
				'path'                => isset( $row['path'] ) ? $row['path'] : $filename,
				'absolute_path'       => isset( $row['absolute_path'] ) ? $row['absolute_path'] : '',
				'is_directory'        => ! empty( $row['is_directory'] ),
				'pattern'             => isset( $row['pattern'] ) ? $row['pattern'] : '',
				'risk'                => $risk,
				'risk_level'          => $risk,
				'risk_label'          => isset( $row['risk_label'] ) ? $row['risk_label'] : $risk,
				'status'              => $row['effective_status'],
				'status_label'        => $row['status_label'],
				'effective_status'    => $row['effective_status'],
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
			);
		}

		$count   = count( $findings );
		$flagged = $critical + $warning + $suspicious;

		return array(
			'success'             => $coverage_ok && 0 === $flagged,
			'coverage_complete'   => $coverage_ok,
			'absence_reconciled'  => $coverage_ok,
			'completion_status'   => $completion,
			'scan_incomplete'     => ! empty( $run_meta['scan_incomplete'] ) || ! $coverage_ok,
			'errors'              => isset( $run_meta['errors'] ) && is_array( $run_meta['errors'] ) ? $run_meta['errors'] : array(),
			'findings'            => $findings,
			'confirmed_this_run'  => $confirmed,
			'prior_findings_only' => ! $coverage_ok && $count > 0 && 0 === $confirmed,
			'summary'             => array(
				'critical'   => $critical,
				'warning'    => $warning,
				'suspicious' => $suspicious,
				'alert'      => 0,
				'safe'       => 0,
				'info'       => $info,
				'total'      => $count,
				'flagged'    => $flagged,
			),
			'scanned_at'          => time(),
			'execution_id'        => $execution_id,
			'findings_backend'    => 'sassh',
		);
	}

	/**
	 * Whether contents should be shown as text.
	 *
	 * @param string $name    Basename.
	 * @param string $pattern Pattern ID.
	 * @return bool
	 */
	private function is_text_previewable( $name, $pattern ) {
		if ( in_array( $pattern, array( 'backup_archive', 'git_dir', 'svn_dir' ), true ) ) {
			return false;
		}

		$lower = strtolower( (string) $name );
		foreach ( array( '.zip', '.tar', '.tar.gz', '.tgz', '.gz', '.7z', '.rar' ) as $extension ) {
			$ext_len = strlen( $extension );
			if ( strlen( $lower ) > $ext_len && substr( $lower, -$ext_len ) === $extension ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Read up to CONTENTS_CHAR_LIMIT characters from a file.
	 *
	 * @param string $path Absolute path.
	 * @return string
	 */
	private function read_truncated_contents( $path ) {
		if ( '' === $path || ! is_readable( $path ) || is_dir( $path ) ) {
			return '';
		}

		$handle = fopen( $path, 'rb' );
		if ( false === $handle ) {
			return '';
		}

		$chunk = fread( $handle, self::CONTENTS_CHAR_LIMIT );
		fclose( $handle );

		if ( false === $chunk ) {
			return '';
		}

		if ( function_exists( 'mb_substr' ) ) {
			return mb_substr( $chunk, 0, self::CONTENTS_CHAR_LIMIT );
		}

		return substr( $chunk, 0, self::CONTENTS_CHAR_LIMIT );
	}

	/**
	 * Format octal permission bits (e.g. 644).
	 *
	 * @param string $path Absolute path.
	 * @return string
	 */
	private function format_permissions( $path ) {
		if ( ! file_exists( $path ) ) {
			return __( 'Unavailable', 'choctaw-wp-security' );
		}

		$perms = @fileperms( $path );
		if ( false === $perms ) {
			return __( 'Unavailable', 'choctaw-wp-security' );
		}

		return sprintf( '%o', $perms & 0777 );
	}

	/**
	 * Format file owner name or UID.
	 *
	 * @param string $path Absolute path.
	 * @return string
	 */
	private function format_owner( $path ) {
		if ( ! file_exists( $path ) ) {
			return __( 'Unavailable', 'choctaw-wp-security' );
		}

		$uid = @fileowner( $path );
		if ( false === $uid ) {
			return __( 'Unavailable', 'choctaw-wp-security' );
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
	 * Format a filemtime value for display.
	 *
	 * @param int|false $modified Unix timestamp or false.
	 * @return string
	 */
	private function format_modified_label( $modified ) {
		if ( false === $modified || ! $modified ) {
			return __( 'Unavailable', 'choctaw-wp-security' );
		}

		return wp_date(
			sprintf( '%s %s', get_option( 'date_format' ), get_option( 'time_format' ) ),
			(int) $modified
		);
	}
}
