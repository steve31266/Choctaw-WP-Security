<?php
/**
 * Uploads folder PHP executable scanner (Sassh Findings producer).
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Discovers PHP-like files under the WordPress uploads directory.
 */
class Choctaw_Wp_Security_Uploads_Folder_Scanner {

	const CONTENTS_CHAR_LIMIT = 16384;
	const FILE_LIMIT          = 200;
	const CATEGORY_KEY        = 'php_executable';
	const SCANNER_ID          = 'uploads-folder';
	const RULE_ID             = 'php-file-in-uploads';

	/**
	 * Scan the uploads folder for PHP-like files and persist via Sassh Findings.
	 *
	 * @return array<string, mixed>
	 */
	public function scan() {
		Sassh_Findings_Schema::maybe_upgrade();

		$uploads  = wp_get_upload_dir();
		$basedir  = isset( $uploads['basedir'] ) ? (string) $uploads['basedir'] : '';
		$scope_key = Sassh_Findings_Service::uploads_scope_key( $basedir );
		$service  = new Sassh_Findings_Service();

		$execution_id = $service->begin_scanner_execution(
			self::SCANNER_ID,
			array(
				'scope_key'  => $scope_key,
				'run_type'   => 'individual',
				'run_source' => 'wordpress_admin',
			)
		);

		if ( '' === $basedir || ! is_dir( $basedir ) ) {
			$service->finalize_scanner_execution( $execution_id, 'failed' );
			return $this->build_report_from_findings( $service, false, $execution_id );
		}

		try {
			$paths        = $this->find_php_files( $basedir );
			$observations = array();

			foreach ( $paths as $absolute_path ) {
				$observation = $this->build_observation( $absolute_path );

				if ( null !== $observation ) {
					$observations[] = $observation;
				}
			}

			$service->record_observations( $execution_id, $observations );
			$ok = $service->finalize_scanner_execution( $execution_id, 'success' );

			return $this->build_report_from_findings( $service, $ok, $execution_id );
		} catch ( Exception $e ) {
			$service->finalize_scanner_execution( $execution_id, 'failed' );
			return $this->build_report_from_findings( $service, false, $execution_id );
		}
	}

	/**
	 * Category labels for UI filters.
	 *
	 * @return array<string, string>
	 */
	public static function get_category_labels() {
		return array(
			self::CATEGORY_KEY => __( 'PHP Executable', 'choctaw-wp-security' ),
		);
	}

	/**
	 * Build a Findings observation for one file.
	 *
	 * @param string $absolute_path Absolute path.
	 * @return array<string, mixed>|null
	 */
	private function build_observation( $absolute_path ) {
		$object_key = Sassh_Object_Path_Normalizer::normalize_in_root( $absolute_path );

		if ( '' === $object_key ) {
			return null;
		}

		$fingerprint = Sassh_Findings_Service::file_content_fingerprint( $absolute_path );
		$meta        = Choctaw_Wp_Security_Utils::get_file_preview_meta( $absolute_path );
		$labels      = self::get_category_labels();
		$blog_id     = Sassh_Findings_Service::blog_id_from_uploads_path( $object_key );

		return array(
			'scanner_id'             => self::SCANNER_ID,
			'rule_id'                => self::RULE_ID,
			'object_type'            => Sassh_Object_Type_Registry::TYPE_FILE,
			'object_key'             => $object_key,
			'blog_id'                => $blog_id,
			'risk_level'             => 'warning',
			'sassh_classification'   => 'needs_review',
			'content_fingerprint'    => $fingerprint,
			'object_fingerprint'     => $fingerprint,
			'title'                  => $this->format_display_path( $absolute_path ),
			'description'            => __( 'PHP-like file found in the uploads folder.', 'choctaw-wp-security' ),
			'metadata'               => array(
				'path'              => $this->format_display_path( $absolute_path ),
				'absolute_path'     => $absolute_path,
				'category'          => self::CATEGORY_KEY,
				'category_label'    => $labels[ self::CATEGORY_KEY ],
				'size'              => $meta['size'],
				'size_label'        => $meta['size_label'],
				'modified'          => $meta['modified'],
				'modified_label'    => $meta['modified_label'],
				'permissions'       => $meta['permissions'],
				'owner'             => $meta['owner'],
				'contents'          => $meta['contents'],
				'contents_truncated'  => ! empty( $meta['contents_truncated'] ),
				'why_seeing_this'   => __( 'The WordPress uploads folder is intended for media files such as images, PDFs, videos, and documents. PHP scripts normally do not belong here because this directory is writable by WordPress and is a common target for attackers attempting to upload and execute malicious code.', 'choctaw-wp-security' ),
				'how_to_proceed'    => __( 'Review each PHP file carefully. If it was intentionally placed there by a trusted plugin or developer, it may be legitimate. Otherwise, treat it as suspicious, identify how it was uploaded, remove it if appropriate, and restore any affected files from a known-good backup. Enabling "Disable PHP Execution in Uploads" helps prevent uploaded PHP files from being executed.', 'choctaw-wp-security' ),
			),
		);
	}

	/**
	 * Build UI report payload from persisted findings.
	 *
	 * @param Sassh_Findings_Service $service      Service.
	 * @param bool                   $success      Whether finalize succeeded.
	 * @param int                    $execution_id Execution id.
	 * @return array<string, mixed>
	 */
	private function build_report_from_findings( Sassh_Findings_Service $service, $success, $execution_id ) {
		$rows     = $service->list_findings(
			array(
				'scanner_id'      => self::SCANNER_ID,
				'detection_state' => 'active',
			)
		);
		$findings = array();
		$warning  = 0;

		foreach ( $rows as $row ) {
			$finding = array(
				'id'                  => $row['finding_id'],
				'finding_id'          => $row['finding_id'],
				'fingerprint'         => $row['content_fingerprint'],
				'content_fingerprint' => $row['content_fingerprint'],
				'object_fingerprint'  => $row['object_fingerprint'],
				'path'                => isset( $row['path'] ) ? $row['path'] : $row['object_key'],
				'absolute_path'       => isset( $row['absolute_path'] ) ? $row['absolute_path'] : '',
				'risk'                => $row['risk_level'],
				'risk_level'          => $row['risk_level'],
				'risk_label'          => $row['risk_label'],
				'status'              => $row['effective_status'],
				'status_label'        => $row['status_label'],
				'effective_status'    => $row['effective_status'],
				'category'            => isset( $row['category'] ) ? $row['category'] : self::CATEGORY_KEY,
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
				'categories'          => ( isset( $row['categories'] ) && is_array( $row['categories'] ) ) ? $row['categories'] : array(),
				'category_label_display' => isset( $row['category_label_display'] ) ? $row['category_label_display'] : ( isset( $row['category_label'] ) ? $row['category_label'] : '' ),
				'extra_rule_count'    => isset( $row['extra_rule_count'] ) ? (int) $row['extra_rule_count'] : 0,
				'guidance'            => ( isset( $row['guidance'] ) && is_array( $row['guidance'] ) ) ? $row['guidance'] : array(),
			);

			if ( 'warning' === $finding['risk_level'] || 'critical' === $finding['risk_level'] ) {
				++$warning;
			}

			$findings[] = $finding;
		}

		$count = count( $findings );

		return array(
			'success'      => (bool) $success,
			'findings'     => $findings,
			'summary'      => array(
				'critical'   => 0,
				'warning'    => $warning,
				'suspicious' => 0,
				'alert'      => 0,
				'safe'       => 0,
				'info'       => 0,
				'total'      => $count,
				'flagged'    => $count,
			),
			'scanned_at'   => time(),
			'execution_id' => $execution_id,
			'findings_backend' => 'sassh',
		);
	}

	/**
	 * Find PHP-like files in a directory.
	 *
	 * @param string $folder Directory path.
	 * @return array<int, string>
	 */
	private function find_php_files( $folder ) {
		$folder = (string) $folder;

		if ( '' === $folder || ! is_dir( $folder ) || ! is_readable( $folder ) ) {
			return array();
		}

		$matches    = array();
		$extensions = array( 'php', 'phtml', 'phar', 'php3', 'php4', 'php5', 'php7' );

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $folder, FilesystemIterator::SKIP_DOTS )
			);

			foreach ( $iterator as $file ) {
				if ( count( $matches ) >= self::FILE_LIMIT ) {
					break;
				}

				if ( ! $file->isFile() ) {
					continue;
				}

				$extension = strtolower( $file->getExtension() );

				if ( in_array( $extension, $extensions, true ) ) {
					$matches[] = $file->getPathname();
				}
			}
		} catch ( Exception $exception ) {
			return $matches;
		}

		sort( $matches, SORT_STRING );

		return $matches;
	}

	/**
	 * Format a display path relative to ABSPATH when possible.
	 *
	 * @param string $absolute_path Absolute path.
	 * @return string
	 */
	private function format_display_path( $absolute_path ) {
		$normalized = Sassh_Object_Path_Normalizer::normalize_in_root( $absolute_path );

		if ( '' !== $normalized ) {
			return $normalized;
		}

		return wp_normalize_path( (string) $absolute_path );
	}
}
