<?php
/**
 * Must-Use plugins folder scanner (Sassh Findings producer).
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Discovers PHP-like files under the WordPress mu-plugins directory.
 */
class Choctaw_Wp_Security_Mu_Plugins_Scanner {

	const CONTENTS_CHAR_LIMIT = 16384;
	const FILE_LIMIT          = 200;
	const CATEGORY_KEY        = 'mu_plugin';
	const SCANNER_ID          = 'mu-plugins';
	const RULE_ID             = 'php-like-file-in-mu-plugins';

	/**
	 * Scan the mu-plugins folder for PHP-like files and persist via Sassh Findings.
	 *
	 * @return array<string, mixed>
	 */
	public function scan() {
		Sassh_Findings_Schema::maybe_upgrade();

		$dir       = defined( 'WPMU_PLUGIN_DIR' ) ? (string) WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
		$scope_key = Sassh_Findings_Service::mu_plugins_scope_key( $dir );
		$service   = new Sassh_Findings_Service();

		$execution_id = $service->begin_scanner_execution(
			self::SCANNER_ID,
			array(
				'scope_key'  => $scope_key,
				'run_type'   => 'individual',
				'run_source' => 'wordpress_admin',
			)
		);

		// Confirmed missing directory = successful empty scope (absence may run).
		if ( ! file_exists( $dir ) ) {
			$service->record_observations( $execution_id, array() );
			$ok = $service->finalize_scanner_execution( $execution_id, 'success' );

			return $this->build_report_from_findings( $service, $ok, $execution_id );
		}

		// Exists but not a readable directory = incomplete; no absence.
		if ( ! is_dir( $dir ) || ! is_readable( $dir ) ) {
			$service->finalize_scanner_execution( $execution_id, 'failed' );

			return $this->build_report_from_findings( $service, false, $execution_id );
		}

		try {
			$discovery = $this->find_php_files( $dir );

			if ( ! empty( $discovery['error'] ) ) {
				$service->finalize_scanner_execution( $execution_id, 'failed' );

				return $this->build_report_from_findings( $service, false, $execution_id );
			}

			if ( ! empty( $discovery['limit_exceeded'] ) ) {
				$observations = array();

				foreach ( $discovery['paths'] as $absolute_path ) {
					$observation = $this->build_observation( $absolute_path );

					if ( null !== $observation ) {
						$observations[] = $observation;
					}
				}

				$service->record_observations( $execution_id, $observations );
				$service->finalize_scanner_execution( $execution_id, 'partial' );

				return $this->build_report_from_findings( $service, false, $execution_id );
			}

			$observations   = array();
			$hash_failures  = 0;

			foreach ( $discovery['paths'] as $absolute_path ) {
				$observation = $this->build_observation( $absolute_path );

				if ( null === $observation ) {
					++$hash_failures;
					continue;
				}

				$observations[] = $observation;
			}

			if ( $hash_failures > 0 ) {
				$service->record_observations( $execution_id, $observations );
				$service->finalize_scanner_execution( $execution_id, 'partial' );

				return $this->build_report_from_findings( $service, false, $execution_id );
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
			self::CATEGORY_KEY => __( 'MU-Plugin', 'choctaw-wp-security' ),
		);
	}

	/**
	 * Build a Findings observation for one PHP-like MU-plugin file.
	 *
	 * @param string $absolute_path Absolute path.
	 * @return array<string, mixed>|null Null when fingerprint cannot be computed.
	 */
	private function build_observation( $absolute_path ) {
		$object_key = Sassh_Object_Path_Normalizer::normalize_in_root( $absolute_path );

		if ( '' === $object_key ) {
			return null;
		}

		if ( ! is_readable( $absolute_path ) ) {
			return null;
		}

		$fingerprint = Sassh_Findings_Service::file_content_fingerprint( $absolute_path );

		if ( 'sha256:missing' === $fingerprint || 'sha256:unreadable' === $fingerprint ) {
			return null;
		}

		$meta    = Choctaw_Wp_Security_Utils::get_file_preview_meta( $absolute_path );
		$labels  = self::get_category_labels();
		$headers = $this->read_plugin_headers( $absolute_path );

		return array(
			'scanner_id'           => self::SCANNER_ID,
			'rule_id'              => self::RULE_ID,
			'object_type'          => Sassh_Object_Type_Registry::TYPE_FILE,
			'object_key'           => $object_key,
			'blog_id'              => null,
			'risk_level'           => 'suspicious',
			'sassh_classification' => 'needs_review',
			'content_fingerprint'  => $fingerprint,
			'object_fingerprint'   => $fingerprint,
			'title'                => $this->format_display_path( $absolute_path ),
			'description'          => __( 'PHP-like file found in the Must-Use plugins folder.', 'choctaw-wp-security' ),
			'metadata'             => array(
				'path'              => $this->format_display_path( $absolute_path ),
				'absolute_path'     => $absolute_path,
				'category'          => self::CATEGORY_KEY,
				'category_label'    => $labels[ self::CATEGORY_KEY ],
				'version'           => $this->header_or_empty( $headers, 'Version' ),
				'author'            => $this->header_or_empty( $headers, 'Author' ),
				'plugin_uri'        => $this->header_or_empty( $headers, 'PluginURI' ),
				'update_uri'        => $this->header_or_empty( $headers, 'UpdateURI' ),
				'description'       => $this->header_or_empty( $headers, 'Description' ),
				'size'              => $meta['size'],
				'size_label'        => $meta['size_label'],
				'modified'          => $meta['modified'],
				'modified_label'    => $meta['modified_label'],
				'permissions'       => isset( $meta['permissions'] ) ? $meta['permissions'] : '',
				'owner'             => isset( $meta['owner'] ) ? $meta['owner'] : '',
				'contents'          => $meta['contents'],
				'contents_truncated'  => ! empty( $meta['contents_truncated'] ),
				'why_seeing_this'   => __( 'The wp-content/mu-plugins directory contains "Must-Use" plugins that WordPress loads automatically. It\'s a popular target for hackers because these plugins remain hidden from the WordPress dashboard. However, many managed hosting providers, security plugins, backup systems, and performance plugins install files here as part of their normal operation.', 'choctaw-wp-security' ),
				'how_to_proceed'    => __( 'Verify that each file belongs to software you intentionally installed or to your hosting provider. Unknown or unexpected files should be investigated before removal, as deleting legitimate Must-Use plugins can disable important site functionality or hosting features.', 'choctaw-wp-security' ),
			),
		);
	}

	/**
	 * Build UI report payload from persisted findings.
	 *
	 * @param Sassh_Findings_Service $service      Service.
	 * @param bool                   $success      Whether finalize succeeded as full success.
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
		$findings   = array();
		$suspicious = 0;

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
				'can_dismiss'         => ! empty( $row['can_dismiss'] ),
				'dismissal_control_state' => isset( $row['dismissal_control_state'] ) ? $row['dismissal_control_state'] : Sassh_Findings_Service::dismissal_control_state( $row ),
				'category'            => isset( $row['category'] ) ? $row['category'] : self::CATEGORY_KEY,
				'category_label'      => isset( $row['category_label'] ) ? $row['category_label'] : '',
				'version'             => isset( $row['version'] ) ? $row['version'] : '',
				'author'              => isset( $row['author'] ) ? $row['author'] : '',
				'plugin_uri'          => isset( $row['plugin_uri'] ) ? $row['plugin_uri'] : '',
				'update_uri'          => isset( $row['update_uri'] ) ? $row['update_uri'] : '',
				'description'         => isset( $row['description'] ) ? $row['description'] : '',
				'size'                => isset( $row['size'] ) ? $row['size'] : 0,
				'size_label'          => isset( $row['size_label'] ) ? $row['size_label'] : '',
				'modified'            => isset( $row['modified'] ) ? $row['modified'] : 0,
				'modified_label'      => isset( $row['modified_label'] ) ? $row['modified_label'] : '',
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

			if ( 'suspicious' === $finding['risk_level'] ) {
				++$suspicious;
			}

			$findings[] = $finding;
		}

		$count = count( $findings );

		return array(
			'success'          => (bool) $success,
			'findings'         => $findings,
			'summary'          => array(
				'critical'   => 0,
				'warning'    => 0,
				'suspicious' => $suspicious,
				'alert'      => 0,
				'safe'       => 0,
				'info'       => 0,
				'total'      => $count,
				'flagged'    => $count,
			),
			'scanned_at'       => time(),
			'execution_id'     => $execution_id,
			'findings_backend' => 'sassh',
		);
	}

	/**
	 * Read WordPress plugin headers from a PHP file.
	 *
	 * @param string $path Absolute path.
	 * @return array<string, string>
	 */
	private function read_plugin_headers( $path ) {
		if ( ! function_exists( 'get_plugin_data' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		if ( ! is_readable( $path ) ) {
			return array();
		}

		$data = get_plugin_data( $path, false, false );

		return is_array( $data ) ? $data : array();
	}

	/**
	 * Return a trimmed header value or empty string.
	 *
	 * @param array<string, string> $headers Plugin headers.
	 * @param string                $key     Header key.
	 * @return string
	 */
	private function header_or_empty( array $headers, $key ) {
		if ( empty( $headers[ $key ] ) ) {
			return '';
		}

		return trim( wp_strip_all_tags( (string) $headers[ $key ] ) );
	}

	/**
	 * Find PHP-like files in a directory.
	 *
	 * Exactly FILE_LIMIT matches is still complete unless a further candidate is seen.
	 *
	 * @param string $folder Directory path.
	 * @return array{paths: array<int, string>, limit_exceeded: bool, error: string}
	 */
	private function find_php_files( $folder ) {
		$folder = (string) $folder;
		$result = array(
			'paths'          => array(),
			'limit_exceeded' => false,
			'error'          => '',
		);

		if ( '' === $folder || ! is_dir( $folder ) || ! is_readable( $folder ) ) {
			$result['error'] = 'unreadable';

			return $result;
		}

		$extensions = array( 'php', 'phtml', 'phar', 'php3', 'php4', 'php5', 'php7' );

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $folder, FilesystemIterator::SKIP_DOTS )
			);

			foreach ( $iterator as $file ) {
				if ( ! $file->isFile() ) {
					continue;
				}

				$extension = strtolower( $file->getExtension() );

				if ( ! in_array( $extension, $extensions, true ) ) {
					continue;
				}

				if ( count( $result['paths'] ) >= self::FILE_LIMIT ) {
					// Confirmed overflow: at least one more PHP-like file beyond the cap.
					$result['limit_exceeded'] = true;
					break;
				}

				$result['paths'][] = $file->getPathname();
			}
		} catch ( Exception $exception ) {
			$result['error'] = 'traversal';

			return $result;
		}

		sort( $result['paths'], SORT_STRING );

		return $result;
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
