<?php
/**
 * Uploads folder PHP executable scanner.
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

	/**
	 * Scan the uploads folder for PHP-like files.
	 *
	 * @return array<string, mixed>
	 */
	public function scan() {
		$uploads = wp_get_upload_dir();
		$basedir = isset( $uploads['basedir'] ) ? (string) $uploads['basedir'] : '';
		$paths   = $this->find_php_files( $basedir );
		$findings = array();

		foreach ( $paths as $index => $absolute_path ) {
			$findings[] = $this->build_finding( $absolute_path, $index );
		}

		$count = count( $findings );

		return array(
			'success'  => true,
			'findings' => $findings,
			'summary'  => array(
				'critical'   => $count,
				'suspicious' => 0,
				'alert'      => 0,
				'safe'       => 0,
				'info'       => 0,
				'total'      => $count,
				'flagged'    => $count,
			),
			'scanned_at' => time(),
		);
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
	 * Build one finding from an absolute file path.
	 *
	 * @param string $absolute_path Absolute filesystem path.
	 * @param int    $index         Finding index.
	 * @return array<string, mixed>
	 */
	private function build_finding( $absolute_path, $index ) {
		$labels      = self::get_category_labels();
		$fingerprint = Choctaw_Wp_Security_Finding_Status_Store::fingerprint_uploads_file( $absolute_path );
		$meta        = Choctaw_Wp_Security_Utils::get_file_preview_meta( $absolute_path );

		return array(
			'id'               => $fingerprint,
			'fingerprint'      => $fingerprint,
			'path'             => $this->format_display_path( $absolute_path ),
			'absolute_path'    => $absolute_path,
			'risk'             => 'critical',
			'risk_label'       => __( 'Critical', 'choctaw-wp-security' ),
			'category'         => self::CATEGORY_KEY,
			'category_label'   => $labels[ self::CATEGORY_KEY ],
			'size'             => $meta['size'],
			'size_label'       => $meta['size_label'],
			'modified'         => $meta['modified'],
			'modified_label'   => $meta['modified_label'],
			'permissions'      => $meta['permissions'],
			'owner'            => $meta['owner'],
			'contents'         => $meta['contents'],
			'contents_truncated' => ! empty( $meta['contents_truncated'] ),
			'why_seeing_this'  => __( 'The WordPress uploads folder is intended for media files such as images, PDFs, videos, and documents. PHP scripts normally do not belong here because this directory is writable by WordPress and is a common target for attackers attempting to upload and execute malicious code.', 'choctaw-wp-security' ),
			'how_to_proceed'   => __( 'Review each PHP file carefully. If it was intentionally placed there by a trusted plugin or developer, it may be legitimate. Otherwise, treat it as suspicious, identify how it was uploaded, remove it if appropriate, and restore any affected files from a known-good backup. Enabling "Disable PHP Execution in Uploads" helps prevent uploaded PHP files from being executed.', 'choctaw-wp-security' ),
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
	 * Format a path relative to the WordPress root when possible.
	 *
	 * @param string $path File path.
	 * @return string
	 */
	private function format_display_path( $path ) {
		$normalized_path = wp_normalize_path( $path );
		$root            = trailingslashit( wp_normalize_path( ABSPATH ) );

		if ( 0 === strpos( $normalized_path, $root ) ) {
			return ltrim( substr( $normalized_path, strlen( $root ) ), '/' );
		}

		return $normalized_path;
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
