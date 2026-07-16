<?php
/**
 * Must-Use plugins folder scanner.
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

	/**
	 * Scan the mu-plugins folder for PHP-like files.
	 *
	 * @return array<string, mixed>
	 */
	public function scan() {
		$dir      = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
		$paths    = $this->find_php_files( (string) $dir );
		$findings = array();

		foreach ( $paths as $index => $absolute_path ) {
			$findings[] = $this->build_finding( $absolute_path, $index );
		}

		$count = count( $findings );

		return array(
			'success'  => true,
			'findings' => $findings,
			'summary'  => array(
				'critical'   => 0,
				'suspicious' => 0,
				'alert'      => $count,
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
			self::CATEGORY_KEY => __( 'MU-Plugin', 'choctaw-wp-security' ),
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
		$size        = file_exists( $absolute_path ) ? (int) filesize( $absolute_path ) : 0;
		$modified    = file_exists( $absolute_path ) ? filemtime( $absolute_path ) : false;
		$headers     = $this->read_plugin_headers( $absolute_path );
		$labels      = self::get_category_labels();
		$fingerprint = Choctaw_Wp_Security_Finding_Status_Store::fingerprint_mu_plugin( $absolute_path );
		$preview     = Choctaw_Wp_Security_Utils::read_file_contents_preview_result( $absolute_path, self::CONTENTS_CHAR_LIMIT );

		return array(
			'id'                => $fingerprint,
			'fingerprint'       => $fingerprint,
			'path'              => $this->format_display_path( $absolute_path ),
			'absolute_path'     => $absolute_path,
			'risk'              => 'alert',
			'risk_label'        => __( 'Alert', 'choctaw-wp-security' ),
			'category'          => self::CATEGORY_KEY,
			'category_label'    => $labels[ self::CATEGORY_KEY ],
			'version'           => $this->header_or_empty( $headers, 'Version' ),
			'author'            => $this->header_or_empty( $headers, 'Author' ),
			'plugin_uri'        => $this->header_or_empty( $headers, 'PluginURI' ),
			'update_uri'        => $this->header_or_empty( $headers, 'UpdateURI' ),
			'description'       => $this->header_or_empty( $headers, 'Description' ),
			'size'              => $size,
			'size_label'        => size_format( $size ),
			'modified'          => false === $modified ? 0 : (int) $modified,
			'modified_label'    => $this->format_modified_label( $modified ),
			'contents'          => $preview['contents'],
			'contents_truncated' => ! empty( $preview['truncated'] ),
			'why_seeing_this'   => __( 'The wp-content/mu-plugins directory contains "Must-Use" plugins that WordPress loads automatically. It\'s a popular target for hackers because these plugins remain hidden from the WordPress dashboard. However, many managed hosting providers, security plugins, backup systems, and performance plugins install files here as part of their normal operation.', 'choctaw-wp-security' ),
			'how_to_proceed'    => __( 'Verify that each file belongs to software you intentionally installed or to your hosting provider. Unknown or unexpected files should be investigated before removal, as deleting legitimate Must-Use plugins can disable important site functionality or hosting features.', 'choctaw-wp-security' ),
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
