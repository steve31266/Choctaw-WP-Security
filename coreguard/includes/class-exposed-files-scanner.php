<?php
/**
 * Exposed files scanner for the WordPress document root.
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

	/**
	 * Scan the WordPress root for exposed sensitive files.
	 *
	 * @return array<string, mixed>
	 */
	public function scan() {
		$entries  = $this->list_root_entries();
		$findings = array();
		$index    = 0;

		foreach ( $entries as $entry ) {
			if ( count( $findings ) >= self::FILE_LIMIT ) {
				break;
			}

			$finding = $this->analyze_entry( $entry, $index );
			if ( null === $finding ) {
				continue;
			}

			$findings[] = $finding;
			++$index;
		}

		return $this->build_result( $findings );
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
	 * @return array<int, array{name: string, path: string, is_dir: bool}>
	 */
	private function list_root_entries() {
		$root = wp_normalize_path( ABSPATH );

		if ( '' === $root || ! is_dir( $root ) || ! is_readable( $root ) ) {
			return array();
		}

		$names = @scandir( $root );
		if ( ! is_array( $names ) ) {
			return array();
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
	 * Analyze one root entry and return a finding when it matches.
	 *
	 * @param array{name: string, path: string, is_dir: bool} $entry Entry metadata.
	 * @param int                                               $index Finding index.
	 * @return array<string, mixed>|null
	 */
	private function analyze_entry( array $entry, $index ) {
		$name   = (string) $entry['name'];
		$path   = (string) $entry['path'];
		$is_dir = ! empty( $entry['is_dir'] );
		$size   = ( ! $is_dir && file_exists( $path ) ) ? (int) @filesize( $path ) : 0;

		$needs_snippet = $this->needs_content_snippet( $name, $is_dir );
		$snippet       = $needs_snippet ? $this->read_truncated_contents( $path ) : '';

		$match = Choctaw_Wp_Security_Exposed_Files_Patterns::match_entry( $name, $is_dir, $size, $snippet );
		if ( null === $match ) {
			return null;
		}

		return $this->build_finding( $entry, $match, $size, $snippet, $index );
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
	 * Build one enriched finding.
	 *
	 * @param array{name: string, path: string, is_dir: bool} $entry  Entry metadata.
	 * @param array{pattern: string, category: string, risk: string} $match Match result.
	 * @param int                                             $size    File size.
	 * @param string                                          $snippet Already-read snippet (may be empty).
	 * @param int                                             $index   Finding index.
	 * @return array<string, mixed>
	 */
	private function build_finding( array $entry, array $match, $size, $snippet, $index ) {
		$path     = (string) $entry['path'];
		$name     = (string) $entry['name'];
		$is_dir   = ! empty( $entry['is_dir'] );
		$modified = file_exists( $path ) ? @filemtime( $path ) : false;
		$labels   = self::get_category_labels();
		$risks    = Choctaw_Wp_Security_Exposed_Files_Patterns::get_risk_labels();
		$guidance = Choctaw_Wp_Security_Exposed_Files_Patterns::get_guidance( $match['pattern'] );
		$category = $match['category'];
		$risk     = $match['risk'];

		$contents           = $snippet;
		$contents_truncated = false;
		if ( '' === $contents && ! $is_dir && $this->is_text_previewable( $name, $match['pattern'] ) ) {
			$preview            = Choctaw_Wp_Security_Utils::read_file_contents_preview_result( $path, self::CONTENTS_CHAR_LIMIT );
			$contents           = $preview['contents'];
			$contents_truncated = ! empty( $preview['truncated'] );
		} elseif ( $is_dir ) {
			$contents = __( 'Directory — contents not listed.', 'choctaw-wp-security' );
		} elseif ( ! $this->is_text_previewable( $name, $match['pattern'] ) ) {
			$contents = __( 'Binary archive — contents not displayed.', 'choctaw-wp-security' );
		}

		$fingerprint = Choctaw_Wp_Security_Finding_Status_Store::fingerprint_exposed_file( $path );

		return array(
			'id'              => $fingerprint,
			'fingerprint'     => $fingerprint,
			'filename'        => $name,
			'path'            => $name,
			'absolute_path'   => $path,
			'is_directory'    => $is_dir,
			'pattern'         => $match['pattern'],
			'category'        => $category,
			'category_label'  => isset( $labels[ $category ] ) ? $labels[ $category ] : $category,
			'risk'            => $risk,
			'risk_label'      => isset( $risks[ $risk ] ) ? $risks[ $risk ] : $risk,
			'size'            => $is_dir ? 0 : (int) $size,
			'size_label'      => $is_dir ? '—' : size_format( (int) $size ),
			'modified'        => false === $modified ? 0 : (int) $modified,
			'modified_label'  => $this->format_modified_label( $modified ),
			'permissions'     => $this->format_permissions( $path ),
			'owner'           => $this->format_owner( $path ),
			'contents'        => $contents,
			'contents_truncated' => $contents_truncated,
			'why_seeing_this' => $guidance['why'],
			'how_to_proceed'  => $guidance['how'],
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

	/**
	 * Build the scan result payload.
	 *
	 * @param array<int, array<string, mixed>> $findings Findings.
	 * @return array<string, mixed>
	 */
	private function build_result( array $findings ) {
		$summary = array(
			'critical' => 0,
			'alert'    => 0,
			'warning'  => 0,
			'info'     => 0,
			'total'    => count( $findings ),
			'flagged'  => 0,
		);

		foreach ( $findings as $finding ) {
			$risk = isset( $finding['risk'] ) ? (string) $finding['risk'] : 'info';
			if ( isset( $summary[ $risk ] ) ) {
				++$summary[ $risk ];
			}
			if ( 'info' !== $risk ) {
				++$summary['flagged'];
			}
		}

		return array(
			'success'    => 0 === ( $summary['critical'] + $summary['alert'] ),
			'findings'   => $findings,
			'summary'    => $summary,
			'scanned_at' => time(),
		);
	}
}
