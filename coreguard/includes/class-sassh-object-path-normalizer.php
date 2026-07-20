<?php
/**
 * Shared WordPress-root-relative path normalization for Sassh Findings.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Normalizes in-root file paths for object keys and correlation.
 */
class Sassh_Object_Path_Normalizer {

	/**
	 * Normalize an absolute or relative path to ABSPATH-relative form.
	 *
	 * Rules: forward slashes, no leading slash, no ./ or unresolved .., preserve case.
	 * Returns empty string if the path is outside the WordPress root.
	 *
	 * @param string $path Absolute or relative path.
	 * @return string
	 */
	public static function normalize_in_root( $path ) {
		$path = wp_normalize_path( (string) $path );
		$path = str_replace( '\\', '/', $path );

		if ( '' === $path ) {
			return '';
		}

		$root = wp_normalize_path( ABSPATH );
		$root = rtrim( str_replace( '\\', '/', $root ), '/' ) . '/';

		if ( 0 === strpos( $path, $root ) ) {
			$relative = substr( $path, strlen( $root ) );
		} elseif ( 0 === strpos( $path, '/' ) || preg_match( '#^[A-Za-z]:/#', $path ) ) {
			// Absolute path outside ABSPATH.
			return '';
		} else {
			$relative = ltrim( $path, '/' );
		}

		$relative = self::collapse_dot_segments( $relative );

		if ( '' === $relative || 0 === strpos( $relative, '../' ) || '../' === $relative || '..' === $relative ) {
			return '';
		}

		return $relative;
	}

	/**
	 * Collapse . and .. segments; reject escaping above root.
	 *
	 * @param string $relative Relative path.
	 * @return string
	 */
	private static function collapse_dot_segments( $relative ) {
		$parts  = explode( '/', $relative );
		$stack  = array();

		foreach ( $parts as $part ) {
			if ( '' === $part || '.' === $part ) {
				continue;
			}

			if ( '..' === $part ) {
				if ( empty( $stack ) ) {
					return '';
				}
				array_pop( $stack );
				continue;
			}

			$stack[] = $part;
		}

		return implode( '/', $stack );
	}
}
