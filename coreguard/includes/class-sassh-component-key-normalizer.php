<?php
/**
 * Sassh Findings component object-key / fingerprint / stable vuln-id helpers.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Shared rules for object_type=component (Phase 3.5).
 */
class Sassh_Component_Key_Normalizer {

	/**
	 * Max length for a stable vuln id segment inside rule_id (after prefix).
	 *
	 * @var int
	 */
	const STABLE_ID_MAX = 120;

	/**
	 * Max length for deterministic hash fallback inputs before hashing.
	 *
	 * @var int
	 */
	const FALLBACK_INPUT_MAX = 512;

	/**
	 * Normalize a plugin main file for object_key (forward slashes, no leading slash).
	 *
	 * @param string $plugin_file Plugin basename path (e.g. akismet/akismet.php).
	 * @return string
	 */
	public static function normalize_plugin_file( $plugin_file ) {
		$file = ltrim( wp_normalize_path( (string) $plugin_file ), '/' );

		return $file;
	}

	/**
	 * Normalize a theme stylesheet slug for object_key.
	 *
	 * @param string $stylesheet Theme stylesheet.
	 * @return string
	 */
	public static function normalize_theme_stylesheet( $stylesheet ) {
		return trim( (string) $stylesheet );
	}

	/**
	 * Build object_key for a component kind.
	 *
	 * @param string $kind        core|plugin|theme.
	 * @param string $identity    Plugin file, theme stylesheet, or ignored for core.
	 * @return string|WP_Error
	 */
	public static function object_key( $kind, $identity = '' ) {
		$kind = strtolower( trim( (string) $kind ) );

		if ( 'core' === $kind ) {
			return 'core:wordpress';
		}

		if ( 'plugin' === $kind ) {
			$file = self::normalize_plugin_file( $identity );

			if ( '' === $file ) {
				return new WP_Error(
					'sassh_component_plugin_empty',
					__( 'Plugin file path is empty.', 'choctaw-wp-security' )
				);
			}

			return 'plugin:' . $file;
		}

		if ( 'theme' === $kind ) {
			$stylesheet = self::normalize_theme_stylesheet( $identity );

			if ( '' === $stylesheet ) {
				return new WP_Error(
					'sassh_component_theme_empty',
					__( 'Theme stylesheet is empty.', 'choctaw-wp-security' )
				);
			}

			return 'theme:' . $stylesheet;
		}

		return new WP_Error(
			'sassh_component_kind_invalid',
			__( 'Unknown component kind.', 'choctaw-wp-security' )
		);
	}

	/**
	 * Object fingerprint (kind + object_key + installed version).
	 *
	 * @param string $kind        core|plugin|theme.
	 * @param string $object_key  Object key.
	 * @param string $version     Installed version.
	 * @return string sha256:hex
	 */
	public static function object_fingerprint( $kind, $object_key, $version ) {
		$payload = strtolower( trim( (string) $kind ) )
			. "\n"
			. (string) $object_key
			. "\n"
			. trim( (string) $version );

		return Sassh_Findings_Service::content_fingerprint_from_string( $payload );
	}

	/**
	 * Category fingerprint for unrecognized-component.
	 *
	 * @param string $kind       core|plugin|theme.
	 * @param string $object_key Object key.
	 * @param string $version    Installed version.
	 * @return string sha256:hex
	 */
	public static function unrecognized_category_fingerprint( $kind, $object_key, $version ) {
		$payload = strtolower( trim( (string) $kind ) )
			. "\n"
			. (string) $object_key
			. "\n"
			. trim( (string) $version )
			. "\n"
			. 'unrecognized';

		return Sassh_Findings_Service::content_fingerprint_from_string( $payload );
	}

	/**
	 * Category fingerprint for a vuln:* advisory category.
	 *
	 * @param string $stable_vuln_id Normalized stable id (without vuln: prefix).
	 * @param string $severity_code  n|l|m|h|c|empty.
	 * @param string $version_range  Display/operator range string.
	 * @param bool   $unfixed        Unfixed flag.
	 * @param bool   $closed         Closed flag.
	 * @return string sha256:hex
	 */
	public static function vuln_category_fingerprint( $stable_vuln_id, $severity_code, $version_range, $unfixed, $closed ) {
		$payload = self::length_bound( (string) $stable_vuln_id, self::STABLE_ID_MAX )
			. "\n"
			. self::normalize_severity_code( $severity_code )
			. "\n"
			. self::normalize_version_range( $version_range )
			. "\n"
			. ( $unfixed ? '1' : '0' )
			. "\n"
			. ( $closed ? '1' : '0' );

		return Sassh_Findings_Service::content_fingerprint_from_string( $payload );
	}

	/**
	 * Resolve stable vuln id and full rule_id for one advisory record.
	 *
	 * Priority: provider advisory id → CVE → deterministic hash fallback.
	 *
	 * @param array<string, mixed> $vulnerability Normalized or raw-ish advisory fields.
	 * @return array{stable_id: string, rule_id: string}
	 */
	public static function stable_vuln_identity( array $vulnerability ) {
		$stable = '';

		// 1) Stable provider-supplied advisory identifier when present.
		// WPVulnerability payloads sometimes expose uuid / id / slug-like keys; document usage.
		foreach ( array( 'uuid', 'id', 'advisory_id', 'vuln_id' ) as $key ) {
			if ( empty( $vulnerability[ $key ] ) || ! is_scalar( $vulnerability[ $key ] ) ) {
				continue;
			}

			$candidate = self::normalize_provider_advisory_id( (string) $vulnerability[ $key ] );

			if ( '' !== $candidate ) {
				$stable = $candidate;
				break;
			}
		}

		// 2) CVE when available (do not assume every advisory has one).
		if ( '' === $stable ) {
			$name = isset( $vulnerability['name'] ) ? (string) $vulnerability['name'] : '';
			$cve  = self::extract_cve_id( $name );

			if ( '' === $cve && ! empty( $vulnerability['cve'] ) && is_scalar( $vulnerability['cve'] ) ) {
				$cve = self::extract_cve_id( (string) $vulnerability['cve'] );
			}

			if ( '' !== $cve ) {
				$stable = $cve;
			}
		}

		// 3) Deterministic hash fallback.
		if ( '' === $stable ) {
			$name     = isset( $vulnerability['name'] ) ? (string) $vulnerability['name'] : '';
			$range    = isset( $vulnerability['version_range'] ) ? (string) $vulnerability['version_range'] : '';
			$severity = isset( $vulnerability['severity_code'] ) ? (string) $vulnerability['severity_code'] : '';

			if ( '' === $severity && isset( $vulnerability['severity'] ) ) {
				$severity = self::severity_label_to_code( (string) $vulnerability['severity'] );
			}

			$canonical = self::length_bound(
				self::normalize_advisory_name( $name )
					. '|'
					. self::normalize_version_range( $range )
					. '|'
					. self::normalize_severity_code( $severity ),
				self::FALLBACK_INPUT_MAX
			);

			$stable = 'hash:' . substr( hash( 'sha256', $canonical ), 0, 12 );
		}

		$stable = self::length_bound( $stable, self::STABLE_ID_MAX );

		return array(
			'stable_id' => $stable,
			'rule_id'   => 'vuln:' . $stable,
		);
	}

	/**
	 * Normalize a provider advisory id for rule_id use.
	 *
	 * @param string $raw Raw id.
	 * @return string
	 */
	public static function normalize_provider_advisory_id( $raw ) {
		$raw = trim( (string) $raw );

		if ( '' === $raw ) {
			return '';
		}

		// Prefer CVE if the provider id is itself a CVE.
		$cve = self::extract_cve_id( $raw );

		if ( '' !== $cve ) {
			return $cve;
		}

		// Length-bound, case-fold, strip unsafe characters for rule_id segment.
		$raw = strtolower( $raw );
		$raw = preg_replace( '/[^a-z0-9._:-]+/', '-', $raw );
		$raw = trim( (string) $raw, '-._:' );

		return self::length_bound( $raw, self::STABLE_ID_MAX );
	}

	/**
	 * Extract uppercase CVE-YYYY-NNNN… from text when present.
	 *
	 * @param string $text Text that may contain a CVE.
	 * @return string Empty when none.
	 */
	public static function extract_cve_id( $text ) {
		if ( ! preg_match( '/CVE-\d{4}-\d+/i', (string) $text, $matches ) ) {
			return '';
		}

		return strtoupper( $matches[0] );
	}

	/**
	 * Normalize advisory name for hash fallback (trim, collapse whitespace, case-fold).
	 *
	 * @param string $name Name.
	 * @return string
	 */
	public static function normalize_advisory_name( $name ) {
		$name = strtolower( trim( (string) $name ) );
		$name = preg_replace( '/\s+/', ' ', $name );

		return is_string( $name ) ? $name : '';
	}

	/**
	 * Normalize version-range expressions so superficial formatting does not evade dedup.
	 *
	 * @param string $range Version range string.
	 * @return string
	 */
	public static function normalize_version_range( $range ) {
		$range = strtolower( trim( (string) $range ) );
		$range = preg_replace( '/\s+/', '', $range );
		$range = str_replace( array( '<=', '>=', '!=', '==' ), array( 'le', 'ge', 'ne', 'eq' ), (string) $range );
		$range = str_replace( array( '<', '>', '=' ), array( 'lt', 'gt', 'eq' ), (string) $range );
		$range = preg_replace( '/[^a-z0-9._|,-]+/', '', (string) $range );

		return self::length_bound( is_string( $range ) ? $range : '', self::FALLBACK_INPUT_MAX );
	}

	/**
	 * Normalize severity code band.
	 *
	 * @param string $code Raw code or empty.
	 * @return string n|l|m|h|c|unknown
	 */
	public static function normalize_severity_code( $code ) {
		$code = strtolower( trim( (string) $code ) );

		if ( in_array( $code, array( 'n', 'l', 'm', 'h', 'c' ), true ) ) {
			return $code;
		}

		$from_label = self::severity_label_to_code( $code );

		return '' !== $from_label ? $from_label : 'unknown';
	}

	/**
	 * Map display severity label back to code when needed.
	 *
	 * @param string $label Label.
	 * @return string
	 */
	public static function severity_label_to_code( $label ) {
		$map = array(
			'none'     => 'n',
			'low'      => 'l',
			'medium'   => 'm',
			'high'     => 'h',
			'critical' => 'c',
			'n'        => 'n',
			'l'        => 'l',
			'm'        => 'm',
			'h'        => 'h',
			'c'        => 'c',
		);

		$key = strtolower( trim( (string) $label ) );

		return isset( $map[ $key ] ) ? $map[ $key ] : '';
	}

	/**
	 * Length-bound a string without breaking mid-UTF-8 when mbstring is available.
	 *
	 * @param string $value Value.
	 * @param int    $max   Max length.
	 * @return string
	 */
	public static function length_bound( $value, $max ) {
		$value = (string) $value;
		$max   = (int) $max;

		if ( $max <= 0 || strlen( $value ) <= $max ) {
			return $value;
		}

		if ( function_exists( 'mb_substr' ) ) {
			return (string) mb_substr( $value, 0, $max, 'UTF-8' );
		}

		return substr( $value, 0, $max );
	}

	/**
	 * Accept only http/https URIs for display as external links.
	 *
	 * Rejects unsupported schemes, empty values, and non-http(s) URLs.
	 * Component headers are untrusted informational metadata only.
	 *
	 * @param string $raw Raw URI from a plugin/theme header or similar.
	 * @return string Sanitized absolute http(s) URL, or empty string when invalid.
	 */
	public static function sanitize_external_http_url( $raw ) {
		$raw = trim( (string) $raw );

		if ( '' === $raw ) {
			return '';
		}

		// Reject scheme-relative and non-http schemes early.
		if ( preg_match( '#^(javascript|data|vbscript|file|about):#i', $raw ) ) {
			return '';
		}

		$parts = wp_parse_url( $raw );

		if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
			return '';
		}

		$scheme = strtolower( (string) $parts['scheme'] );

		if ( 'http' !== $scheme && 'https' !== $scheme ) {
			return '';
		}

		if ( function_exists( 'wp_http_validate_url' ) && ! wp_http_validate_url( $raw ) ) {
			return '';
		}

		$safe = esc_url_raw( $raw, array( 'http', 'https' ) );

		if ( ! is_string( $safe ) || '' === $safe ) {
			return '';
		}

		// Re-check after esc_url_raw.
		$recheck = wp_parse_url( $safe );

		if ( ! is_array( $recheck ) || empty( $recheck['scheme'] ) || empty( $recheck['host'] ) ) {
			return '';
		}

		$re_scheme = strtolower( (string) $recheck['scheme'] );

		if ( 'http' !== $re_scheme && 'https' !== $re_scheme ) {
			return '';
		}

		return self::length_bound( $safe, 2048 );
	}

	/**
	 * Hostname from a validated http(s) URL (informational display only).
	 *
	 * @param string $url Already-sanitized http(s) URL, or raw candidate.
	 * @return string Lowercased host, or empty.
	 */
	public static function hostname_from_http_url( $url ) {
		$safe = self::sanitize_external_http_url( $url );

		if ( '' === $safe ) {
			return '';
		}

		$host = wp_parse_url( $safe, PHP_URL_HOST );

		if ( ! is_string( $host ) || '' === $host ) {
			return '';
		}

		return strtolower( $host );
	}
}
