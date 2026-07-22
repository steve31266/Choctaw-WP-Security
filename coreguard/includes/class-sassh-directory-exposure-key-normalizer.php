<?php
/**
 * Sassh Findings directory_exposure object-key / fingerprint helpers.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Shared rules for object_type=directory_exposure (Phase 3.6).
 */
class Sassh_Directory_Exposure_Key_Normalizer {

	const KEY_HTACCESS = 'htaccess:.htaccess';
	const KEY_PLUGINS  = 'folder:plugins';
	const KEY_THEMES   = 'folder:themes';
	const KEY_UPLOADS  = 'folder:uploads';

	const BROWSING_OPEN         = 'open';
	const BROWSING_NOT_OBSERVED = 'not_observed';
	const BROWSING_UNKNOWN      = 'unknown';

	/**
	 * Object key for site-root .htaccess control surface.
	 *
	 * @return string
	 */
	public static function htaccess_object_key() {
		return self::KEY_HTACCESS;
	}

	/**
	 * Object key for a folder kind.
	 *
	 * @param string $folder_key plugins|themes|uploads.
	 * @return string|WP_Error
	 */
	public static function folder_object_key( $folder_key ) {
		$folder_key = strtolower( trim( (string) $folder_key ) );

		$map = array(
			'plugins' => self::KEY_PLUGINS,
			'themes'  => self::KEY_THEMES,
			'uploads' => self::KEY_UPLOADS,
		);

		if ( ! isset( $map[ $folder_key ] ) ) {
			return new WP_Error(
				'sassh_directory_exposure_folder_invalid',
				__( 'Unknown directory exposure folder kind.', 'choctaw-wp-security' )
			);
		}

		return $map[ $folder_key ];
	}

	/**
	 * blog_id for a folder object (uploads may be subsite-owned).
	 *
	 * @param string $folder_key    plugins|themes|uploads.
	 * @param string $display_path  ABSPATH-relative display path.
	 * @return int|null
	 */
	public static function blog_id_for_folder( $folder_key, $display_path ) {
		if ( 'uploads' !== strtolower( trim( (string) $folder_key ) ) ) {
			return null;
		}

		$path = ltrim( wp_normalize_path( (string) $display_path ), '/' );

		if ( preg_match( '#^wp-content/uploads/sites/(\d+)(?:/|$)#', $path, $matches ) ) {
			return (int) $matches[1];
		}

		return null;
	}

	/**
	 * Object fingerprint for .htaccess posture (non-compound base).
	 *
	 * @param string      $server_family  apache|litespeed|nginx|unknown.
	 * @param bool        $exists         Whether file exists.
	 * @param string|null $indexes_state  off|on|null.
	 * @param string      $unknown_reason Reason band when inconclusive.
	 * @return string sha256:hex
	 */
	public static function htaccess_object_fingerprint( $server_family, $exists, $indexes_state, $unknown_reason = '' ) {
		$state = null === $indexes_state ? 'null' : (string) $indexes_state;
		$payload = strtolower( trim( (string) $server_family ) )
			. "\n"
			. ( $exists ? '1' : '0' )
			. "\n"
			. $state
			. "\n"
			. trim( (string) $unknown_reason );

		return Sassh_Findings_Service::content_fingerprint_from_string( $payload );
	}

	/**
	 * Category fingerprint for a non-compound htaccess rule.
	 *
	 * @param string      $rule_id        Rule id.
	 * @param string      $server_family  Server family.
	 * @param bool        $exists         Exists.
	 * @param string|null $indexes_state  Indexes state.
	 * @param string      $unknown_reason Unknown reason band.
	 * @return string
	 */
	public static function htaccess_category_fingerprint( $rule_id, $server_family, $exists, $indexes_state, $unknown_reason = '' ) {
		$payload = (string) $rule_id
			. "\n"
			. strtolower( trim( (string) $server_family ) )
			. "\n"
			. ( $exists ? '1' : '0' )
			. "\n"
			. ( null === $indexes_state ? 'null' : (string) $indexes_state )
			. "\n"
			. trim( (string) $unknown_reason );

		return Sassh_Findings_Service::content_fingerprint_from_string( $payload );
	}

	/**
	 * Deterministic aggregate of folder probe postures for compound htaccess categories.
	 *
	 * @param array<string, string> $folder_bands Map folder_key => open|not_observed|unknown.
	 * @return string
	 */
	public static function aggregate_folder_posture_payload( array $folder_bands ) {
		$keys = array_keys( $folder_bands );
		sort( $keys, SORT_STRING );
		$parts = array();

		foreach ( $keys as $key ) {
			$band = (string) $folder_bands[ $key ];
			if ( ! in_array( $band, array( self::BROWSING_OPEN, self::BROWSING_NOT_OBSERVED, self::BROWSING_UNKNOWN ), true ) ) {
				$band = self::BROWSING_UNKNOWN;
			}
			$parts[] = $key . '=' . $band;
		}

		return implode( ';', $parts );
	}

	/**
	 * Object / category fingerprint for compound htaccess + folder aggregate rules.
	 *
	 * @param string                $rule_id        Compound rule id.
	 * @param string                $server_family  Server family.
	 * @param bool                  $exists         Htaccess exists.
	 * @param string|null           $indexes_state  Indexes state.
	 * @param string                $unknown_reason Unknown reason.
	 * @param array<string, string> $folder_bands   Aggregate folder postures.
	 * @return string
	 */
	public static function htaccess_compound_fingerprint( $rule_id, $server_family, $exists, $indexes_state, $unknown_reason, array $folder_bands ) {
		$payload = (string) $rule_id
			. "\n"
			. strtolower( trim( (string) $server_family ) )
			. "\n"
			. ( $exists ? '1' : '0' )
			. "\n"
			. ( null === $indexes_state ? 'null' : (string) $indexes_state )
			. "\n"
			. trim( (string) $unknown_reason )
			. "\n"
			. self::aggregate_folder_posture_payload( $folder_bands );

		return Sassh_Findings_Service::content_fingerprint_from_string( $payload );
	}

	/**
	 * Object fingerprint for a folder root.
	 *
	 * @param string $folder_key Folder kind.
	 * @param string $browsing   open|not_observed|unknown.
	 * @param string $http_class listing|non_listing|failed|inconclusive|….
	 * @param bool   $has_index  Whether an index file exists.
	 * @return string
	 */
	public static function folder_object_fingerprint( $folder_key, $browsing, $http_class, $has_index ) {
		$payload = strtolower( trim( (string) $folder_key ) )
			. "\n"
			. (string) $browsing
			. "\n"
			. (string) $http_class
			. "\n"
			. ( $has_index ? '1' : '0' );

		return Sassh_Findings_Service::content_fingerprint_from_string( $payload );
	}

	/**
	 * Category fingerprint for a folder rule.
	 *
	 * @param string $rule_id    Rule id.
	 * @param string $folder_key Folder kind.
	 * @param string $browsing   Browsing band.
	 * @param string $http_class HTTP class band.
	 * @param bool   $has_index  Has index.
	 * @return string
	 */
	public static function folder_category_fingerprint( $rule_id, $folder_key, $browsing, $http_class, $has_index ) {
		$payload = (string) $rule_id
			. "\n"
			. strtolower( trim( (string) $folder_key ) )
			. "\n"
			. (string) $browsing
			. "\n"
			. (string) $http_class
			. "\n"
			. ( $has_index ? '1' : '0' );

		return Sassh_Findings_Service::content_fingerprint_from_string( $payload );
	}

	/**
	 * Canonical risk for a directory-browsing rule_id.
	 *
	 * @param string $rule_id Rule id.
	 * @return string
	 */
	public static function risk_level_for_rule( $rule_id ) {
		$table = array(
			'directory-listing-open'                    => 'warning',
			'directory-listing-unknown'                 => 'suspicious',
			'directory-listing-not-observed'            => 'safe',
			'htaccess-indexes-disabled'                 => 'safe',
			'htaccess-nginx-ignored'                    => 'info',
			'htaccess-unprotected-folders-not-observed' => 'info',
			'htaccess-indexes-inconclusive'             => 'suspicious',
			'htaccess-indexes-enabled'                  => 'warning',
			'htaccess-unprotected-folders-open'         => 'warning',
		);

		$rule_id = (string) $rule_id;

		return isset( $table[ $rule_id ] ) ? $table[ $rule_id ] : 'suspicious';
	}
}
