<?php
/**
 * Discovers WordPress table prefixes and resolves scan table targets.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Finds leftover WordPress installs by table prefix and maps them to scan tables.
 */
class Choctaw_Wp_Security_Table_Prefix_Discovery {

	/**
	 * Options table discovery helper.
	 *
	 * @var Choctaw_Wp_Security_Options_Table_Discovery
	 */
	private $options_discovery;

	/**
	 * Posts table discovery helper.
	 *
	 * @var Choctaw_Wp_Security_Posts_Table_Discovery
	 */
	private $posts_discovery;

	/**
	 * Users table discovery helper.
	 *
	 * @var Choctaw_Wp_Security_Users_Table_Discovery
	 */
	private $users_discovery;

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->options_discovery = new Choctaw_Wp_Security_Options_Table_Discovery();
		$this->posts_discovery   = new Choctaw_Wp_Security_Posts_Table_Discovery();
		$this->users_discovery   = new Choctaw_Wp_Security_Users_Table_Discovery();
	}

	/**
	 * Get the table prefix WordPress is configured to use.
	 *
	 * @return string
	 */
	public static function get_wordpress_configured_prefix() {
		global $wpdb;

		return (string) $wpdb->prefix;
	}

	/**
	 * Get the connected MySQL database name for display.
	 *
	 * @return string
	 */
	public function get_database_name() {
		global $wpdb;

		if ( ! empty( $wpdb->dbname ) ) {
			return (string) $wpdb->dbname;
		}

		$name = $wpdb->get_var( 'SELECT DATABASE()' );

		return is_string( $name ) ? $name : '';
	}

	/**
	 * Discover candidate WordPress table prefixes in the current database.
	 *
	 * @return array<int, string>
	 */
	public function discover_prefixes() {
		$prefixes = array();
		$tables   = $this->options_discovery->discover_options_tables();

		foreach ( $tables as $table ) {
			$prefix = $this->prefix_from_options_table( $table );

			if ( '' === $prefix ) {
				continue;
			}

			$prefixes[] = $prefix;
		}

		$prefixes = array_values( array_unique( $prefixes ) );
		$default  = self::get_wordpress_configured_prefix();

		usort(
			$prefixes,
			function ( $left, $right ) use ( $default ) {
				if ( $left === $default ) {
					return -1;
				}

				if ( $right === $default ) {
					return 1;
				}

				return strnatcasecmp( $left, $right );
			}
		);

		return $prefixes;
	}

	/**
	 * Validate a table prefix against the discovered allowlist.
	 *
	 * @param string                    $prefix     Prefix to validate.
	 * @param array<int, string>|null $discovered Optional discovered prefixes.
	 * @return string|false
	 */
	public function validate_prefix( $prefix, $discovered = null ) {
		$prefix = (string) $prefix;

		if ( ! preg_match( '/^[A-Za-z0-9_]+$/', $prefix ) ) {
			return false;
		}

		if ( ! is_array( $discovered ) ) {
			$discovered = $this->discover_prefixes();
		}

		if ( ! in_array( $prefix, $discovered, true ) ) {
			return false;
		}

		return $prefix;
	}

	/**
	 * Resolve which table prefix should be used for scans.
	 *
	 * An empty requested prefix means Auto (WordPress configured).
	 *
	 * @param string $requested_prefix Requested prefix or empty for auto.
	 * @return string
	 */
	public function resolve_scan_prefix( $requested_prefix = '' ) {
		$discovered = $this->discover_prefixes();
		$default    = self::get_wordpress_configured_prefix();

		if ( '' !== $requested_prefix ) {
			$validated = $this->validate_prefix( $requested_prefix, $discovered );

			if ( false !== $validated ) {
				return $validated;
			}
		}

		if ( in_array( $default, $discovered, true ) ) {
			return $default;
		}

		if ( ! empty( $discovered ) ) {
			return $discovered[0];
		}

		return $default;
	}

	/**
	 * Resolve the options table for a prefix.
	 *
	 * @param string $prefix Table prefix.
	 * @return string
	 */
	public function get_options_table( $prefix ) {
		$prefix = (string) $prefix;

		if ( '' === $prefix ) {
			return Choctaw_Wp_Security_Options_Table_Discovery::get_wordpress_configured_table();
		}

		return $this->options_discovery->resolve_scan_table( $prefix . 'options' );
	}

	/**
	 * Resolve the posts table for a prefix.
	 *
	 * @param string $prefix Table prefix.
	 * @return string
	 */
	public function get_posts_table( $prefix ) {
		$prefix = (string) $prefix;

		if ( '' === $prefix ) {
			return Choctaw_Wp_Security_Posts_Table_Discovery::get_wordpress_configured_table();
		}

		return $this->posts_discovery->resolve_scan_table( $prefix . 'posts' );
	}

	/**
	 * Resolve the users table for a prefix.
	 *
	 * @param string $prefix Table prefix.
	 * @return string
	 */
	public function get_users_table( $prefix ) {
		$prefix = (string) $prefix;

		if ( '' === $prefix ) {
			return Choctaw_Wp_Security_Users_Table_Discovery::get_wordpress_configured_table();
		}

		return $this->users_discovery->resolve_scan_table( $prefix . 'users' );
	}

	/**
	 * Resolve the configured prefix into concrete scan tables.
	 *
	 * Uses the saved Settings override when present and valid; otherwise Auto.
	 *
	 * @return array{prefix: string, is_override: bool, options_table: string, posts_table: string, users_table: string}
	 */
	public function resolve_configured_tables() {
		$saved    = Choctaw_Wp_Security_Utils::get_database_scan_table_prefix();
		$resolved = $this->resolve_scan_prefix( $saved );
		$default  = self::get_wordpress_configured_prefix();

		return array(
			'prefix'        => $resolved,
			'is_override'   => ( '' !== $saved && $saved !== $default ),
			'options_table' => $this->get_options_table( $resolved ),
			'posts_table'   => $this->get_posts_table( $resolved ),
			'users_table'   => $this->get_users_table( $resolved ),
		);
	}

	/**
	 * Collect metadata for each discovered prefix.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public function get_prefixes_with_metadata() {
		$prefixes         = $this->discover_prefixes();
		$default          = self::get_wordpress_configured_prefix();
		$options_meta_map = $this->index_options_metadata();
		$posts_meta_map   = $this->index_posts_metadata();
		$users_meta_map   = $this->index_users_metadata();
		$metadata         = array();

		foreach ( $prefixes as $prefix ) {
			$options_table = $prefix . 'options';
			$posts_table   = $prefix . 'posts';
			$users_table   = $prefix . 'users';
			$options_meta  = isset( $options_meta_map[ $options_table ] ) ? $options_meta_map[ $options_table ] : array();
			$posts_meta    = isset( $posts_meta_map[ $posts_table ] ) ? $posts_meta_map[ $posts_table ] : array();
			$users_meta    = isset( $users_meta_map[ $users_table ] ) ? $users_meta_map[ $users_table ] : array();

			$metadata[] = array(
				'prefix'                  => $prefix,
				'is_wordpress_configured' => ( $prefix === $default ),
				'url_matches_site'        => ! empty( $options_meta['url_matches_site'] ),
				'options_table'           => $options_table,
				'posts_table'             => isset( $posts_meta['table_name'] ) ? (string) $posts_meta['table_name'] : '',
				'users_table'             => isset( $users_meta['table_name'] ) ? (string) $users_meta['table_name'] : '',
				'row_count'               => isset( $options_meta['row_count'] ) ? (int) $options_meta['row_count'] : 0,
				'data_size'               => isset( $options_meta['data_size'] ) ? (int) $options_meta['data_size'] : 0,
				'siteurl_host'            => isset( $options_meta['siteurl_host'] ) ? (string) $options_meta['siteurl_host'] : '',
				'home_host'               => isset( $options_meta['home_host'] ) ? (string) $options_meta['home_host'] : '',
				'create_time'             => isset( $options_meta['create_time'] ) ? (string) $options_meta['create_time'] : '',
				'update_time'             => isset( $options_meta['update_time'] ) ? (string) $options_meta['update_time'] : '',
			);
		}

		return $metadata;
	}

	/**
	 * Build a mismatch warning when another prefix matches the site URL better.
	 *
	 * @param array<int, array<string, mixed>> $prefixes_metadata Prefix metadata rows.
	 * @return string
	 */
	public function get_mismatch_warning( array $prefixes_metadata ) {
		if ( count( $prefixes_metadata ) < 2 ) {
			return '';
		}

		$default           = self::get_wordpress_configured_prefix();
		$configured_meta   = null;
		$matching_prefixes = array();

		foreach ( $prefixes_metadata as $meta ) {
			if ( empty( $meta['prefix'] ) ) {
				continue;
			}

			$prefix = (string) $meta['prefix'];

			if ( $prefix === $default ) {
				$configured_meta = $meta;
			}

			if ( ! empty( $meta['url_matches_site'] ) ) {
				$matching_prefixes[] = $prefix;
			}
		}

		if ( empty( $matching_prefixes ) || null === $configured_meta ) {
			return '';
		}

		if ( ! empty( $configured_meta['url_matches_site'] ) ) {
			return '';
		}

		$alternate_prefixes = array_values(
			array_filter(
				$matching_prefixes,
				function ( $prefix ) use ( $default ) {
					return $prefix !== $default;
				}
			)
		);

		if ( empty( $alternate_prefixes ) ) {
			return '';
		}

		return sprintf(
			/* translators: 1: WordPress configured table prefix, 2: comma-separated alternate prefixes */
			__( 'WordPress is configured to use the %1$s prefix, but %2$s appears to match this site\'s URL. Verify $table_prefix in wp-config.php or choose a different prefix below.', 'choctaw-wp-security' ),
			$default,
			implode( ', ', $alternate_prefixes )
		);
	}

	/**
	 * Derive a prefix from an options table name.
	 *
	 * @param string $options_table Options table name.
	 * @return string
	 */
	private function prefix_from_options_table( $options_table ) {
		$options_table = (string) $options_table;

		if ( strlen( $options_table ) <= 7 || 'options' !== substr( $options_table, -7 ) ) {
			return '';
		}

		$prefix = substr( $options_table, 0, -7 );

		if ( ! preg_match( '/^[A-Za-z0-9_]+$/', $prefix ) ) {
			return '';
		}

		return $prefix;
	}

	/**
	 * Index options table metadata by table name.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private function index_options_metadata() {
		$map = array();

		foreach ( $this->options_discovery->get_tables_with_metadata() as $meta ) {
			if ( empty( $meta['table_name'] ) ) {
				continue;
			}

			$map[ (string) $meta['table_name'] ] = $meta;
		}

		return $map;
	}

	/**
	 * Index posts table metadata by table name.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private function index_posts_metadata() {
		$map = array();

		foreach ( $this->posts_discovery->get_tables_with_metadata() as $meta ) {
			if ( empty( $meta['table_name'] ) ) {
				continue;
			}

			$map[ (string) $meta['table_name'] ] = $meta;
		}

		return $map;
	}

	/**
	 * Index users table metadata by table name.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private function index_users_metadata() {
		$map = array();

		foreach ( $this->users_discovery->get_tables_with_metadata() as $meta ) {
			if ( empty( $meta['table_name'] ) ) {
				continue;
			}

			$map[ (string) $meta['table_name'] ] = $meta;
		}

		return $map;
	}
}
