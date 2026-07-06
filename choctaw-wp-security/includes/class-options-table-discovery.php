<?php
/**
 * Discovers and describes WordPress options tables in the database.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Finds candidate options tables and collects metadata for admin selection.
 */
class Choctaw_Wp_Security_Options_Table_Discovery {

	/**
	 * Required columns for a WordPress options table.
	 *
	 * @var array<int, string>
	 */
	private static $required_columns = array(
		'option_id',
		'option_name',
		'option_value',
		'autoload',
	);

	/**
	 * Get the options table WordPress is configured to use.
	 *
	 * @return string
	 */
	public static function get_wordpress_configured_table() {
		global $wpdb;

		return (string) $wpdb->options;
	}

	/**
	 * Discover plausible WordPress options tables in the current database.
	 *
	 * @return array<int, string>
	 */
	public function discover_options_tables() {
		global $wpdb;

		$tables  = array();
		$results = $wpdb->get_col( "SHOW TABLES LIKE '%options'", 0 );

		if ( ! is_array( $results ) ) {
			return $tables;
		}

		foreach ( $results as $table ) {
			$table = (string) $table;

			if ( ! $this->is_valid_table_identifier( $table ) ) {
				continue;
			}

			if ( ! $this->ends_with_options( $table ) ) {
				continue;
			}

			if ( ! $this->has_options_schema( $table ) ) {
				continue;
			}

			$tables[] = $table;
		}

		$tables = array_values( array_unique( $tables ) );
		$wp_table = self::get_wordpress_configured_table();

		usort(
			$tables,
			function ( $left, $right ) use ( $wp_table ) {
				if ( $left === $wp_table ) {
					return -1;
				}

				if ( $right === $wp_table ) {
					return 1;
				}

				return strnatcasecmp( $left, $right );
			}
		);

		return $tables;
	}

	/**
	 * Validate a table name against the discovered allowlist.
	 *
	 * @param string               $table_name Table name to validate.
	 * @param array<int, string>|null $discovered Optional discovered tables.
	 * @return string|false
	 */
	public function validate_table_name( $table_name, $discovered = null ) {
		$table_name = (string) $table_name;

		if ( ! $this->is_valid_table_identifier( $table_name ) ) {
			return false;
		}

		if ( ! is_array( $discovered ) ) {
			$discovered = $this->discover_options_tables();
		}

		if ( ! in_array( $table_name, $discovered, true ) ) {
			return false;
		}

		return $table_name;
	}

	/**
	 * Resolve which options table should be scanned.
	 *
	 * @param string $requested_table Requested table name.
	 * @return string
	 */
	public function resolve_scan_table( $requested_table = '' ) {
		$discovered = $this->discover_options_tables();
		$default    = self::get_wordpress_configured_table();

		if ( '' !== $requested_table ) {
			$validated = $this->validate_table_name( $requested_table, $discovered );

			if ( false !== $validated ) {
				return $validated;
			}
		}

		$stored = Choctaw_Wp_Security_Utils::get_database_scan_options_table();

		if ( '' !== $stored ) {
			$validated = $this->validate_table_name( $stored, $discovered );

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
	 * Collect metadata for each discovered options table.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public function get_tables_with_metadata() {
		$tables         = $this->discover_options_tables();
		$wp_table       = self::get_wordpress_configured_table();
		$expected_hosts = $this->get_expected_hosts();
		$metadata       = array();

		foreach ( $tables as $table ) {
			$metadata[] = $this->get_table_metadata( $table, $wp_table, $expected_hosts );
		}

		return $metadata;
	}

	/**
	 * Build a mismatch warning when another table matches the site URL better.
	 *
	 * @param array<int, array<string, mixed>> $tables_metadata Table metadata rows.
	 * @return string
	 */
	public function get_mismatch_warning( array $tables_metadata ) {
		if ( count( $tables_metadata ) < 2 ) {
			return '';
		}

		$wp_table = self::get_wordpress_configured_table();
		$configured_meta = null;
		$matching_tables = array();

		foreach ( $tables_metadata as $meta ) {
			if ( empty( $meta['table_name'] ) ) {
				continue;
			}

			if ( $meta['table_name'] === $wp_table ) {
				$configured_meta = $meta;
			}

			if ( ! empty( $meta['url_matches_site'] ) ) {
				$matching_tables[] = (string) $meta['table_name'];
			}
		}

		if ( empty( $matching_tables ) || null === $configured_meta ) {
			return '';
		}

		if ( ! empty( $configured_meta['url_matches_site'] ) ) {
			return '';
		}

		$alternate_tables = array_values(
			array_filter(
				$matching_tables,
				function ( $table_name ) use ( $wp_table ) {
					return $table_name !== $wp_table;
				}
			)
		);

		if ( empty( $alternate_tables ) ) {
			return '';
		}

		return sprintf(
			/* translators: 1: WordPress configured options table, 2: comma-separated alternate table names */
			__( 'WordPress is configured to use %1$s, but %2$s appears to match this site\'s URL. Verify your table prefix in wp-config.php or select the correct table below.', 'choctaw-wp-security' ),
			$wp_table,
			implode( ', ', $alternate_tables )
		);
	}

	/**
	 * Collect metadata for one options table.
	 *
	 * @param string             $table_name     Table name.
	 * @param string             $wp_table       WordPress configured table.
	 * @param array<int, string> $expected_hosts Expected site hosts.
	 * @return array<string, mixed>
	 */
	private function get_table_metadata( $table_name, $wp_table, array $expected_hosts ) {
		global $wpdb;

		$table_sql   = $this->quote_table_name( $table_name );
		$row_count   = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table_sql}" );
		$siteurl     = (string) $wpdb->get_var( "SELECT option_value FROM {$table_sql} WHERE option_name = 'siteurl' LIMIT 1" );
		$home        = (string) $wpdb->get_var( "SELECT option_value FROM {$table_sql} WHERE option_name = 'home' LIMIT 1" );
		$siteurl_host = $this->normalize_host( $siteurl );
		$home_host    = $this->normalize_host( $home );
		$schema_meta  = $this->get_information_schema_metadata( $table_name );

		$url_matches_site = $this->host_matches_expected( $siteurl_host, $expected_hosts )
			|| $this->host_matches_expected( $home_host, $expected_hosts );

		return array(
			'table_name'              => $table_name,
			'is_wordpress_configured' => ( $table_name === $wp_table ),
			'url_matches_site'        => $url_matches_site,
			'row_count'               => $row_count,
			'data_size'               => isset( $schema_meta['data_length'] ) ? (int) $schema_meta['data_length'] : 0,
			'siteurl_host'            => $siteurl_host,
			'home_host'               => $home_host,
			'create_time'             => isset( $schema_meta['create_time'] ) ? (string) $schema_meta['create_time'] : '',
			'update_time'             => isset( $schema_meta['update_time'] ) ? (string) $schema_meta['update_time'] : '',
		);
	}

	/**
	 * Read table metadata from information_schema.
	 *
	 * @param string $table_name Table name.
	 * @return array<string, mixed>
	 */
	private function get_information_schema_metadata( $table_name ) {
		global $wpdb;

		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT DATA_LENGTH, CREATE_TIME, UPDATE_TIME
				FROM information_schema.TABLES
				WHERE TABLE_SCHEMA = %s
				AND TABLE_NAME = %s',
				$this->get_database_name(),
				$table_name
			),
			ARRAY_A
		);

		if ( ! is_array( $row ) ) {
			return array();
		}

		return array(
			'data_length'  => isset( $row['DATA_LENGTH'] ) ? (int) $row['DATA_LENGTH'] : 0,
			'create_time'  => isset( $row['CREATE_TIME'] ) ? (string) $row['CREATE_TIME'] : '',
			'update_time'  => isset( $row['UPDATE_TIME'] ) ? (string) $row['UPDATE_TIME'] : '',
		);
	}

	/**
	 * Determine whether a table has the standard WordPress options schema.
	 *
	 * @param string $table_name Table name.
	 * @return bool
	 */
	private function has_options_schema( $table_name ) {
		global $wpdb;

		$table_sql = $this->quote_table_name( $table_name );
		$columns   = $wpdb->get_col( "DESCRIBE {$table_sql}", 0 );

		if ( ! is_array( $columns ) ) {
			return false;
		}

		foreach ( self::$required_columns as $required_column ) {
			if ( ! in_array( $required_column, $columns, true ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Get the current database name.
	 *
	 * @return string
	 */
	private function get_database_name() {
		global $wpdb;

		if ( ! empty( $wpdb->dbname ) ) {
			return (string) $wpdb->dbname;
		}

		$name = $wpdb->get_var( 'SELECT DATABASE()' );

		return is_string( $name ) ? $name : '';
	}

	/**
	 * Determine whether a table name ends with "options".
	 *
	 * @param string $table_name Table name.
	 * @return bool
	 */
	private function ends_with_options( $table_name ) {
		return 'options' === substr( $table_name, -7 );
	}

	/**
	 * Determine whether a table identifier is safe to use in SQL.
	 *
	 * @param string $table_name Table name.
	 * @return bool
	 */
	private function is_valid_table_identifier( $table_name ) {
		return (bool) preg_match( '/^[A-Za-z0-9_]+$/', $table_name );
	}

	/**
	 * Quote a validated table name for SQL usage.
	 *
	 * @param string $table_name Table name.
	 * @return string
	 */
	public function quote_table_name( $table_name ) {
		return '`' . str_replace( '`', '``', $table_name ) . '`';
	}

	/**
	 * Get expected site hosts for comparison.
	 *
	 * @return array<int, string>
	 */
	private function get_expected_hosts() {
		$hosts = array();

		if ( ! empty( $_SERVER['HTTP_HOST'] ) ) {
			$hosts[] = $this->normalize_host( (string) wp_unslash( $_SERVER['HTTP_HOST'] ) );
		}

		if ( defined( 'WP_HOME' ) ) {
			$hosts[] = $this->normalize_host( WP_HOME );
		}

		if ( defined( 'WP_SITEURL' ) ) {
			$hosts[] = $this->normalize_host( WP_SITEURL );
		}

		return array_values( array_unique( array_filter( $hosts ) ) );
	}

	/**
	 * Normalize a URL or host string.
	 *
	 * @param string $value URL or host.
	 * @return string
	 */
	private function normalize_host( $value ) {
		if ( '' === $value ) {
			return '';
		}

		$parts = wp_parse_url( $value );
		$host  = '';

		if ( is_array( $parts ) && ! empty( $parts['host'] ) ) {
			$host = (string) $parts['host'];
		} else {
			$host = (string) $value;
		}

		$host = strtolower( trim( $host ) );

		if ( 0 === strpos( $host, 'www.' ) ) {
			$host = substr( $host, 4 );
		}

		return $host;
	}

	/**
	 * Check whether a host matches expected site hosts.
	 *
	 * @param string             $host     Host to test.
	 * @param array<int, string> $expected Expected hosts.
	 * @return bool
	 */
	private function host_matches_expected( $host, array $expected ) {
		$host = $this->normalize_host( $host );

		if ( '' === $host ) {
			return false;
		}

		foreach ( $expected as $expected_host ) {
			if ( $host === $this->normalize_host( $expected_host ) ) {
				return true;
			}
		}

		return false;
	}
}
