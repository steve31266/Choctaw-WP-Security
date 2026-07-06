<?php
/**
 * Discovers and describes WordPress users tables in the database.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Finds candidate users tables and collects metadata for admin selection.
 */
class Choctaw_Wp_Security_Users_Table_Discovery {

	/**
	 * Required columns for a WordPress users table.
	 *
	 * @var array<int, string>
	 */
	private static $required_columns = array(
		'ID',
		'user_login',
		'user_email',
		'user_registered',
		'user_status',
		'display_name',
	);

	/**
	 * Get the users table WordPress is configured to use.
	 *
	 * @return string
	 */
	public static function get_wordpress_configured_table() {
		global $wpdb;

		return (string) $wpdb->users;
	}

	/**
	 * Discover plausible WordPress users tables in the current database.
	 *
	 * @return array<int, string>
	 */
	public function discover_users_tables() {
		global $wpdb;

		$tables  = array();
		$results = $wpdb->get_col( "SHOW TABLES LIKE '%users'", 0 );

		if ( ! is_array( $results ) ) {
			return $tables;
		}

		foreach ( $results as $table ) {
			$table = (string) $table;

			if ( ! $this->is_valid_table_identifier( $table ) ) {
				continue;
			}

			if ( ! $this->ends_with_users( $table ) ) {
				continue;
			}

			if ( ! $this->has_users_schema( $table ) ) {
				continue;
			}

			$tables[] = $table;
		}

		$tables   = array_values( array_unique( $tables ) );
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
	 * @param string                    $table_name Table name to validate.
	 * @param array<int, string>|null $discovered Optional discovered tables.
	 * @return string|false
	 */
	public function validate_table_name( $table_name, $discovered = null ) {
		$table_name = (string) $table_name;

		if ( ! $this->is_valid_table_identifier( $table_name ) ) {
			return false;
		}

		if ( ! is_array( $discovered ) ) {
			$discovered = $this->discover_users_tables();
		}

		if ( ! in_array( $table_name, $discovered, true ) ) {
			return false;
		}

		return $table_name;
	}

	/**
	 * Resolve which users table should be loaded.
	 *
	 * @param string $requested_table Requested table name.
	 * @return string
	 */
	public function resolve_scan_table( $requested_table = '' ) {
		$discovered = $this->discover_users_tables();
		$default    = self::get_wordpress_configured_table();

		if ( '' !== $requested_table ) {
			$validated = $this->validate_table_name( $requested_table, $discovered );

			if ( false !== $validated ) {
				return $validated;
			}
		}

		$stored = Choctaw_Wp_Security_Utils::get_database_scan_users_table();

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
	 * Collect metadata for each discovered users table.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public function get_tables_with_metadata() {
		$tables   = $this->discover_users_tables();
		$wp_table = self::get_wordpress_configured_table();
		$metadata = array();

		foreach ( $tables as $table ) {
			$metadata[] = $this->get_table_metadata( $table, $wp_table );
		}

		return $metadata;
	}

	/**
	 * Derive the table prefix from a users table name.
	 *
	 * @param string $users_table Users table name.
	 * @return string
	 */
	public function get_table_prefix( $users_table ) {
		$users_table = (string) $users_table;

		if ( strlen( $users_table ) <= 5 || 'users' !== substr( $users_table, -5 ) ) {
			return '';
		}

		return substr( $users_table, 0, -5 );
	}

	/**
	 * Resolve the usermeta table for a users table prefix.
	 *
	 * @param string $users_table Users table name.
	 * @return string|false
	 */
	public function get_usermeta_table( $users_table ) {
		$prefix = $this->get_table_prefix( $users_table );

		if ( '' === $prefix ) {
			return false;
		}

		$table_name = $prefix . 'usermeta';

		if ( ! $this->is_valid_table_identifier( $table_name ) || ! $this->table_exists( $table_name ) ) {
			return false;
		}

		return $table_name;
	}

	/**
	 * Resolve the posts table for a users table prefix.
	 *
	 * @param string $users_table Users table name.
	 * @return string|false
	 */
	public function get_posts_table( $users_table ) {
		$prefix = $this->get_table_prefix( $users_table );

		if ( '' === $prefix ) {
			return false;
		}

		$table_name = $prefix . 'posts';

		if ( ! $this->is_valid_table_identifier( $table_name ) || ! $this->table_exists( $table_name ) ) {
			return false;
		}

		if ( ! $this->has_posts_schema( $table_name ) ) {
			return false;
		}

		return $table_name;
	}

	/**
	 * Resolve the comments table for a users table prefix.
	 *
	 * @param string $users_table Users table name.
	 * @return string|false
	 */
	public function get_comments_table( $users_table ) {
		$prefix = $this->get_table_prefix( $users_table );

		if ( '' === $prefix ) {
			return false;
		}

		$table_name = $prefix . 'comments';

		if ( ! $this->is_valid_table_identifier( $table_name ) || ! $this->table_exists( $table_name ) ) {
			return false;
		}

		if ( ! $this->has_comments_schema( $table_name ) ) {
			return false;
		}

		return $table_name;
	}

	/**
	 * Get the capabilities meta key for a users table prefix.
	 *
	 * @param string $users_table Users table name.
	 * @return string
	 */
	public function get_capabilities_meta_key( $users_table ) {
		return $this->get_table_prefix( $users_table ) . 'capabilities';
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
	 * Collect metadata for one users table.
	 *
	 * @param string $table_name Table name.
	 * @param string $wp_table   WordPress configured table.
	 * @return array<string, mixed>
	 */
	private function get_table_metadata( $table_name, $wp_table ) {
		global $wpdb;

		$table_sql   = $this->quote_table_name( $table_name );
		$row_count   = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table_sql}" );
		$schema_meta = $this->get_information_schema_metadata( $table_name );

		return array(
			'table_name'              => $table_name,
			'is_wordpress_configured' => ( $table_name === $wp_table ),
			'row_count'               => $row_count,
			'data_size'               => isset( $schema_meta['data_length'] ) ? (int) $schema_meta['data_length'] : 0,
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
			'data_length' => isset( $row['DATA_LENGTH'] ) ? (int) $row['DATA_LENGTH'] : 0,
			'create_time' => isset( $row['CREATE_TIME'] ) ? (string) $row['CREATE_TIME'] : '',
			'update_time' => isset( $row['UPDATE_TIME'] ) ? (string) $row['UPDATE_TIME'] : '',
		);
	}

	/**
	 * Determine whether a table has the standard WordPress users schema.
	 *
	 * @param string $table_name Table name.
	 * @return bool
	 */
	private function has_users_schema( $table_name ) {
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
	 * Determine whether a table has the minimum posts schema for activity queries.
	 *
	 * @param string $table_name Table name.
	 * @return bool
	 */
	private function has_posts_schema( $table_name ) {
		global $wpdb;

		$table_sql = $this->quote_table_name( $table_name );
		$columns   = $wpdb->get_col( "DESCRIBE {$table_sql}", 0 );

		if ( ! is_array( $columns ) ) {
			return false;
		}

		foreach ( array( 'ID', 'post_author', 'post_date', 'post_title', 'post_status', 'post_type', 'post_parent' ) as $required_column ) {
			if ( ! in_array( $required_column, $columns, true ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Determine whether a table has the minimum comments schema for activity queries.
	 *
	 * @param string $table_name Table name.
	 * @return bool
	 */
	private function has_comments_schema( $table_name ) {
		global $wpdb;

		$table_sql = $this->quote_table_name( $table_name );
		$columns   = $wpdb->get_col( "DESCRIBE {$table_sql}", 0 );

		if ( ! is_array( $columns ) ) {
			return false;
		}

		foreach ( array( 'comment_ID', 'comment_post_ID', 'comment_author', 'comment_date', 'comment_content', 'user_id' ) as $required_column ) {
			if ( ! in_array( $required_column, $columns, true ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Determine whether a table exists in the current database.
	 *
	 * @param string $table_name Table name.
	 * @return bool
	 */
	private function table_exists( $table_name ) {
		global $wpdb;

		$found = $wpdb->get_var(
			$wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name )
		);

		return is_string( $found ) && $found === $table_name;
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
	 * Determine whether a table name ends with "users".
	 *
	 * @param string $table_name Table name.
	 * @return bool
	 */
	private function ends_with_users( $table_name ) {
		return 'users' === substr( $table_name, -5 );
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
}
