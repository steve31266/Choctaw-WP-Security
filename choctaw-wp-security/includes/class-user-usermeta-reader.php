<?php
/**
 * Reads usermeta rows for a WordPress user.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Fetches all usermeta records for one user from a paired usermeta table.
 */
class Choctaw_Wp_Security_User_Usermeta_Reader {

	const META_CAP = 500;

	/**
	 * Users table discovery helper.
	 *
	 * @var Choctaw_Wp_Security_Users_Table_Discovery
	 */
	private $discovery;

	/**
	 * Users table reader helper.
	 *
	 * @var Choctaw_Wp_Security_Users_Table_Reader
	 */
	private $users_reader;

	/**
	 * Constructor.
	 *
	 * @param Choctaw_Wp_Security_Users_Table_Discovery|null $discovery    Optional discovery helper.
	 * @param Choctaw_Wp_Security_Users_Table_Reader|null    $users_reader Optional users reader helper.
	 */
	public function __construct( $discovery = null, $users_reader = null ) {
		$this->discovery    = $discovery instanceof Choctaw_Wp_Security_Users_Table_Discovery
			? $discovery
			: new Choctaw_Wp_Security_Users_Table_Discovery();
		$this->users_reader = $users_reader instanceof Choctaw_Wp_Security_Users_Table_Reader
			? $users_reader
			: new Choctaw_Wp_Security_Users_Table_Reader( $this->discovery );
	}

	/**
	 * Fetch all usermeta rows for one user.
	 *
	 * @param string $users_table Validated users table name.
	 * @param int    $user_id     User ID.
	 * @return array<string, mixed>
	 */
	public function fetch_user_usermeta( $users_table, $user_id ) {
		global $wpdb;

		$users_table = $this->discovery->validate_table_name( $users_table );
		$user_id     = (int) $user_id;

		if ( false === $users_table || $user_id <= 0 ) {
			return $this->error_response(
				__( 'The requested usermeta could not be loaded.', 'choctaw-wp-security' )
			);
		}

		if ( ! $this->users_reader->user_exists( $users_table, $user_id ) ) {
			return $this->error_response(
				__( 'The requested user was not found in the selected users table.', 'choctaw-wp-security' )
			);
		}

		$usermeta_table = $this->discovery->get_usermeta_table( $users_table );

		if ( false === $usermeta_table ) {
			return $this->error_response(
				__( 'Usermeta data is unavailable because the related usermeta table was not found for this table prefix.', 'choctaw-wp-security' )
			);
		}

		$usermeta_sql = $this->discovery->quote_table_name( $usermeta_table );
		$rows         = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT umeta_id, meta_key, meta_value
				FROM {$usermeta_sql}
				WHERE user_id = %d
				ORDER BY umeta_id ASC
				LIMIT %d",
				$user_id,
				self::META_CAP + 1
			),
			ARRAY_A
		);

		if ( ! is_array( $rows ) ) {
			$rows = array();
		}

		$capped = count( $rows ) > self::META_CAP;

		if ( $capped ) {
			$rows = array_slice( $rows, 0, self::META_CAP );
		}

		$meta_rows = array();

		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}

			$meta_rows[] = array(
				'umeta_id'   => isset( $row['umeta_id'] ) ? (int) $row['umeta_id'] : 0,
				'meta_key'   => isset( $row['meta_key'] ) ? (string) $row['meta_key'] : '',
				'meta_value' => isset( $row['meta_value'] ) ? (string) $row['meta_value'] : '',
			);
		}

		return array(
			'success'    => true,
			'user_id'    => $user_id,
			'meta_rows'  => $meta_rows,
			'capped'     => $capped,
			'cap'        => self::META_CAP,
		);
	}

	/**
	 * Build an error response payload.
	 *
	 * @param string $message Error message.
	 * @return array<string, mixed>
	 */
	private function error_response( $message ) {
		return array(
			'success'   => false,
			'message'   => (string) $message,
			'meta_rows' => array(),
			'capped'    => false,
			'cap'       => self::META_CAP,
		);
	}
}
