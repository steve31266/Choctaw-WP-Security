<?php
/**
 * Reads user records from a WordPress users table.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Fetches users and role labels from a selected users table.
 */
class Choctaw_Wp_Security_Users_Table_Reader {

	/**
	 * Users table discovery helper.
	 *
	 * @var Choctaw_Wp_Security_Users_Table_Discovery
	 */
	private $discovery;

	/**
	 * Constructor.
	 *
	 * @param Choctaw_Wp_Security_Users_Table_Discovery|null $discovery Optional discovery helper.
	 */
	public function __construct( $discovery = null ) {
		$this->discovery = $discovery instanceof Choctaw_Wp_Security_Users_Table_Discovery
			? $discovery
			: new Choctaw_Wp_Security_Users_Table_Discovery();
	}

	/**
	 * Fetch all users from the selected users table.
	 *
	 * @param string $users_table Validated users table name.
	 * @return array<string, mixed>
	 */
	public function fetch_users( $users_table ) {
		global $wpdb;

		$users_table = $this->discovery->validate_table_name( $users_table );

		if ( false === $users_table ) {
			return array(
				'success'                    => false,
				'message'                    => __( 'The selected users table is not valid.', 'choctaw-wp-security' ),
				'users_table'                => '',
				'wordpress_configured_table'   => Choctaw_Wp_Security_Users_Table_Discovery::get_wordpress_configured_table(),
				'users'                      => array(),
				'summary'                    => array(
					'total' => 0,
				),
			);
		}

		$users_sql       = $this->discovery->quote_table_name( $users_table );
		$usermeta_table  = $this->discovery->get_usermeta_table( $users_table );
		$capabilities_key = $this->discovery->get_capabilities_meta_key( $users_table );
		$users           = array();

		if ( false !== $usermeta_table ) {
			$usermeta_sql = $this->discovery->quote_table_name( $usermeta_table );
			$rows         = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT u.ID, u.user_login, u.user_email, u.user_registered, u.display_name, um.meta_value AS capabilities
					FROM {$users_sql} u
					LEFT JOIN {$usermeta_sql} um ON u.ID = um.user_id AND um.meta_key = %s
					ORDER BY u.ID ASC",
					$capabilities_key
				),
				ARRAY_A
			);
		} else {
			$rows = $wpdb->get_results(
				"SELECT u.ID, u.user_login, u.user_email, u.user_registered, u.display_name, '' AS capabilities
				FROM {$users_sql} u
				ORDER BY u.ID ASC",
				ARRAY_A
			);
		}

		if ( is_array( $rows ) ) {
			foreach ( $rows as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}

				$users[] = array(
					'ID'              => isset( $row['ID'] ) ? (int) $row['ID'] : 0,
					'user_login'      => isset( $row['user_login'] ) ? (string) $row['user_login'] : '',
					'user_email'      => isset( $row['user_email'] ) ? (string) $row['user_email'] : '',
					'user_registered' => isset( $row['user_registered'] ) ? (string) $row['user_registered'] : '',
					'user_status'     => $this->resolve_role_label( isset( $row['capabilities'] ) ? $row['capabilities'] : '' ),
					'display_name'    => isset( $row['display_name'] ) ? (string) $row['display_name'] : '',
				);
			}
		}

		return array(
			'success'                  => true,
			'users_table'              => $users_table,
			'wordpress_configured_table' => Choctaw_Wp_Security_Users_Table_Discovery::get_wordpress_configured_table(),
			'users'                    => $users,
			'summary'                  => array(
				'total' => count( $users ),
			),
		);
	}

	/**
	 * Resolve a human-readable role label from serialized capabilities.
	 *
	 * @param mixed $capabilities Serialized capabilities meta value.
	 * @return string
	 */
	public function resolve_role_label( $capabilities ) {
		$roles = $this->resolve_role_slugs( $capabilities );

		if ( empty( $roles ) ) {
			return __( 'No role', 'choctaw-wp-security' );
		}

		$labels = array();

		foreach ( $roles as $role_slug ) {
			$labels[] = translate_user_role( ucfirst( $role_slug ) );
		}

		return implode( ', ', $labels );
	}

	/**
	 * Extract enabled role slugs from serialized capabilities.
	 *
	 * @param mixed $capabilities Serialized capabilities meta value.
	 * @return array<int, string>
	 */
	private function resolve_role_slugs( $capabilities ) {
		$capabilities = maybe_unserialize( $capabilities );

		if ( ! is_array( $capabilities ) ) {
			return array();
		}

		$roles = array();

		foreach ( $capabilities as $role_slug => $enabled ) {
			if ( ! $enabled ) {
				continue;
			}

			$role_slug = sanitize_key( (string) $role_slug );

			if ( '' !== $role_slug ) {
				$roles[] = $role_slug;
			}
		}

		return $roles;
	}

	/**
	 * Determine whether a user ID exists in the selected users table.
	 *
	 * @param string $users_table Validated users table name.
	 * @param int    $user_id     User ID.
	 * @return bool
	 */
	public function user_exists( $users_table, $user_id ) {
		global $wpdb;

		$users_table = $this->discovery->validate_table_name( $users_table );

		if ( false === $users_table || $user_id <= 0 ) {
			return false;
		}

		$users_sql = $this->discovery->quote_table_name( $users_table );
		$found     = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT ID FROM {$users_sql} WHERE ID = %d LIMIT 1",
				$user_id
			)
		);

		return (int) $found === $user_id;
	}
}
