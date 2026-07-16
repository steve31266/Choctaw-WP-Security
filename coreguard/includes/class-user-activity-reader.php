<?php
/**
 * Reconstructs detectable user activity from WordPress database tables.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Reads forensic user activity from posts and comments tables.
 */
class Choctaw_Wp_Security_User_Activity_Reader {

	const ACTIVITY_CAP = 500;

	/**
	 * Post types excluded from created-content activity.
	 *
	 * @var array<int, string>
	 */
	private static $excluded_post_types = array(
		'revision',
		'nav_menu_item',
		'customize_changeset',
		'wp_global_styles',
		'wp_template',
		'wp_template_part',
		'wp_navigation',
		'oembed_cache',
		'user_request',
		'attachment',
	);

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
	 * Fetch detectable activity for one user.
	 *
	 * @param string $users_table Validated users table name.
	 * @param int    $user_id     User ID.
	 * @return array<string, mixed>
	 */
	public function fetch_user_activity( $users_table, $user_id ) {
		$users_table = $this->discovery->validate_table_name( $users_table );
		$user_id     = (int) $user_id;

		if ( false === $users_table || $user_id <= 0 ) {
			return $this->error_response(
				__( 'The requested user activity could not be loaded.', 'choctaw-wp-security' )
			);
		}

		if ( ! $this->users_reader->user_exists( $users_table, $user_id ) ) {
			return $this->error_response(
				__( 'The requested user was not found in the selected users table.', 'choctaw-wp-security' )
			);
		}

		$posts_table    = $this->discovery->get_posts_table( $users_table );
		$comments_table = $this->discovery->get_comments_table( $users_table );

		if ( false === $posts_table && false === $comments_table ) {
			return $this->error_response(
				__( 'Activity data is unavailable because the related posts and comments tables were not found for this table prefix.', 'choctaw-wp-security' )
			);
		}

		$activities = array();

		if ( false !== $posts_table ) {
			$activities = array_merge(
				$activities,
				$this->fetch_created_content( $posts_table, $user_id ),
				$this->fetch_edited_content( $posts_table, $user_id ),
				$this->fetch_uploads( $posts_table, $user_id )
			);
		}

		if ( false !== $comments_table ) {
			$activities = array_merge(
				$activities,
				$this->fetch_comments( $comments_table, $user_id )
			);
		}

		usort(
			$activities,
			function ( $left, $right ) {
				return strcmp( (string) $right['date'], (string) $left['date'] );
			}
		);

		$capped = count( $activities ) > self::ACTIVITY_CAP;

		if ( $capped ) {
			$activities = array_slice( $activities, 0, self::ACTIVITY_CAP );
		}

		return array(
			'success'    => true,
			'user_id'    => $user_id,
			'activities' => $activities,
			'capped'     => $capped,
			'cap'        => self::ACTIVITY_CAP,
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
			'success'    => false,
			'message'    => (string) $message,
			'activities' => array(),
			'capped'     => false,
			'cap'        => self::ACTIVITY_CAP,
		);
	}

	/**
	 * Fetch created or trashed content attributed to a user.
	 *
	 * @param string $posts_table Posts table name.
	 * @param int    $user_id     User ID.
	 * @return array<int, array<string, mixed>>
	 */
	private function fetch_created_content( $posts_table, $user_id ) {
		global $wpdb;

		$posts_sql          = $this->discovery->quote_table_name( $posts_table );
		$excluded_post_types = implode(
			"','",
			array_map( 'esc_sql', self::$excluded_post_types )
		);

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ID, post_title, post_status, post_type, post_date
				FROM {$posts_sql}
				WHERE post_author = %d
				AND post_type NOT IN ('{$excluded_post_types}')
				ORDER BY post_date DESC
				LIMIT %d",
				$user_id,
				self::ACTIVITY_CAP
			),
			ARRAY_A
		);

		return $this->map_post_rows( is_array( $rows ) ? $rows : array(), 'created_content' );
	}

	/**
	 * Fetch content edits attributed to a user via revision rows.
	 *
	 * @param string $posts_table Posts table name.
	 * @param int    $user_id     User ID.
	 * @return array<int, array<string, mixed>>
	 */
	private function fetch_edited_content( $posts_table, $user_id ) {
		global $wpdb;

		$posts_sql = $this->discovery->quote_table_name( $posts_table );
		$rows      = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT r.ID, r.post_date, r.post_parent, p.post_title, p.post_type, p.post_status
				FROM {$posts_sql} r
				INNER JOIN {$posts_sql} p ON p.ID = r.post_parent
				WHERE r.post_type = 'revision'
				AND r.post_author = %d
				ORDER BY r.post_date DESC
				LIMIT %d",
				$user_id,
				self::ACTIVITY_CAP
			),
			ARRAY_A
		);

		if ( ! is_array( $rows ) ) {
			return array();
		}

		$activities = array();

		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}

			$post_type   = isset( $row['post_type'] ) ? (string) $row['post_type'] : '';
			$post_title  = isset( $row['post_title'] ) ? (string) $row['post_title'] : '';
			$post_status = isset( $row['post_status'] ) ? (string) $row['post_status'] : '';

			$activities[] = array(
				'activity_type'  => 'edited_content',
				'activity_label' => sprintf(
					/* translators: %s: post type slug */
					__( 'Edited %s', 'choctaw-wp-security' ),
					$this->format_post_type_label( $post_type )
				),
				'object_id'      => isset( $row['ID'] ) ? (int) $row['ID'] : 0,
				'parent_id'      => isset( $row['post_parent'] ) ? (int) $row['post_parent'] : 0,
				'title'          => $post_title,
				'object_subtype' => $post_type,
				'status'         => $post_status,
				'date'           => isset( $row['post_date'] ) ? (string) $row['post_date'] : '',
				'detail'         => sprintf(
					/* translators: 1: parent post title, 2: post type slug, 3: post status */
					__( 'Edited: %1$s (%2$s / %3$s)', 'choctaw-wp-security' ),
					$post_title,
					$post_type,
					$post_status
				),
			);
		}

		return $activities;
	}

	/**
	 * Fetch media uploads attributed to a user.
	 *
	 * @param string $posts_table Posts table name.
	 * @param int    $user_id     User ID.
	 * @return array<int, array<string, mixed>>
	 */
	private function fetch_uploads( $posts_table, $user_id ) {
		global $wpdb;

		$posts_sql = $this->discovery->quote_table_name( $posts_table );
		$rows      = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ID, post_title, post_status, post_type, post_date
				FROM {$posts_sql}
				WHERE post_author = %d
				AND post_type = 'attachment'
				ORDER BY post_date DESC
				LIMIT %d",
				$user_id,
				self::ACTIVITY_CAP
			),
			ARRAY_A
		);

		return $this->map_post_rows( is_array( $rows ) ? $rows : array(), 'upload' );
	}

	/**
	 * Fetch comments attributed to a user.
	 *
	 * @param string $comments_table Comments table name.
	 * @param int    $user_id        User ID.
	 * @return array<int, array<string, mixed>>
	 */
	private function fetch_comments( $comments_table, $user_id ) {
		global $wpdb;

		$comments_sql = $this->discovery->quote_table_name( $comments_table );
		$rows         = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT comment_ID, comment_post_ID, comment_author, comment_date, comment_content
				FROM {$comments_sql}
				WHERE user_id = %d
				ORDER BY comment_date DESC
				LIMIT %d",
				$user_id,
				self::ACTIVITY_CAP
			),
			ARRAY_A
		);

		if ( ! is_array( $rows ) ) {
			return array();
		}

		$activities = array();

		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}

			$comment_excerpt = wp_html_excerpt(
				wp_strip_all_tags( isset( $row['comment_content'] ) ? (string) $row['comment_content'] : '' ),
				80,
				'...'
			);

			$activities[] = array(
				'activity_type'  => 'comment',
				'activity_label' => __( 'Posted comment', 'choctaw-wp-security' ),
				'object_id'      => isset( $row['comment_ID'] ) ? (int) $row['comment_ID'] : 0,
				'parent_id'      => isset( $row['comment_post_ID'] ) ? (int) $row['comment_post_ID'] : 0,
				'title'          => $comment_excerpt,
				'object_subtype' => 'comment',
				'status'         => '',
				'date'           => isset( $row['comment_date'] ) ? (string) $row['comment_date'] : '',
				'detail'         => sprintf(
					/* translators: %d: post ID the comment belongs to */
					__( 'Comment on post ID %d', 'choctaw-wp-security' ),
					isset( $row['comment_post_ID'] ) ? (int) $row['comment_post_ID'] : 0
				),
			);
		}

		return $activities;
	}

	/**
	 * Map post rows into activity items.
	 *
	 * @param array<int, array<string, mixed>> $rows          Post rows.
	 * @param string                           $activity_type Activity type key.
	 * @return array<int, array<string, mixed>>
	 */
	private function map_post_rows( array $rows, $activity_type ) {
		$activities = array();

		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}

			$post_type   = isset( $row['post_type'] ) ? (string) $row['post_type'] : '';
			$post_title  = isset( $row['post_title'] ) ? (string) $row['post_title'] : '';
			$post_status = isset( $row['post_status'] ) ? (string) $row['post_status'] : '';

			if ( 'upload' === $activity_type ) {
				$activity_label = __( 'Uploaded file', 'choctaw-wp-security' );
			} else {
				$activity_label = sprintf(
					/* translators: %s: post type slug */
					__( 'Created %s', 'choctaw-wp-security' ),
					$this->format_post_type_label( $post_type )
				);
			}

			$activities[] = array(
				'activity_type'  => $activity_type,
				'activity_label' => $activity_label,
				'object_id'      => isset( $row['ID'] ) ? (int) $row['ID'] : 0,
				'parent_id'      => 0,
				'title'          => $post_title,
				'object_subtype' => $post_type,
				'status'         => $post_status,
				'date'           => isset( $row['post_date'] ) ? (string) $row['post_date'] : '',
				'detail'         => $post_type . ' / ' . $post_status,
			);
		}

		return $activities;
	}

	/**
	 * Format a post type slug for display.
	 *
	 * @param string $post_type Post type slug.
	 * @return string
	 */
	private function format_post_type_label( $post_type ) {
		$post_type = sanitize_key( (string) $post_type );

		if ( '' === $post_type ) {
			return __( 'content', 'choctaw-wp-security' );
		}

		return str_replace( '_', ' ', $post_type );
	}
}
