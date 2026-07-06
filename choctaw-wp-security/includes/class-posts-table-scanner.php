<?php
/**
 * wp_posts table scanner for potentially compromised records.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Scans the WordPress posts table for high-risk compromise indicators.
 */
class Choctaw_Wp_Security_Posts_Table_Scanner {

	/**
	 * Scan start time.
	 *
	 * @var float
	 */
	private $start_time = 0;

	/**
	 * Whether the scan stopped early due to time budget.
	 *
	 * @var bool
	 */
	private $scan_incomplete = false;

	/**
	 * Selected posts table name.
	 *
	 * @var string
	 */
	private $posts_table = '';

	/**
	 * Resolved users table for display name lookups.
	 *
	 * @var string
	 */
	private $users_table = '';

	/**
	 * Cached user_id => display_name pairs.
	 *
	 * @var array<int, string>
	 */
	private $user_display_names = array();

	/**
	 * Table discovery helper.
	 *
	 * @var Choctaw_Wp_Security_Posts_Table_Discovery
	 */
	private $discovery;

	/**
	 * Create a scanner for a specific posts table.
	 *
	 * @param string $posts_table Requested posts table name.
	 */
	public function __construct( $posts_table = '' ) {
		$this->discovery   = new Choctaw_Wp_Security_Posts_Table_Discovery();
		$this->posts_table  = $this->discovery->resolve_scan_table( $posts_table );
		$this->users_table  = $this->resolve_users_table();
	}

	/**
	 * Run the full wp_posts scan.
	 *
	 * @return array<string, mixed>
	 */
	public function scan() {
		$this->start_time      = microtime( true );
		$this->scan_incomplete = false;

		$sections = $this->empty_sections();
		$baseline = $this->load_baseline();

		$this->scan_php_execution_patterns( $sections['php_execution_patterns']['findings'] );
		$this->scan_script_iframe_injection( $sections['script_iframe_injection']['findings'] );
		$this->scan_high_confidence_scripts( $sections['high_confidence_scripts']['findings'] );
		$this->scan_seo_spam_titles( $sections['seo_spam_titles']['findings'] );
		$this->scan_large_post_content( $sections['large_post_content']['findings'] );
		$this->scan_baseline_diff( $sections['baseline_diff'], $baseline );

		$snapshot = $this->capture_baseline_snapshot();
		$this->save_baseline( $snapshot );

		$summary = $this->build_summary( $sections );

		return array(
			'success'                    => 0 === ( $summary['critical'] + $summary['warning'] ),
			'scan_incomplete'            => $this->scan_incomplete,
			'baseline_established'       => $this->is_baseline_uninitialized( $baseline ),
			'sections'                   => $sections,
			'summary'                    => $summary,
			'posts_table'                => $this->posts_table,
			'wordpress_configured_table' => Choctaw_Wp_Security_Posts_Table_Discovery::get_wordpress_configured_table(),
		);
	}

	/**
	 * Capture and save a baseline snapshot without running a full scan.
	 *
	 * @param string $posts_table Requested posts table name.
	 * @return bool
	 */
	public static function reset_baseline( $posts_table = '' ) {
		$scanner  = new self( $posts_table );
		$snapshot = $scanner->capture_baseline_snapshot();

		return $scanner->save_baseline( $snapshot );
	}

	/**
	 * Get the selected posts table name.
	 *
	 * @return string
	 */
	public function get_posts_table() {
		return $this->posts_table;
	}

	/**
	 * Determine whether a baseline is uninitialized for the selected table.
	 *
	 * @param array<string, mixed>|null $baseline Stored baseline.
	 * @return bool
	 */
	private function is_baseline_uninitialized( $baseline ) {
		if ( empty( $baseline ) || ! is_array( $baseline ) ) {
			return true;
		}

		$baseline_table = isset( $baseline['posts_table'] ) ? (string) $baseline['posts_table'] : '';

		return $baseline_table !== $this->posts_table;
	}

	/**
	 * Quote the selected posts table for SQL usage.
	 *
	 * @return string
	 */
	private function get_posts_table_sql() {
		return $this->discovery->quote_table_name( $this->posts_table );
	}

	/**
	 * Resolve the users table used for display name lookups.
	 *
	 * @return string
	 */
	private function resolve_users_table() {
		$paired = $this->discovery->get_users_table( $this->posts_table );

		if ( is_string( $paired ) && '' !== $paired ) {
			return $paired;
		}

		return (string) $GLOBALS['wpdb']->users;
	}

	/**
	 * Initialize empty section payloads.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private function empty_sections() {
		$sections = array();
		$meta     = Choctaw_Wp_Security_Posts_Scan_Patterns::get_section_meta();

		foreach ( Choctaw_Wp_Security_Posts_Scan_Patterns::$section_keys as $section_key ) {
			$sections[ $section_key ] = array(
				'title'        => $meta[ $section_key ]['title'],
				'guidance'     => $meta[ $section_key ]['guidance'],
				'findings'     => array(),
				'truncated'    => 0,
				'info_message' => '',
			);
		}

		return $sections;
	}

	/**
	 * Scan for PHP tags and execution patterns.
	 *
	 * @param array<int, array<string, mixed>> $findings Findings list.
	 * @return void
	 */
	private function scan_php_execution_patterns( array &$findings ) {
		$patterns = array_merge(
			Choctaw_Wp_Security_Posts_Scan_Patterns::$php_tag_patterns,
			Choctaw_Wp_Security_Posts_Scan_Patterns::$execution_patterns
		);

		$this->scan_content_patterns( $patterns, $findings, 'php_execution_patterns', 'critical' );
	}

	/**
	 * Scan for generic script and iframe patterns.
	 *
	 * @param array<int, array<string, mixed>> $findings Findings list.
	 * @return void
	 */
	private function scan_script_iframe_injection( array &$findings ) {
		$this->scan_content_patterns(
			Choctaw_Wp_Security_Posts_Scan_Patterns::$script_patterns,
			$findings,
			'script_iframe_injection',
			'warning'
		);
	}

	/**
	 * Scan for higher-confidence script injection patterns.
	 *
	 * @param array<int, array<string, mixed>> $findings Findings list.
	 * @return void
	 */
	private function scan_high_confidence_scripts( array &$findings ) {
		$this->scan_content_patterns(
			Choctaw_Wp_Security_Posts_Scan_Patterns::$high_confidence_script_patterns,
			$findings,
			'high_confidence_scripts',
			'warning'
		);
	}

	/**
	 * Scan published post titles for SEO spam keywords.
	 *
	 * @param array<int, array<string, mixed>> $findings Findings list.
	 * @return void
	 */
	private function scan_seo_spam_titles( array &$findings ) {
		global $wpdb;

		if ( $this->is_time_exceeded() ) {
			$this->scan_incomplete = true;
			return;
		}

		$keywords = Choctaw_Wp_Security_Posts_Scan_Patterns::$seo_spam_keywords;

		if ( empty( $keywords ) ) {
			return;
		}

		$table         = $this->get_posts_table_sql();
		$where_clauses = array();
		$where_values  = array();

		foreach ( $keywords as $keyword ) {
			$where_clauses[] = 'post_title LIKE %s';
			$where_values[]  = '%' . $wpdb->esc_like( $keyword ) . '%';
		}

		$sql = 'SELECT ID, post_author, post_title, post_type, post_status, LENGTH(post_content) AS content_size
			FROM ' . $table . '
			WHERE post_status = %s
			AND (' . implode( ' OR ', $where_clauses ) . ')';

		$args = array_merge( array( $sql, 'publish' ), $where_values );
		$rows = $wpdb->get_results( call_user_func_array( array( $wpdb, 'prepare' ), $args ), ARRAY_A );

		if ( ! is_array( $rows ) ) {
			return;
		}

		foreach ( $rows as $row ) {
			if ( $this->is_time_exceeded() ) {
				$this->scan_incomplete = true;
				break;
			}

			$post_title = isset( $row['post_title'] ) ? (string) $row['post_title'] : '';
			$matched    = $this->find_matching_pattern( $post_title, $keywords );

			if ( '' === $matched ) {
				continue;
			}

			$findings[] = $this->make_finding(
				'seo_spam_title_match',
				'warning',
				$row,
				isset( $row['content_size'] ) ? (int) $row['content_size'] : 0,
				sprintf(
					/* translators: %s: matched keyword */
					__( 'Matched spam keyword: %s', 'choctaw-wp-security' ),
					$matched
				),
				$post_title
			);
		}
	}

	/**
	 * Scan for unusually large post content rows.
	 *
	 * @param array<int, array<string, mixed>> $findings Findings list.
	 * @return void
	 */
	private function scan_large_post_content( array &$findings ) {
		global $wpdb;

		if ( $this->is_time_exceeded() ) {
			$this->scan_incomplete = true;
			return;
		}

		$table = $this->get_posts_table_sql();
		$threshold = (int) Choctaw_Wp_Security_Posts_Scan_Patterns::CONTENT_SIZE_THRESHOLD;
		$sql   = 'SELECT ID, post_author, post_title, post_type, post_status,
				LENGTH(post_content) AS content_size,
				LEFT(post_content, %d) AS content_excerpt
			FROM ' . $table . '
			WHERE ' . $this->get_content_scan_exclusion_sql() . '
			AND post_content != %s
			AND LENGTH(post_content) >= %d
			ORDER BY content_size DESC
			LIMIT %d';

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				$sql,
				Choctaw_Wp_Security_Posts_Scan_Patterns::LARGE_CONTENT_PREVIEW_LENGTH,
				'',
				$threshold,
				Choctaw_Wp_Security_Posts_Scan_Patterns::LARGE_CONTENT_TOP_LIMIT
			),
			ARRAY_A
		);

		if ( ! is_array( $rows ) ) {
			return;
		}

		foreach ( $rows as $row ) {
			$content_size = isset( $row['content_size'] ) ? (int) $row['content_size'] : 0;

			$findings[] = $this->make_finding(
				'large_post_content',
				'warning',
				$row,
				$content_size,
				sprintf(
					/* translators: %s: formatted content size */
					__( 'Post content size: %s', 'choctaw-wp-security' ),
					size_format( $content_size )
				),
				isset( $row['content_excerpt'] ) ? (string) $row['content_excerpt'] : ''
			);
		}
	}

	/**
	 * Compare current posts against a stored baseline snapshot.
	 *
	 * @param array<string, mixed>      $section  Section payload.
	 * @param array<string, mixed>|null $baseline Prior baseline.
	 * @return void
	 */
	private function scan_baseline_diff( array &$section, $baseline ) {
		$baseline_table = ( is_array( $baseline ) && isset( $baseline['posts_table'] ) ) ? (string) $baseline['posts_table'] : '';

		if ( $this->is_baseline_uninitialized( $baseline ) ) {
			if ( '' !== $baseline_table && $baseline_table !== $this->posts_table ) {
				$section['info_message'] = sprintf(
					/* translators: 1: previous posts table, 2: selected posts table */
					__( 'Baseline was captured for %1$s. Establishing a new baseline for %2$s.', 'choctaw-wp-security' ),
					$baseline_table,
					$this->posts_table
				);
			} else {
				$section['info_message'] = __( 'Baseline established. Future scans will report posts that are new or changed since this scan.', 'choctaw-wp-security' );
			}
			return;
		}

		if ( empty( $baseline ) || ! isset( $baseline['posts'] ) || ! is_array( $baseline['posts'] ) ) {
			$section['info_message'] = __( 'Baseline established. Future scans will report posts that are new or changed since this scan.', 'choctaw-wp-security' );
			return;
		}

		$current  = $this->capture_baseline_snapshot();
		$previous = $baseline['posts'];
		$findings = array();

		foreach ( $current['posts'] as $post_id => $meta ) {
			if ( ! isset( $previous[ $post_id ] ) ) {
				$findings[] = $this->make_baseline_finding( 'new', $post_id, $meta, 0, isset( $meta['size'] ) ? (int) $meta['size'] : 0 );
				continue;
			}

			$old_hash = isset( $previous[ $post_id ]['hash'] ) ? (string) $previous[ $post_id ]['hash'] : '';
			$new_hash = isset( $meta['hash'] ) ? (string) $meta['hash'] : '';

			if ( $old_hash !== $new_hash ) {
				$findings[] = $this->make_baseline_finding(
					'changed',
					$post_id,
					$meta,
					isset( $previous[ $post_id ]['size'] ) ? (int) $previous[ $post_id ]['size'] : 0,
					isset( $meta['size'] ) ? (int) $meta['size'] : 0
				);
			}
		}

		foreach ( $previous as $post_id => $meta ) {
			if ( ! isset( $current['posts'][ $post_id ] ) ) {
				$findings[] = $this->make_baseline_finding(
					'removed',
					(int) $post_id,
					$meta,
					isset( $meta['size'] ) ? (int) $meta['size'] : 0,
					0
				);
			}
		}

		$section['findings'] = $findings;
	}

	/**
	 * Run pattern scans against post content and excerpt fields.
	 *
	 * @param array<int, string>             $patterns          Patterns to search.
	 * @param array<int, array<string, mixed>> $findings          Findings list.
	 * @param string                         $finding_id_prefix Finding ID prefix.
	 * @param string                         $severity          Default severity.
	 * @return void
	 */
	private function scan_content_patterns( array $patterns, array &$findings, $finding_id_prefix, $severity ) {
		global $wpdb;

		if ( empty( $patterns ) || $this->is_time_exceeded() ) {
			if ( $this->is_time_exceeded() ) {
				$this->scan_incomplete = true;
			}
			return;
		}

		$table         = $this->get_posts_table_sql();
		$where_clauses = array();
		$where_values  = array();

		foreach ( $patterns as $pattern ) {
			$where_clauses[] = 'post_content LIKE %s';
			$where_values[]  = '%' . $wpdb->esc_like( $pattern ) . '%';
			$where_clauses[] = 'post_excerpt LIKE %s';
			$where_values[]  = '%' . $wpdb->esc_like( $pattern ) . '%';
		}

		$sql = 'SELECT ID, post_author, post_title, post_type, post_status,
				LENGTH(post_content) AS content_size, post_content, post_excerpt
			FROM ' . $table . '
			WHERE ' . $this->get_content_scan_exclusion_sql() . '
			AND (post_content != %s OR post_excerpt != %s)
			AND (' . implode( ' OR ', $where_clauses ) . ')';

		$args = array_merge( array( $sql, '', '' ), $where_values );
		$rows = $wpdb->get_results( call_user_func_array( array( $wpdb, 'prepare' ), $args ), ARRAY_A );

		if ( ! is_array( $rows ) ) {
			return;
		}

		$seen = array();

		foreach ( $rows as $row ) {
			if ( $this->is_time_exceeded() ) {
				$this->scan_incomplete = true;
				break;
			}

			$post_id = isset( $row['ID'] ) ? (int) $row['ID'] : 0;

			if ( $post_id <= 0 || isset( $seen[ $post_id ] ) ) {
				continue;
			}

			$post_content = isset( $row['post_content'] ) ? (string) $row['post_content'] : '';
			$post_excerpt = isset( $row['post_excerpt'] ) ? (string) $row['post_excerpt'] : '';
			$matched      = $this->find_matching_pattern( $post_content, $patterns );
			$value        = $post_content;
			$field_label  = 'post_content';

			if ( '' === $matched ) {
				$matched     = $this->find_matching_pattern( $post_excerpt, $patterns );
				$value       = $post_excerpt;
				$field_label = 'post_excerpt';
			}

			if ( '' === $matched ) {
				continue;
			}

			$seen[ $post_id ] = true;

			$findings[] = $this->make_finding(
				$finding_id_prefix . '_match',
				$severity,
				$row,
				isset( $row['content_size'] ) ? (int) $row['content_size'] : strlen( $post_content ),
				sprintf(
					/* translators: 1: matched pattern, 2: field name */
					__( 'Matched pattern: %1$s (%2$s)', 'choctaw-wp-security' ),
					$matched,
					$field_label
				),
				$this->extract_excerpt( $value, $matched )
			);
		}
	}

	/**
	 * Build SQL exclusions for content scans.
	 *
	 * @return string
	 */
	private function get_content_scan_exclusion_sql() {
		global $wpdb;

		$sql = '1=1';

		foreach ( Choctaw_Wp_Security_Posts_Scan_Patterns::$excluded_post_types as $post_type ) {
			$sql .= $wpdb->prepare( ' AND post_type != %s', $post_type );
		}

		foreach ( Choctaw_Wp_Security_Posts_Scan_Patterns::$excluded_post_statuses as $post_status ) {
			$sql .= $wpdb->prepare( ' AND post_status != %s', $post_status );
		}

		return $sql;
	}

	/**
	 * Capture a baseline snapshot of wp_posts rows.
	 *
	 * @return array<string, mixed>
	 */
	private function capture_baseline_snapshot() {
		global $wpdb;

		$table = $this->get_posts_table_sql();
		$rows  = $wpdb->get_results(
			'SELECT ID, post_author, post_title, post_type, post_status, post_content
			FROM ' . $table . '
			WHERE ' . $this->get_content_scan_exclusion_sql(),
			ARRAY_A
		);

		$posts = array();

		if ( is_array( $rows ) ) {
			foreach ( $rows as $row ) {
				$post_id = isset( $row['ID'] ) ? (int) $row['ID'] : 0;

				if ( $post_id <= 0 ) {
					continue;
				}

				$content = isset( $row['post_content'] ) ? (string) $row['post_content'] : '';

				$posts[ $post_id ] = array(
					'hash'       => md5( $content ),
					'size'       => strlen( $content ),
					'post_title' => isset( $row['post_title'] ) ? (string) $row['post_title'] : '',
					'post_type'  => isset( $row['post_type'] ) ? (string) $row['post_type'] : '',
					'post_status'=> isset( $row['post_status'] ) ? (string) $row['post_status'] : '',
					'user_id'    => isset( $row['post_author'] ) ? (int) $row['post_author'] : 0,
				);
			}
		}

		return array(
			'posts_table' => $this->posts_table,
			'captured_at' => gmdate( 'Y-m-d H:i:s' ),
			'posts'       => $posts,
		);
	}

	/**
	 * Load a stored baseline snapshot.
	 *
	 * @return array<string, mixed>|null
	 */
	private function load_baseline() {
		$baseline = get_option( Choctaw_Wp_Security_Posts_Scan_Patterns::BASELINE_OPTION_KEY, null );

		return is_array( $baseline ) ? $baseline : null;
	}

	/**
	 * Save a baseline snapshot.
	 *
	 * @param array<string, mixed> $snapshot Snapshot payload.
	 * @return bool
	 */
	private function save_baseline( array $snapshot ) {
		return update_option(
			Choctaw_Wp_Security_Posts_Scan_Patterns::BASELINE_OPTION_KEY,
			$snapshot,
			false
		);
	}

	/**
	 * Build severity summary counts.
	 *
	 * @param array<string, array<string, mixed>> $sections Section payloads.
	 * @return array<string, int>
	 */
	private function build_summary( array $sections ) {
		$summary = array(
			'critical' => 0,
			'warning'  => 0,
			'info'     => 0,
		);

		foreach ( $sections as $section ) {
			if ( empty( $section['findings'] ) || ! is_array( $section['findings'] ) ) {
				continue;
			}

			foreach ( $section['findings'] as $finding ) {
				$severity = isset( $finding['severity'] ) ? (string) $finding['severity'] : 'info';

				if ( ! isset( $summary[ $severity ] ) ) {
					$summary['info']++;
					continue;
				}

				$summary[ $severity ]++;
			}
		}

		return $summary;
	}

	/**
	 * Look up a user's display name with caching.
	 *
	 * @param int $user_id User ID.
	 * @return string
	 */
	private function get_user_display_name( $user_id ) {
		$user_id = (int) $user_id;

		if ( $user_id <= 0 ) {
			return '';
		}

		if ( isset( $this->user_display_names[ $user_id ] ) ) {
			return $this->user_display_names[ $user_id ];
		}

		global $wpdb;

		$users_table = $this->discovery->quote_table_name( $this->users_table );
		$display_name = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT display_name FROM {$users_table} WHERE ID = %d LIMIT 1",
				$user_id
			)
		);

		$this->user_display_names[ $user_id ] = is_string( $display_name ) ? $display_name : '';

		return $this->user_display_names[ $user_id ];
	}

	/**
	 * Find the first matching pattern in a value.
	 *
	 * @param string             $value    Value to inspect.
	 * @param array<int, string> $patterns Patterns to search.
	 * @return string
	 */
	private function find_matching_pattern( $value, array $patterns ) {
		foreach ( $patterns as $pattern ) {
			if ( false !== stripos( $value, $pattern ) ) {
				return $pattern;
			}
		}

		return '';
	}

	/**
	 * Build a standardized finding payload.
	 *
	 * @param string               $id       Finding ID.
	 * @param string               $severity Severity level.
	 * @param array<string, mixed> $row      Post row data.
	 * @param int                  $size     Content size.
	 * @param string               $detail   Human-readable detail.
	 * @param string               $excerpt  Value excerpt.
	 * @return array<string, mixed>
	 */
	private function make_finding( $id, $severity, array $row, $size, $detail, $excerpt = '' ) {
		$user_id = isset( $row['post_author'] ) ? (int) $row['post_author'] : 0;

		return array(
			'id'                => $id,
			'severity'          => $severity,
			'post_id'           => isset( $row['ID'] ) ? (int) $row['ID'] : 0,
			'user_id'           => $user_id,
			'user_display_name' => $this->get_user_display_name( $user_id ),
			'post_title'        => isset( $row['post_title'] ) ? (string) $row['post_title'] : '',
			'post_type'         => isset( $row['post_type'] ) ? (string) $row['post_type'] : '',
			'post_status'       => isset( $row['post_status'] ) ? (string) $row['post_status'] : '',
			'size'              => (int) $size,
			'detail'            => $detail,
			'excerpt'           => $this->trim_excerpt( $excerpt ),
		);
	}

	/**
	 * Build a baseline diff finding payload.
	 *
	 * @param string               $change_type Change type.
	 * @param int                  $post_id     Post ID.
	 * @param array<string, mixed> $meta        Post metadata.
	 * @param int                  $old_size    Previous size.
	 * @param int                  $new_size    Current size.
	 * @return array<string, mixed>
	 */
	private function make_baseline_finding( $change_type, $post_id, array $meta, $old_size, $new_size ) {
		$user_id = isset( $meta['user_id'] ) ? (int) $meta['user_id'] : 0;
		$detail  = '';

		if ( 'new' === $change_type ) {
			$detail = sprintf(
				/* translators: %s: formatted content size */
				__( 'New post (size: %s)', 'choctaw-wp-security' ),
				size_format( $new_size )
			);
		} elseif ( 'changed' === $change_type ) {
			$detail = sprintf(
				/* translators: 1: old size, 2: new size */
				__( 'Changed post (was %1$s, now %2$s)', 'choctaw-wp-security' ),
				size_format( $old_size ),
				size_format( $new_size )
			);
		} else {
			$detail = sprintf(
				/* translators: %s: formatted content size */
				__( 'Removed post (was %s)', 'choctaw-wp-security' ),
				size_format( $old_size )
			);
		}

		return array(
			'id'                => 'baseline_' . $change_type,
			'severity'          => 'info',
			'post_id'           => (int) $post_id,
			'user_id'           => $user_id,
			'user_display_name' => $this->get_user_display_name( $user_id ),
			'post_title'        => isset( $meta['post_title'] ) ? (string) $meta['post_title'] : '',
			'post_type'         => isset( $meta['post_type'] ) ? (string) $meta['post_type'] : '',
			'post_status'       => isset( $meta['post_status'] ) ? (string) $meta['post_status'] : '',
			'size'              => (int) $new_size,
			'detail'            => $detail,
			'excerpt'           => ucfirst( $change_type ),
			'change_type'       => $change_type,
			'old_size'          => (int) $old_size,
			'new_size'          => (int) $new_size,
		);
	}

	/**
	 * Extract an excerpt around a matched pattern.
	 *
	 * @param string $value   Full value.
	 * @param string $pattern Matched pattern.
	 * @return string
	 */
	private function extract_excerpt( $value, $pattern ) {
		$position = stripos( $value, $pattern );

		if ( false === $position ) {
			return $this->trim_excerpt( $value );
		}

		$start = max( 0, $position - 40 );

		return $this->trim_excerpt( substr( $value, $start, Choctaw_Wp_Security_Posts_Scan_Patterns::EXCERPT_LENGTH ) );
	}

	/**
	 * Trim and normalize an excerpt string.
	 *
	 * @param string $excerpt Raw excerpt.
	 * @return string
	 */
	private function trim_excerpt( $excerpt ) {
		$excerpt = wp_strip_all_tags( (string) $excerpt );
		$excerpt = preg_replace( '/\s+/', ' ', $excerpt );

		if ( ! is_string( $excerpt ) ) {
			return '';
		}

		if ( strlen( $excerpt ) > Choctaw_Wp_Security_Posts_Scan_Patterns::EXCERPT_LENGTH ) {
			$excerpt = substr( $excerpt, 0, Choctaw_Wp_Security_Posts_Scan_Patterns::EXCERPT_LENGTH ) . '...';
		}

		return trim( $excerpt );
	}

	/**
	 * Determine whether the scan time budget has been exceeded.
	 *
	 * @return bool
	 */
	private function is_time_exceeded() {
		$elapsed = microtime( true ) - $this->start_time;

		return $elapsed >= (float) Choctaw_Wp_Security_Posts_Scan_Patterns::SCAN_TIME_BUDGET;
	}
}
