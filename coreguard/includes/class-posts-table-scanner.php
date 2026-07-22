<?php
/**
 * wp_posts table scanner (Sassh Findings producer).
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Scans a WordPress posts table for compromise indicators and records
 * Sassh Findings observations for the mapped registered-site blog_id.
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
	 * Count of candidate rows that could not be fingerprinted.
	 *
	 * @var int
	 */
	private $hash_failures = 0;

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
	 * Accumulator: post_id => draft observation (fields + categories by rule_id).
	 *
	 * @var array<int, array<string, mixed>>
	 */
	private $post_drafts = array();

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
		$this->posts_table = $this->discovery->resolve_scan_table( $posts_table );
		$this->users_table = $this->resolve_users_table();
	}

	/**
	 * Run the wp_posts scan and persist observations via Sassh Findings.
	 *
	 * @return array<string, mixed>
	 */
	public function scan() {
		Sassh_Findings_Schema::maybe_upgrade();

		$this->start_time      = microtime( true );
		$this->scan_incomplete = false;
		$this->hash_failures   = 0;
		$this->post_drafts     = array();

		$blog_id = Sassh_Post_Key_Normalizer::map_posts_table_to_registered_site_blog_id( $this->posts_table );

		if ( is_wp_error( $blog_id ) ) {
			return $this->build_rejection_report( $blog_id );
		}

		$blog_id = (int) $blog_id;

		$scope_key    = Sassh_Findings_Service::wp_posts_scope_key( $this->posts_table );
		$service      = new Sassh_Findings_Service();
		$execution_id = $service->begin_scanner_execution(
			Sassh_Findings_Service::SCANNER_WP_POSTS,
			array(
				'scope_key'  => $scope_key,
				'run_type'   => 'individual',
				'run_source' => 'wordpress_admin',
				'meta'       => array(
					'posts_table'                => $this->posts_table,
					'wordpress_configured_table' => Choctaw_Wp_Security_Posts_Table_Discovery::get_wordpress_configured_table(),
					'blog_id'                    => $blog_id,
				),
			)
		);

		$this->scan_php_execution_patterns( $blog_id );
		$this->scan_scripts( $blog_id );
		$this->scan_seo_spam_titles( $blog_id );
		$this->scan_large_post_content( $blog_id );

		$observations = $this->build_observations_from_drafts( $blog_id );
		$service->record_observations( $execution_id, $observations );

		$errors            = array();
		$completion_status = 'success';

		if ( $this->scan_incomplete ) {
			$completion_status = 'partial';
			$errors[]          = __( 'Scan stopped before completing every check due to the time budget. Previously detected findings were not cleared.', 'choctaw-wp-security' );
		}

		if ( $this->hash_failures > 0 ) {
			$completion_status = 'partial';
			$errors[]          = __( 'One or more posts could not be fingerprinted.', 'choctaw-wp-security' );
		}

		$ok = $service->finalize_scanner_execution( $execution_id, $completion_status );

		if ( 'success' === $completion_status && ! $ok ) {
			$completion_status = 'failed';
			$errors[]          = __( 'The scan could not be finalized.', 'choctaw-wp-security' );
		}

		return $this->build_report_from_findings(
			$service,
			$execution_id,
			array(
				'completion_status' => $completion_status,
				'scan_incomplete'   => 'success' !== $completion_status,
				'errors'            => $errors,
			)
		);
	}

	/**
	 * No-op. Baseline snapshots are no longer written by the Findings producer;
	 * the legacy baseline option is left orphaned in place.
	 *
	 * @param string $posts_table Requested posts table name (unused).
	 * @return bool Always false.
	 */
	public static function reset_baseline( $posts_table = '' ) {
		return false;
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
	 * Build the rejection payload for an unmappable posts table.
	 *
	 * @param WP_Error $error Mapping error.
	 * @return array<string, mixed>
	 */
	private function build_rejection_report( WP_Error $error ) {
		$message = $error->get_error_message();

		if ( '' === $message ) {
			$message = __( 'The selected posts table is not associated with a registered WordPress site.', 'choctaw-wp-security' );
		}

		return array(
			'success'                    => false,
			'rejected'                   => true,
			'findings_backend'           => 'sassh',
			'errors'                     => array( $message ),
			'findings'                   => array(),
			'summary'                    => array(
				'critical'   => 0,
				'warning'    => 0,
				'suspicious' => 0,
				'safe'       => 0,
				'info'       => 0,
				'total'      => 0,
				'flagged'    => 0,
			),
			'posts_table'                => $this->posts_table,
			'wordpress_configured_table' => Choctaw_Wp_Security_Posts_Table_Discovery::get_wordpress_configured_table(),
			'scan_incomplete'            => false,
			'coverage_complete'          => false,
			'absence_reconciled'         => false,
			'completion_status'          => 'rejected',
			'confirmed_this_run'         => 0,
			'scanned_at'                 => time(),
		);
	}

	/**
	 * Scan for PHP tags and execution patterns.
	 *
	 * @param int $blog_id Mapped blog id.
	 * @return void
	 */
	private function scan_php_execution_patterns( $blog_id ) {
		$patterns = array_merge(
			Choctaw_Wp_Security_Posts_Scan_Patterns::$php_tag_patterns,
			Choctaw_Wp_Security_Posts_Scan_Patterns::$execution_patterns
		);

		$this->scan_content_patterns(
			$patterns,
			$blog_id,
			Sassh_Findings_Service::RULE_POST_PHP_EXECUTION_PATTERNS_MATCH,
			'php_execution_patterns'
		);
	}

	/**
	 * Scan for script/iframe patterns (high-confidence preferred over generic).
	 *
	 * @param int $blog_id Mapped blog id.
	 * @return void
	 */
	private function scan_scripts( $blog_id ) {
		$this->scan_content_patterns(
			Choctaw_Wp_Security_Posts_Scan_Patterns::$high_confidence_script_patterns,
			$blog_id,
			Sassh_Findings_Service::RULE_POST_SCRIPTS_HIGH_CONFIDENCE,
			'scripts'
		);

		$this->scan_content_patterns(
			Choctaw_Wp_Security_Posts_Scan_Patterns::$script_patterns,
			$blog_id,
			Sassh_Findings_Service::RULE_POST_SCRIPTS_GENERIC,
			'scripts',
			true
		);
	}

	/**
	 * Scan published post titles for SEO spam keywords.
	 *
	 * @param int $blog_id Mapped blog id.
	 * @return void
	 */
	private function scan_seo_spam_titles( $blog_id ) {
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

		$sql = 'SELECT ID, post_author, post_title, post_type, post_status, post_content, post_excerpt,
				LENGTH(post_content) AS content_size
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
			$matched    = $this->find_all_matching_patterns( $post_title, $keywords );

			if ( empty( $matched ) ) {
				continue;
			}

			$rule_id    = Sassh_Findings_Service::RULE_POST_SEO_SPAM_TITLE;
			$risk_level = Sassh_Findings_Service::wp_posts_risk_level( $rule_id );
			$category_fp = Sassh_Post_Key_Normalizer::seo_category_fingerprint( $post_title, $matched );

			$this->add_category_to_draft(
				$row,
				$blog_id,
				$rule_id,
				'seo_spam_titles',
				$risk_level,
				$category_fp,
				sprintf(
					/* translators: %s: matched keyword list */
					__( 'Matched spam keyword: %s', 'choctaw-wp-security' ),
					implode( ', ', $matched )
				),
				array(
					'matched_field'    => 'post_title',
					'matched_patterns' => $matched,
					'matched_snippet'  => $post_title,
					'excerpt'          => $this->trim_excerpt( $post_title ),
					'contents_truncated' => false,
				)
			);
		}
	}

	/**
	 * Scan for unusually large post content in ID-ordered batches (full coverage).
	 *
	 * @param int $blog_id Mapped blog id.
	 * @return void
	 */
	private function scan_large_post_content( $blog_id ) {
		global $wpdb;

		$threshold = (int) Choctaw_Wp_Security_Posts_Scan_Patterns::CONTENT_SIZE_THRESHOLD;
		$batch     = (int) Choctaw_Wp_Security_Posts_Scan_Patterns::LARGE_CONTENT_BATCH_SIZE;
		$last_id   = 0;
		$table     = $this->get_posts_table_sql();

		if ( $batch <= 0 ) {
			$batch = 50;
		}

		while ( true ) {
			if ( $this->is_time_exceeded() ) {
				$this->scan_incomplete = true;
				return;
			}

			$sql = 'SELECT ID, post_author, post_title, post_type, post_status, post_content, post_excerpt,
					LENGTH(post_content) AS content_size
				FROM ' . $table . '
				WHERE ' . $this->get_content_scan_exclusion_sql() . '
				AND post_content != %s
				AND LENGTH(post_content) >= %d
				AND ID > %d
				ORDER BY ID ASC
				LIMIT %d';

			$rows = $wpdb->get_results(
				$wpdb->prepare(
					$sql,
					'',
					$threshold,
					$last_id,
					$batch
				),
				ARRAY_A
			);

			if ( ! is_array( $rows ) || empty( $rows ) ) {
				return;
			}

			foreach ( $rows as $row ) {
				if ( $this->is_time_exceeded() ) {
					$this->scan_incomplete = true;
					return;
				}

				$post_id = isset( $row['ID'] ) ? (int) $row['ID'] : 0;
				if ( $post_id > $last_id ) {
					$last_id = $post_id;
				}

				$content_size = isset( $row['content_size'] ) ? (int) $row['content_size'] : 0;
				$post_content = isset( $row['post_content'] ) ? (string) $row['post_content'] : '';
				$rule_id      = Sassh_Findings_Service::RULE_POST_LARGE_CONTENT;
				$risk_level   = Sassh_Findings_Service::wp_posts_risk_level( $rule_id );
				$category_fp  = Sassh_Post_Key_Normalizer::large_content_category_fingerprint( $content_size, $post_content );
				$preview      = Choctaw_Wp_Security_Utils::truncate_report_contents_result(
					$post_content,
					Choctaw_Wp_Security_Posts_Scan_Patterns::MATCHED_SNIPPET_LENGTH
				);

				$this->add_category_to_draft(
					$row,
					$blog_id,
					$rule_id,
					'large_post_content',
					$risk_level,
					$category_fp,
					sprintf(
						/* translators: %s: formatted content size */
						__( 'Post content size: %s', 'choctaw-wp-security' ),
						size_format( $content_size )
					),
					array(
						'matched_field'      => 'post_content',
						'matched_patterns'   => array(),
						'matched_snippet'    => $preview['contents'],
						'excerpt'            => $this->trim_excerpt( $preview['contents'] ),
						'contents_truncated' => ! empty( $preview['truncated'] ),
					)
				);
			}

			if ( count( $rows ) < $batch ) {
				return;
			}
		}
	}

	/**
	 * Run pattern scans against post content and excerpt fields.
	 *
	 * @param array<int, string> $patterns           Patterns to search.
	 * @param int                $blog_id            Mapped blog id.
	 * @param string             $rule_id            Rule id.
	 * @param string             $section_key        UI section key.
	 * @param bool               $skip_if_same_family When true, skip if a scripts high-confidence category already exists.
	 * @return void
	 */
	private function scan_content_patterns( array $patterns, $blog_id, $rule_id, $section_key, $skip_if_same_family = false ) {
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

		foreach ( $rows as $row ) {
			if ( $this->is_time_exceeded() ) {
				$this->scan_incomplete = true;
				break;
			}

			$post_id = isset( $row['ID'] ) ? (int) $row['ID'] : 0;

			if ( $post_id <= 0 ) {
				continue;
			}

			if ( $skip_if_same_family && isset( $this->post_drafts[ $post_id ]['categories'][ Sassh_Findings_Service::RULE_POST_SCRIPTS_HIGH_CONFIDENCE ] ) ) {
				continue;
			}

			$post_content = isset( $row['post_content'] ) ? (string) $row['post_content'] : '';
			$post_excerpt = isset( $row['post_excerpt'] ) ? (string) $row['post_excerpt'] : '';
			$content_hits = $this->find_all_matching_patterns( $post_content, $patterns );
			$excerpt_hits = $this->find_all_matching_patterns( $post_excerpt, $patterns );
			$matched      = array_values( array_unique( array_merge( $content_hits, $excerpt_hits ) ) );

			if ( empty( $matched ) ) {
				continue;
			}

			$field_label = ! empty( $content_hits ) ? 'post_content' : 'post_excerpt';
			$field_value = 'post_content' === $field_label ? $post_content : $post_excerpt;
			// Fingerprint both fields when both contributed; otherwise the matched field.
			$fp_value = ! empty( $content_hits ) && ! empty( $excerpt_hits )
				? self::length_prefixed_pair( $post_content, $post_excerpt )
				: $field_value;

			$evidence = array(
				'matched_patterns' => $matched,
			);

			if ( Sassh_Findings_Service::RULE_POST_PHP_EXECUTION_PATTERNS_MATCH === $rule_id ) {
				$evidence['php_tag_patterns']          = Choctaw_Wp_Security_Posts_Scan_Patterns::$php_tag_patterns;
				$evidence['high_specificity_patterns'] = Choctaw_Wp_Security_Posts_Scan_Patterns::high_specificity_execution_patterns();
				$evidence['low_specificity_patterns']  = Choctaw_Wp_Security_Posts_Scan_Patterns::low_specificity_execution_patterns();
			}

			$risk_level  = Sassh_Findings_Service::wp_posts_risk_level( $rule_id, $evidence );
			$category_fp = Sassh_Post_Key_Normalizer::pattern_category_fingerprint( $fp_value, $matched );
			$primary     = $matched[0];
			$snippet     = $this->extract_matched_snippet( $field_value, $primary );

			$this->add_category_to_draft(
				$row,
				$blog_id,
				$rule_id,
				$section_key,
				$risk_level,
				$category_fp,
				sprintf(
					/* translators: 1: matched patterns, 2: field name */
					__( 'Matched pattern: %1$s (%2$s)', 'choctaw-wp-security' ),
					implode( ', ', $matched ),
					$field_label
				),
				array(
					'matched_field'      => $field_label,
					'matched_patterns'   => $matched,
					'matched_snippet'    => $snippet['contents'],
					'excerpt'            => $this->extract_excerpt( $field_value, $primary ),
					'contents_truncated' => ! empty( $snippet['truncated'] ),
				)
			);
		}
	}

	/**
	 * Ensure a draft exists and attach a category.
	 *
	 * @param array<string, mixed> $row         Post row.
	 * @param int                  $blog_id     Blog id.
	 * @param string               $rule_id     Rule id.
	 * @param string               $section_key Section key.
	 * @param string               $risk_level  Risk.
	 * @param string               $category_fp Category fingerprint.
	 * @param string               $detail      Detail sentence.
	 * @param array<string, mixed> $extra       Extra category metadata.
	 * @return void
	 */
	private function add_category_to_draft( array $row, $blog_id, $rule_id, $section_key, $risk_level, $category_fp, $detail, array $extra ) {
		$post_id = isset( $row['ID'] ) ? (int) $row['ID'] : 0;

		if ( $post_id <= 0 || '' === $category_fp ) {
			if ( $post_id > 0 && '' === $category_fp ) {
				++$this->hash_failures;
			}
			return;
		}

		$object_key = Sassh_Post_Key_Normalizer::object_key_for_post_id( $post_id );

		if ( is_wp_error( $object_key ) ) {
			++$this->hash_failures;
			return;
		}

		if ( ! isset( $this->post_drafts[ $post_id ] ) ) {
			$user_id = isset( $row['post_author'] ) ? (int) $row['post_author'] : 0;

			$this->post_drafts[ $post_id ] = array(
				'object_key'        => $object_key,
				'blog_id'           => (int) $blog_id,
				'post_id'           => $post_id,
				'user_id'           => $user_id,
				'user_display_name' => $this->get_user_display_name( $user_id ),
				'post_title'        => isset( $row['post_title'] ) ? (string) $row['post_title'] : '',
				'post_type'         => isset( $row['post_type'] ) ? (string) $row['post_type'] : '',
				'post_status'       => isset( $row['post_status'] ) ? (string) $row['post_status'] : '',
				'post_content'      => isset( $row['post_content'] ) ? (string) $row['post_content'] : '',
				'post_excerpt'      => isset( $row['post_excerpt'] ) ? (string) $row['post_excerpt'] : '',
				'size'              => isset( $row['content_size'] ) ? (int) $row['content_size'] : ( isset( $row['post_content'] ) ? strlen( (string) $row['post_content'] ) : 0 ),
				'categories'        => array(),
			);
		} else {
			// Prefer fuller row data when later sections include content fields.
			if ( isset( $row['post_content'] ) && '' === $this->post_drafts[ $post_id ]['post_content'] ) {
				$this->post_drafts[ $post_id ]['post_content'] = (string) $row['post_content'];
			}
			if ( isset( $row['post_excerpt'] ) && '' === $this->post_drafts[ $post_id ]['post_excerpt'] ) {
				$this->post_drafts[ $post_id ]['post_excerpt'] = (string) $row['post_excerpt'];
			}
			if ( isset( $row['content_size'] ) ) {
				$this->post_drafts[ $post_id ]['size'] = (int) $row['content_size'];
			}
		}

		$labels   = Choctaw_Wp_Security_Posts_Scan_Patterns::get_category_labels();
		$guidance = $this->guidance_contributions_for_rule( $rule_id, $risk_level );

		$this->post_drafts[ $post_id ]['categories'][ $rule_id ] = array(
			'rule_id'                => $rule_id,
			'risk_level'             => $risk_level,
			'sassh_classification'   => Sassh_Findings_Service::default_classification( $risk_level ),
			'category_fingerprint'   => $category_fp,
			'title'                  => $rule_id,
			'metadata'               => array_merge(
				array(
					'section_key'    => $section_key,
					'category'       => $section_key,
					'category_label' => isset( $labels[ $section_key ] ) ? $labels[ $section_key ] : $section_key,
					'detail'         => $detail,
					'posts_table'    => $this->posts_table,
				),
				$extra
			),
			'guidance_contributions' => $guidance,
		);

		// Keep primary detail/snippet at draft level from highest-risk category later.
		if ( ! isset( $this->post_drafts[ $post_id ]['detail'] ) || $this->risk_rank( $risk_level ) >= $this->risk_rank( isset( $this->post_drafts[ $post_id ]['primary_risk'] ) ? $this->post_drafts[ $post_id ]['primary_risk'] : 'info' ) ) {
			$this->post_drafts[ $post_id ]['detail']       = $detail;
			$this->post_drafts[ $post_id ]['primary_risk'] = $risk_level;
			if ( isset( $extra['matched_snippet'] ) ) {
				$this->post_drafts[ $post_id ]['matched_snippet']    = $extra['matched_snippet'];
				$this->post_drafts[ $post_id ]['contents_truncated'] = ! empty( $extra['contents_truncated'] );
			}
			if ( isset( $extra['excerpt'] ) ) {
				$this->post_drafts[ $post_id ]['excerpt'] = $extra['excerpt'];
			}
		}
	}

	/**
	 * Convert drafts into object-level observations.
	 *
	 * @param int $blog_id Blog id.
	 * @return array<int, array<string, mixed>>
	 */
	private function build_observations_from_drafts( $blog_id ) {
		$observations = array();

		foreach ( $this->post_drafts as $draft ) {
			if ( empty( $draft['categories'] ) || ! is_array( $draft['categories'] ) ) {
				continue;
			}

			$object_fp = Sassh_Post_Key_Normalizer::object_fingerprint(
				(int) $draft['post_id'],
				(string) $draft['post_title'],
				(string) $draft['post_content'],
				(string) $draft['post_excerpt'],
				(string) $draft['post_type'],
				(string) $draft['post_status']
			);

			if ( '' === $object_fp ) {
				++$this->hash_failures;
				continue;
			}

			$title = '' !== (string) $draft['post_title']
				? (string) $draft['post_title']
				: sprintf(
					/* translators: %d: post ID */
					__( 'Post #%d', 'choctaw-wp-security' ),
					(int) $draft['post_id']
				);

			$observations[] = array(
				'scanner_id'         => Sassh_Findings_Service::SCANNER_WP_POSTS,
				'object_type'        => Sassh_Object_Type_Registry::TYPE_POST,
				'object_key'         => (string) $draft['object_key'],
				'blog_id'            => (int) $blog_id,
				'object_fingerprint' => $object_fp,
				'title'              => $title,
				'description'        => isset( $draft['detail'] ) ? (string) $draft['detail'] : '',
				'metadata'           => array(
					'post_id'            => (int) $draft['post_id'],
					'user_id'            => (int) $draft['user_id'],
					'user_display_name'  => (string) $draft['user_display_name'],
					'post_title'         => (string) $draft['post_title'],
					'post_type'          => (string) $draft['post_type'],
					'post_status'        => (string) $draft['post_status'],
					'size'               => (int) $draft['size'],
					'detail'             => isset( $draft['detail'] ) ? (string) $draft['detail'] : '',
					'excerpt'            => isset( $draft['excerpt'] ) ? (string) $draft['excerpt'] : '',
					'matched_snippet'    => isset( $draft['matched_snippet'] ) ? (string) $draft['matched_snippet'] : '',
					'contents_truncated'  => ! empty( $draft['contents_truncated'] ),
					'posts_table'        => $this->posts_table,
				),
				'categories'         => array_values( $draft['categories'] ),
			);
		}

		return $observations;
	}

	/**
	 * Built-in guidance contribution packs per rule.
	 *
	 * @param string $rule_id    Rule id.
	 * @param string $risk_level Risk level.
	 * @return array<int, array<string, mixed>>
	 */
	private function guidance_contributions_for_rule( $rule_id, $risk_level ) {
		unset( $risk_level );

		switch ( (string) $rule_id ) {
			case Sassh_Findings_Service::RULE_POST_PHP_EXECUTION_PATTERNS_MATCH:
				return array(
					array(
						'id'               => 'post.php.evidence.patterns',
						'kind'             => 'evidence_fact',
						'display_priority' => 10,
						'text'             => 'This post matched PHP tag and/or execution/obfuscation-related substrings in post content or excerpt.',
						'concern'          => 'post.php.evidence',
					),
					array(
						'id'               => 'post.php.interpretation.inert',
						'kind'             => 'warning_caveat',
						'display_priority' => 10,
						'text'             => 'WordPress core does not ordinarily execute PHP stored in post_content or post_excerpt. Stored PHP is normally inert, but it may indicate injection or become dangerous when another plugin, shortcode, template, or vulnerability evaluates stored content.',
						'concern'          => 'post.php.certainty',
						'severity'        => 80,
					),
					array(
						'id'               => 'post.php.action.review',
						'kind'             => 'recommended_action',
						'display_priority' => 20,
						'text'             => 'Review the Matched Snippet in context. Remove unexpected markup, or trash/restore from a clean backup. Do not execute suspicious code. Check the author account and related posts when the content looks injected.',
						'tags'             => array( 'investigate', 'nondestructive' ),
						'concern'          => 'post.php.proceed',
					),
				);

			case Sassh_Findings_Service::RULE_POST_SCRIPTS_HIGH_CONFIDENCE:
				return array(
					array(
						'id'               => 'post.scripts_hc.evidence',
						'kind'             => 'evidence_fact',
						'display_priority' => 10,
						'text'             => 'High-confidence script or iframe injection patterns were found (for example remote script/iframe sources, document.write, or eval/unescape).',
						'concern'          => 'post.scripts.evidence',
					),
					array(
						'id'               => 'post.scripts_hc.action',
						'kind'             => 'recommended_action',
						'display_priority' => 20,
						'text'             => 'Review the Matched Snippet and remove unauthorized scripts/iframes. Prefer restoring from a clean revision when the post is heavily altered, then search other posts for the same injection.',
						'tags'             => array( 'investigate' ),
						'concern'          => 'post.scripts.proceed',
					),
				);

			case Sassh_Findings_Service::RULE_POST_SCRIPTS_GENERIC:
				return array(
					array(
						'id'               => 'post.scripts_generic.evidence',
						'kind'             => 'evidence_fact',
						'display_priority' => 10,
						'text'             => 'Script or iframe markup appears in this post. Some embeds are legitimate, but unexpected scripts—especially from unknown hosts—are a common compromise indicator.',
						'concern'          => 'post.scripts.evidence',
					),
					array(
						'id'               => 'post.scripts_generic.action',
						'kind'             => 'recommended_action',
						'display_priority' => 20,
						'text'             => 'Confirm the embed is intentional (trusted video/map/widget). Remove anything you do not recognize, update the post, and rescan.',
						'tags'             => array( 'investigate', 'nondestructive' ),
						'concern'          => 'post.scripts.proceed',
					),
				);

			case Sassh_Findings_Service::RULE_POST_SEO_SPAM_TITLE:
				return array(
					array(
						'id'               => 'post.seo.evidence',
						'kind'             => 'evidence_fact',
						'display_priority' => 10,
						'text'             => 'This published post title contains terms associated with SEO spam injections (for example pharmaceutical, casino, or loan spam).',
						'concern'          => 'post.seo.evidence',
					),
					array(
						'id'               => 'post.seo.action',
						'kind'             => 'recommended_action',
						'display_priority' => 20,
						'text'             => 'Verify authorship and intent. If the post is spam, trash it (prefer trash over permanent delete while investigating) and review other posts from the same author.',
						'tags'             => array( 'investigate' ),
						'concern'          => 'post.seo.proceed',
					),
				);

			case Sassh_Findings_Service::RULE_POST_LARGE_CONTENT:
				return array(
					array(
						'id'               => 'post.large.evidence',
						'kind'             => 'evidence_fact',
						'display_priority' => 10,
						'text'             => 'This post meets the large-content size threshold used by this scan. Size alone is not proof of compromise, but large posts can hide injected payloads.',
						'concern'          => 'post.large.evidence',
					),
					array(
						'id'               => 'post.large.action',
						'kind'             => 'recommended_action',
						'display_priority' => 20,
						'text'             => 'Confirm whether the size is expected (long guide, imported content). If not, search the content for hidden scripts or PHP and clean as needed.',
						'tags'             => array( 'investigate', 'nondestructive' ),
						'concern'          => 'post.large.proceed',
					),
				);

			default:
				return array();
		}
	}

	/**
	 * Build Findings report DTO for the admin UI.
	 *
	 * @param Sassh_Findings_Service   $service      Service.
	 * @param int                      $execution_id Execution id.
	 * @param array<string, mixed>     $run_meta     Run meta.
	 * @return array<string, mixed>
	 */
	private function build_report_from_findings( Sassh_Findings_Service $service, $execution_id, array $run_meta ) {
		$completion  = isset( $run_meta['completion_status'] ) ? (string) $run_meta['completion_status'] : 'failed';
		$coverage_ok = ( 'success' === $completion );

		$rows = $service->list_findings(
			array(
				'scanner_id'      => Sassh_Findings_Service::SCANNER_WP_POSTS,
				'detection_state' => 'active',
			)
		);

		$findings   = array();
		$critical   = 0;
		$warning    = 0;
		$suspicious = 0;
		$info       = 0;
		$safe       = 0;
		$confirmed  = 0;

		foreach ( $rows as $row ) {
			if ( isset( $row['posts_table'] ) && '' !== (string) $row['posts_table'] && (string) $row['posts_table'] !== $this->posts_table ) {
				continue;
			}

			$confirmed_this_run = isset( $row['last_scanner_execution_id'] )
				&& (int) $row['last_scanner_execution_id'] === (int) $execution_id;

			if ( $confirmed_this_run ) {
				++$confirmed;
			}

			$risk = isset( $row['risk_level'] ) ? (string) $row['risk_level'] : 'info';

			switch ( $risk ) {
				case 'critical':
					++$critical;
					break;
				case 'warning':
					++$warning;
					break;
				case 'suspicious':
					++$suspicious;
					break;
				case 'safe':
					++$safe;
					break;
				default:
					++$info;
					break;
			}

			$why = isset( $row['why_seeing_this'] ) ? $row['why_seeing_this'] : '';
			$how = isset( $row['how_to_proceed'] ) ? $row['how_to_proceed'] : '';

			$findings[] = array(
				'id'                      => $row['finding_id'],
				'finding_id'              => $row['finding_id'],
				'fingerprint'             => $row['content_fingerprint'],
				'content_fingerprint'     => $row['content_fingerprint'],
				'object_fingerprint'      => $row['object_fingerprint'],
				'rule_id'                 => isset( $row['primary_rule_id'] ) ? $row['primary_rule_id'] : ( isset( $row['rule_id'] ) ? $row['rule_id'] : '' ),
				'post_id'                 => isset( $row['post_id'] ) ? (int) $row['post_id'] : (int) $row['object_key'],
				'user_id'                 => isset( $row['user_id'] ) ? (int) $row['user_id'] : 0,
				'user_display_name'       => isset( $row['user_display_name'] ) ? (string) $row['user_display_name'] : '',
				'post_title'              => isset( $row['post_title'] ) ? (string) $row['post_title'] : ( isset( $row['title'] ) ? (string) $row['title'] : '' ),
				'post_type'               => isset( $row['post_type'] ) ? (string) $row['post_type'] : '',
				'post_status'             => isset( $row['post_status'] ) ? (string) $row['post_status'] : '',
				'size'                    => isset( $row['size'] ) ? (int) $row['size'] : 0,
				'detail'                  => isset( $row['detail'] ) ? (string) $row['detail'] : ( isset( $row['description'] ) ? (string) $row['description'] : '' ),
				'description'             => isset( $row['description'] ) ? (string) $row['description'] : '',
				'excerpt'                 => isset( $row['excerpt'] ) ? (string) $row['excerpt'] : '',
				'matched_snippet'         => isset( $row['matched_snippet'] ) ? (string) $row['matched_snippet'] : '',
				'contents_truncated'       => ! empty( $row['contents_truncated'] ),
				'risk'                    => $risk,
				'risk_level'              => $risk,
				'risk_label'              => isset( $row['risk_label'] ) ? $row['risk_label'] : $risk,
				'status'                  => $row['effective_status'],
				'status_label'            => $row['status_label'],
				'effective_status'        => $row['effective_status'],
				'can_dismiss'             => ! empty( $row['can_dismiss'] ),
				'dismissal_control_state' => isset( $row['dismissal_control_state'] ) ? $row['dismissal_control_state'] : Sassh_Findings_Service::dismissal_control_state( $row ),
				'category'                => isset( $row['category'] ) ? $row['category'] : '',
				'category_label'          => isset( $row['category_label_display'] ) ? $row['category_label_display'] : ( isset( $row['category_label'] ) ? $row['category_label'] : '' ),
				'section_key'             => isset( $row['section_key'] ) ? $row['section_key'] : '',
				'why_seeing_this'         => $why,
				'how_to_proceed'          => $how,
				'matched_patterns'        => ( isset( $row['matched_patterns'] ) && is_array( $row['matched_patterns'] ) ) ? $row['matched_patterns'] : array(),
				'posts_table'             => isset( $row['posts_table'] ) ? $row['posts_table'] : $this->posts_table,
				'blog_id'                 => isset( $row['blog_id'] ) ? (int) $row['blog_id'] : null,
				'first_seen_at'           => $row['first_seen_at'],
				'last_seen_at'            => $row['last_seen_at'],
				'detection_state'         => $row['detection_state'],
				'confirmed_this_run'      => $confirmed_this_run,
				'findings_backend'        => 'sassh',
				'categories'              => ( isset( $row['categories'] ) && is_array( $row['categories'] ) ) ? $row['categories'] : array(),
				'extra_rule_count'        => isset( $row['extra_rule_count'] ) ? (int) $row['extra_rule_count'] : 0,
				'guidance'                => ( isset( $row['guidance'] ) && is_array( $row['guidance'] ) ) ? $row['guidance'] : array(),
			);
		}

		$count   = count( $findings );
		$flagged = $critical + $warning + $suspicious;

		return array(
			'success'                    => $coverage_ok && 0 === $flagged,
			'rejected'                   => false,
			'coverage_complete'          => $coverage_ok,
			'absence_reconciled'         => $coverage_ok,
			'completion_status'          => $completion,
			'scan_incomplete'            => ! empty( $run_meta['scan_incomplete'] ) || ! $coverage_ok,
			'errors'                     => isset( $run_meta['errors'] ) && is_array( $run_meta['errors'] ) ? $run_meta['errors'] : array(),
			'findings'                   => $findings,
			'confirmed_this_run'         => $confirmed,
			'prior_findings_only'        => ! $coverage_ok && $count > 0 && 0 === $confirmed,
			'summary'                    => array(
				'critical'   => $critical,
				'warning'    => $warning,
				'suspicious' => $suspicious,
				'safe'       => $safe,
				'info'       => $info,
				'total'      => $count,
				'flagged'    => $flagged,
			),
			'posts_table'                => $this->posts_table,
			'wordpress_configured_table' => Choctaw_Wp_Security_Posts_Table_Discovery::get_wordpress_configured_table(),
			'findings_backend'           => 'sassh',
			'scanned_at'                 => time(),
		);
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

		$users_table  = $this->discovery->quote_table_name( $this->users_table );
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
	 * Find all matching patterns in a value (case-insensitive).
	 *
	 * @param string             $value    Value to inspect.
	 * @param array<int, string> $patterns Patterns to search.
	 * @return array<int, string>
	 */
	private function find_all_matching_patterns( $value, array $patterns ) {
		$matched = array();

		foreach ( $patterns as $pattern ) {
			$pattern = (string) $pattern;
			if ( '' !== $pattern && false !== stripos( (string) $value, $pattern ) ) {
				$matched[] = $pattern;
			}
		}

		return array_values( array_unique( $matched ) );
	}

	/**
	 * Extract a longer snippet around a matched pattern for the eye panel.
	 *
	 * @param string $value   Full value.
	 * @param string $pattern Matched pattern.
	 * @return array{contents:string,truncated:bool}
	 */
	private function extract_matched_snippet( $value, $pattern ) {
		$position = stripos( $value, $pattern );
		$length   = Choctaw_Wp_Security_Posts_Scan_Patterns::MATCHED_SNIPPET_LENGTH;

		if ( false === $position ) {
			return Choctaw_Wp_Security_Utils::truncate_report_contents_result( (string) $value, $length );
		}

		$start = max( 0, $position - 80 );
		return Choctaw_Wp_Security_Utils::truncate_report_contents_result( substr( (string) $value, $start ), $length );
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
	 * Length-prefixed pair for dual-field fingerprints.
	 *
	 * @param string $a First value.
	 * @param string $b Second value.
	 * @return string
	 */
	private static function length_prefixed_pair( $a, $b ) {
		$a = (string) $a;
		$b = (string) $b;

		return strlen( $a ) . ':' . $a . "\n" . strlen( $b ) . ':' . $b . "\n";
	}

	/**
	 * Risk rank for draft primary selection.
	 *
	 * @param string $risk Risk level.
	 * @return int
	 */
	private function risk_rank( $risk ) {
		$map = array(
			'safe'       => 0,
			'info'       => 1,
			'suspicious' => 2,
			'warning'    => 3,
			'critical'   => 4,
		);

		return isset( $map[ $risk ] ) ? $map[ $risk ] : 1;
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
