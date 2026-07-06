<?php
/**
 * wp_options table scanner for potentially compromised records.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Scans the WordPress options table for high-risk compromise indicators.
 */
class Choctaw_Wp_Security_Options_Table_Scanner {

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
	 * Cached map of option_name => option_id.
	 *
	 * @var array<string, int>|null
	 */
	private $option_id_map = null;

	/**
	 * Run the full wp_options scan.
	 *
	 * @return array<string, mixed>
	 */
	public function scan() {
		global $wpdb;

		$this->start_time      = microtime( true );
		$this->scan_incomplete = false;
		$this->option_id_map   = null;

		$this->load_option_id_map();

		$sections = $this->empty_sections();
		$baseline = $this->load_baseline();

		$this->scan_site_url_security( $sections['site_url_security']['findings'] );
		$this->scan_active_plugins( $sections['active_plugins']['findings'] );
		$this->scan_cron_events( $sections['cron_events']['findings'] );
		$this->scan_large_autoload( $sections['large_autoload']['findings'] );
		$this->scan_php_execution_patterns( $sections['php_execution_patterns']['findings'] );
		$this->scan_malware_option_names( $sections['malware_option_names']['findings'] );
		$this->scan_scripts_non_widget( $sections['scripts_non_widget']['findings'] );
		$this->scan_baseline_diff( $sections['baseline_diff'], $baseline );

		$snapshot = $this->capture_baseline_snapshot();
		$this->save_baseline( $snapshot );

		$summary = $this->build_summary( $sections );

		return array(
			'success'              => 0 === ( $summary['critical'] + $summary['warning'] ),
			'scan_incomplete'      => $this->scan_incomplete,
			'baseline_established' => empty( $baseline ),
			'sections'             => $sections,
			'summary'              => $summary,
			'options_table'        => $wpdb->options,
		);
	}

	/**
	 * Capture and save a baseline snapshot without running a full scan.
	 *
	 * @return bool
	 */
	public static function reset_baseline() {
		$scanner  = new self();
		$snapshot = $scanner->capture_baseline_snapshot();

		return $scanner->save_baseline( $snapshot );
	}

	/**
	 * Initialize empty section payloads.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private function empty_sections() {
		$sections = array();

		foreach ( Choctaw_Wp_Security_Options_Scan_Patterns::$section_keys as $section_key ) {
			$meta = Choctaw_Wp_Security_Options_Scan_Patterns::get_section_meta();

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
	 * Scan site URL and security-related options.
	 *
	 * @param array<int, array<string, mixed>> $findings Findings list.
	 * @return void
	 */
	private function scan_site_url_security( array &$findings ) {
		$home     = (string) get_option( 'home', '' );
		$siteurl  = (string) get_option( 'siteurl', '' );
		$expected = $this->get_expected_hosts();

		if ( '' !== $home && '' !== $siteurl ) {
			$home_host    = $this->normalize_host( $home );
			$siteurl_host = $this->normalize_host( $siteurl );

			if ( '' !== $home_host && '' !== $siteurl_host && $home_host !== $siteurl_host ) {
				$findings[] = $this->make_finding(
					'home_siteurl_mismatch',
					'critical',
					'home / siteurl',
					max( strlen( $home ), strlen( $siteurl ) ),
					sprintf(
						/* translators: 1: home host, 2: siteurl host */
						__( 'home (%1$s) and siteurl (%2$s) point to different hosts.', 'choctaw-wp-security' ),
						$home_host,
						$siteurl_host
					),
					'',
					0,
					$this->format_option_id_label( array( 'home', 'siteurl' ) )
				);
			}
		}

		foreach ( array( 'home' => $home, 'siteurl' => $siteurl ) as $option_name => $value ) {
			if ( '' === $value ) {
				continue;
			}

			$constant_name = 'home' === $option_name ? 'WP_HOME' : 'WP_SITEURL';

			if ( defined( $constant_name ) ) {
				$constant_host = $this->normalize_host( constant( $constant_name ) );
				$option_host   = $this->normalize_host( $value );

				if ( '' !== $constant_host && '' !== $option_host && $constant_host !== $option_host ) {
					$findings[] = $this->make_finding(
						$option_name . '_constant_mismatch',
						'critical',
						$option_name,
						strlen( $value ),
						sprintf(
							/* translators: 1: option name, 2: wp-config constant value */
							__( '%1$s does not match the %2$s value defined in wp-config.php.', 'choctaw-wp-security' ),
							$option_name,
							constant( $constant_name )
						),
						$value
					);
				}
			}

			$host = $this->normalize_host( $value );

			if ( '' === $host ) {
				continue;
			}

			if ( ! empty( $expected ) && ! $this->host_matches_expected( $host, $expected ) ) {
				$findings[] = $this->make_finding(
					$option_name . '_external_host',
					'critical',
					$option_name,
					strlen( $value ),
					sprintf(
						/* translators: %s: external host */
						__( 'Points to an unexpected external host: %s', 'choctaw-wp-security' ),
						$host
					),
					$value
				);
			}
		}

		if ( (bool) get_option( 'users_can_register', false ) ) {
			$findings[] = $this->make_finding(
				'users_can_register_enabled',
				'warning',
				'users_can_register',
				1,
				__( 'Open user registration is enabled.', 'choctaw-wp-security' )
			);
		}

		$default_role = (string) get_option( 'default_role', 'subscriber' );

		if ( 'administrator' === $default_role ) {
			$findings[] = $this->make_finding(
				'default_role_administrator',
				'critical',
				'default_role',
				strlen( $default_role ),
				__( 'Default role for new users is set to administrator.', 'choctaw-wp-security' ),
				$default_role
			);
		}

		$admin_email = (string) get_option( 'admin_email', '' );

		if ( '' === $admin_email || ! is_email( $admin_email ) ) {
			$findings[] = $this->make_finding(
				'admin_email_invalid',
				'warning',
				'admin_email',
				strlen( $admin_email ),
				__( 'Administrator email is empty or invalid.', 'choctaw-wp-security' ),
				$admin_email
			);
		}

		$this->scan_critical_option_urls( $findings, $expected );
	}

	/**
	 * Look for external domains in critical option values.
	 *
	 * @param array<int, array<string, mixed>> $findings  Findings list.
	 * @param array<int, string>               $expected  Expected hosts.
	 * @return void
	 */
	private function scan_critical_option_urls( array &$findings, array $expected ) {
		foreach ( Choctaw_Wp_Security_Options_Scan_Patterns::$critical_option_keys as $option_name ) {
			if ( in_array( $option_name, array( 'home', 'siteurl' ), true ) ) {
				continue;
			}

			$value = get_option( $option_name, null );

			if ( ! is_string( $value ) || '' === $value ) {
				continue;
			}

			$domains = $this->extract_external_domains( $value, $expected );

			foreach ( $domains as $domain ) {
				$findings[] = $this->make_finding(
					'critical_option_external_url',
					'warning',
					$option_name,
					strlen( $value ),
					sprintf(
						/* translators: 1: option name, 2: external domain */
						__( 'External domain found in %1$s: %2$s', 'choctaw-wp-security' ),
						$option_name,
						$domain
					),
					$this->trim_excerpt( $value )
				);
			}
		}
	}

	/**
	 * Scan active_plugins consistency.
	 *
	 * @param array<int, array<string, mixed>> $findings Findings list.
	 * @return void
	 */
	private function scan_active_plugins( array &$findings ) {
		$active_plugins = get_option( 'active_plugins', array() );

		if ( ! is_array( $active_plugins ) ) {
			$findings[] = $this->make_finding(
				'active_plugins_invalid',
				'critical',
				'active_plugins',
				0,
				__( 'active_plugins is not a valid array.', 'choctaw-wp-security' )
			);
			return;
		}

		$plugins_dir = wp_normalize_path( WP_PLUGIN_DIR );

		foreach ( $active_plugins as $plugin_file ) {
			$plugin_file = (string) $plugin_file;

			if ( '' === $plugin_file ) {
				continue;
			}

			$plugin_path = wp_normalize_path( $plugins_dir . '/' . $plugin_file );

			if ( 0 !== strpos( $plugin_path, $plugins_dir . '/' ) ) {
				$findings[] = $this->make_finding(
					'active_plugin_suspicious_path',
					'critical',
					'active_plugins',
					strlen( $plugin_file ),
					sprintf(
						/* translators: %s: plugin path */
						__( 'Active plugin path is outside wp-content/plugins: %s', 'choctaw-wp-security' ),
						$plugin_file
					),
					$plugin_file
				);
				continue;
			}

			if ( ! file_exists( $plugin_path ) ) {
				$findings[] = $this->make_finding(
					'active_plugin_missing',
					'critical',
					'active_plugins',
					strlen( $plugin_file ),
					sprintf(
						/* translators: %s: plugin file */
						__( 'Active plugin listed but file is missing: %s', 'choctaw-wp-security' ),
						$plugin_file
					),
					$plugin_file
				);
			}
		}
	}

	/**
	 * Scan cron events stored in the cron option.
	 *
	 * @param array<int, array<string, mixed>> $findings Findings list.
	 * @return void
	 */
	private function scan_cron_events( array &$findings ) {
		$cron_raw = get_option( 'cron', array() );
		$cron     = _get_cron_array();

		if ( is_array( $cron_raw ) ) {
			$cron_raw_string = maybe_serialize( $cron_raw );
		} else {
			$cron_raw_string = (string) $cron_raw;
		}

		if ( '' !== $cron_raw_string ) {
			$this->scan_value_for_suspicious_strings(
				$cron_raw_string,
				'cron',
				$findings,
				array(
					'eval(',
					'base64_decode(',
					'gzinflate(',
				)
			);
		}

		if ( ! is_array( $cron ) || empty( $cron ) ) {
			return;
		}

		foreach ( $cron as $timestamp => $hooks ) {
			if ( ! is_array( $hooks ) ) {
				continue;
			}

			foreach ( $hooks as $hook => $events ) {
				$hook = (string) $hook;

				if ( '' === $hook ) {
					continue;
				}

				if ( ! $this->is_known_cron_hook( $hook ) ) {
					$findings[] = $this->make_finding(
						'cron_unknown_hook',
						'warning',
						'cron',
						strlen( $hook ),
						sprintf(
							/* translators: 1: cron hook, 2: scheduled timestamp */
							__( 'Unknown cron hook with no registered handler: %1$s (scheduled %2$s)', 'choctaw-wp-security' ),
							$hook,
							gmdate( 'Y-m-d H:i:s', (int) $timestamp )
						),
						$hook
					);
				}

				if ( ! is_array( $events ) ) {
					continue;
				}

				foreach ( $events as $event ) {
					if ( ! is_array( $event ) ) {
						continue;
					}

					$serialized = maybe_serialize( $event );

					$this->scan_value_for_suspicious_strings(
						$serialized,
						'cron',
						$findings,
						array(
							'eval(',
							'base64_decode(',
							'gzinflate(',
						),
						$hook
					);
				}
			}
		}
	}

	/**
	 * Scan for large autoloaded options.
	 *
	 * @param array<int, array<string, mixed>> $findings Findings list.
	 * @return void
	 */
	private function scan_large_autoload( array &$findings ) {
		global $wpdb;

		if ( $this->is_time_exceeded() ) {
			$this->scan_incomplete = true;
			return;
		}

		$table = $wpdb->options;
		$limit = (int) Choctaw_Wp_Security_Options_Scan_Patterns::AUTOLOAD_TOP_LIMIT;
		$rows  = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_id, option_name, LENGTH(option_value) AS option_size, LEFT(option_value, %d) AS option_excerpt
				FROM {$table}
				WHERE autoload = %s
				ORDER BY option_size DESC
				LIMIT %d",
				Choctaw_Wp_Security_Options_Scan_Patterns::LARGE_AUTOLOAD_PREVIEW_LENGTH,
				'yes',
				$limit
			),
			ARRAY_A
		);

		if ( ! is_array( $rows ) ) {
			return;
		}

		$threshold = (int) Choctaw_Wp_Security_Options_Scan_Patterns::AUTOLOAD_SIZE_THRESHOLD;

		foreach ( $rows as $row ) {
			$option_name = isset( $row['option_name'] ) ? (string) $row['option_name'] : '';
			$option_size = isset( $row['option_size'] ) ? (int) $row['option_size'] : 0;

			if ( '' === $option_name ) {
				continue;
			}

			$severity = $option_size >= $threshold ? 'warning' : 'info';

			$findings[] = $this->make_finding(
				'large_autoload_option',
				$severity,
				$option_name,
				$option_size,
				sprintf(
					/* translators: %s: formatted option size */
					__( 'Autoloaded option size: %s', 'choctaw-wp-security' ),
					size_format( $option_size )
				),
				$this->format_value_preview(
					isset( $row['option_excerpt'] ) ? (string) $row['option_excerpt'] : '',
					$option_size,
					Choctaw_Wp_Security_Options_Scan_Patterns::LARGE_AUTOLOAD_PREVIEW_LENGTH
				),
				isset( $row['option_id'] ) ? (int) $row['option_id'] : null
			);
		}
	}

	/**
	 * Scan for PHP tags and execution patterns.
	 *
	 * @param array<int, array<string, mixed>> $findings Findings list.
	 * @return void
	 */
	private function scan_php_execution_patterns( array &$findings ) {
		$patterns = array_merge(
			Choctaw_Wp_Security_Options_Scan_Patterns::$php_tag_patterns,
			Choctaw_Wp_Security_Options_Scan_Patterns::$execution_patterns
		);

		$this->scan_option_patterns( $patterns, $findings, 'php_execution_patterns', 'critical', true );
	}

	/**
	 * Scan for known-malware option names.
	 *
	 * @param array<int, array<string, mixed>> $findings Findings list.
	 * @return void
	 */
	private function scan_malware_option_names( array &$findings ) {
		global $wpdb;

		if ( $this->is_time_exceeded() ) {
			$this->scan_incomplete = true;
			return;
		}

		$names = Choctaw_Wp_Security_Options_Scan_Patterns::$malware_option_names;

		if ( empty( $names ) ) {
			return;
		}

		$table        = $wpdb->options;
		$placeholders = implode( ', ', array_fill( 0, count( $names ), '%s' ) );
		$sql          = "SELECT option_id, option_name, LENGTH(option_value) AS option_size, LEFT(option_value, %d) AS option_excerpt
			FROM {$table}
			WHERE option_name IN ({$placeholders})";
		$args         = array_merge( array( $sql, Choctaw_Wp_Security_Options_Scan_Patterns::EXCERPT_LENGTH ), $names );
		$query        = call_user_func_array( array( $wpdb, 'prepare' ), $args );

		$rows = $wpdb->get_results( $query, ARRAY_A );

		if ( ! is_array( $rows ) ) {
			return;
		}

		foreach ( $rows as $row ) {
			$option_name = isset( $row['option_name'] ) ? (string) $row['option_name'] : '';

			if ( '' === $option_name ) {
				continue;
			}

			$findings[] = $this->make_finding(
				'malware_option_name',
				'warning',
				$option_name,
				isset( $row['option_size'] ) ? (int) $row['option_size'] : 0,
				__( 'Option name matches a pattern commonly used by malware.', 'choctaw-wp-security' ),
				isset( $row['option_excerpt'] ) ? (string) $row['option_excerpt'] : '',
				isset( $row['option_id'] ) ? (int) $row['option_id'] : null
			);
		}
	}

	/**
	 * Scan for script and iframe patterns outside widget/theme options.
	 *
	 * @param array<int, array<string, mixed>> $findings Findings list.
	 * @return void
	 */
	private function scan_scripts_non_widget( array &$findings ) {
		$this->scan_option_patterns(
			Choctaw_Wp_Security_Options_Scan_Patterns::$script_patterns,
			$findings,
			'scripts_non_widget',
			'warning',
			true,
			true
		);
	}

	/**
	 * Compare current options against a stored baseline snapshot.
	 *
	 * @param array<string, mixed>      $section  Section payload.
	 * @param array<string, mixed>|null $baseline Prior baseline.
	 * @return void
	 */
	private function scan_baseline_diff( array &$section, $baseline ) {
		if ( empty( $baseline ) || ! isset( $baseline['options'] ) || ! is_array( $baseline['options'] ) ) {
			$section['info_message'] = __( 'Baseline established. Future scans will report options that are new or changed since this scan.', 'choctaw-wp-security' );
			return;
		}

		$current  = $this->capture_baseline_snapshot();
		$previous = $baseline['options'];
		$findings = array();

		foreach ( $current['options'] as $option_name => $meta ) {
			if ( ! isset( $previous[ $option_name ] ) ) {
				$findings[] = $this->make_baseline_finding(
					'new',
					$option_name,
					0,
					isset( $meta['size'] ) ? (int) $meta['size'] : 0,
					isset( $meta['option_id'] ) ? (int) $meta['option_id'] : 0
				);
				continue;
			}

			$old_hash = isset( $previous[ $option_name ]['hash'] ) ? (string) $previous[ $option_name ]['hash'] : '';
			$new_hash = isset( $meta['hash'] ) ? (string) $meta['hash'] : '';

			if ( $old_hash !== $new_hash ) {
				$findings[] = $this->make_baseline_finding(
					'changed',
					$option_name,
					isset( $previous[ $option_name ]['size'] ) ? (int) $previous[ $option_name ]['size'] : 0,
					isset( $meta['size'] ) ? (int) $meta['size'] : 0,
					isset( $meta['option_id'] ) ? (int) $meta['option_id'] : 0
				);
			}
		}

		foreach ( $previous as $option_name => $meta ) {
			if ( ! isset( $current['options'][ $option_name ] ) ) {
				$findings[] = $this->make_baseline_finding(
					'removed',
					(string) $option_name,
					isset( $meta['size'] ) ? (int) $meta['size'] : 0,
					0,
					isset( $meta['option_id'] ) ? (int) $meta['option_id'] : 0
				);
			}
		}

		$section['findings'] = $findings;
	}

	/**
	 * Run pattern scans against option values.
	 *
	 * @param array<int, string>             $patterns             Patterns to search.
	 * @param array<int, array<string, mixed>> $findings             Findings list.
	 * @param string                         $finding_id_prefix    Finding ID prefix.
	 * @param string                         $severity             Default severity.
	 * @param bool                           $exclude_transients   Whether to skip transients.
	 * @param bool                           $exclude_widget_theme Whether to skip widget/theme options.
	 * @return void
	 */
	private function scan_option_patterns( array $patterns, array &$findings, $finding_id_prefix, $severity, $exclude_transients, $exclude_widget_theme = false ) {
		global $wpdb;

		if ( empty( $patterns ) || $this->is_time_exceeded() ) {
			if ( $this->is_time_exceeded() ) {
				$this->scan_incomplete = true;
			}
			return;
		}

		$table         = $wpdb->options;
		$where_clauses = array();
		$where_values  = array();

		foreach ( $patterns as $pattern ) {
			$where_clauses[] = 'option_value LIKE %s';
			$where_values[]  = '%' . $wpdb->esc_like( $pattern ) . '%';
		}

		$sql = 'SELECT option_id, option_name, LENGTH(option_value) AS option_size, option_value
			FROM ' . $table . '
			WHERE (' . implode( ' OR ', $where_clauses ) . ')';

		if ( $exclude_transients ) {
			$sql .= $wpdb->prepare( ' AND option_name NOT LIKE %s', $wpdb->esc_like( '_transient_' ) . '%' );
			$sql .= $wpdb->prepare( ' AND option_name NOT LIKE %s', $wpdb->esc_like( '_site_transient_' ) . '%' );
		}

		if ( $exclude_widget_theme ) {
			foreach ( Choctaw_Wp_Security_Options_Scan_Patterns::$widget_theme_prefixes as $prefix ) {
				$sql .= $wpdb->prepare( ' AND option_name NOT LIKE %s', $wpdb->esc_like( $prefix ) . '%' );
			}
		}

		$sql .= ' LIMIT ' . (int) ( Choctaw_Wp_Security_Options_Scan_Patterns::FINDINGS_DISPLAY_LIMIT + 1 );

		$rows = $wpdb->get_results( $wpdb->prepare( $sql, $where_values ), ARRAY_A );

		if ( ! is_array( $rows ) ) {
			return;
		}

		$seen = array();

		foreach ( $rows as $row ) {
			if ( $this->is_time_exceeded() ) {
				$this->scan_incomplete = true;
				break;
			}

			$option_name  = isset( $row['option_name'] ) ? (string) $row['option_name'] : '';
			$option_value = isset( $row['option_value'] ) ? (string) $row['option_value'] : '';

			if ( '' === $option_name || isset( $seen[ $option_name ] ) ) {
				continue;
			}

			$matched_pattern = $this->find_matching_pattern( $option_value, $patterns );

			if ( '' === $matched_pattern ) {
				continue;
			}

			$seen[ $option_name ] = true;

			$findings[] = $this->make_finding(
				$finding_id_prefix . '_match',
				$severity,
				$option_name,
				isset( $row['option_size'] ) ? (int) $row['option_size'] : strlen( $option_value ),
				sprintf(
					/* translators: %s: matched pattern */
					__( 'Matched pattern: %s', 'choctaw-wp-security' ),
					$matched_pattern
				),
				$this->extract_excerpt( $option_value, $matched_pattern ),
				isset( $row['option_id'] ) ? (int) $row['option_id'] : null
			);
		}
	}

	/**
	 * Scan a string value for suspicious substrings.
	 *
	 * @param string                           $value    Value to inspect.
	 * @param string                           $option_name Option name for context.
	 * @param array<int, array<string, mixed>> $findings Findings list.
	 * @param array<int, string>               $patterns Patterns to search.
	 * @param string                           $context  Additional context label.
	 * @return void
	 */
	private function scan_value_for_suspicious_strings( $value, $option_name, array &$findings, array $patterns, $context = '' ) {
		$matched_pattern = $this->find_matching_pattern( $value, $patterns );

		if ( '' === $matched_pattern ) {
			return;
		}

		$detail = sprintf(
			/* translators: 1: matched pattern, 2: additional context */
			__( 'Matched pattern: %1$s%2$s', 'choctaw-wp-security' ),
			$matched_pattern,
			'' !== $context ? ' (' . $context . ')' : ''
		);

		$findings[] = $this->make_finding(
			'cron_suspicious_content',
			'warning',
			$option_name,
			strlen( $value ),
			$detail,
			$this->extract_excerpt( $value, $matched_pattern )
		);
	}

	/**
	 * Capture a baseline snapshot of wp_options rows.
	 *
	 * @return array<string, mixed>
	 */
	private function capture_baseline_snapshot() {
		global $wpdb;

		$table = $wpdb->options;
		$rows  = $wpdb->get_results(
			"SELECT option_id, option_name, option_value
			FROM {$table}
			WHERE option_name NOT LIKE '" . esc_sql( $wpdb->esc_like( '_transient_' ) ) . "%'
			AND option_name NOT LIKE '" . esc_sql( $wpdb->esc_like( '_site_transient_' ) ) . "%'",
			ARRAY_A
		);

		$options = array();

		if ( is_array( $rows ) ) {
			foreach ( $rows as $row ) {
				$option_name = isset( $row['option_name'] ) ? (string) $row['option_name'] : '';

				if ( '' === $option_name ) {
					continue;
				}

				$value = isset( $row['option_value'] ) ? (string) $row['option_value'] : '';

				$options[ $option_name ] = array(
					'hash'      => md5( $value ),
					'size'      => strlen( $value ),
					'option_id' => isset( $row['option_id'] ) ? (int) $row['option_id'] : 0,
				);
			}
		}

		return array(
			'captured_at' => gmdate( 'Y-m-d H:i:s' ),
			'options'     => $options,
		);
	}

	/**
	 * Load a stored baseline snapshot.
	 *
	 * @return array<string, mixed>|null
	 */
	private function load_baseline() {
		$baseline = get_option( Choctaw_Wp_Security_Options_Scan_Patterns::BASELINE_OPTION_KEY, null );

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
			Choctaw_Wp_Security_Options_Scan_Patterns::BASELINE_OPTION_KEY,
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
	 * Determine whether a cron hook appears to be registered.
	 *
	 * @param string $hook Cron hook name.
	 * @return bool
	 */
	private function is_known_cron_hook( $hook ) {
		if ( has_action( $hook ) ) {
			return true;
		}

		$core_hooks = array(
			'wp_version_check',
			'wp_update_plugins',
			'wp_update_themes',
			'wp_scheduled_delete',
			'delete_expired_transients',
			'wp_scheduled_auto_draft_delete',
			'recovery_mode_clean_expired_keys',
			'wp_privacy_delete_old_export_files',
		);

		return in_array( $hook, $core_hooks, true );
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

		foreach ( $expected as $expected_host ) {
			if ( $host === $this->normalize_host( $expected_host ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Extract external domains from a string.
	 *
	 * @param string             $value    Value to inspect.
	 * @param array<int, string> $expected Expected hosts.
	 * @return array<int, string>
	 */
	private function extract_external_domains( $value, array $expected ) {
		$domains  = array();
		$pattern  = '#https?://([^/\s\'"]+)#i';
		$matches  = array();
		$matched  = preg_match_all( $pattern, $value, $matches );

		if ( false === $matched || empty( $matches[1] ) ) {
			return $domains;
		}

		foreach ( $matches[1] as $raw_host ) {
			$host = $this->normalize_host( (string) $raw_host );

			if ( '' === $host || $this->host_matches_expected( $host, $expected ) ) {
				continue;
			}

			$domains[ $host ] = $host;
		}

		return array_values( $domains );
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
	 * Load and cache option_name => option_id pairs.
	 *
	 * @return void
	 */
	private function load_option_id_map() {
		global $wpdb;

		$this->option_id_map = array();

		$rows = $wpdb->get_results(
			"SELECT option_id, option_name FROM {$wpdb->options}",
			ARRAY_A
		);

		if ( ! is_array( $rows ) ) {
			return;
		}

		foreach ( $rows as $row ) {
			$option_name = isset( $row['option_name'] ) ? (string) $row['option_name'] : '';

			if ( '' === $option_name ) {
				continue;
			}

			$this->option_id_map[ $option_name ] = isset( $row['option_id'] ) ? (int) $row['option_id'] : 0;
		}
	}

	/**
	 * Look up an option_id by option name.
	 *
	 * @param string $option_name Option name.
	 * @return int
	 */
	private function get_option_id_for_name( $option_name ) {
		if ( ! is_array( $this->option_id_map ) ) {
			$this->load_option_id_map();
		}

		return isset( $this->option_id_map[ $option_name ] ) ? (int) $this->option_id_map[ $option_name ] : 0;
	}

	/**
	 * Format option IDs for composite option labels.
	 *
	 * @param array<int, string> $option_names Option names.
	 * @return string
	 */
	private function format_option_id_label( array $option_names ) {
		$labels = array();

		foreach ( $option_names as $option_name ) {
			$option_id = $this->get_option_id_for_name( $option_name );

			if ( $option_id > 0 ) {
				$labels[] = (string) $option_id;
			}
		}

		if ( empty( $labels ) ) {
			return '';
		}

		return implode( ' / ', $labels );
	}

	/**
	 * Build a standardized finding payload.
	 *
	 * @param string      $id               Finding ID.
	 * @param string      $severity         Severity level.
	 * @param string      $option_name      Option name.
	 * @param int         $size             Value size.
	 * @param string      $detail           Human-readable detail.
	 * @param string      $excerpt          Value excerpt.
	 * @param int|null    $option_id        Option ID when known.
	 * @param string      $option_id_label  Optional display label for composite rows.
	 * @return array<string, mixed>
	 */
	private function make_finding( $id, $severity, $option_name, $size, $detail, $excerpt = '', $option_id = null, $option_id_label = '' ) {
		if ( null === $option_id ) {
			$option_id = $this->get_option_id_for_name( $option_name );
		}

		$finding = array(
			'id'          => $id,
			'severity'    => $severity,
			'option_name' => $option_name,
			'option_id'   => (int) $option_id,
			'size'        => (int) $size,
			'detail'      => $detail,
			'excerpt'     => $this->trim_excerpt( $excerpt ),
		);

		if ( '' !== $option_id_label ) {
			$finding['option_id_label'] = $option_id_label;
		}

		return $finding;
	}

	/**
	 * Build a baseline diff finding payload.
	 *
	 * @param string $change_type Change type.
	 * @param string $option_name Option name.
	 * @param int    $old_size    Previous size.
	 * @param int    $new_size    Current size.
	 * @param int    $option_id   Option ID.
	 * @return array<string, mixed>
	 */
	private function make_baseline_finding( $change_type, $option_name, $old_size, $new_size, $option_id = 0 ) {
		$severity = 'info';
		$detail   = '';

		if ( 'new' === $change_type ) {
			$detail = sprintf(
				/* translators: %s: formatted option size */
				__( 'New option (size: %s)', 'choctaw-wp-security' ),
				size_format( $new_size )
			);

			if ( in_array( $option_name, Choctaw_Wp_Security_Options_Scan_Patterns::$malware_option_names, true ) ) {
				$severity = 'warning';
			}
		} elseif ( 'changed' === $change_type ) {
			$detail = sprintf(
				/* translators: 1: old size, 2: new size */
				__( 'Changed option (was %1$s, now %2$s)', 'choctaw-wp-security' ),
				size_format( $old_size ),
				size_format( $new_size )
			);

			if ( in_array( $option_name, Choctaw_Wp_Security_Options_Scan_Patterns::$malware_option_names, true ) ) {
				$severity = 'warning';
			}
		} else {
			$detail = sprintf(
				/* translators: %s: formatted option size */
				__( 'Removed option (was %s)', 'choctaw-wp-security' ),
				size_format( $old_size )
			);
		}

		return array(
			'id'          => 'baseline_' . $change_type,
			'severity'    => $severity,
			'option_name' => $option_name,
			'option_id'   => (int) $option_id,
			'size'        => $new_size,
			'detail'      => $detail,
			'excerpt'     => ucfirst( $change_type ),
			'change_type' => $change_type,
			'old_size'    => (int) $old_size,
			'new_size'    => (int) $new_size,
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

		return $this->trim_excerpt( substr( $value, $start, Choctaw_Wp_Security_Options_Scan_Patterns::EXCERPT_LENGTH ) );
	}

	/**
	 * Format a truncated option value preview with an ellipsis suffix.
	 *
	 * @param string $value          Raw value excerpt.
	 * @param int    $full_size      Full stored value size.
	 * @param int    $preview_length Maximum preview length.
	 * @return string
	 */
	private function format_value_preview( $value, $full_size, $preview_length ) {
		$value = wp_strip_all_tags( (string) $value );
		$value = preg_replace( '/\s+/', ' ', $value );

		if ( ! is_string( $value ) ) {
			return '';
		}

		$value = trim( $value );

		if ( '' === $value ) {
			return '';
		}

		if ( strlen( $value ) > $preview_length ) {
			$value = substr( $value, 0, $preview_length );
		}

		$value = rtrim( $value );

		if ( (int) $full_size > $preview_length || strlen( $value ) >= $preview_length ) {
			return $value . '...';
		}

		return $value;
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

		if ( strlen( $excerpt ) > Choctaw_Wp_Security_Options_Scan_Patterns::EXCERPT_LENGTH ) {
			$excerpt = substr( $excerpt, 0, Choctaw_Wp_Security_Options_Scan_Patterns::EXCERPT_LENGTH ) . '...';
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

		return $elapsed >= (float) Choctaw_Wp_Security_Options_Scan_Patterns::SCAN_TIME_BUDGET;
	}
}
