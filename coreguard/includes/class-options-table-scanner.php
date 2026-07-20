<?php
/**
 * wp_options table scanner (Sassh Findings producer).
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Scans a WordPress options table for compromise indicators and records
 * Sassh Findings observations for the mapped registered-site blog_id.
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
	 * Count of candidate rows that could not be fingerprinted.
	 *
	 * @var int
	 */
	private $hash_failures = 0;

	/**
	 * Cached map of option_name => option_id.
	 *
	 * @var array<string, int>|null
	 */
	private $option_id_map = null;

	/**
	 * Selected options table name.
	 *
	 * @var string
	 */
	private $options_table = '';

	/**
	 * Table discovery helper.
	 *
	 * @var Choctaw_Wp_Security_Options_Table_Discovery
	 */
	private $discovery;

	/**
	 * Create a scanner for a specific options table.
	 *
	 * @param string $options_table Requested options table name.
	 */
	public function __construct( $options_table = '' ) {
		$this->discovery     = new Choctaw_Wp_Security_Options_Table_Discovery();
		$this->options_table = $this->discovery->resolve_scan_table( $options_table );
	}

	/**
	 * Run the wp_options scan and persist observations via Sassh Findings.
	 *
	 * @return array<string, mixed>
	 */
	public function scan() {
		Sassh_Findings_Schema::maybe_upgrade();

		$this->start_time      = microtime( true );
		$this->scan_incomplete = false;
		$this->hash_failures   = 0;
		$this->option_id_map   = null;

		$blog_id = Sassh_Option_Key_Normalizer::map_options_table_to_registered_site_blog_id( $this->options_table );

		if ( is_wp_error( $blog_id ) ) {
			return $this->build_rejection_report( $blog_id );
		}

		$blog_id = (int) $blog_id;

		$this->load_option_id_map();

		$scope_key    = Sassh_Findings_Service::database_scan_scope_key( $this->options_table );
		$service      = new Sassh_Findings_Service();
		$execution_id = $service->begin_scanner_execution(
			Sassh_Findings_Service::SCANNER_DATABASE_SCAN,
			array(
				'scope_key'  => $scope_key,
				'run_type'   => 'individual',
				'run_source' => 'wordpress_admin',
				'meta'       => array(
					'options_table'              => $this->options_table,
					'wordpress_configured_table' => Choctaw_Wp_Security_Options_Table_Discovery::get_wordpress_configured_table(),
					'blog_id'                    => $blog_id,
				),
			)
		);

		$observations = array();

		$this->scan_site_url_security( $observations, $blog_id );
		$this->scan_active_plugins( $observations, $blog_id );
		$autoload_meta = $this->scan_large_autoload( $observations, $blog_id );
		$this->scan_php_execution_patterns( $observations, $blog_id );
		$this->scan_malware_option_names( $observations, $blog_id );
		$this->scan_scripts_non_widget( $observations, $blog_id );

		$service->record_observations( $execution_id, $observations );

		if ( ! empty( $autoload_meta['stats'] ) ) {
			$service->update_execution_meta(
				$execution_id,
				array(
					'autoload_stats'               => $autoload_meta['stats'],
					'autoload_below_threshold_top' => isset( $autoload_meta['top_below_threshold'] ) ? $autoload_meta['top_below_threshold'] : array(),
				)
			);
		}

		$errors             = array();
		$completion_status = 'success';

		if ( $this->scan_incomplete ) {
			$completion_status = 'partial';
			$errors[]          = __( 'Scan stopped before completing every check due to the time budget. Previously detected findings were not cleared.', 'choctaw-wp-security' );
		}

		if ( $this->hash_failures > 0 ) {
			$completion_status = 'partial';
			$errors[]          = __( 'One or more option values could not be fingerprinted.', 'choctaw-wp-security' );
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
				'autoload_meta'     => $autoload_meta,
			)
		);
	}

	/**
	 * No-op. Baseline snapshots are no longer written by the Findings producer;
	 * the legacy baseline option is left orphaned in place.
	 *
	 * @param string $options_table Requested options table name (unused).
	 * @return bool Always false.
	 */
	public static function reset_baseline( $options_table = '' ) {
		return false;
	}

	/**
	 * Get the selected options table name.
	 *
	 * @return string
	 */
	public function get_options_table() {
		return $this->options_table;
	}

	/**
	 * Quote the selected options table for SQL usage.
	 *
	 * @return string
	 */
	private function get_options_table_sql() {
		return $this->discovery->quote_table_name( $this->options_table );
	}

	/**
	 * Read an option value from the selected options table (unserialized).
	 *
	 * @param string $option_name Option name.
	 * @param mixed  $default     Default value when missing.
	 * @return mixed
	 */
	private function get_table_option( $option_name, $default = false ) {
		global $wpdb;

		$value = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT option_value FROM ' . $this->get_options_table_sql() . ' WHERE option_name = %s LIMIT 1',
				$option_name
			)
		);

		if ( null === $value ) {
			return $default;
		}

		return maybe_unserialize( $value );
	}

	/**
	 * Read the raw (unserialized-untouched) option value string.
	 *
	 * @param string $option_name Option name.
	 * @param mixed  $default     Default value when missing.
	 * @return mixed
	 */
	private function get_table_option_raw( $option_name, $default = '' ) {
		global $wpdb;

		$value = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT option_value FROM ' . $this->get_options_table_sql() . ' WHERE option_name = %s LIMIT 1',
				$option_name
			)
		);

		return null === $value ? $default : (string) $value;
	}

	/**
	 * Build the rejection payload for a table that cannot be mapped to a
	 * registered/current network site. No scanner execution is started.
	 *
	 * @param WP_Error $error Mapping error.
	 * @return array<string, mixed>
	 */
	private function build_rejection_report( WP_Error $error ) {
		$message = $error->get_error_message();

		if ( '' === $message ) {
			$message = __( 'The selected options table is not associated with a registered WordPress site.', 'choctaw-wp-security' );
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
			'options_table'              => $this->options_table,
			'wordpress_configured_table' => Choctaw_Wp_Security_Options_Table_Discovery::get_wordpress_configured_table(),
			'scan_incomplete'            => false,
			'coverage_complete'          => false,
			'absence_reconciled'         => false,
			'completion_status'          => 'rejected',
			'confirmed_this_run'         => 0,
			'scanned_at'                 => time(),
		);
	}

	/**
	 * Build a standardized observation payload for Sassh_Findings_Service.
	 *
	 * @param string                $rule_id             Rule id.
	 * @param string                $object_key           Normalized object key.
	 * @param int                   $blog_id              Registered/current network site blog id.
	 * @param string                $risk_level           Risk level.
	 * @param string                $content_fingerprint  Finding content fingerprint.
	 * @param string                $object_fingerprint   Object fingerprint.
	 * @param string                $title                Display title.
	 * @param string                $description          Detail sentence.
	 * @param array<string, mixed>  $metadata             Metadata payload.
	 * @return array<string, mixed>
	 */
	private function make_observation( $rule_id, $object_key, $blog_id, $risk_level, $content_fingerprint, $object_fingerprint, $title, $description, array $metadata ) {
		return array(
			'scanner_id'           => Sassh_Findings_Service::SCANNER_DATABASE_SCAN,
			'rule_id'              => $rule_id,
			'object_type'          => Sassh_Object_Type_Registry::TYPE_OPTION,
			'object_key'           => $object_key,
			'blog_id'              => (int) $blog_id,
			'risk_level'           => $risk_level,
			'sassh_classification' => Sassh_Findings_Service::default_classification( $risk_level ),
			'content_fingerprint'  => $content_fingerprint,
			'object_fingerprint'   => $object_fingerprint,
			'title'                => $title,
			'description'          => $description,
			'metadata'             => $metadata,
		);
	}

	/**
	 * Build the shared metadata payload for one observation.
	 *
	 * @param string               $option_name        Option name.
	 * @param int                  $option_id          Option id when known.
	 * @param string               $section_key        UI section / category key.
	 * @param string               $risk_level         Risk level for guidance lookup.
	 * @param int                  $size               Value size in bytes.
	 * @param string               $excerpt            Trimmed excerpt.
	 * @param string               $full_value         Capped full value for the detail panel.
	 * @param bool                 $contents_truncated Whether full_value was truncated.
	 * @param array<string, mixed> $extra              Additional rule-specific metadata.
	 * @return array<string, mixed>
	 */
	private function build_metadata( $option_name, $option_id, $section_key, $risk_level, $size, $excerpt, $full_value, $contents_truncated, array $extra = array() ) {
		$category_labels = Choctaw_Wp_Security_Options_Scan_Patterns::get_category_labels();
		$guidance         = Choctaw_Wp_Security_Options_Scan_Patterns::resolve_detail_guidance( $section_key, $risk_level );

		$metadata = array(
			'option_name'        => (string) $option_name,
			'option_id'          => (int) $option_id,
			'section_key'        => $section_key,
			'category'           => $section_key,
			'category_label'     => isset( $category_labels[ $section_key ] ) ? $category_labels[ $section_key ] : $section_key,
			'size'               => (int) $size,
			'excerpt'            => (string) $excerpt,
			'full_value'         => (string) $full_value,
			'contents_truncated' => (bool) $contents_truncated,
			'why_seeing_this'    => $guidance['why'],
			'how_to_proceed'     => $guidance['how'],
			'options_table'      => $this->options_table,
		);

		return array_merge( $metadata, $extra );
	}

	/**
	 * Scan site URL and security-related options.
	 *
	 * @param array<int, array<string, mixed>> $observations Observations list.
	 * @param int                               $blog_id      Mapped blog id.
	 * @return void
	 */
	private function scan_site_url_security( array &$observations, $blog_id ) {
		$home_raw    = $this->get_table_option_raw( 'home', '' );
		$siteurl_raw = $this->get_table_option_raw( 'siteurl', '' );
		$expected    = $this->get_expected_hosts();

		if ( '' !== $home_raw && '' !== $siteurl_raw ) {
			$home_host    = $this->normalize_host( $home_raw );
			$siteurl_host = $this->normalize_host( $siteurl_raw );

			if ( '' !== $home_host && '' !== $siteurl_host && $home_host !== $siteurl_host ) {
				$observations[] = $this->build_home_siteurl_mismatch_observation( $home_raw, $siteurl_raw, $home_host, $siteurl_host, $blog_id );
			}
		}

		foreach ( array( 'home' => $home_raw, 'siteurl' => $siteurl_raw ) as $option_name => $value ) {
			if ( '' === $value ) {
				continue;
			}

			$constant_name          = 'home' === $option_name ? 'WP_HOME' : 'WP_SITEURL';
			$rule_constant_mismatch = 'home' === $option_name ? Sassh_Findings_Service::RULE_HOME_CONSTANT_MISMATCH : Sassh_Findings_Service::RULE_SITEURL_CONSTANT_MISMATCH;
			$rule_external_host     = 'home' === $option_name ? Sassh_Findings_Service::RULE_HOME_EXTERNAL_HOST : Sassh_Findings_Service::RULE_SITEURL_EXTERNAL_HOST;

			if ( defined( $constant_name ) ) {
				$constant_host = $this->normalize_host( constant( $constant_name ) );
				$option_host   = $this->normalize_host( $value );

				if ( '' !== $constant_host && '' !== $option_host && $constant_host !== $option_host ) {
					$observations[] = $this->build_option_state_observation(
						$rule_constant_mismatch,
						$option_name,
						'site_url_security',
						$blog_id,
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
				$observations[] = $this->build_option_state_observation(
					$rule_external_host,
					$option_name,
					'site_url_security',
					$blog_id,
					sprintf(
						/* translators: %s: external host */
						__( 'Points to an unexpected external host: %s', 'choctaw-wp-security' ),
						$host
					),
					$value
				);
			}
		}

		$users_can_register_raw = $this->get_table_option_raw( 'users_can_register', '0' );

		if ( (bool) $this->get_table_option( 'users_can_register', false ) ) {
			$observations[] = $this->build_option_state_observation(
				Sassh_Findings_Service::RULE_USERS_CAN_REGISTER_ENABLED,
				'users_can_register',
				'site_url_security',
				$blog_id,
				__( 'Open user registration is enabled.', 'choctaw-wp-security' ),
				$users_can_register_raw,
				array( 'state_key' => 'users_can_register:1' )
			);
		}

		$default_role_raw = $this->get_table_option_raw( 'default_role', 'subscriber' );

		if ( 'administrator' === $default_role_raw ) {
			$observations[] = $this->build_option_state_observation(
				Sassh_Findings_Service::RULE_DEFAULT_ROLE_ADMINISTRATOR,
				'default_role',
				'site_url_security',
				$blog_id,
				__( 'Default role for new users is set to administrator.', 'choctaw-wp-security' ),
				$default_role_raw,
				array( 'state_key' => 'default_role:administrator' )
			);
		}

		$admin_email = $this->get_table_option_raw( 'admin_email', '' );

		if ( '' === $admin_email || ! is_email( $admin_email ) ) {
			$observations[] = $this->build_option_state_observation(
				Sassh_Findings_Service::RULE_ADMIN_EMAIL_INVALID,
				'admin_email',
				'site_url_security',
				$blog_id,
				__( 'Administrator email is empty or invalid.', 'choctaw-wp-security' ),
				$admin_email,
				array( 'state_key' => 'admin_email:' . $admin_email )
			);
		}

		$this->scan_critical_option_urls( $observations, $expected, $blog_id );
	}

	/**
	 * Build an observation for a single-option state/host/constant rule.
	 *
	 * @param string               $rule_id     Rule id.
	 * @param string               $option_name Option name.
	 * @param string               $section_key UI section key.
	 * @param int                  $blog_id     Mapped blog id.
	 * @param string               $description Detail sentence.
	 * @param string               $raw_value   Raw DB option value.
	 * @param array<string, mixed> $extra       Additional metadata; state_key overrides the finding fingerprint input.
	 * @return array<string, mixed>
	 */
	private function build_option_state_observation( $rule_id, $option_name, $section_key, $blog_id, $description, $raw_value, array $extra = array() ) {
		$risk_level = Sassh_Findings_Service::database_scan_risk_level( $rule_id );
		$object_key = Sassh_Option_Key_Normalizer::object_key_for_option( $option_name );
		$object_fp  = Sassh_Findings_Service::content_fingerprint_from_string( $raw_value );

		$state_key = isset( $extra['state_key'] ) ? (string) $extra['state_key'] : $raw_value;
		unset( $extra['state_key'] );
		$content_fp = Sassh_Findings_Service::content_fingerprint_from_string( $state_key );

		$prepared = $this->prepare_full_value( $raw_value );

		$metadata = $this->build_metadata(
			$option_name,
			$this->get_option_id_for_name( $option_name ),
			$section_key,
			$risk_level,
			strlen( $raw_value ),
			$this->trim_excerpt( $raw_value ),
			$prepared['contents'],
			! empty( $prepared['truncated'] ),
			$extra
		);

		return $this->make_observation(
			$rule_id,
			$object_key,
			$blog_id,
			$risk_level,
			$content_fp,
			$object_fp,
			$option_name,
			$description,
			$metadata
		);
	}

	/**
	 * Build the composite home/siteurl mismatch observation.
	 *
	 * @param string $home_raw     Raw home value.
	 * @param string $siteurl_raw  Raw siteurl value.
	 * @param string $home_host    Normalized home host.
	 * @param string $siteurl_host Normalized siteurl host.
	 * @param int    $blog_id      Mapped blog id.
	 * @return array<string, mixed>
	 */
	private function build_home_siteurl_mismatch_observation( $home_raw, $siteurl_raw, $home_host, $siteurl_host, $blog_id ) {
		$rule_id     = Sassh_Findings_Service::RULE_HOME_SITEURL_MISMATCH;
		$risk_level  = Sassh_Findings_Service::database_scan_risk_level( $rule_id );
		$object_key  = Sassh_Option_Key_Normalizer::object_key_home_siteurl();
		$fingerprint = 'sha256:' . Sassh_Findings_Service::hash_tuple( array( $home_raw, $siteurl_raw ) );

		$metadata = $this->build_metadata(
			'home / siteurl',
			0,
			'site_url_security',
			$risk_level,
			max( strlen( $home_raw ), strlen( $siteurl_raw ) ),
			'',
			'',
			false,
			array(
				'option_id_label' => $this->format_option_id_label( array( 'home', 'siteurl' ) ),
				'option_names'    => array( 'home', 'siteurl' ),
				'option_ids'      => array(
					'home'    => $this->get_option_id_for_name( 'home' ),
					'siteurl' => $this->get_option_id_for_name( 'siteurl' ),
				),
			)
		);

		return $this->make_observation(
			$rule_id,
			$object_key,
			$blog_id,
			$risk_level,
			$fingerprint,
			$fingerprint,
			'home / siteurl',
			sprintf(
				/* translators: 1: home host, 2: siteurl host */
				__( 'home (%1$s) and siteurl (%2$s) point to different hosts.', 'choctaw-wp-security' ),
				$home_host,
				$siteurl_host
			),
			$metadata
		);
	}

	/**
	 * Look for external domains in critical option values.
	 *
	 * @param array<int, array<string, mixed>> $observations Observations list.
	 * @param array<int, string>               $expected     Expected hosts.
	 * @param int                               $blog_id      Mapped blog id.
	 * @return void
	 */
	private function scan_critical_option_urls( array &$observations, array $expected, $blog_id ) {
		foreach ( Choctaw_Wp_Security_Options_Scan_Patterns::$critical_option_keys as $option_name ) {
			if ( in_array( $option_name, array( 'home', 'siteurl' ), true ) ) {
				continue;
			}

			$value = $this->get_table_option_raw( $option_name, null );

			if ( ! is_string( $value ) || '' === $value ) {
				continue;
			}

			$domains = $this->extract_external_domains( $value, $expected );

			if ( empty( $domains ) ) {
				continue;
			}

			$rule_id    = Sassh_Findings_Service::RULE_CRITICAL_OPTION_EXTERNAL_URL;
			$risk_level = Sassh_Findings_Service::database_scan_risk_level( $rule_id );
			$object_key = Sassh_Option_Key_Normalizer::object_key_for_option( $option_name );
			$fp         = Sassh_Findings_Service::content_fingerprint_from_string( $value );
			$prepared   = $this->prepare_full_value( $value );

			$metadata = $this->build_metadata(
				$option_name,
				$this->get_option_id_for_name( $option_name ),
				'site_url_security',
				$risk_level,
				strlen( $value ),
				$this->trim_excerpt( $value ),
				$prepared['contents'],
				! empty( $prepared['truncated'] ),
				array( 'external_domains' => $domains )
			);

			$observations[] = $this->make_observation(
				$rule_id,
				$object_key,
				$blog_id,
				$risk_level,
				$fp,
				$fp,
				$option_name,
				sprintf(
					/* translators: 1: option name, 2: comma-separated external domains */
					__( 'External domain found in %1$s: %2$s', 'choctaw-wp-security' ),
					$option_name,
					implode( ', ', $domains )
				),
				$metadata
			);
		}
	}

	/**
	 * Scan active_plugins consistency.
	 *
	 * @param array<int, array<string, mixed>> $observations Observations list.
	 * @param int                               $blog_id      Mapped blog id.
	 * @return void
	 */
	private function scan_active_plugins( array &$observations, $blog_id ) {
		$raw_value      = $this->get_table_option_raw( 'active_plugins', '' );
		$active_plugins = $this->get_table_option( 'active_plugins', array() );

		if ( ! is_array( $active_plugins ) ) {
			$rule_id    = Sassh_Findings_Service::RULE_ACTIVE_PLUGINS_INVALID;
			$risk_level = Sassh_Findings_Service::database_scan_risk_level( $rule_id );
			$fp         = Sassh_Findings_Service::content_fingerprint_from_string( $raw_value );
			$prepared   = $this->prepare_full_value( $raw_value );

			$metadata = $this->build_metadata(
				'active_plugins',
				$this->get_option_id_for_name( 'active_plugins' ),
				'active_plugins',
				$risk_level,
				strlen( $raw_value ),
				$this->trim_excerpt( $raw_value ),
				$prepared['contents'],
				! empty( $prepared['truncated'] )
			);

			$observations[] = $this->make_observation(
				$rule_id,
				Sassh_Option_Key_Normalizer::object_key_for_option( 'active_plugins' ),
				$blog_id,
				$risk_level,
				$fp,
				$fp,
				'active_plugins',
				__( 'active_plugins is not a valid array.', 'choctaw-wp-security' ),
				$metadata
			);
			return;
		}

		$plugins_dir        = wp_normalize_path( WP_PLUGIN_DIR );
		$active_plugins_fp  = Sassh_Findings_Service::content_fingerprint_from_string( $raw_value );

		foreach ( $active_plugins as $plugin_file ) {
			$plugin_file = (string) $plugin_file;

			if ( '' === $plugin_file ) {
				continue;
			}

			$plugin_path = wp_normalize_path( $plugins_dir . '/' . $plugin_file );

			if ( 0 !== strpos( $plugin_path, $plugins_dir . '/' ) ) {
				$observations[] = $this->build_active_plugin_observation(
					Sassh_Findings_Service::RULE_ACTIVE_PLUGIN_SUSPICIOUS_PATH,
					$plugin_file,
					$active_plugins_fp,
					$blog_id,
					sprintf(
						/* translators: %s: plugin path */
						__( 'Active plugin path is outside wp-content/plugins: %s', 'choctaw-wp-security' ),
						$plugin_file
					)
				);
				continue;
			}

			if ( ! file_exists( $plugin_path ) ) {
				$observations[] = $this->build_active_plugin_observation(
					Sassh_Findings_Service::RULE_ACTIVE_PLUGIN_MISSING,
					$plugin_file,
					$active_plugins_fp,
					$blog_id,
					sprintf(
						/* translators: %s: plugin file */
						__( 'Active plugin listed but file is missing: %s', 'choctaw-wp-security' ),
						$plugin_file
					)
				);
			}
		}
	}

	/**
	 * Build one active_plugins list-entry observation.
	 *
	 * @param string $rule_id            Rule id.
	 * @param string $plugin_file        Plugin relative path as stored.
	 * @param string $active_plugins_fp  Fingerprint of the full raw active_plugins value.
	 * @param int    $blog_id            Mapped blog id.
	 * @param string $description        Detail sentence.
	 * @return array<string, mixed>
	 */
	private function build_active_plugin_observation( $rule_id, $plugin_file, $active_plugins_fp, $blog_id, $description ) {
		$evidence   = ( Sassh_Findings_Service::RULE_ACTIVE_PLUGIN_SUSPICIOUS_PATH === $rule_id ) ? array( 'plugin_path' => $plugin_file ) : array();
		$risk_level = Sassh_Findings_Service::database_scan_risk_level( $rule_id, $evidence );
		$object_key = Sassh_Option_Key_Normalizer::object_key_for_active_plugin( $plugin_file );
		$content_fp = Sassh_Findings_Service::content_fingerprint_from_string( $plugin_file );

		$metadata = $this->build_metadata(
			'active_plugins',
			$this->get_option_id_for_name( 'active_plugins' ),
			'active_plugins',
			$risk_level,
			strlen( $plugin_file ),
			$this->trim_excerpt( $plugin_file ),
			$plugin_file,
			false,
			array( 'plugin_path' => $plugin_file )
		);

		return $this->make_observation(
			$rule_id,
			$object_key,
			$blog_id,
			$risk_level,
			$content_fp,
			$active_plugins_fp,
			$plugin_file,
			$description,
			$metadata
		);
	}

	/**
	 * Scan for large autoloaded options. Only rows at or above
	 * AUTOLOAD_SIZE_THRESHOLD become Findings; smaller rows are summarized
	 * as informational execution metadata only.
	 *
	 * @param array<int, array<string, mixed>> $observations Observations list.
	 * @param int                               $blog_id      Mapped blog id.
	 * @return array{stats: array<string, int>, top_below_threshold: array<int, array<string, mixed>>}
	 */
	private function scan_large_autoload( array &$observations, $blog_id ) {
		global $wpdb;

		$result = array(
			'stats'               => array(
				'count'                      => 0,
				'total_bytes'                => 0,
				'count_over_threshold'       => 0,
				'total_bytes_over_threshold' => 0,
			),
			'top_below_threshold' => array(),
		);

		if ( $this->is_time_exceeded() ) {
			$this->scan_incomplete = true;
			return $result;
		}

		$table = $this->get_options_table_sql();
		$rows  = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_id, option_name, LENGTH(option_value) AS option_size
				FROM {$table}
				WHERE autoload = %s
				ORDER BY option_size DESC",
				'yes'
			),
			ARRAY_A
		);

		if ( ! is_array( $rows ) ) {
			return $result;
		}

		$threshold       = (int) Choctaw_Wp_Security_Options_Scan_Patterns::AUTOLOAD_SIZE_THRESHOLD;
		$top_limit       = (int) Choctaw_Wp_Security_Options_Scan_Patterns::AUTOLOAD_TOP_LIMIT;
		$below_threshold = array();

		foreach ( $rows as $row ) {
			$option_name = isset( $row['option_name'] ) ? (string) $row['option_name'] : '';
			$option_size = isset( $row['option_size'] ) ? (int) $row['option_size'] : 0;

			if ( '' === $option_name ) {
				continue;
			}

			++$result['stats']['count'];
			$result['stats']['total_bytes'] += $option_size;

			if ( $option_size >= $threshold ) {
				++$result['stats']['count_over_threshold'];
				$result['stats']['total_bytes_over_threshold'] += $option_size;

				$observation = $this->build_large_autoload_observation( $option_name, $option_size, $blog_id );

				if ( null === $observation ) {
					++$this->hash_failures;
				} else {
					$observations[] = $observation;
				}
			} else {
				$below_threshold[] = array(
					'option_name' => $option_name,
					'size'        => $option_size,
				);
			}

			if ( $this->is_time_exceeded() ) {
				$this->scan_incomplete = true;
				break;
			}
		}

		$result['top_below_threshold'] = array_slice( $below_threshold, 0, $top_limit );

		return $result;
	}

	/**
	 * Build one large-autoload observation.
	 *
	 * @param string $option_name Option name.
	 * @param int    $option_size Value size in bytes.
	 * @param int    $blog_id     Mapped blog id.
	 * @return array<string, mixed>|null Null when the raw value cannot be read.
	 */
	private function build_large_autoload_observation( $option_name, $option_size, $blog_id ) {
		$raw_value = $this->get_table_option_raw( $option_name, null );

		if ( null === $raw_value ) {
			return null;
		}

		$rule_id    = Sassh_Findings_Service::RULE_LARGE_AUTOLOAD_OPTION;
		$risk_level = Sassh_Findings_Service::database_scan_risk_level( $rule_id );
		$object_key = Sassh_Option_Key_Normalizer::object_key_for_option( $option_name );
		$object_fp  = Sassh_Findings_Service::content_fingerprint_from_string( $raw_value );
		$content_fp = Sassh_Findings_Service::content_fingerprint_from_string( $option_size . ':' . $raw_value );
		$prepared   = $this->prepare_full_value( $raw_value );

		$metadata = $this->build_metadata(
			$option_name,
			$this->get_option_id_for_name( $option_name ),
			'large_autoload',
			$risk_level,
			$option_size,
			$this->format_value_preview( $raw_value, $option_size, Choctaw_Wp_Security_Options_Scan_Patterns::LARGE_AUTOLOAD_PREVIEW_LENGTH ),
			$prepared['contents'],
			! empty( $prepared['truncated'] )
		);

		return $this->make_observation(
			$rule_id,
			$object_key,
			$blog_id,
			$risk_level,
			$content_fp,
			$object_fp,
			$option_name,
			sprintf(
				/* translators: %s: formatted option size */
				__( 'Autoloaded option size: %s', 'choctaw-wp-security' ),
				size_format( $option_size )
			),
			$metadata
		);
	}

	/**
	 * Scan for PHP tags and execution/obfuscation patterns.
	 *
	 * @param array<int, array<string, mixed>> $observations Observations list.
	 * @param int                               $blog_id      Mapped blog id.
	 * @return void
	 */
	private function scan_php_execution_patterns( array &$observations, $blog_id ) {
		$tag_patterns  = Choctaw_Wp_Security_Options_Scan_Patterns::$php_tag_patterns;
		$exec_patterns = Choctaw_Wp_Security_Options_Scan_Patterns::$execution_patterns;

		$this->scan_option_patterns(
			array_merge( $tag_patterns, $exec_patterns ),
			$observations,
			$blog_id,
			Sassh_Findings_Service::RULE_PHP_EXECUTION_PATTERNS_MATCH,
			'php_execution_patterns',
			true,
			false,
			array(
				'php_tag_patterns'   => $tag_patterns,
				'execution_patterns' => $exec_patterns,
			)
		);
	}

	/**
	 * Scan for known-malware option names.
	 *
	 * @param array<int, array<string, mixed>> $observations Observations list.
	 * @param int                               $blog_id      Mapped blog id.
	 * @return void
	 */
	private function scan_malware_option_names( array &$observations, $blog_id ) {
		global $wpdb;

		if ( $this->is_time_exceeded() ) {
			$this->scan_incomplete = true;
			return;
		}

		$names = Choctaw_Wp_Security_Options_Scan_Patterns::$malware_option_names;

		if ( empty( $names ) ) {
			return;
		}

		$table        = $this->get_options_table_sql();
		$placeholders = implode( ', ', array_fill( 0, count( $names ), '%s' ) );
		$sql          = "SELECT option_id, option_name, option_value
			FROM {$table}
			WHERE option_name IN ({$placeholders})";
		$args         = array_merge( array( $sql ), $names );
		$query        = call_user_func_array( array( $wpdb, 'prepare' ), $args );

		$rows = $wpdb->get_results( $query, ARRAY_A );

		if ( ! is_array( $rows ) ) {
			return;
		}

		$rule_id    = Sassh_Findings_Service::RULE_MALWARE_OPTION_NAME;
		$risk_level = Sassh_Findings_Service::database_scan_risk_level( $rule_id );

		foreach ( $rows as $row ) {
			$option_name = isset( $row['option_name'] ) ? (string) $row['option_name'] : '';

			if ( '' === $option_name ) {
				continue;
			}

			$raw_value  = isset( $row['option_value'] ) ? (string) $row['option_value'] : '';
			$object_fp  = Sassh_Findings_Service::content_fingerprint_from_string( $raw_value );
			$content_fp = Sassh_Findings_Service::content_fingerprint_from_string( 'malware_option_name:' . $option_name );
			$prepared   = $this->prepare_full_value( $raw_value );

			$metadata = $this->build_metadata(
				$option_name,
				isset( $row['option_id'] ) ? (int) $row['option_id'] : $this->get_option_id_for_name( $option_name ),
				'malware_option_names',
				$risk_level,
				strlen( $raw_value ),
				$this->trim_excerpt( $raw_value ),
				$prepared['contents'],
				! empty( $prepared['truncated'] )
			);

			$observations[] = $this->make_observation(
				$rule_id,
				Sassh_Option_Key_Normalizer::object_key_for_option( $option_name ),
				$blog_id,
				$risk_level,
				$content_fp,
				$object_fp,
				$option_name,
				__( 'Option name matches a pattern commonly used by malware.', 'choctaw-wp-security' ),
				$metadata
			);
		}
	}

	/**
	 * Scan for script and iframe patterns outside widget/theme options.
	 *
	 * @param array<int, array<string, mixed>> $observations Observations list.
	 * @param int                               $blog_id      Mapped blog id.
	 * @return void
	 */
	private function scan_scripts_non_widget( array &$observations, $blog_id ) {
		$this->scan_option_patterns(
			Choctaw_Wp_Security_Options_Scan_Patterns::$script_patterns,
			$observations,
			$blog_id,
			Sassh_Findings_Service::RULE_SCRIPTS_NON_WIDGET_MATCH,
			'scripts_non_widget',
			true,
			true
		);
	}

	/**
	 * Run pattern scans against option values, collecting all matching
	 * patterns per option (not just the first) and deduplicating one
	 * observation per option name.
	 *
	 * @param array<int, string>                $patterns             Patterns to search.
	 * @param array<int, array<string, mixed>>  $observations         Observations list.
	 * @param int                                $blog_id              Mapped blog id.
	 * @param string                             $rule_id              Rule id.
	 * @param string                             $section_key          UI section key.
	 * @param bool                               $exclude_transients   Whether to skip transients.
	 * @param bool                               $exclude_widget_theme Whether to skip widget/theme options.
	 * @param array<string, mixed>               $risk_evidence_lists  Additional evidence lists passed to the risk resolver.
	 * @return void
	 */
	private function scan_option_patterns( array $patterns, array &$observations, $blog_id, $rule_id, $section_key, $exclude_transients, $exclude_widget_theme = false, array $risk_evidence_lists = array() ) {
		global $wpdb;

		if ( empty( $patterns ) || $this->is_time_exceeded() ) {
			if ( $this->is_time_exceeded() ) {
				$this->scan_incomplete = true;
			}
			return;
		}

		$table         = $this->get_options_table_sql();
		$where_clauses = array();
		$where_values  = array();

		foreach ( $patterns as $pattern ) {
			$where_clauses[] = 'option_value LIKE %s';
			$where_values[]  = '%' . $wpdb->esc_like( $pattern ) . '%';
		}

		$sql = 'SELECT option_id, option_name, option_value
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

			$matched_patterns = $this->find_all_matching_patterns( $option_value, $patterns );

			if ( empty( $matched_patterns ) ) {
				continue;
			}

			$seen[ $option_name ] = true;

			$evidence = array_merge(
				array( 'matched_patterns' => $matched_patterns ),
				$risk_evidence_lists
			);

			$risk_level = Sassh_Findings_Service::database_scan_risk_level( $rule_id, $evidence );
			$object_key = Sassh_Option_Key_Normalizer::object_key_for_option( $option_name );
			$fp         = Sassh_Findings_Service::content_fingerprint_from_string( $option_value );
			$prepared   = $this->prepare_full_value( $option_value );

			$metadata = $this->build_metadata(
				$option_name,
				isset( $row['option_id'] ) ? (int) $row['option_id'] : $this->get_option_id_for_name( $option_name ),
				$section_key,
				$risk_level,
				strlen( $option_value ),
				$this->extract_excerpt( $option_value, $matched_patterns[0] ),
				$prepared['contents'],
				! empty( $prepared['truncated'] ),
				array( 'matched_patterns' => $matched_patterns )
			);

			$observations[] = $this->make_observation(
				$rule_id,
				$object_key,
				$blog_id,
				$risk_level,
				$fp,
				$fp,
				$option_name,
				sprintf(
					/* translators: %s: comma-separated matched patterns */
					__( 'Matched pattern(s): %s', 'choctaw-wp-security' ),
					implode( ', ', $matched_patterns )
				),
				$metadata
			);
		}
	}

	/**
	 * Build the Findings-backed report DTO for the admin UI.
	 *
	 * @param Sassh_Findings_Service $service      Service.
	 * @param int                    $execution_id Execution id.
	 * @param array<string, mixed>   $run_meta     Run summary fields.
	 * @return array<string, mixed>
	 */
	private function build_report_from_findings( Sassh_Findings_Service $service, $execution_id, array $run_meta ) {
		$completion  = isset( $run_meta['completion_status'] ) ? (string) $run_meta['completion_status'] : 'failed';
		$coverage_ok = ( 'success' === $completion );

		$rows = $service->list_findings(
			array(
				'scanner_id'      => Sassh_Findings_Service::SCANNER_DATABASE_SCAN,
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
			if ( isset( $row['options_table'] ) && '' !== (string) $row['options_table'] && (string) $row['options_table'] !== $this->options_table ) {
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

			$option_name = isset( $row['option_name'] ) ? (string) $row['option_name'] : (string) $row['object_key'];

			$findings[] = array(
				'id'                  => $row['finding_id'],
				'finding_id'          => $row['finding_id'],
				'fingerprint'         => $row['content_fingerprint'],
				'content_fingerprint' => $row['content_fingerprint'],
				'object_fingerprint'  => $row['object_fingerprint'],
				'rule_id'             => isset( $row['rule_id'] ) ? $row['rule_id'] : '',
				'title'               => isset( $row['title'] ) ? $row['title'] : $option_name,
				'option_name'         => $option_name,
				'option_id'           => isset( $row['option_id'] ) ? (int) $row['option_id'] : 0,
				'option_id_label'     => isset( $row['option_id_label'] ) ? (string) $row['option_id_label'] : '',
				'size'                => isset( $row['size'] ) ? (int) $row['size'] : 0,
				'detail'              => isset( $row['description'] ) ? (string) $row['description'] : '',
				'description'         => isset( $row['description'] ) ? (string) $row['description'] : '',
				'excerpt'             => isset( $row['excerpt'] ) ? (string) $row['excerpt'] : '',
				'full_value'          => isset( $row['full_value'] ) ? (string) $row['full_value'] : '',
				'contents_truncated'  => ! empty( $row['contents_truncated'] ),
				'risk'                => $risk,
				'risk_level'          => $risk,
				'risk_label'          => isset( $row['risk_label'] ) ? $row['risk_label'] : $risk,
				'status'              => $row['effective_status'],
				'status_label'        => $row['status_label'],
				'effective_status'    => $row['effective_status'],
				'category'            => isset( $row['category'] ) ? $row['category'] : '',
				'category_label'      => isset( $row['category_label'] ) ? $row['category_label'] : '',
				'section_key'         => isset( $row['section_key'] ) ? $row['section_key'] : '',
				'why_seeing_this'     => isset( $row['why_seeing_this'] ) ? $row['why_seeing_this'] : '',
				'how_to_proceed'      => isset( $row['how_to_proceed'] ) ? $row['how_to_proceed'] : '',
				'matched_patterns'    => ( isset( $row['matched_patterns'] ) && is_array( $row['matched_patterns'] ) ) ? $row['matched_patterns'] : array(),
				'plugin_path'         => isset( $row['plugin_path'] ) ? $row['plugin_path'] : '',
				'options_table'       => isset( $row['options_table'] ) ? $row['options_table'] : $this->options_table,
				'blog_id'             => isset( $row['blog_id'] ) ? (int) $row['blog_id'] : null,
				'first_seen_at'       => $row['first_seen_at'],
				'last_seen_at'        => $row['last_seen_at'],
				'detection_state'     => $row['detection_state'],
				'confirmed_this_run'  => $confirmed_this_run,
				'findings_backend'    => 'sassh',
			);
		}

		$count   = count( $findings );
		$flagged = $critical + $warning + $suspicious;

		$result = array(
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
			'scanned_at'                 => time(),
			'execution_id'               => $execution_id,
			'findings_backend'           => 'sassh',
			'options_table'              => $this->options_table,
			'wordpress_configured_table' => Choctaw_Wp_Security_Options_Table_Discovery::get_wordpress_configured_table(),
		);

		if ( ! empty( $run_meta['autoload_meta'] ) && is_array( $run_meta['autoload_meta'] ) ) {
			$result['autoload_meta'] = $run_meta['autoload_meta'];
		}

		return $result;
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
		$domains = array();
		$pattern = '#https?://([^/\s\'"]+)#i';
		$matches = array();
		$matched = preg_match_all( $pattern, $value, $matches );

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
	 * Find all matching patterns in a value (not only the first).
	 *
	 * @param string             $value    Value to inspect.
	 * @param array<int, string> $patterns Patterns to search.
	 * @return array<int, string>
	 */
	private function find_all_matching_patterns( $value, array $patterns ) {
		$matches = array();

		foreach ( $patterns as $pattern ) {
			if ( false !== stripos( $value, $pattern ) ) {
				$matches[] = $pattern;
			}
		}

		return $matches;
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
			'SELECT option_id, option_name FROM ' . $this->get_options_table_sql(),
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
	 * Cap a full option value for the expandable detail panel.
	 *
	 * @param string $value Raw option value.
	 * @return array{contents:string,truncated:bool}
	 */
	private function prepare_full_value( $value ) {
		return Choctaw_Wp_Security_Utils::truncate_report_contents_result( (string) $value );
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
