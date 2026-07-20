<?php
/**
 * Plugin settings and admin UI.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Registers settings and renders the admin page.
 */
class Choctaw_Wp_Security_Settings {

	/**
	 * Register admin hooks.
	 *
	 * @return void
	 */
	public function register_hooks() {
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		if ( is_multisite() ) {
			add_action( 'network_admin_menu', array( $this, 'register_menu' ) );
			add_action( 'network_admin_edit_sassh_save_settings', array( $this, 'handle_network_settings_save' ) );
		} else {
			add_action( 'admin_menu', array( $this, 'register_menu' ) );
		}
		add_action( 'admin_head', array( $this, 'hide_admin_submenu_css' ) );
		add_action( 'network_admin_head', array( $this, 'hide_admin_submenu_css' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_menu_assets' ) );
		add_action( 'network_admin_enqueue_scripts', array( $this, 'enqueue_admin_menu_assets' ) );
		add_filter( 'parent_file', array( $this, 'filter_admin_parent_file' ) );
		// Scan load handlers are registered from register_menu() using the real
		// submenu hook suffix WordPress returns (derived from the menu title).
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
		add_action( 'network_admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
		add_action( 'wp_ajax_choctaw_wp_security_database_scan', array( $this, 'ajax_database_scan' ) );
		add_action( 'wp_ajax_choctaw_wp_security_database_scan_baseline_reset', array( $this, 'ajax_database_scan_baseline_reset' ) );
		add_action( 'wp_ajax_choctaw_wp_security_scheduled_tasks_scan', array( $this, 'ajax_scheduled_tasks_scan' ) );
		add_action( 'wp_ajax_choctaw_wp_security_posts_scan', array( $this, 'ajax_posts_scan' ) );
		add_action( 'wp_ajax_choctaw_wp_security_posts_scan_baseline_reset', array( $this, 'ajax_posts_scan_baseline_reset' ) );
		add_action( 'wp_ajax_choctaw_wp_security_uploads_folder_scan', array( $this, 'ajax_uploads_folder_scan' ) );
		add_action( 'wp_ajax_choctaw_wp_security_mu_plugins_scan', array( $this, 'ajax_mu_plugins_scan' ) );
		add_action( 'wp_ajax_choctaw_wp_security_exposed_files_scan', array( $this, 'ajax_exposed_files_scan' ) );
		add_action( 'wp_ajax_choctaw_wp_security_directory_browsing_scan', array( $this, 'ajax_directory_browsing_scan' ) );
		add_action( 'wp_ajax_choctaw_wp_security_users_table_load', array( $this, 'ajax_users_table_load' ) );
		add_action( 'wp_ajax_choctaw_wp_security_user_activity_load', array( $this, 'ajax_user_activity_load' ) );
		add_action( 'wp_ajax_choctaw_wp_security_user_usermeta_load', array( $this, 'ajax_user_usermeta_load' ) );
		add_action( 'wp_ajax_choctaw_wp_security_user_file_activity_load', array( $this, 'ajax_user_file_activity_load' ) );
		add_action( 'wp_ajax_choctaw_wp_security_file_changes_checksum', array( $this, 'ajax_file_changes_checksum' ) );
		add_action( 'wp_ajax_choctaw_wp_security_finding_dismiss', array( $this, 'ajax_finding_dismiss' ) );
		add_action( 'wp_ajax_choctaw_wp_security_finding_undismiss', array( $this, 'ajax_finding_undismiss' ) );
		add_action( 'wp_ajax_choctaw_wp_security_finding_clear_history', array( $this, 'ajax_finding_clear_history' ) );
		add_action( 'wp_ajax_sassh_finding_dismiss', array( $this, 'ajax_sassh_finding_dismiss' ) );
		add_action( 'wp_ajax_sassh_finding_undismiss', array( $this, 'ajax_sassh_finding_undismiss' ) );
		add_action( 'wp_ajax_sassh_finding_related', array( $this, 'ajax_sassh_finding_related' ) );
	}

	/**
	 * Register settings with the WordPress Settings API.
	 *
	 * @return void
	 */
	public function register_settings() {
		register_setting(
			'choctaw_wp_security',
			Choctaw_Wp_Security_Utils::OPTION_KEY,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_options' ),
				'default'           => Choctaw_Wp_Security_Utils::default_options(),
			)
		);

		add_settings_section(
			'choctaw_wp_security_xmlrpc',
			__( 'Disable XML-RPC', 'choctaw-wp-security' ),
			array( $this, 'render_xmlrpc_section' ),
			'sassh-settings'
		);

		add_settings_field(
			'xmlrpc_blocking_enabled',
			'',
			array( $this, 'render_xmlrpc_blocking_field' ),
			'sassh-settings',
			'choctaw_wp_security_xmlrpc',
			array(
				'label_for' => 'xmlrpc_blocking_enabled',
				'option'    => 'xmlrpc_blocking_enabled',
				'label'     => __( 'Block XML-RPC requests', 'choctaw-wp-security' ),
				'help_id'   => 'xmlrpc_blocking',
			)
		);

		add_settings_section(
			'choctaw_wp_security_uploads_php',
			__( 'Disable PHP Execution in Uploads', 'choctaw-wp-security' ),
			array( $this, 'render_uploads_php_section' ),
			'sassh-settings'
		);

		add_settings_field(
			'uploads_php_lockdown_enabled',
			'',
			array( $this, 'render_uploads_lockdown_field' ),
			'sassh-settings',
			'choctaw_wp_security_uploads_php',
			array(
				'label_for' => 'uploads_php_lockdown_enabled',
				'option'    => 'uploads_php_lockdown_enabled',
				'label'     => __( 'Disable PHP Execution in Uploads', 'choctaw-wp-security' ),
				'help_id'   => 'uploads_php_lockdown',
			)
		);

		add_settings_section(
			'choctaw_wp_security_username_discovery',
			__( 'Reduce Username Exposure', 'choctaw-wp-security' ),
			array( $this, 'render_username_discovery_section' ),
			'sassh-settings'
		);

		add_settings_field(
			'block_user_rest_api_enabled',
			'',
			array( $this, 'render_security_feature_field' ),
			'sassh-settings',
			'choctaw_wp_security_username_discovery',
			array(
				'label_for' => 'block_user_rest_api_enabled',
				'option'    => 'block_user_rest_api_enabled',
				'label'     => __( 'Block anonymous access to User REST API', 'choctaw-wp-security' ),
				'help_id'   => 'block_user_rest_api',
			)
		);

		add_settings_field(
			'block_author_query_enabled',
			'',
			array( $this, 'render_security_feature_field' ),
			'sassh-settings',
			'choctaw_wp_security_username_discovery',
			array(
				'label_for' => 'block_author_query_enabled',
				'option'    => 'block_author_query_enabled',
				'label'     => __( 'Block anonymous access to user enumeration', 'choctaw-wp-security' ),
				'help_id'   => 'block_author_query',
			)
		);

		add_settings_field(
			'block_author_archives_enabled',
			'',
			array( $this, 'render_security_feature_field' ),
			'sassh-settings',
			'choctaw_wp_security_username_discovery',
			array(
				'label_for' => 'block_author_archives_enabled',
				'option'    => 'block_author_archives_enabled',
				'label'     => __( 'Block anonymous access to author archive pages', 'choctaw-wp-security' ),
				'help_id'   => 'block_author_archives',
			)
		);

		add_settings_field(
			'normalize_login_errors_enabled',
			'',
			array( $this, 'render_security_feature_field' ),
			'sassh-settings',
			'choctaw_wp_security_username_discovery',
			array(
				'label_for' => 'normalize_login_errors_enabled',
				'option'    => 'normalize_login_errors_enabled',
				'label'     => __( 'Normalize failed login error message', 'choctaw-wp-security' ),
				'help_id'   => 'normalize_login_errors',
			)
		);

		add_settings_section(
			'choctaw_wp_security_policy',
			__( 'Login Rate Limiting', 'choctaw-wp-security' ),
			array( $this, 'render_policy_section' ),
			'sassh-settings'
		);

		add_settings_field(
			'login_rate_limit_enabled',
			'',
			array( $this, 'render_security_feature_field' ),
			'sassh-settings',
			'choctaw_wp_security_policy',
			array(
				'label_for' => 'login_rate_limit_enabled',
				'option'    => 'login_rate_limit_enabled',
				'label'     => __( 'Enable login rate limiting', 'choctaw-wp-security' ),
				'help_id'   => 'login_rate_limit',
			)
		);

		add_settings_field(
			'allowed_failed_attempts',
			'',
			array( $this, 'render_policy_number_field' ),
			'sassh-settings',
			'choctaw_wp_security_policy',
			array(
				'label_for' => 'allowed_failed_attempts',
				'option'    => 'allowed_failed_attempts',
				'label'     => __( 'Allowed Failed Attempts', 'choctaw-wp-security' ),
				'min'       => 1,
				'max'       => 100,
				'step'      => 1,
				'help_id'   => 'allowed_failed_attempts',
			)
		);

		add_settings_field(
			'failure_window_minutes',
			'',
			array( $this, 'render_policy_number_field' ),
			'sassh-settings',
			'choctaw_wp_security_policy',
			array(
				'label_for' => 'failure_window_minutes',
				'option'    => 'failure_window_minutes',
				'label'     => __( 'Failure Window (minutes)', 'choctaw-wp-security' ),
				'min'       => 1,
				'max'       => 1440,
				'step'      => 1,
				'help_id'   => 'failure_window_minutes',
			)
		);

		add_settings_field(
			'lockout_duration_minutes',
			'',
			array( $this, 'render_policy_number_field' ),
			'sassh-settings',
			'choctaw_wp_security_policy',
			array(
				'label_for' => 'lockout_duration_minutes',
				'option'    => 'lockout_duration_minutes',
				'label'     => __( 'Lockout Duration (minutes)', 'choctaw-wp-security' ),
				'min'       => 1,
				'max'       => 1440,
				'step'      => 1,
				'help_id'   => 'lockout_duration_minutes',
			)
		);

		add_settings_section(
			'choctaw_wp_security_table_prefix',
			__( 'WordPress Tables', 'choctaw-wp-security' ),
			array( $this, 'render_table_prefix_section' ),
			'sassh-settings'
		);

		add_settings_field(
			'database_scan_table_prefix',
			'',
			array( $this, 'render_table_prefix_field' ),
			'sassh-settings',
			'choctaw_wp_security_table_prefix',
			array(
				'label_for' => 'database_scan_table_prefix',
			)
		);
	}

	/**
	 * Add Sassh as a single top-level admin menu.
	 *
	 * Section pages stay registered under the Sassh parent for routing and
	 * capability checks. The WordPress submenu flyout is hidden via
	 * {@see hide_admin_submenu_css()} so only the top-level item is visible.
	 *
	 * @return void
	 */
	public function register_menu() {
		$capability = is_multisite() ? 'manage_network_options' : 'manage_options';

		add_menu_page(
			__( 'Sassh', 'choctaw-wp-security' ),
			__( 'Sassh Security', 'choctaw-wp-security' ),
			$capability,
			'sassh',
			array( $this, 'render_home_page' ),
			$this->get_admin_menu_icon_url(),
			80
		);

		add_submenu_page(
			'sassh',
			__( 'Sassh', 'choctaw-wp-security' ),
			__( 'Home', 'choctaw-wp-security' ),
			$capability,
			'sassh',
			array( $this, 'render_home_page' )
		);

		add_submenu_page(
			'sassh',
			__( 'Sassh Settings', 'choctaw-wp-security' ),
			__( 'Settings', 'choctaw-wp-security' ),
			$capability,
			'sassh-settings',
			array( $this, 'render_settings_page' )
		);

		$scans_hook = add_submenu_page(
			'sassh',
			__( 'Sassh Scans', 'choctaw-wp-security' ),
			__( 'Scans', 'choctaw-wp-security' ),
			$capability,
			'sassh-scans',
			array( $this, 'render_scans_page' )
		);

		add_submenu_page(
			'sassh',
			__( 'About Sassh', 'choctaw-wp-security' ),
			__( 'About', 'choctaw-wp-security' ),
			$capability,
			'sassh-about',
			array( $this, 'render_about_page' )
		);

		if ( is_string( $scans_hook ) && '' !== $scans_hook ) {
			add_action( 'load-' . $scans_hook, array( $this, 'handle_core_checksum_scan' ) );
			add_action( 'load-' . $scans_hook, array( $this, 'handle_component_scan' ) );
			add_action( 'load-' . $scans_hook, array( $this, 'handle_exposed_folders_scan' ) );
			add_action( 'load-' . $scans_hook, array( $this, 'handle_database_scan' ) );
			add_action( 'load-' . $scans_hook, array( $this, 'handle_database_scan_baseline_reset' ) );
			add_action( 'load-' . $scans_hook, array( $this, 'handle_scheduled_tasks_scan' ) );
			add_action( 'load-' . $scans_hook, array( $this, 'handle_posts_scan' ) );
			add_action( 'load-' . $scans_hook, array( $this, 'handle_posts_scan_baseline_reset' ) );
			add_action( 'load-' . $scans_hook, array( $this, 'handle_uploads_folder_scan' ) );
			add_action( 'load-' . $scans_hook, array( $this, 'handle_mu_plugins_scan' ) );
			add_action( 'load-' . $scans_hook, array( $this, 'handle_exposed_files_scan' ) );
			add_action( 'load-' . $scans_hook, array( $this, 'handle_users_table_load' ) );
		}
	}

	/**
	 * Hide the Sassh WordPress submenu flyout on all admin screens.
	 *
	 * Submenu pages must remain in `$submenu` so WordPress can authorize them;
	 * CSS hides the flyout so only the top-level Sassh item is shown.
	 * Pair with {@see enqueue_admin_menu_assets()} so mobile taps still navigate.
	 *
	 * @return void
	 */
	public function hide_admin_submenu_css() {
		echo '<style id="cws-hide-admin-submenu">#toplevel_page_sassh .wp-submenu{display:none!important;}</style>' . "\n";
	}

	/**
	 * Enqueue a small script so the Sassh top-level menu item navigates on mobile.
	 *
	 * Loaded on all admin screens (not only Sassh pages) because the user
	 * must be able to open Sassh from anywhere in wp-admin.
	 *
	 * @return void
	 */
	public function enqueue_admin_menu_assets() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			return;
		}

		wp_enqueue_script(
			'choctaw-wp-security-admin-wp-menu',
			CHOCTAW_WP_SECURITY_URL . 'assets/js/admin-wp-menu.js',
			array(),
			(string) filemtime( CHOCTAW_WP_SECURITY_PATH . 'assets/js/admin-wp-menu.js' ),
			true
		);
	}

	/**
	 * Keep the Sassh top-level menu highlighted on all plugin pages.
	 *
	 * @param string $parent_file Current parent file.
	 * @return string
	 */
	public function filter_admin_parent_file( $parent_file ) {
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';

		if ( in_array( $page, array( 'sassh', 'sassh-settings', 'sassh-scans', 'sassh-about' ), true ) ) {
			return 'sassh';
		}

		return $parent_file;
	}

	/**
	 * Get the admin menu icon as a base64 SVG data URI.
	 *
	 * WordPress svg-painter.js recolors filled SVG menu icons to match the
	 * admin color scheme (same behavior as Dashicons).
	 *
	 * @return string
	 */
	private function get_admin_menu_icon_url() {
		$svg_path = CHOCTAW_WP_SECURITY_PATH . 'assets/images/sassh-20.svg';

		if ( ! is_readable( $svg_path ) ) {
			return 'dashicons-shield';
		}

		$svg = file_get_contents( $svg_path );

		if ( false === $svg || '' === $svg ) {
			return 'dashicons-shield';
		}

		// Strip XML declaration; keep a compact SVG with a paintable fill.
		$svg = preg_replace( '/<\?xml[^>]*\?>\s*/', '', $svg );
		$svg = preg_replace( '/fill="#(?:ffffff|FFFFFF|000000|000)"/', 'fill="black"', $svg );
		$svg = preg_replace( '/\s+/', ' ', trim( $svg ) );

		return 'data:image/svg+xml;base64,' . base64_encode( $svg );
	}

	/**
	 * Build a Sassh admin page URL.
	 *
	 * @param string               $page_slug Page slug.
	 * @param array<string, mixed> $args      Extra query args.
	 * @return string
	 */
	private function get_admin_page_url( $page_slug, array $args = array() ) {
		$args = array_merge( array( 'page' => $page_slug ), $args );
		$base = is_multisite() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' );

		return add_query_arg( $args, $base );
	}

	/**
	 * Build a Scans submenu URL with optional tab and extra args.
	 *
	 * @param string               $tab  Scan tab key.
	 * @param array<string, mixed> $args Extra query args.
	 * @return string
	 */
	private function get_scans_page_url( $tab = '', array $args = array() ) {
		if ( '' !== $tab ) {
			$args['cws_tab'] = $tab;
		}

		return $this->get_admin_page_url( 'sassh-scans', $args );
	}

	/**
	 * Current Sassh admin page slug from the request, if any.
	 *
	 * @return string
	 */
	private function get_current_admin_page_slug() {
		return isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	}

	/**
	 * Whether the current admin screen is a Sassh page.
	 *
	 * Prefer the `page` query arg: WordPress submenu hook suffixes use
	 * sanitize_title( menu title ), so "Sassh Security" becomes
	 * `sassh-security_page_*` rather than `sassh_page_*`.
	 *
	 * @param string $hook_suffix Current admin page hook suffix.
	 * @return bool
	 */
	private function is_coreguard_admin_page( $hook_suffix ) {
		$page = $this->get_current_admin_page_slug();

		if ( in_array( $page, array( 'sassh', 'sassh-settings', 'sassh-scans', 'sassh-about' ), true ) ) {
			return true;
		}

		if ( 'toplevel_page_sassh' === $hook_suffix ) {
			return true;
		}

		return is_string( $hook_suffix ) && preg_match( '/_page_sassh(-(settings|scans|about))?$/', $hook_suffix );
	}

	/**
	 * Whether the current admin screen is the Scans page.
	 *
	 * @param string $hook_suffix Current admin page hook suffix.
	 * @return bool
	 */
	private function is_scans_admin_page( $hook_suffix ) {
		if ( 'sassh-scans' === $this->get_current_admin_page_slug() ) {
			return true;
		}

		return is_string( $hook_suffix ) && preg_match( '/_page_sassh-scans$/', $hook_suffix );
	}

	/**
	 * Sanitize submitted option values.
	 *
	 * @param mixed $input Raw submitted options.
	 * @return array<string, mixed>
	 */
	public function sanitize_options( $input ) {
		$existing = Choctaw_Wp_Security_Utils::get_options();
		$input    = is_array( $input ) ? $input : array();

		$sanitized = array_merge(
			$existing,
			array(
				'xmlrpc_blocking_enabled'        => ! empty( $input['xmlrpc_blocking_enabled'] ),
				'login_rate_limit_enabled'       => ! empty( $input['login_rate_limit_enabled'] ),
				'uploads_php_lockdown_enabled'   => $this->sanitize_uploads_php_lockdown_enabled( $input ),
				'block_user_rest_api_enabled'    => ! empty( $input['block_user_rest_api_enabled'] ),
				'block_author_query_enabled'     => ! empty( $input['block_author_query_enabled'] ),
				'block_author_archives_enabled'  => ! empty( $input['block_author_archives_enabled'] ),
				'normalize_login_errors_enabled' => ! empty( $input['normalize_login_errors_enabled'] ),
				'allowed_failed_attempts'        => $this->clamp_int( $input, 'allowed_failed_attempts', 1, 100, (int) $existing['allowed_failed_attempts'] ),
				'failure_window_minutes'         => $this->clamp_int( $input, 'failure_window_minutes', 1, 1440, (int) $existing['failure_window_minutes'] ),
				'lockout_duration_minutes'       => $this->clamp_int( $input, 'lockout_duration_minutes', 1, 1440, (int) $existing['lockout_duration_minutes'] ),
				'database_scan_table_prefix'     => $this->sanitize_database_scan_table_prefix( $input, $existing ),
			)
		);

		return $sanitized;
	}

	/**
	 * Sanitize the WordPress Tables prefix override.
	 *
	 * Empty string or the live WordPress prefix means Auto.
	 *
	 * @param array<string, mixed> $input    Raw submitted options.
	 * @param array<string, mixed> $existing Existing options.
	 * @return string
	 */
	private function sanitize_database_scan_table_prefix( $input, $existing ) {
		$default = Choctaw_Wp_Security_Table_Prefix_Discovery::get_wordpress_configured_prefix();
		$raw     = isset( $input['database_scan_table_prefix'] ) ? (string) wp_unslash( $input['database_scan_table_prefix'] ) : '';

		if ( '' === $raw || $raw === $default ) {
			return '';
		}

		$discovery = new Choctaw_Wp_Security_Table_Prefix_Discovery();
		$validated = $discovery->validate_prefix( $raw );

		if ( false === $validated ) {
			$fallback = isset( $existing['database_scan_table_prefix'] ) ? (string) $existing['database_scan_table_prefix'] : '';

			if ( '' === $fallback ) {
				return '';
			}

			$fallback_validated = $discovery->validate_prefix( $fallback );

			return false !== $fallback_validated ? $fallback_validated : '';
		}

		return $validated;
	}

	/**
	 * Sanitize the uploads PHP lockdown option with Nginx-aware enforcement.
	 *
	 * @param array<string, mixed> $input Raw submitted options.
	 * @return bool
	 */
	private function sanitize_uploads_php_lockdown_enabled( $input ) {
		$lockdown = new Choctaw_Wp_Security_Uploads_Php_Lockdown();

		if ( Choctaw_Wp_Security_Uploads_Php_Lockdown::SERVER_NGINX === $lockdown->get_server_type() ) {
			return false;
		}

		return ! empty( $input['uploads_php_lockdown_enabled'] );
	}

	/**
	 * Clamp an integer option to an allowed range.
	 *
	 * @param array<string, mixed> $input    Raw input array.
	 * @param string               $key      Option key.
	 * @param int                  $min      Minimum allowed value.
	 * @param int                  $max      Maximum allowed value.
	 * @param int                  $fallback Fallback value.
	 * @return int
	 */
	private function clamp_int( $input, $key, $min, $max, $fallback ) {
		if ( ! isset( $input[ $key ] ) ) {
			return (int) $fallback;
		}

		$value = (int) $input[ $key ];

		if ( $value < $min ) {
			return $min;
		}

		if ( $value > $max ) {
			return $max;
		}

		return $value;
	}

	/**
	 * Render the Home submenu page.
	 *
	 * @return void
	 */
	public function render_home_page() {
		$this->render_admin_shell( 'home' );
	}

	/**
	 * Render the Settings submenu page.
	 *
	 * @return void
	 */
	public function render_settings_page() {
		$this->render_admin_shell( 'settings' );
	}

	/**
	 * Render the Scans submenu page.
	 *
	 * @return void
	 */
	public function render_scans_page() {
		$this->render_admin_shell( 'scans' );
	}

	/**
	 * Render the About submenu page.
	 *
	 * @return void
	 */
	public function render_about_page() {
		$this->render_admin_shell( 'about' );
	}

	/**
	 * Render shared admin chrome for a Sassh section.
	 *
	 * @param string $section Section key: home, settings, scans, or about.
	 * @return void
	 */
	private function render_admin_shell( $section ) {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			return;
		}

		$active_tab = 'scans' === $section ? $this->get_active_admin_tab() : '';
		?>
		<div class="wrap cws-admin-app">
			<div class="cws-admin-header">
				<h1 class="cws-page-title">
					<?php $this->render_coreguard_logo( 'cws-page-title-logo', 260 ); ?>
				</h1>
				<button
					type="button"
					class="button cws-menu-toggle"
					aria-controls="cws-admin-nav"
					aria-expanded="false"
				>
					<span class="dashicons dashicons-menu" aria-hidden="true"></span>
					<span><?php esc_html_e( 'Menu', 'choctaw-wp-security' ); ?></span>
				</button>
			</div>

			<div class="cws-admin-layout">
				<?php $this->render_vertical_admin_nav( $section, $active_tab ); ?>
				<div class="cws-admin-layout-main">
					<?php if ( 'scans' === $section ) : ?>
						<?php $this->render_active_admin_tab( $active_tab ); ?>
					<?php elseif ( 'settings' === $section ) : ?>
						<?php $this->render_main_tab(); ?>
					<?php elseif ( 'about' === $section ) : ?>
						<?php $this->render_about_this_plugin_tab(); ?>
					<?php else : ?>
						<?php $this->render_home_tab(); ?>
					<?php endif; ?>
				</div>
			</div>
			<div class="cws-menu-backdrop" hidden></div>
		</div>
		<?php
	}

	/**
	 * Get top-level Sassh sections for in-plugin navigation.
	 *
	 * @return array<string, array{label: string, icon: string, page: string}>
	 */
	private function get_admin_sections() {
		return array(
			'home'     => array(
				'label' => __( 'Home', 'choctaw-wp-security' ),
				'icon'  => 'dashicons-admin-home',
				'page'  => 'sassh',
			),
			'settings' => array(
				'label' => __( 'Settings', 'choctaw-wp-security' ),
				'icon'  => 'dashicons-admin-generic',
				'page'  => 'sassh-settings',
			),
			'about'    => array(
				'label' => __( 'About', 'choctaw-wp-security' ),
				'icon'  => 'dashicons-info',
				'page'  => 'sassh-about',
			),
		);
	}

	/**
	 * Get Scans page tabs.
	 *
	 * @return array<string, array{label: string, icon: string, group: string}>
	 */
	private function get_admin_tabs() {
		$tabs = array(
			'file-changes'     => array(
				'label' => __( 'File Changes', 'choctaw-wp-security' ),
				'icon'  => 'dashicons-media-document',
				'group' => 'file-security',
			),
			'exposed-files'    => array(
				'label' => __( 'Exposed Files', 'choctaw-wp-security' ),
				'icon'  => 'dashicons-hidden',
				'group' => 'file-security',
			),
			'uploads-folder'   => array(
				'label' => __( 'Uploads Folder', 'choctaw-wp-security' ),
				'icon'  => 'dashicons-upload',
				'group' => 'file-security',
			),
			'mu-plugins'       => array(
				'label' => __( 'MU-Plugins', 'choctaw-wp-security' ),
				'icon'  => 'dashicons-admin-plugins',
				'group' => 'file-security',
			),
			'exposed-folders'  => array(
				'label' => __( 'Directory Browsing', 'choctaw-wp-security' ),
				'icon'  => 'dashicons-portfolio',
				'group' => 'file-security',
			),
			'verify-checksums' => array(
				'label' => __( 'Verify Checksums', 'choctaw-wp-security' ),
				'icon'  => 'dashicons-shield',
				'group' => 'file-security',
			),
			'component-scan'   => array(
				'label' => __( 'Vulnerabilities', 'choctaw-wp-security' ),
				'icon'  => 'dashicons-warning',
				'group' => 'system',
			),
			'scheduled-tasks'  => array(
				'label' => __( 'WP-Cron', 'choctaw-wp-security' ),
				'icon'  => 'dashicons-clock',
				'group' => 'system',
			),
			'database-scan'    => array(
				'label' => __( 'wp_options', 'choctaw-wp-security' ),
				'icon'  => 'dashicons-database',
				'group' => 'database',
			),
			'wp-posts'         => array(
				'label' => __( 'wp_posts', 'choctaw-wp-security' ),
				'icon'  => 'dashicons-media-text',
				'group' => 'database',
			),
			'wp-users'         => array(
				'label' => __( 'wp_users', 'choctaw-wp-security' ),
				'icon'  => 'dashicons-admin-users',
				'group' => 'database',
			),
		);

		// Uploads uses Sassh Findings (network-wide). Hide from users who cannot manage Sassh.
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			unset( $tabs['uploads-folder'] );
		}

		return $tabs;
	}

	/**
	 * Get ordered Scans page tab groups for the vertical nav.
	 *
	 * @return array<string, array{label: string, tabs: list<string>}>
	 */
	private function get_admin_tab_groups() {
		return array(
			'file-security' => array(
				'label' => __( 'File Security', 'choctaw-wp-security' ),
				'tabs'  => array(
					'file-changes',
					'exposed-files',
					'uploads-folder',
					'mu-plugins',
					'exposed-folders',
					'verify-checksums',
				),
			),
			'database'      => array(
				'label' => __( 'Database', 'choctaw-wp-security' ),
				'tabs'  => array(
					'database-scan',
					'wp-posts',
					'wp-users',
				),
			),
			'system'        => array(
				'label' => __( 'System', 'choctaw-wp-security' ),
				'tabs'  => array(
					'component-scan',
					'scheduled-tasks',
				),
			),
		);
	}

	/**
	 * Get the current scan tab, defaulting to File Changes.
	 *
	 * @return string
	 */
	private function get_active_admin_tab() {
		$tabs = $this->get_admin_tabs();
		$tab  = isset( $_GET['cws_tab'] ) ? sanitize_key( wp_unslash( $_GET['cws_tab'] ) ) : 'file-changes';

		if ( 'file-changes-uploads' === $tab ) {
			$tab = 'file-changes';
		}

		if ( ! isset( $tabs[ $tab ] ) ) {
			return 'file-changes';
		}

		return $tab;
	}

	/**
	 * Render the Sassh navigation (desktop sidebar / tablet-phone drawer).
	 *
	 * @param string $section    Active section key.
	 * @param string $active_tab Active scan tab key when on Scans.
	 * @return void
	 */
	private function render_vertical_admin_nav( $section, $active_tab ) {
		$tabs = $this->get_admin_tabs();
		?>
		<aside id="cws-admin-nav" class="cws-admin-nav" aria-label="<?php esc_attr_e( 'Sassh', 'choctaw-wp-security' ); ?>">
			<div class="cws-admin-nav-drawer-header">
				<span class="cws-admin-nav-drawer-title"><?php esc_html_e( 'Sassh', 'choctaw-wp-security' ); ?></span>
				<button
					type="button"
					class="button-link cws-menu-close"
					aria-label="<?php esc_attr_e( 'Close Sassh menu', 'choctaw-wp-security' ); ?>"
				>
					<span class="dashicons dashicons-no-alt" aria-hidden="true"></span>
				</button>
			</div>

			<nav aria-label="<?php esc_attr_e( 'Sassh sections and scans', 'choctaw-wp-security' ); ?>">
				<ul class="cws-admin-nav-sections">
					<?php foreach ( $this->get_admin_sections() as $section_key => $item ) : ?>
						<?php $is_active = $section === $section_key; ?>
						<li>
							<a
								class="cws-admin-nav-link<?php echo $is_active ? ' is-active' : ''; ?>"
								href="<?php echo esc_url( $this->get_admin_page_url( $item['page'] ) ); ?>"
								<?php echo $is_active ? 'aria-current="page"' : ''; ?>
							>
								<span class="dashicons <?php echo esc_attr( $item['icon'] ); ?>" aria-hidden="true"></span>
								<span class="cws-admin-tab-label"><?php echo esc_html( $item['label'] ); ?></span>
							</a>
						</li>
					<?php endforeach; ?>
				</ul>

				<div class="cws-admin-nav-scans">
					<p class="cws-admin-nav-title"><?php esc_html_e( 'Scans', 'choctaw-wp-security' ); ?></p>
					<?php foreach ( $this->get_admin_tab_groups() as $group ) : ?>
						<div class="cws-admin-nav-group">
							<p class="cws-admin-nav-group-label"><?php echo esc_html( $group['label'] ); ?></p>
							<ul class="cws-admin-nav-list">
								<?php foreach ( $group['tabs'] as $tab_key ) : ?>
									<?php
									if ( ! isset( $tabs[ $tab_key ] ) ) {
										continue;
									}
									$tab       = $tabs[ $tab_key ];
									$is_active = 'scans' === $section && $active_tab === $tab_key;
									?>
									<li>
										<a
											class="cws-admin-nav-link<?php echo $is_active ? ' is-active' : ''; ?>"
											href="<?php echo esc_url( $this->get_scans_page_url( $tab_key ) ); ?>"
											<?php echo $is_active ? 'aria-current="page"' : ''; ?>
										>
											<span class="dashicons <?php echo esc_attr( $tab['icon'] ); ?>" aria-hidden="true"></span>
											<span class="cws-admin-tab-label"><?php echo esc_html( $tab['label'] ); ?></span>
										</a>
									</li>
								<?php endforeach; ?>
							</ul>
						</div>
					<?php endforeach; ?>
				</div>
			</nav>
		</aside>
		<?php
	}

	/**
	 * Render the active scan tab.
	 *
	 * @param string $active_tab Active tab key.
	 * @return void
	 */
	private function render_active_admin_tab( $active_tab ) {
		if ( 'file-changes' === $active_tab ) {
			$this->render_file_changes_tab();
			return;
		}

		if ( 'exposed-files' === $active_tab ) {
			$this->render_exposed_files_section();
			return;
		}

		if ( 'uploads-folder' === $active_tab ) {
			$this->render_uploads_folder_section();
			return;
		}

		if ( 'mu-plugins' === $active_tab ) {
			$this->render_mu_plugins_section();
			return;
		}

		if ( 'verify-checksums' === $active_tab ) {
			$this->render_core_checksum_section();
			return;
		}

		if ( 'component-scan' === $active_tab ) {
			$this->render_component_scan_section();
			return;
		}

		if ( 'exposed-folders' === $active_tab ) {
			$this->render_exposed_folders_section();
			return;
		}

		if ( 'database-scan' === $active_tab ) {
			$this->render_database_scan_section();
			return;
		}

		if ( 'scheduled-tasks' === $active_tab ) {
			$this->render_scheduled_tasks_section();
			return;
		}

		if ( 'wp-posts' === $active_tab ) {
			$this->render_posts_scan_section();
			return;
		}

		if ( 'wp-users' === $active_tab ) {
			$this->render_users_table_section();
			return;
		}

		$this->render_file_changes_tab();
	}

	/**
	 * Render the Home tab.
	 *
	 * @return void
	 */
	private function render_home_tab() {
		$options        = Choctaw_Wp_Security_Utils::get_options();
		$events         = Choctaw_Wp_Security_Utils::get_lockout_log();
		$uploads_status = ( new Choctaw_Wp_Security_Uploads_Php_Lockdown() )->get_status();
		?>
		<div class="cws-admin-tab-panel">
			<?php
			$this->render_status_section( $options, $uploads_status );
			$this->render_recent_lockouts_section( $events );
			?>
		</div>
		<?php
	}

	/**
	 * Render the Settings tab.
	 *
	 * @return void
	 */
	private function render_main_tab() {
		$form_action = is_multisite()
			? network_admin_url( 'edit.php?action=sassh_save_settings' )
			: admin_url( 'options.php' );
		?>
		<div class="cws-admin-tab-panel">
			<?php if ( is_multisite() && isset( $_GET['updated'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Settings saved.', 'choctaw-wp-security' ); ?></p></div>
			<?php endif; ?>
			<form action="<?php echo esc_url( $form_action ); ?>" method="post">
				<?php
				if ( is_multisite() ) {
					wp_nonce_field( 'sassh_save_network_settings' );
					echo '<input type="hidden" name="option_page" value="choctaw_wp_security" />';
				} else {
					settings_fields( 'choctaw_wp_security' );
				}
				do_settings_sections( 'sassh-settings' );
				submit_button();
				?>
			</form>
		</div>
		<?php
	}

	/**
	 * Persist Sassh settings from Network Admin (network option; no site-option migration).
	 *
	 * @return void
	 */
	public function handle_network_settings_save() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to manage Sassh settings.', 'choctaw-wp-security' ) );
		}

		check_admin_referer( 'sassh_save_network_settings' );

		$raw = isset( $_POST[ Choctaw_Wp_Security_Utils::OPTION_KEY ] )
			? wp_unslash( $_POST[ Choctaw_Wp_Security_Utils::OPTION_KEY ] ) // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			: array();

		if ( ! is_array( $raw ) ) {
			$raw = array();
		}

		$sanitized = $this->sanitize_options( $raw );
		Choctaw_Wp_Security_Utils::update_options( $sanitized );

		wp_safe_redirect(
			add_query_arg(
				array(
					'page'    => 'sassh-settings',
					'updated' => 'true',
				),
				network_admin_url( 'admin.php' )
			)
		);
		exit;
	}

	/**
	 * Render the Status section.
	 *
	 * @param array<string, mixed> $options        Plugin options.
	 * @param array<string, mixed> $uploads_status Uploads lockdown status.
	 * @return void
	 */
	private function render_status_section( $options, $uploads_status ) {
		?>
		<div class="cws-report-section">
		<h2><?php esc_html_e( 'Status', 'choctaw-wp-security' ); ?></h2>
		<table class="widefat striped">
			<tbody>
				<tr>
					<th scope="row"><?php esc_html_e( 'Plugin Version', 'choctaw-wp-security' ); ?></th>
					<td><?php echo esc_html( CHOCTAW_WP_SECURITY_VERSION ); ?></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'WordPress Tables', 'choctaw-wp-security' ); ?></th>
					<td>
						<?php
						$prefix_discovery = new Choctaw_Wp_Security_Table_Prefix_Discovery();
						$resolved_tables  = $prefix_discovery->resolve_configured_tables();
						$mode_label       = ! empty( $resolved_tables['is_override'] )
							? __( 'Override', 'choctaw-wp-security' )
							: __( 'Auto', 'choctaw-wp-security' );
						$database_name    = $prefix_discovery->get_database_name();

						echo esc_html(
							sprintf(
								/* translators: 1: table prefix, 2: Auto or Override */
								__( '%1$s (%2$s)', 'choctaw-wp-security' ),
								(string) $resolved_tables['prefix'],
								$mode_label
							)
						);

						if ( '' !== $database_name ) {
							echo '<br /><span class="description">';
							echo esc_html(
								sprintf(
									/* translators: %s: MySQL database name */
									__( 'Database: %s', 'choctaw-wp-security' ),
									$database_name
								)
							);
							echo '</span>';
						}
						?>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'XML-RPC Blocking', 'choctaw-wp-security' ); ?></th>
					<td><?php echo esc_html( $this->status_label( ! empty( $options['xmlrpc_blocking_enabled'] ) ) ); ?></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Login Rate Limiting', 'choctaw-wp-security' ); ?></th>
					<td><?php echo esc_html( $this->status_label( ! empty( $options['login_rate_limit_enabled'] ) ) ); ?></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Uploads PHP Lockdown', 'choctaw-wp-security' ); ?></th>
					<td>
						<?php echo esc_html( $uploads_status['label'] ); ?>
						<?php if ( ! empty( $uploads_status['note'] ) ) : ?>
							<p class="description"><?php echo wp_kses( $uploads_status['note'], $this->get_allowed_file_path_markup() ); ?></p>
						<?php endif; ?>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Reduce Username Exposure', 'choctaw-wp-security' ); ?></th>
					<td><?php echo esc_html( $this->username_discovery_status_label( $options ) ); ?></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Current Policy', 'choctaw-wp-security' ); ?></th>
					<td>
						<?php
						echo esc_html(
							sprintf(
								/* translators: 1: allowed attempts, 2: failure window minutes, 3: lockout duration minutes */
								__( '%1$d failed attempts within %2$d minutes triggers a %3$d minute lockout.', 'choctaw-wp-security' ),
								(int) $options['allowed_failed_attempts'],
								(int) $options['failure_window_minutes'],
								(int) $options['lockout_duration_minutes']
							)
						);
						?>
					</td>
				</tr>
			</tbody>
		</table>
		</div>
		<?php
	}

	/**
	 * Render recent login lockouts.
	 *
	 * @param array<int, array<string, mixed>> $events Recent lockout events.
	 * @return void
	 */
	private function render_recent_lockouts_section( $events ) {
		if ( empty( $events ) ) {
			return;
		}

		usort(
			$events,
			static function ( $left, $right ) {
				return ( isset( $right['timestamp'] ) ? (int) $right['timestamp'] : 0 )
					<=> ( isset( $left['timestamp'] ) ? (int) $left['timestamp'] : 0 );
			}
		);

		$pagination = $this->paginate_report_items( $events, $this->get_report_page_number( 'cws_lockouts' ) );
		?>
		<div class="cws-report-section">
		<h2><?php esc_html_e( 'Recent Lockouts', 'choctaw-wp-security' ); ?></h2>
		<?php Choctaw_Wp_Security_Admin_Help::render_field_description( 'recent_lockouts' ); ?>
		<table class="widefat striped cws-core-checksum-table" id="cws-recent-lockouts-table">
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'Risk', 'choctaw-wp-security' ); ?></th>
					<th scope="col" data-sort-key="time" class="cws-sortable-th">
						<button type="button" class="button-link cws-sortable-column"><?php esc_html_e( 'Time', 'choctaw-wp-security' ); ?> <span class="cws-sort-indicator">▼</span></button>
					</th>
					<th scope="col" data-sort-key="ip" class="cws-sortable-th">
						<button type="button" class="button-link cws-sortable-column"><?php esc_html_e( 'IP Address', 'choctaw-wp-security' ); ?></button>
					</th>
					<th scope="col" data-sort-key="username" class="cws-sortable-th">
						<button type="button" class="button-link cws-sortable-column"><?php esc_html_e( 'Attempted Username', 'choctaw-wp-security' ); ?></button>
					</th>
					<th scope="col" data-sort-key="scope" class="cws-sortable-th">
						<button type="button" class="button-link cws-sortable-column"><?php esc_html_e( 'Scope', 'choctaw-wp-security' ); ?></button>
					</th>
					<th scope="col" data-sort-key="duration" class="cws-sortable-th">
						<button type="button" class="button-link cws-sortable-column"><?php esc_html_e( 'Lockout Duration', 'choctaw-wp-security' ); ?></button>
					</th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $pagination['items'] as $event ) : ?>
					<?php
					$duration_seconds = isset( $event['lockout_duration'] ) ? (int) $event['lockout_duration'] : 0;
					$duration_minutes = max( 1, (int) round( $duration_seconds / MINUTE_IN_SECONDS ) );
					$timestamp        = isset( $event['timestamp'] ) ? (int) $event['timestamp'] : 0;
					?>
					<tr
						data-time="<?php echo esc_attr( (string) $timestamp ); ?>"
						data-ip="<?php echo esc_attr( isset( $event['ip'] ) ? (string) $event['ip'] : '' ); ?>"
						data-username="<?php echo esc_attr( isset( $event['username'] ) ? (string) $event['username'] : '' ); ?>"
						data-scope="<?php echo esc_attr( isset( $event['scope'] ) ? (string) $event['scope'] : '' ); ?>"
						data-duration="<?php echo esc_attr( (string) $duration_minutes ); ?>"
					>
						<td><?php $this->render_risk_badge( 'info', __( 'Info', 'choctaw-wp-security' ) ); ?></td>
						<td><?php echo esc_html( $this->format_timestamp( $timestamp ) ); ?></td>
						<td><?php echo esc_html( isset( $event['ip'] ) ? (string) $event['ip'] : '' ); ?></td>
						<td><?php echo esc_html( isset( $event['username'] ) ? (string) $event['username'] : '' ); ?></td>
						<td><?php echo esc_html( $this->format_scope( isset( $event['scope'] ) ? (string) $event['scope'] : '' ) ); ?></td>
						<td>
							<?php
							echo esc_html(
								sprintf(
									/* translators: %d: lockout duration in minutes */
									__( '%d minutes', 'choctaw-wp-security' ),
									$duration_minutes
								)
							);
							?>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php $this->render_report_pagination( 'cws_lockouts', $pagination, __( 'lockouts', 'choctaw-wp-security' ) ); ?>
		</div>
		<?php
	}

	/**
	 * Render the File Changes tab (Recent File Changes only).
	 *
	 * @return void
	 */
	private function render_file_changes_tab() {
		$core_file_changes = $this->get_core_file_changes();
		?>
		<div class="cws-admin-tab-panel">

			<div class="cws-report-section">
			<h2><?php esc_html_e( 'Recent File Changes', 'choctaw-wp-security' ); ?></h2>
			<?php Choctaw_Wp_Security_Admin_Help::render_field_description( 'file_changes_recent' ); ?>
			<div class="cws-report-toolbar" id="cws-file-changes-toolbar">
				<label>
					<span class="screen-reader-text"><?php esc_html_e( 'Risk', 'choctaw-wp-security' ); ?></span>
					<select id="cws-file-changes-risk-filter">
						<option value=""><?php esc_html_e( 'All risks', 'choctaw-wp-security' ); ?></option>
						<option value="critical"><?php esc_html_e( 'Critical', 'choctaw-wp-security' ); ?></option>
						<option value="missing"><?php esc_html_e( 'Missing', 'choctaw-wp-security' ); ?></option>
						<option value="safe"><?php esc_html_e( 'Safe', 'choctaw-wp-security' ); ?></option>
						<option value="na"><?php esc_html_e( 'N/A', 'choctaw-wp-security' ); ?></option>
					</select>
				</label>
			</div>
			<table id="cws-core-file-changes-table" class="widefat striped cws-core-checksum-table">
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'Risk', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'File', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Last Modified', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Action', 'choctaw-wp-security' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $core_file_changes as $index => $file_change ) : ?>
						<?php
						$file_help_detail = Choctaw_Wp_Security_Admin_Help_Content::get_core_file_change_detail( $file_change['checksum_path'] );
						$row_id           = 'cws-file-change-' . (int) $index;
						$how_html         = '' !== $file_help_detail
							? $file_help_detail
							: '<p>' . esc_html__( 'Review this file carefully. Confirm whether the modification date and contents match what you expect for your site. Unexpected changes to these high-value WordPress files should be investigated promptly.', 'choctaw-wp-security' ) . '</p>';
						?>
						<tr
							data-checksum-path="<?php echo esc_attr( $file_change['checksum_path'] ); ?>"
							data-risk="pending"
							data-row-id="<?php echo esc_attr( $row_id ); ?>"
						>
							<td class="cws-file-change-risk-cell">
								<span class="cws-checksum-status is-pending"><?php esc_html_e( 'Checking…', 'choctaw-wp-security' ); ?></span>
							</td>
							<td class="cws-core-file-cell"><?php $this->render_file_path( $file_change['label'] ); ?></td>
							<td><?php echo esc_html( $file_change['modified'] ); ?></td>
							<td>
								<button
									type="button"
									class="cws-report-eye"
									data-expand-target="<?php echo esc_attr( $row_id ); ?>"
									aria-expanded="false"
									aria-label="<?php esc_attr_e( 'View details', 'choctaw-wp-security' ); ?>"
								>
									<span class="dashicons dashicons-visibility" aria-hidden="true"></span>
								</button>
							</td>
						</tr>
						<tr class="cws-report-detail-row" id="<?php echo esc_attr( $row_id ); ?>" hidden>
							<td colspan="4">
								<div class="cws-report-detail-grid cws-report-detail-standard">
									<div class="cws-report-detail-left">
										<div class="cws-report-info-panel">
											<h4><?php esc_html_e( 'Info', 'choctaw-wp-security' ); ?></h4>
											<dl>
												<dt><?php esc_html_e( 'Modified Date/Time', 'choctaw-wp-security' ); ?></dt>
												<dd><?php echo esc_html( $this->display_or_em_dash( isset( $file_change['modified_label'] ) ? (string) $file_change['modified_label'] : '' ) ); ?></dd>
												<dt><?php esc_html_e( 'File Size', 'choctaw-wp-security' ); ?></dt>
												<dd><?php echo esc_html( $this->display_or_em_dash( isset( $file_change['size_label'] ) ? (string) $file_change['size_label'] : '' ) ); ?></dd>
												<dt><?php esc_html_e( 'Permissions', 'choctaw-wp-security' ); ?></dt>
												<dd><?php echo esc_html( $this->display_or_em_dash( isset( $file_change['permissions'] ) ? (string) $file_change['permissions'] : '' ) ); ?></dd>
												<dt><?php esc_html_e( 'Owner', 'choctaw-wp-security' ); ?></dt>
												<dd><?php echo esc_html( $this->display_or_em_dash( isset( $file_change['owner'] ) ? (string) $file_change['owner'] : '' ) ); ?></dd>
											</dl>
										</div>
										<div class="cws-report-contents">
											<h4><?php esc_html_e( 'Contents', 'choctaw-wp-security' ); ?></h4>
											<textarea class="cws-file-contents-textarea large-text code" rows="14" readonly><?php echo esc_textarea( $this->with_report_contents_footer( isset( $file_change['contents'] ) ? (string) $file_change['contents'] : '', ! empty( $file_change['contents_truncated'] ), __( 'File', 'choctaw-wp-security' ) ) ); ?></textarea>
										</div>
									</div>
									<div class="cws-report-detail-right">
										<div>
											<h4><?php esc_html_e( 'Why you are seeing this', 'choctaw-wp-security' ); ?></h4>
											<p class="cws-file-change-risk-explanation" data-risk-explanation><?php esc_html_e( 'Checksum status is still being verified.', 'choctaw-wp-security' ); ?></p>
										</div>
										<div>
											<h4><?php esc_html_e( 'How to proceed', 'choctaw-wp-security' ); ?></h4>
											<?php echo wp_kses_post( $how_html ); ?>
										</div>
									</div>
								</div>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
			<div id="cws-core-file-changes-checksum-status" class="cws-checksum-scan-status" hidden></div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Exposed Files scan section.
	 *
	 * @return void
	 */
	private function render_exposed_files_section() {
		$result          = false;
		$results_missing = false;

		if ( isset( $_GET['exposed_files_run'] ) ) {
			$result = $this->load_report_result(
				$this->get_exposed_files_result_transient_key(),
				Choctaw_Wp_Security_Utils::USER_META_EXPOSED_FILES_RESULT
			);

			if ( false === $result ) {
				$results_missing = true;
			}
		}

		$stored_result = $this->load_report_result(
			$this->get_exposed_files_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_EXPOSED_FILES_RESULT
		);
		$has_result = is_array( $result ) || is_array( $stored_result );
		?>
		<div class="cws-admin-tab-panel cws-exposed-files-panel">
			<div class="cws-report-section">
				<h2><?php esc_html_e( 'Exposed Files', 'choctaw-wp-security' ); ?></h2>
				<?php Choctaw_Wp_Security_Admin_Help::render_tab_intro( 'exposed_files' ); ?>

				<?php if ( $results_missing ) : ?>
					<div class="notice notice-warning">
						<p><?php esc_html_e( 'The previous exposed files scan results are no longer available. Run Scan Now to generate a fresh report.', 'choctaw-wp-security' ); ?></p>
					</div>
				<?php endif; ?>

				<form method="post" class="cws-exposed-files-form" id="cws-exposed-files-form">
					<?php wp_nonce_field( 'choctaw_wp_security_exposed_files_scan_form' ); ?>
					<input type="hidden" name="cws_tab" value="exposed-files" />
					<?php submit_button( __( 'Scan Now', 'choctaw-wp-security' ), 'secondary', 'choctaw_wp_security_exposed_files_scan', false ); ?>
					<?php $this->render_clear_history_button( 'exposed-files' ); ?>
				</form>

				<div id="cws-exposed-files-js-notices" aria-live="polite"></div>
				<div id="cws-exposed-files-js-results"></div>

				<div id="cws-exposed-files-fallback-results">
					<?php if ( is_array( $result ) ) : ?>
						<?php $this->render_exposed_files_results( $result ); ?>
					<?php endif; ?>
				</div>

				<div
					id="cws-exposed-files-help-boxes"
					class="cws-help-boxes cws-exposed-files-help-boxes"
					<?php echo $has_result ? '' : ' hidden'; ?>
				>
					<?php Choctaw_Wp_Security_Admin_Help::render_info_box( 'exposed_files_categories' ); ?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render Exposed Files scan results (no-JS fallback).
	 *
	 * @param array<string, mixed> $result Scan result payload.
	 * @return void
	 */
	private function render_exposed_files_results( $result ) {
		$findings = isset( $result['findings'] ) && is_array( $result['findings'] ) ? $result['findings'] : array();
		$summary  = isset( $result['summary'] ) && is_array( $result['summary'] ) ? $result['summary'] : array();
		$critical = isset( $summary['critical'] ) ? (int) $summary['critical'] : 0;
		$alert    = isset( $summary['alert'] ) ? (int) $summary['alert'] : 0;
		$warning  = isset( $summary['warning'] ) ? (int) $summary['warning'] : 0;
		$info     = isset( $summary['info'] ) ? (int) $summary['info'] : 0;
		$total    = isset( $summary['total'] ) ? (int) $summary['total'] : count( $findings );

		if ( $critical > 0 ) {
			$panel = 'cws-core-checksum-results is-error';
		} elseif ( ( $alert + $warning ) > 0 ) {
			$panel = 'cws-core-checksum-results is-warning';
		} else {
			$panel = 'cws-core-checksum-results is-success';
		}
		?>
		<div class="<?php echo esc_attr( $panel ); ?>">
			<p class="cws-core-checksum-summary">
				<?php
				if ( 0 === $total ) {
					esc_html_e( 'Scan complete. No exposed sensitive files were found in the WordPress root.', 'choctaw-wp-security' );
				} else {
					echo esc_html(
						sprintf(
							/* translators: 1: critical count, 2: alert count, 3: warning count, 4: info count, 5: total findings */
							__( 'Scan complete. %1$s critical, %2$s alert, %3$s warning, and %4$s informational finding(s) among %5$s exposed file(s).', 'choctaw-wp-security' ),
							number_format_i18n( $critical ),
							number_format_i18n( $alert ),
							number_format_i18n( $warning ),
							number_format_i18n( $info ),
							number_format_i18n( $total )
						)
					);
				}
				?>
			</p>
		</div>
		<?php if ( empty( $findings ) ) : ?>
			<p><?php esc_html_e( 'No exposed sensitive files were found.', 'choctaw-wp-security' ); ?></p>
			<?php
			return;
		endif;

		$pagination = $this->paginate_report_items( $findings, $this->get_report_page_number( 'cws_exposed_files' ) );
		?>
		<table class="widefat striped cws-core-checksum-table cws-exposed-files-table">
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'Risk', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Category', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Filename', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Action', 'choctaw-wp-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $pagination['items'] as $index => $finding ) : ?>
					<?php
					$row_id   = 'cws-exposed-files-fallback-' . (int) $index;
					$filename = isset( $finding['filename'] ) ? (string) $finding['filename'] : ( isset( $finding['path'] ) ? (string) $finding['path'] : '' );
					$risk     = isset( $finding['risk'] ) ? (string) $finding['risk'] : 'info';
					$risk_label = isset( $finding['risk_label'] ) ? (string) $finding['risk_label'] : $risk;
					?>
					<tr>
						<td><?php $this->render_risk_badge( $risk, $risk_label ); ?></td>
						<td><span class="cws-report-pill"><?php echo esc_html( isset( $finding['category_label'] ) ? (string) $finding['category_label'] : '' ); ?></span></td>
						<td><?php $this->render_file_path( $filename ); ?></td>
						<td>
							<button type="button" class="cws-report-eye" data-expand-target="<?php echo esc_attr( $row_id ); ?>" aria-expanded="false" aria-label="<?php esc_attr_e( 'View details', 'choctaw-wp-security' ); ?>">
								<span class="dashicons dashicons-visibility" aria-hidden="true"></span>
							</button>
						</td>
					</tr>
					<tr class="cws-report-detail-row" id="<?php echo esc_attr( $row_id ); ?>" hidden>
						<td colspan="4">
							<div class="cws-report-detail-grid cws-exposed-files-detail-grid">
								<div class="cws-exposed-files-detail-left">
									<div class="cws-exposed-files-info-panel">
										<h4><?php esc_html_e( 'Info', 'choctaw-wp-security' ); ?></h4>
										<dl>
											<dt><?php esc_html_e( 'Modified Date/Time', 'choctaw-wp-security' ); ?></dt>
											<dd><?php echo esc_html( isset( $finding['modified_label'] ) ? (string) $finding['modified_label'] : '—' ); ?></dd>
											<dt><?php esc_html_e( 'File Size', 'choctaw-wp-security' ); ?></dt>
											<dd><?php echo esc_html( isset( $finding['size_label'] ) ? (string) $finding['size_label'] : '—' ); ?></dd>
											<dt><?php esc_html_e( 'Permissions', 'choctaw-wp-security' ); ?></dt>
											<dd><?php echo esc_html( isset( $finding['permissions'] ) ? (string) $finding['permissions'] : '—' ); ?></dd>
											<dt><?php esc_html_e( 'Owner', 'choctaw-wp-security' ); ?></dt>
											<dd><?php echo esc_html( isset( $finding['owner'] ) ? (string) $finding['owner'] : '—' ); ?></dd>
										</dl>
									</div>
									<div class="cws-exposed-files-contents">
										<h4><?php esc_html_e( 'Contents', 'choctaw-wp-security' ); ?></h4>
										<textarea class="cws-file-contents-textarea large-text code" rows="14" readonly><?php echo esc_textarea( $this->with_report_contents_footer( isset( $finding['contents'] ) ? (string) $finding['contents'] : '', ! empty( $finding['contents_truncated'] ), __( 'File', 'choctaw-wp-security' ) ) ); ?></textarea>
									</div>
								</div>
								<div class="cws-exposed-files-detail-right">
									<div>
										<h4><?php esc_html_e( 'Why you are seeing this', 'choctaw-wp-security' ); ?></h4>
										<p><?php echo esc_html( isset( $finding['why_seeing_this'] ) ? (string) $finding['why_seeing_this'] : '' ); ?></p>
									</div>
									<div>
										<h4><?php esc_html_e( 'How to proceed', 'choctaw-wp-security' ); ?></h4>
										<p><?php echo esc_html( isset( $finding['how_to_proceed'] ) ? (string) $finding['how_to_proceed'] : '' ); ?></p>
									</div>
								</div>
							</div>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
		$this->render_report_pagination( 'cws_exposed_files', $pagination, __( 'findings', 'choctaw-wp-security' ) );
	}

	/**
	 * Render the Uploads Folder scan section.
	 *
	 * @return void
	 */
	private function render_uploads_folder_section() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			?>
			<div class="cws-admin-tab-panel cws-uploads-folder-panel">
				<div class="cws-report-section">
					<h2><?php esc_html_e( 'Uploads Folder', 'choctaw-wp-security' ); ?></h2>
					<div class="notice notice-error">
						<p><?php esc_html_e( 'You do not have permission to view Sassh network-wide security findings.', 'choctaw-wp-security' ); ?></p>
					</div>
				</div>
			</div>
			<?php
			return;
		}

		$result          = false;
		$results_missing = false;

		if ( isset( $_GET['uploads_folder_run'] ) ) {
			$result = $this->load_report_result(
				$this->get_uploads_folder_result_transient_key(),
				Choctaw_Wp_Security_Utils::USER_META_UPLOADS_FOLDER_RESULT
			);

			if ( false === $result ) {
				$results_missing = true;
			}
		}
		?>
		<div class="cws-admin-tab-panel cws-uploads-folder-panel">
			<div class="cws-report-section">
				<h2><?php esc_html_e( 'Uploads Folder', 'choctaw-wp-security' ); ?></h2>
				<?php Choctaw_Wp_Security_Admin_Help::render_tab_intro( 'uploads_folder' ); ?>

				<?php if ( $results_missing ) : ?>
					<div class="notice notice-warning">
						<p><?php esc_html_e( 'The previous uploads folder scan results are no longer available. Run Scan Now to generate a fresh report.', 'choctaw-wp-security' ); ?></p>
					</div>
				<?php endif; ?>

				<form method="post" class="cws-uploads-folder-form" id="cws-uploads-folder-form">
					<?php wp_nonce_field( 'choctaw_wp_security_uploads_folder_scan_form' ); ?>
					<input type="hidden" name="cws_tab" value="uploads-folder" />
					<?php submit_button( __( 'Scan Now', 'choctaw-wp-security' ), 'secondary', 'choctaw_wp_security_uploads_folder_scan', false ); ?>
				</form>

				<div id="cws-uploads-folder-js-notices" aria-live="polite"></div>
				<div id="cws-uploads-folder-js-results"></div>

				<div id="cws-uploads-folder-fallback-results">
					<?php if ( is_array( $result ) ) : ?>
						<?php $this->render_uploads_folder_results( $result ); ?>
					<?php endif; ?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render Uploads Folder scan results (no-JS fallback).
	 *
	 * @param array<string, mixed> $result Scan result payload.
	 * @return void
	 */
	private function render_uploads_folder_results( $result ) {
		$findings = isset( $result['findings'] ) && is_array( $result['findings'] ) ? $result['findings'] : array();
		$summary  = isset( $result['summary'] ) && is_array( $result['summary'] ) ? $result['summary'] : array();
		$warning  = isset( $summary['warning'] ) ? (int) $summary['warning'] : count( $findings );
		$panel    = $warning > 0 ? 'cws-core-checksum-results is-error' : 'cws-core-checksum-results is-success';
		?>
		<div class="<?php echo esc_attr( $panel ); ?>">
			<p class="cws-core-checksum-summary">
				<?php
				if ( $warning > 0 ) {
					echo esc_html(
						sprintf(
							/* translators: %s: warning finding count */
							__( 'Scan complete. %s warning finding(s) in the uploads folder.', 'choctaw-wp-security' ),
							number_format_i18n( $warning )
						)
					);
				} else {
					esc_html_e( 'Scan complete. No PHP executable files were found in the uploads folder.', 'choctaw-wp-security' );
				}
				?>
			</p>
		</div>
		<?php if ( empty( $findings ) ) : ?>
			<p><?php esc_html_e( 'No PHP executable files were found.', 'choctaw-wp-security' ); ?></p>
			<?php
			return;
		endif;

		$pagination = $this->paginate_report_items( $findings, $this->get_report_page_number( 'cws_uploads_folder' ) );
		?>
		<table class="widefat striped cws-core-checksum-table cws-uploads-folder-table">
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'Risk', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Status', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Category', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'File', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Action', 'choctaw-wp-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $pagination['items'] as $index => $finding ) : ?>
					<?php
					$row_id       = 'cws-uploads-fallback-' . (int) $index;
					$path         = isset( $finding['path'] ) ? (string) $finding['path'] : '';
					$risk         = isset( $finding['risk'] ) ? (string) $finding['risk'] : 'warning';
					$risk_label   = isset( $finding['risk_label'] ) ? (string) $finding['risk_label'] : __( 'Warning', 'choctaw-wp-security' );
					$status       = isset( $finding['status'] ) ? (string) $finding['status'] : 'needs_review';
					$status_label = isset( $finding['status_label'] ) ? (string) $finding['status_label'] : Sassh_Findings_Service::status_label( $status );
					?>
					<tr>
						<td><?php $this->render_risk_badge( $risk, $risk_label ); ?></td>
						<td><?php $this->render_status_badge( $status, $status_label ); ?></td>
						<td><span class="cws-report-pill"><?php echo esc_html( isset( $finding['category_label'] ) ? (string) $finding['category_label'] : __( 'PHP Executable', 'choctaw-wp-security' ) ); ?></span></td>
						<td><?php $this->render_file_path( $path ); ?></td>
						<td>
							<button type="button" class="cws-report-eye" data-expand-target="<?php echo esc_attr( $row_id ); ?>" aria-expanded="false" aria-label="<?php esc_attr_e( 'View details', 'choctaw-wp-security' ); ?>">
								<span class="dashicons dashicons-visibility" aria-hidden="true"></span>
							</button>
						</td>
					</tr>
					<tr class="cws-report-detail-row" id="<?php echo esc_attr( $row_id ); ?>" hidden>
						<td colspan="5">
							<div class="cws-report-detail-grid cws-uploads-folder-detail-grid">
								<div class="cws-uploads-folder-detail-left">
									<div class="cws-uploads-folder-info-panel">
										<h4><?php esc_html_e( 'Info', 'choctaw-wp-security' ); ?></h4>
										<dl>
											<dt><?php esc_html_e( 'Last Modified', 'choctaw-wp-security' ); ?></dt>
											<dd><?php echo esc_html( isset( $finding['modified_label'] ) ? (string) $finding['modified_label'] : '—' ); ?></dd>
											<dt><?php esc_html_e( 'File Size', 'choctaw-wp-security' ); ?></dt>
											<dd><?php echo esc_html( isset( $finding['size_label'] ) ? (string) $finding['size_label'] : '—' ); ?></dd>
											<dt><?php esc_html_e( 'Permissions', 'choctaw-wp-security' ); ?></dt>
											<dd><?php echo esc_html( isset( $finding['permissions'] ) && '' !== (string) $finding['permissions'] ? (string) $finding['permissions'] : '—' ); ?></dd>
											<dt><?php esc_html_e( 'Owner', 'choctaw-wp-security' ); ?></dt>
											<dd><?php echo esc_html( isset( $finding['owner'] ) && '' !== (string) $finding['owner'] ? (string) $finding['owner'] : '—' ); ?></dd>
										</dl>
									</div>
									<div class="cws-uploads-folder-contents">
										<h4><?php esc_html_e( 'Contents', 'choctaw-wp-security' ); ?></h4>
										<textarea class="cws-file-contents-textarea large-text code" rows="14" readonly><?php echo esc_textarea( $this->with_report_contents_footer( isset( $finding['contents'] ) ? (string) $finding['contents'] : '', ! empty( $finding['contents_truncated'] ), __( 'File', 'choctaw-wp-security' ) ) ); ?></textarea>
									</div>
								</div>
								<div class="cws-uploads-folder-detail-right">
									<div>
										<h4><?php esc_html_e( 'Why you are seeing this', 'choctaw-wp-security' ); ?></h4>
										<p><?php echo esc_html( isset( $finding['why_seeing_this'] ) ? (string) $finding['why_seeing_this'] : '' ); ?></p>
									</div>
									<div>
										<h4><?php esc_html_e( 'How to proceed', 'choctaw-wp-security' ); ?></h4>
										<p><?php echo esc_html( isset( $finding['how_to_proceed'] ) ? (string) $finding['how_to_proceed'] : '' ); ?></p>
									</div>
								</div>
							</div>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
		$this->render_report_pagination( 'cws_uploads_folder', $pagination, __( 'findings', 'choctaw-wp-security' ) );
	}

	/**
	 * Render the MU-Plugins scan section.
	 *
	 * @return void
	 */
	private function render_mu_plugins_section() {
		$result          = false;
		$results_missing = false;

		if ( isset( $_GET['mu_plugins_run'] ) ) {
			$result = $this->load_report_result(
				$this->get_mu_plugins_result_transient_key(),
				Choctaw_Wp_Security_Utils::USER_META_MU_PLUGINS_RESULT
			);

			if ( false === $result ) {
				$results_missing = true;
			}
		}
		?>
		<div class="cws-admin-tab-panel cws-mu-plugins-panel">
			<div class="cws-report-section">
				<h2><?php esc_html_e( 'MU-Plugins', 'choctaw-wp-security' ); ?></h2>
				<?php Choctaw_Wp_Security_Admin_Help::render_tab_intro( 'mu_plugins' ); ?>

				<?php if ( $results_missing ) : ?>
					<div class="notice notice-warning">
						<p><?php esc_html_e( 'The previous MU-Plugins scan results are no longer available. Run Scan Now to generate a fresh report.', 'choctaw-wp-security' ); ?></p>
					</div>
				<?php endif; ?>

				<form method="post" class="cws-mu-plugins-form" id="cws-mu-plugins-form">
					<?php wp_nonce_field( 'choctaw_wp_security_mu_plugins_scan_form' ); ?>
					<input type="hidden" name="cws_tab" value="mu-plugins" />
					<?php submit_button( __( 'Scan Now', 'choctaw-wp-security' ), 'secondary', 'choctaw_wp_security_mu_plugins_scan', false ); ?>
				</form>

				<div id="cws-mu-plugins-js-notices" aria-live="polite"></div>
				<div id="cws-mu-plugins-js-results"></div>

				<div id="cws-mu-plugins-fallback-results">
					<?php if ( is_array( $result ) ) : ?>
						<?php $this->render_mu_plugins_results( $result ); ?>
					<?php endif; ?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render MU-Plugins scan results (no-JS fallback).
	 *
	 * @param array<string, mixed> $result Scan result payload.
	 * @return void
	 */
	private function render_mu_plugins_results( $result ) {
		$findings    = isset( $result['findings'] ) && is_array( $result['findings'] ) ? $result['findings'] : array();
		$summary     = isset( $result['summary'] ) && is_array( $result['summary'] ) ? $result['summary'] : array();
		$suspicious  = isset( $summary['suspicious'] ) ? (int) $summary['suspicious'] : ( isset( $summary['alert'] ) ? (int) $summary['alert'] : 0 );
		$panel       = $suspicious > 0 ? 'cws-core-checksum-results is-warning' : 'cws-core-checksum-results is-success';
		?>
		<div class="<?php echo esc_attr( $panel ); ?>">
			<p class="cws-core-checksum-summary">
				<?php
				if ( $suspicious > 0 ) {
					echo esc_html(
						sprintf(
							/* translators: %s: suspicious finding count */
							__( 'Scan complete. %s suspicious must-use plugin file(s) found for review.', 'choctaw-wp-security' ),
							number_format_i18n( $suspicious )
						)
					);
				} else {
					esc_html_e( 'Scan complete. No PHP-like files were found in the mu-plugins folder.', 'choctaw-wp-security' );
				}
				?>
			</p>
		</div>
		<?php if ( empty( $findings ) ) : ?>
			<p><?php esc_html_e( 'No must-use plugin files were found.', 'choctaw-wp-security' ); ?></p>
			<?php
			return;
		endif;

		$pagination = $this->paginate_report_items( $findings, $this->get_report_page_number( 'cws_mu_plugins' ) );
		?>
		<table class="widefat striped cws-core-checksum-table cws-mu-plugins-table">
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'Risk', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Status', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Category', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'File', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Action', 'choctaw-wp-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $pagination['items'] as $index => $finding ) : ?>
					<?php
					$row_id     = 'cws-mu-fallback-' . (int) $index;
					$path       = isset( $finding['path'] ) ? (string) $finding['path'] : '';
					$risk       = isset( $finding['risk_level'] ) ? (string) $finding['risk_level'] : ( isset( $finding['risk'] ) ? (string) $finding['risk'] : 'suspicious' );
					$risk_label = isset( $finding['risk_label'] ) ? (string) $finding['risk_label'] : __( 'Suspicious', 'choctaw-wp-security' );
					$status_lbl = isset( $finding['status_label'] ) ? (string) $finding['status_label'] : '';
					?>
					<tr>
						<td><?php $this->render_risk_badge( $risk, $risk_label ); ?></td>
						<td><?php echo esc_html( $status_lbl ); ?></td>
						<td><span class="cws-report-pill"><?php echo esc_html( isset( $finding['category_label'] ) ? (string) $finding['category_label'] : __( 'MU-Plugin', 'choctaw-wp-security' ) ); ?></span></td>
						<td><?php $this->render_file_path( $path ); ?></td>
						<td>
							<button type="button" class="cws-report-eye" data-expand-target="<?php echo esc_attr( $row_id ); ?>" aria-expanded="false" aria-label="<?php esc_attr_e( 'View details', 'choctaw-wp-security' ); ?>">
								<span class="dashicons dashicons-visibility" aria-hidden="true"></span>
							</button>
						</td>
					</tr>
					<tr class="cws-report-detail-row" id="<?php echo esc_attr( $row_id ); ?>" hidden>
						<td colspan="5">
							<div class="cws-report-detail-grid cws-mu-plugins-detail-grid">
								<div class="cws-mu-plugins-detail-left">
									<div class="cws-mu-plugins-info-panel">
										<h4><?php esc_html_e( 'Info', 'choctaw-wp-security' ); ?></h4>
										<dl>
											<dt><?php esc_html_e( 'Version', 'choctaw-wp-security' ); ?></dt>
											<dd><?php echo esc_html( $this->display_or_em_dash( isset( $finding['version'] ) ? (string) $finding['version'] : '' ) ); ?></dd>
											<dt><?php esc_html_e( 'Author', 'choctaw-wp-security' ); ?></dt>
											<dd><?php echo esc_html( $this->display_or_em_dash( isset( $finding['author'] ) ? (string) $finding['author'] : '' ) ); ?></dd>
											<dt><?php esc_html_e( 'Plugin URI', 'choctaw-wp-security' ); ?></dt>
											<dd><?php echo esc_html( $this->display_or_em_dash( isset( $finding['plugin_uri'] ) ? (string) $finding['plugin_uri'] : '' ) ); ?></dd>
											<dt><?php esc_html_e( 'Update URI', 'choctaw-wp-security' ); ?></dt>
											<dd><?php echo esc_html( $this->display_or_em_dash( isset( $finding['update_uri'] ) ? (string) $finding['update_uri'] : '' ) ); ?></dd>
											<dt><?php esc_html_e( 'Description', 'choctaw-wp-security' ); ?></dt>
											<dd><?php echo esc_html( $this->display_or_em_dash( isset( $finding['description'] ) ? (string) $finding['description'] : '' ) ); ?></dd>
											<dt><?php esc_html_e( 'File size', 'choctaw-wp-security' ); ?></dt>
											<dd><?php echo esc_html( $this->display_or_em_dash( isset( $finding['size_label'] ) ? (string) $finding['size_label'] : '' ) ); ?></dd>
											<dt><?php esc_html_e( 'Last modified', 'choctaw-wp-security' ); ?></dt>
											<dd><?php echo esc_html( $this->display_or_em_dash( isset( $finding['modified_label'] ) ? (string) $finding['modified_label'] : '' ) ); ?></dd>
										</dl>
									</div>
									<div class="cws-mu-plugins-contents">
										<h4><?php esc_html_e( 'Contents', 'choctaw-wp-security' ); ?></h4>
										<textarea class="cws-file-contents-textarea large-text code" rows="14" readonly><?php echo esc_textarea( $this->with_report_contents_footer( isset( $finding['contents'] ) ? (string) $finding['contents'] : '', ! empty( $finding['contents_truncated'] ), __( 'File', 'choctaw-wp-security' ) ) ); ?></textarea>
									</div>
								</div>
								<div class="cws-mu-plugins-detail-right">
									<div>
										<h4><?php esc_html_e( 'Why you are seeing this', 'choctaw-wp-security' ); ?></h4>
										<p><?php echo esc_html( isset( $finding['why_seeing_this'] ) ? (string) $finding['why_seeing_this'] : '' ); ?></p>
									</div>
									<div>
										<h4><?php esc_html_e( 'How to proceed', 'choctaw-wp-security' ); ?></h4>
										<p><?php echo esc_html( isset( $finding['how_to_proceed'] ) ? (string) $finding['how_to_proceed'] : '' ); ?></p>
									</div>
								</div>
							</div>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
		$this->render_report_pagination( 'cws_mu_plugins', $pagination, __( 'findings', 'choctaw-wp-security' ) );
	}

	/**
	 * Return a display string or an em dash when empty.
	 *
	 * @param string $value Raw value.
	 * @return string
	 */
	private function display_or_em_dash( $value ) {
		$value = trim( (string) $value );
		return '' === $value ? '—' : $value;
	}

	/**
	 * Render the About This Plugin tab.
	 *
	 * @return void
	 */
	private function render_about_this_plugin_tab() {
		?>
		<div class="cws-admin-tab-panel cws-about-plugin">
			<div class="cws-about-content">
				<h2><?php esc_html_e( 'About This Plugin', 'choctaw-wp-security' ); ?></h2>
				<p><?php esc_html_e( 'Sassh is 100% free to use.', 'choctaw-wp-security' ); ?></p>

				<h3><?php esc_html_e( 'Important: Please Read First!', 'choctaw-wp-security' ); ?></h3>
				<p><?php esc_html_e( 'This plugin is offered for free because it is not meant to provide a "set it and forget it" solution towards security. Rather, it is intended to be used as a tool for site admins who take an active approach towards thwarting attacks.', 'choctaw-wp-security' ); ?></p>
				<p><?php esc_html_e( 'As long as a site admin employs the following practices, this plugin will help close the gap towards 100% security:', 'choctaw-wp-security' ); ?></p>
				<ul class="cws-core-checksum-list">
					<li><?php esc_html_e( 'Logs into the WordPress Dashboard regularly and runs the scans available in this plugin.', 'choctaw-wp-security' ); ?></li>
					<li><?php esc_html_e( 'Investigates all reported results from these scans.', 'choctaw-wp-security' ); ?></li>
					<li><?php esc_html_e( 'Keeps the active theme updated.', 'choctaw-wp-security' ); ?></li>
					<li><?php esc_html_e( 'Keeps all active plugins updated.', 'choctaw-wp-security' ); ?></li>
					<li><?php esc_html_e( 'Removes unused themes and deactivated plugins.', 'choctaw-wp-security' ); ?></li>
					<li><?php esc_html_e( 'Periodically changes their login password.', 'choctaw-wp-security' ); ?></li>
				</ul>

				<h3><?php esc_html_e( 'Credits', 'choctaw-wp-security' ); ?></h3>
				<p>
					<?php esc_html_e( 'Please submit feature requests, bugs, and inquiries to its official Github Repository at:', 'choctaw-wp-security' ); ?>
					<a href="https://github.com/steve31266/Choctaw-WP-Security" target="_blank" rel="noopener noreferrer">https://github.com/steve31266/Choctaw-WP-Security</a>
				</p>
				<p>
					<?php esc_html_e( 'Sassh was created by Steve Johnson, Lead Developer, Choctaw Websites.', 'choctaw-wp-security' ); ?>
					<a href="https://www.choctawwebsites.com" target="_blank" rel="noopener noreferrer">https://www.choctawwebsites.com</a>
					<?php esc_html_e( ' Follow Steve on X at:', 'choctaw-wp-security' ); ?>
					<a href="https://x.com/stelis" target="_blank" rel="noopener noreferrer">@stelis</a>
				</p>
				<p>
					<?php esc_html_e( 'The Vulnerabilities tab uses vulnerability data from the WPVulnerability project.', 'choctaw-wp-security' ); ?>
					<a href="https://www.wpvulnerability.com/" target="_blank" rel="noopener noreferrer">https://www.wpvulnerability.com/</a>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Sassh logo.
	 *
	 * @param string $class CSS class for the image.
	 * @param int    $width Display width in pixels (height scales with the image).
	 * @return void
	 */
	private function render_coreguard_logo( $class = 'cws-page-title-logo', $width = 260 ) {
		?>
		<img
			class="<?php echo esc_attr( $class ); ?>"
			src="<?php echo esc_url( CHOCTAW_WP_SECURITY_URL . 'assets/images/sassh-logo.png' ); ?>"
			width="<?php echo esc_attr( (string) (int) $width ); ?>"
			alt="<?php esc_attr_e( 'Sassh logo', 'choctaw-wp-security' ); ?>"
		/>
		<?php
	}

	/**
	 * Handle a manual core checksum scan request.
	 *
	 * @return void
	 */
	public function handle_core_checksum_scan() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			return;
		}

		if ( empty( $_POST['choctaw_wp_security_core_checksum_scan'] ) ) {
			return;
		}

		check_admin_referer( 'choctaw_wp_security_core_checksum_scan' );

		$scanner = new Choctaw_Wp_Security_Core_Checksum_Scanner();
		$result  = $scanner->scan();

		$this->save_report_result(
			$this->get_core_checksum_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_CORE_CHECKSUM_RESULT,
			$result
		);

		wp_safe_redirect(
			$this->get_scans_page_url(
				'verify-checksums',
				array(
					'core_checksum_run' => '1',
				)
			)
		);
		exit;
	}

	/**
	 * Handle a manual component vulnerability scan request.
	 *
	 * @return void
	 */
	public function handle_component_scan() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			return;
		}

		if ( empty( $_POST['choctaw_wp_security_component_scan'] ) ) {
			return;
		}

		check_admin_referer( 'choctaw_wp_security_component_scan' );

		$scanner = new Choctaw_Wp_Security_Component_Vulnerability_Scanner();
		$result  = $scanner->scan();

		$this->save_report_result(
			$this->get_component_scan_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_COMPONENT_SCAN_RESULT,
			$result
		);

		wp_safe_redirect(
			$this->get_scans_page_url(
				'component-scan',
				array(
					'component_scan_run' => '1',
				)
			)
		);
		exit;
	}

	/**
	 * Handle a manual exposed folders scan request.
	 *
	 * @return void
	 */
	public function handle_exposed_folders_scan() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			return;
		}

		if ( empty( $_POST['choctaw_wp_security_exposed_folders_scan'] ) ) {
			return;
		}

		check_admin_referer( 'choctaw_wp_security_exposed_folders_scan_form' );

		$scanner = new Choctaw_Wp_Security_Directory_Browsing_Scanner();
		$result  = $scanner->scan();

		$this->save_report_result(
			$this->get_exposed_folders_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_EXPOSED_FOLDERS_RESULT,
			$result
		);

		wp_safe_redirect(
			$this->get_scans_page_url(
				'exposed-folders',
				array(
					'exposed_folders_run' => '1',
				)
			)
		);
		exit;
	}

	/**
	 * Handle a manual database scan request.
	 *
	 * @return void
	 */
	public function handle_database_scan() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			return;
		}

		if ( empty( $_POST['choctaw_wp_security_database_scan'] ) ) {
			return;
		}

		check_admin_referer( 'choctaw_wp_security_database_scan_form' );

		$resolved      = $this->get_resolved_scan_tables();
		$options_table = $resolved['options_table'];

		$scanner = new Choctaw_Wp_Security_Options_Table_Scanner( $options_table );
		$result  = $scanner->scan();

		$this->save_report_result(
			$this->get_database_scan_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_DATABASE_SCAN_RESULT,
			$result
		);

		wp_safe_redirect(
			$this->get_scans_page_url(
				'database-scan',
				array(
					'database_scan_run' => '1',
				)
			)
		);
		exit;
	}

	/**
	 * Handle a baseline reset request for the database scan.
	 *
	 * @return void
	 */
	public function handle_database_scan_baseline_reset() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			return;
		}

		if ( empty( $_POST['choctaw_wp_security_database_scan_baseline_reset'] ) ) {
			return;
		}

		check_admin_referer( 'choctaw_wp_security_database_scan_form' );

		$resolved      = $this->get_resolved_scan_tables();
		$options_table = $resolved['options_table'];

		Choctaw_Wp_Security_Options_Table_Scanner::reset_baseline( $options_table );

		wp_safe_redirect(
			$this->get_scans_page_url(
				'database-scan',
				array(
					'database_scan_baseline_reset' => '1',
				)
			)
		);
		exit;
	}

	/**
	 * Handle an AJAX database scan request.
	 *
	 * @return void
	 */
	public function ajax_database_scan() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to run database scans.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_database_scan_ajax', 'nonce' );

		$resolved      = $this->get_resolved_scan_tables();
		$options_table = $resolved['options_table'];

		$scanner = new Choctaw_Wp_Security_Options_Table_Scanner( $options_table );
		$result  = $scanner->scan();

		$result = $this->save_report_result(
			$this->get_database_scan_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_DATABASE_SCAN_RESULT,
			$result
		);

		wp_send_json_success(
			array(
				'result' => $result,
			)
		);
	}

	/**
	 * Handle an AJAX database scan baseline reset request.
	 *
	 * @return void
	 */
	public function ajax_database_scan_baseline_reset() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to reset the database scan baseline.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_database_scan_ajax', 'nonce' );

		$resolved      = $this->get_resolved_scan_tables();
		$options_table = $resolved['options_table'];

		Choctaw_Wp_Security_Options_Table_Scanner::reset_baseline( $options_table );

		wp_send_json_success(
			array(
				'message'       => __( 'The database scan baseline was reset for the selected options table.', 'choctaw-wp-security' ),
				'options_table' => $options_table,
			)
		);
	}

	/**
	 * Handle a manual scheduled tasks scan request.
	 *
	 * @return void
	 */
	public function handle_scheduled_tasks_scan() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			return;
		}

		if ( empty( $_POST['choctaw_wp_security_scheduled_tasks_scan'] ) ) {
			return;
		}

		check_admin_referer( 'choctaw_wp_security_scheduled_tasks_form' );

		$resolved      = $this->get_resolved_scan_tables();
		$options_table = $resolved['options_table'];

		$scanner = new Choctaw_Wp_Security_Scheduled_Tasks_Scanner( $options_table );
		$result  = $scanner->scan();

		$this->save_report_result(
			$this->get_scheduled_tasks_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_SCHEDULED_TASKS_RESULT,
			$result
		);

		wp_safe_redirect(
			$this->get_scans_page_url(
				'scheduled-tasks',
				array(
					'scheduled_tasks_run' => '1',
				)
			)
		);
		exit;
	}

	/**
	 * Handle an AJAX scheduled tasks scan request.
	 *
	 * @return void
	 */
	public function ajax_scheduled_tasks_scan() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to run WP-Cron scans.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_scheduled_tasks_ajax', 'nonce' );

		$resolved      = $this->get_resolved_scan_tables();
		$options_table = $resolved['options_table'];

		$scanner = new Choctaw_Wp_Security_Scheduled_Tasks_Scanner( $options_table );
		$result  = $scanner->scan();

		$result = $this->save_report_result(
			$this->get_scheduled_tasks_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_SCHEDULED_TASKS_RESULT,
			$result
		);

		wp_send_json_success(
			array(
				'result' => $result,
			)
		);
	}

	/**
	 * Handle a manual wp_posts scan request.
	 *
	 * @return void
	 */
	public function handle_posts_scan() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			return;
		}

		if ( empty( $_POST['choctaw_wp_security_posts_scan'] ) ) {
			return;
		}

		check_admin_referer( 'choctaw_wp_security_posts_scan_form' );

		$resolved    = $this->get_resolved_scan_tables();
		$posts_table = $resolved['posts_table'];

		$scanner = new Choctaw_Wp_Security_Posts_Table_Scanner( $posts_table );
		$result  = $scanner->scan();

		$this->save_report_result(
			$this->get_posts_scan_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_POSTS_SCAN_RESULT,
			$result
		);

		wp_safe_redirect(
			$this->get_scans_page_url(
				'wp-posts',
				array(
					'posts_scan_run' => '1',
				)
			)
		);
		exit;
	}

	/**
	 * Handle a manual Exposed Files scan request.
	 *
	 * @return void
	 */
	public function handle_exposed_files_scan() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			return;
		}

		if ( empty( $_POST['choctaw_wp_security_exposed_files_scan'] ) ) {
			return;
		}

		check_admin_referer( 'choctaw_wp_security_exposed_files_scan_form' );

		$scanner = new Choctaw_Wp_Security_Exposed_Files_Scanner();
		$result  = $scanner->scan();

		$this->save_report_result(
			$this->get_exposed_files_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_EXPOSED_FILES_RESULT,
			$result
		);

		wp_safe_redirect(
			$this->get_scans_page_url(
				'exposed-files',
				array(
					'exposed_files_run' => '1',
				)
			)
		);
		exit;
	}

	/**
	 * Handle a manual Uploads Folder scan request.
	 *
	 * @return void
	 */
	public function handle_uploads_folder_scan() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			return;
		}

		if ( empty( $_POST['choctaw_wp_security_uploads_folder_scan'] ) ) {
			return;
		}

		check_admin_referer( 'choctaw_wp_security_uploads_folder_scan_form' );

		$scanner = new Choctaw_Wp_Security_Uploads_Folder_Scanner();
		$result  = $scanner->scan();

		$this->save_report_result(
			$this->get_uploads_folder_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_UPLOADS_FOLDER_RESULT,
			$result
		);

		wp_safe_redirect(
			$this->get_scans_page_url(
				'uploads-folder',
				array(
					'uploads_folder_run' => '1',
				)
			)
		);
		exit;
	}

	/**
	 * Handle a manual MU-Plugins scan request.
	 *
	 * @return void
	 */
	public function handle_mu_plugins_scan() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			return;
		}

		if ( empty( $_POST['choctaw_wp_security_mu_plugins_scan'] ) ) {
			return;
		}

		check_admin_referer( 'choctaw_wp_security_mu_plugins_scan_form' );

		$scanner = new Choctaw_Wp_Security_Mu_Plugins_Scanner();
		$result  = $scanner->scan();

		$this->save_report_result(
			$this->get_mu_plugins_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_MU_PLUGINS_RESULT,
			$result
		);

		wp_safe_redirect(
			$this->get_scans_page_url(
				'mu-plugins',
				array(
					'mu_plugins_run' => '1',
				)
			)
		);
		exit;
	}

	/**
	 * Handle a baseline reset request for the wp_posts scan.
	 *
	 * @return void
	 */
	public function handle_posts_scan_baseline_reset() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			return;
		}

		if ( empty( $_POST['choctaw_wp_security_posts_scan_baseline_reset'] ) ) {
			return;
		}

		check_admin_referer( 'choctaw_wp_security_posts_scan_form' );

		$resolved    = $this->get_resolved_scan_tables();
		$posts_table = $resolved['posts_table'];

		Choctaw_Wp_Security_Posts_Table_Scanner::reset_baseline( $posts_table );

		wp_safe_redirect(
			$this->get_scans_page_url(
				'wp-posts',
				array(
					'posts_scan_baseline_reset' => '1',
				)
			)
		);
		exit;
	}

	/**
	 * Handle an AJAX wp_posts scan request.
	 *
	 * @return void
	 */
	public function ajax_posts_scan() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to run posts scans.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_posts_scan_ajax', 'nonce' );

		$resolved    = $this->get_resolved_scan_tables();
		$posts_table = $resolved['posts_table'];

		$scanner = new Choctaw_Wp_Security_Posts_Table_Scanner( $posts_table );
		$result  = $scanner->scan();

		$result = $this->save_report_result(
			$this->get_posts_scan_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_POSTS_SCAN_RESULT,
			$result
		);

		wp_send_json_success(
			array(
				'result' => $result,
			)
		);
	}

	/**
	 * Handle an AJAX wp_posts scan baseline reset request.
	 *
	 * @return void
	 */
	public function ajax_posts_scan_baseline_reset() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to reset the posts scan baseline.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_posts_scan_ajax', 'nonce' );

		$resolved    = $this->get_resolved_scan_tables();
		$posts_table = $resolved['posts_table'];

		Choctaw_Wp_Security_Posts_Table_Scanner::reset_baseline( $posts_table );

		wp_send_json_success(
			array(
				'message'     => __( 'The posts scan baseline was reset for the selected posts table.', 'choctaw-wp-security' ),
				'posts_table' => $posts_table,
			)
		);
	}

	/**
	 * Handle an AJAX Exposed Files scan request.
	 *
	 * @return void
	 */
	public function ajax_exposed_files_scan() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to run exposed files scans.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_exposed_files_ajax', 'nonce' );

		$scanner = new Choctaw_Wp_Security_Exposed_Files_Scanner();
		$result  = $scanner->scan();

		$result = $this->save_report_result(
			$this->get_exposed_files_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_EXPOSED_FILES_RESULT,
			$result
		);

		wp_send_json_success(
			array(
				'result' => $result,
			)
		);
	}

	/**
	 * Handle an AJAX Uploads Folder scan request.
	 *
	 * @return void
	 */
	public function ajax_uploads_folder_scan() {
		Sassh_Capabilities::require_manage_or_json_error(
			__( 'You do not have permission to run uploads folder scans.', 'choctaw-wp-security' )
		);

		check_ajax_referer( 'choctaw_wp_security_uploads_folder_ajax', 'nonce' );

		$scanner = new Choctaw_Wp_Security_Uploads_Folder_Scanner();
		$result  = $scanner->scan();

		$result = $this->save_report_result(
			$this->get_uploads_folder_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_UPLOADS_FOLDER_RESULT,
			$result
		);

		wp_send_json_success(
			array(
				'result' => $result,
			)
		);
	}

	/**
	 * Handle an AJAX MU-Plugins scan request.
	 *
	 * @return void
	 */
	public function ajax_mu_plugins_scan() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to run MU-Plugins scans.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_mu_plugins_ajax', 'nonce' );

		$scanner = new Choctaw_Wp_Security_Mu_Plugins_Scanner();
		$result  = $scanner->scan();

		$result = $this->save_report_result(
			$this->get_mu_plugins_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_MU_PLUGINS_RESULT,
			$result
		);

		wp_send_json_success(
			array(
				'result' => $result,
			)
		);
	}

	/**
	 * Handle an AJAX Directory Browsing scan request.
	 *
	 * @return void
	 */
	public function ajax_directory_browsing_scan() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to run directory browsing scans.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_directory_browsing_ajax', 'nonce' );

		$scanner = new Choctaw_Wp_Security_Directory_Browsing_Scanner();
		$result  = $scanner->scan();

		$result = $this->save_report_result(
			$this->get_exposed_folders_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_EXPOSED_FOLDERS_RESULT,
			$result
		);

		wp_send_json_success(
			array(
				'result' => $result,
			)
		);
	}

	/**
	 * Enqueue admin assets for Sassh pages.
	 *
	 * @param string $hook_suffix Current admin page hook suffix.
	 * @return void
	 */
	public function enqueue_admin_assets( $hook_suffix ) {
		if ( ! $this->is_coreguard_admin_page( $hook_suffix ) ) {
			return;
		}

		wp_enqueue_style(
			'choctaw-wp-security-admin',
			CHOCTAW_WP_SECURITY_URL . 'assets/css/admin-core-checksum.css',
			array(),
			(string) filemtime( CHOCTAW_WP_SECURITY_PATH . 'assets/css/admin-core-checksum.css' )
		);

		wp_enqueue_style(
			'choctaw-wp-security-report-risk',
			CHOCTAW_WP_SECURITY_URL . 'assets/css/admin-report-risk.css',
			array( 'choctaw-wp-security-admin' ),
			(string) filemtime( CHOCTAW_WP_SECURITY_PATH . 'assets/css/admin-report-risk.css' )
		);

		wp_enqueue_script(
			'choctaw-wp-security-admin-navigation',
			CHOCTAW_WP_SECURITY_URL . 'assets/js/admin-navigation.js',
			array(),
			(string) filemtime( CHOCTAW_WP_SECURITY_PATH . 'assets/js/admin-navigation.js' ),
			true
		);

		wp_enqueue_script(
			'choctaw-wp-security-admin-report-tables',
			CHOCTAW_WP_SECURITY_URL . 'assets/js/admin-report-tables.js',
			array(),
			(string) filemtime( CHOCTAW_WP_SECURITY_PATH . 'assets/js/admin-report-tables.js' ),
			true
		);

		Choctaw_Wp_Security_Admin_Help::enqueue_assets();

		if ( ! $this->is_scans_admin_page( $hook_suffix ) ) {
			return;
		}

		wp_enqueue_script(
			'choctaw-wp-security-report-pagination',
			CHOCTAW_WP_SECURITY_URL . 'assets/js/admin-report-pagination.js',
			array(),
			(string) filemtime( CHOCTAW_WP_SECURITY_PATH . 'assets/js/admin-report-pagination.js' ),
			true
		);

		wp_localize_script(
			'choctaw-wp-security-report-pagination',
			'choctawWpSecurityReportPagination',
			array(
				'pageSize' => $this->get_report_page_size(),
				'strings'  => array(
					/* translators: 1: first item number, 2: last item number, 3: total items, 4: item noun (findings, users, events, etc.) */
					'showingRange'  => __( 'Showing %1$s to %2$s of %3$s %4$s.', 'choctaw-wp-security' ),
					'pageOf'        => __( 'Page %1$s of %2$s', 'choctaw-wp-security' ),
					'firstPage'     => __( 'First page', 'choctaw-wp-security' ),
					'previousPage'  => __( 'Previous page', 'choctaw-wp-security' ),
					'nextPage'      => __( 'Next page', 'choctaw-wp-security' ),
					'lastPage'      => __( 'Last page', 'choctaw-wp-security' ),
					'items'         => __( 'items', 'choctaw-wp-security' ),
					'findings'      => __( 'findings', 'choctaw-wp-security' ),
					'users'         => __( 'users', 'choctaw-wp-security' ),
					'events'        => __( 'events', 'choctaw-wp-security' ),
					'components'    => __( 'components', 'choctaw-wp-security' ),
					'lockouts'      => __( 'lockouts', 'choctaw-wp-security' ),
					'matches'                  => __( 'matches', 'choctaw-wp-security' ),
					/* translators: %s: content noun (File, Arguments, Snippet, Option Value) */
					'contentsEndOf'            => __( '---End of %1$s', 'choctaw-wp-security' ),
					'contentsTruncatedFooter'  => Choctaw_Wp_Security_Utils::report_contents_truncated_label(),
					'contentsNounFile'         => __( 'File', 'choctaw-wp-security' ),
					'contentsNounArguments'    => __( 'Arguments', 'choctaw-wp-security' ),
					'contentsNounSnippet'      => __( 'Snippet', 'choctaw-wp-security' ),
					'contentsNounOptionValue'  => __( 'Option Value', 'choctaw-wp-security' ),
				),
			)
		);

		wp_enqueue_script(
			'choctaw-wp-security-report-status',
			CHOCTAW_WP_SECURITY_URL . 'assets/js/admin-report-status.js',
			array( 'choctaw-wp-security-admin-help' ),
			(string) filemtime( CHOCTAW_WP_SECURITY_PATH . 'assets/js/admin-report-status.js' ),
			true
		);

		wp_enqueue_script(
			'choctaw-wp-security-report-related-findings',
			CHOCTAW_WP_SECURITY_URL . 'assets/js/admin-report-related-findings.js',
			array( 'choctaw-wp-security-report-status' ),
			(string) filemtime( CHOCTAW_WP_SECURITY_PATH . 'assets/js/admin-report-related-findings.js' ),
			true
		);

		wp_localize_script(
			'choctaw-wp-security-report-status',
			'choctawWpSecurityFindingStatus',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'choctaw_wp_security_finding_status' ),
				'sasshNonce' => wp_create_nonce( 'sassh_finding_status' ),
				'strings'    => array(
					'status'            => __( 'Status', 'choctaw-wp-security' ),
					'needsReview'       => __( 'Needs Review', 'choctaw-wp-security' ),
					'noActionNeeded'    => __( 'Review Not Needed', 'choctaw-wp-security' ),
					'dismissed'         => __( 'Dismissed', 'choctaw-wp-security' ),
					'allStatuses'       => __( 'All statuses', 'choctaw-wp-security' ),
					'dismissThisItem'   => __( 'Dismiss this item', 'choctaw-wp-security' ),
					'submit'            => __( 'Submit', 'choctaw-wp-security' ),
					'statusError'       => __( 'The status could not be updated.', 'choctaw-wp-security' ),
					'clearHistory'      => __( 'Clear History', 'choctaw-wp-security' ),
					'clearHistoryError' => __( 'History could not be cleared.', 'choctaw-wp-security' ),
					'relatedFindings'   => __( 'Related findings', 'choctaw-wp-security' ),
					'relatedSameFp'     => __( 'Same file contents fingerprint', 'choctaw-wp-security' ),
					'relatedDiffFp'     => __( 'Different file contents fingerprint', 'choctaw-wp-security' ),
					'relatedUnknownFp'  => __( 'Object fingerprint comparison unavailable', 'choctaw-wp-security' ),
					'relatedDismissedHint' => __( 'This file was previously reported by another scanner and dismissed while its contents had the same fingerprint.', 'choctaw-wp-security' ),
					'relatedLoadError'  => __( 'Related findings could not be loaded.', 'choctaw-wp-security' ),
					'notDetected'       => __( 'No Longer Detected', 'choctaw-wp-security' ),
				),
			)
		);

		if ( 'database-scan' === $this->get_active_admin_tab() ) {
			wp_enqueue_script(
				'choctaw-wp-security-database-scan',
				CHOCTAW_WP_SECURITY_URL . 'assets/js/admin-database-scan.js',
				array( 'choctaw-wp-security-admin-help', 'choctaw-wp-security-report-status', 'choctaw-wp-security-report-pagination' ),
				CHOCTAW_WP_SECURITY_VERSION,
				true
			);

			wp_localize_script(
				'choctaw-wp-security-database-scan',
				'choctawWpSecurityDatabaseScan',
				array(
					'ajaxUrl'        => admin_url( 'admin-ajax.php' ),
					'nonce'          => wp_create_nonce( 'choctaw_wp_security_database_scan_ajax' ),
					'scanType'       => 'database-scan',
					'pageSize'       => $this->get_report_page_size(),
					'itemNoun'       => __( 'findings', 'choctaw-wp-security' ),
					'initialResult'  => $this->load_report_result(
						$this->get_database_scan_result_transient_key(),
						Choctaw_Wp_Security_Utils::USER_META_DATABASE_SCAN_RESULT
					),
					'categoryLabels' => Choctaw_Wp_Security_Options_Scan_Patterns::get_category_labels(),
					'detailGuidance' => Choctaw_Wp_Security_Options_Scan_Patterns::get_detail_guidance(),
					'strings'        => array(
						'scanButton'         => __( 'Scan Now', 'choctaw-wp-security' ),
						'rescanButton'       => __( 'Rescan', 'choctaw-wp-security' ),
						'refreshButton'      => __( 'Refresh', 'choctaw-wp-security' ),
						'scanning'           => __( 'Scanning options table...', 'choctaw-wp-security' ),
						'resettingBaseline'  => __( 'Resetting baseline...', 'choctaw-wp-security' ),
						'scanError'          => __( 'The database scan could not be completed.', 'choctaw-wp-security' ),
						'resetError'         => __( 'The database scan baseline could not be reset.', 'choctaw-wp-security' ),
						'noFindings'         => __( 'No findings matched the current filters.', 'choctaw-wp-security' ),
						'noFlagged'          => __( 'No findings requiring review were found. Choose All statuses or a Safe/Info risk filter to view inventory findings.', 'choctaw-wp-security' ),
						'sortAscending'      => __( 'Sort ascending', 'choctaw-wp-security' ),
						'sortDescending'     => __( 'Sort descending', 'choctaw-wp-security' ),
						'configuredTable'    => __( 'WordPress configured table: %s', 'choctaw-wp-security' ),
						'scanCompleteIssues' => __( 'Scan complete. %1$s critical, %2$s suspicious, %3$s safe, and %4$s informational findings.', 'choctaw-wp-security' ),
						'scanCompleteClean'  => __( 'Scan complete. No critical or suspicious findings. %1$s safe and %2$s informational item(s) reported.', 'choctaw-wp-security' ),
						'incomplete'         => __( 'The scan stopped early because it reached its time budget. Review the partial results below and run the scan again if needed.', 'choctaw-wp-security' ),
						'risk'               => __( 'Risk', 'choctaw-wp-security' ),
						'status'             => __( 'Status', 'choctaw-wp-security' ),
						'category'           => __( 'Category', 'choctaw-wp-security' ),
						'allRisks'           => __( 'All risks', 'choctaw-wp-security' ),
						'needsReview'        => __( 'Needs Review', 'choctaw-wp-security' ),
						'allCategories'      => __( 'All categories', 'choctaw-wp-security' ),
						'riskCritical'       => __( 'Critical', 'choctaw-wp-security' ),
						'riskSuspicious'     => __( 'Suspicious', 'choctaw-wp-security' ),
						'riskSafe'           => __( 'Safe', 'choctaw-wp-security' ),
						'riskInfo'           => __( 'Info', 'choctaw-wp-security' ),
						'searchPlaceholder'  => __( 'Search option name or value', 'choctaw-wp-security' ),
						'optionId'           => __( 'Option ID', 'choctaw-wp-security' ),
						'option'             => __( 'Option', 'choctaw-wp-security' ),
						'size'               => __( 'Size', 'choctaw-wp-security' ),
						'detail'             => __( 'Detail', 'choctaw-wp-security' ),
						'excerpt'            => __( 'Excerpt', 'choctaw-wp-security' ),
						'actions'            => __( 'Action', 'choctaw-wp-security' ),
						'optionValue'        => __( 'Option Value', 'choctaw-wp-security' ),
						'infoPanel'          => __( 'Info', 'choctaw-wp-security' ),
						'whySeeingThis'      => __( 'Why you are seeing this', 'choctaw-wp-security' ),
						'howToProceed'       => __( 'How to proceed', 'choctaw-wp-security' ),
						'whySeeingThisFallback' => __( 'This option matched one of the wp_options security checks. Review the Detail and Option Value to understand why it was flagged.', 'choctaw-wp-security' ),
						'howToProceedFallback'  => __( 'Confirm whether the value is expected for your site. If it is not, restore or remove it using a trusted backup or admin workflow, then rescan. Sassh reports findings only — it does not modify options automatically.', 'choctaw-wp-security' ),
						'viewDetails'        => __( 'View details', 'choctaw-wp-security' ),
						'hideDetails'        => __( 'Hide details', 'choctaw-wp-security' ),
					),
				)
			);
		}

		if ( 'scheduled-tasks' === $this->get_active_admin_tab() ) {
			wp_enqueue_style(
				'choctaw-wp-security-scheduled-tasks',
				CHOCTAW_WP_SECURITY_URL . 'assets/css/admin-scheduled-tasks.css',
				array( 'choctaw-wp-security-report-risk' ),
				CHOCTAW_WP_SECURITY_VERSION
			);

			wp_enqueue_script(
				'choctaw-wp-security-scheduled-tasks',
				CHOCTAW_WP_SECURITY_URL . 'assets/js/admin-scheduled-tasks.js',
				array( 'choctaw-wp-security-admin-help', 'choctaw-wp-security-report-status', 'choctaw-wp-security-report-pagination' ),
				CHOCTAW_WP_SECURITY_VERSION,
				true
			);

			wp_localize_script(
				'choctaw-wp-security-scheduled-tasks',
				'choctawWpSecurityScheduledTasks',
				array(
					'ajaxUrl'        => admin_url( 'admin-ajax.php' ),
					'nonce'          => wp_create_nonce( 'choctaw_wp_security_scheduled_tasks_ajax' ),
					'scanType'       => 'scheduled-tasks',
					'pageSize'       => $this->get_report_page_size(),
					'itemNoun'       => __( 'events', 'choctaw-wp-security' ),
					'initialResult'  => $this->load_report_result(
						$this->get_scheduled_tasks_result_transient_key(),
						Choctaw_Wp_Security_Utils::USER_META_SCHEDULED_TASKS_RESULT
					),
					'categoryLabels' => Choctaw_Wp_Security_Scheduled_Tasks_Patterns::get_category_labels(),
					'strings'        => array(
						'scanButton'           => __( 'Scan Now', 'choctaw-wp-security' ),
						'refreshButton'        => __( 'Refresh', 'choctaw-wp-security' ),
						'scanning'             => __( 'Scanning WP-Cron events...', 'choctaw-wp-security' ),
						'scanError'            => __( 'The WP-Cron scan could not be completed.', 'choctaw-wp-security' ),
						'noFindings'           => __( 'No WP-Cron events matched the current filters.', 'choctaw-wp-security' ),
						'noFlagged'            => __( 'No WP-Cron events requiring review were found. Choose All Risk or Info to include recognized maintenance jobs.', 'choctaw-wp-security' ),
						'sortAscending'        => __( 'Sort ascending', 'choctaw-wp-security' ),
						'sortDescending'       => __( 'Sort descending', 'choctaw-wp-security' ),
						'configuredTable'      => __( 'WordPress configured table: %s', 'choctaw-wp-security' ),
						'scanCompleteIssues'   => __( 'Scan complete. %1$s critical, %2$s suspicious, %3$s review, and %4$s informational findings. %5$s flagged for review.', 'choctaw-wp-security' ),
						'scanCompleteClean'    => __( 'Scan complete. No critical or suspicious findings. %1$s review and %2$s informational item(s) reported. %3$s flagged for review.', 'choctaw-wp-security' ),
						'risk'                 => __( 'Risk', 'choctaw-wp-security' ),
						'category'             => __( 'Category', 'choctaw-wp-security' ),
						'hook'                 => __( 'Hook', 'choctaw-wp-security' ),
						'schedule'             => __( 'Schedule', 'choctaw-wp-security' ),
						'nextRun'              => __( 'Next Run', 'choctaw-wp-security' ),
						'source'               => __( 'Source', 'choctaw-wp-security' ),
						'size'                 => __( 'Size', 'choctaw-wp-security' ),
						'details'              => __( 'Details', 'choctaw-wp-security' ),
						'excerpt'              => __( 'Excerpt', 'choctaw-wp-security' ),
						'actions'              => __( 'Action', 'choctaw-wp-security' ),
						'viewDetails'          => __( 'View details', 'choctaw-wp-security' ),
						'hideDetails'          => __( 'Hide details', 'choctaw-wp-security' ),
						'infoPanel'            => __( 'Info', 'choctaw-wp-security' ),
						'rawArguments'         => __( 'Raw Arguments', 'choctaw-wp-security' ),
						'confidence'           => __( 'Confidence: %s', 'choctaw-wp-security' ),
						'whySeeingThis'        => __( 'Why you are seeing this', 'choctaw-wp-security' ),
						'howToProceed'         => __( 'How to proceed', 'choctaw-wp-security' ),
						'allRisk'              => __( 'All Risk', 'choctaw-wp-security' ),
						'needsReview'          => __( 'Needs review', 'choctaw-wp-security' ),
						'allCategories'        => __( 'All Categories', 'choctaw-wp-security' ),
						'allSources'           => __( 'All Sources', 'choctaw-wp-security' ),
						'searchPlaceholder'    => __( 'Search hook or source...', 'choctaw-wp-security' ),
						'riskCritical'         => __( 'Critical', 'choctaw-wp-security' ),
						'riskSuspicious'       => __( 'Suspicious', 'choctaw-wp-security' ),
						'riskReview'           => __( 'Review', 'choctaw-wp-security' ),
						'riskInfo'             => __( 'Info', 'choctaw-wp-security' ),
						'sourcePlugin'         => __( 'Plugin', 'choctaw-wp-security' ),
						'sourceTheme'          => __( 'Theme', 'choctaw-wp-security' ),
						'sourceUnknown'        => __( 'Unknown', 'choctaw-wp-security' ),
						'whyThisMatters'       => Choctaw_Wp_Security_Admin_Help::get_toggle_label(),
					),
				)
			);
		}

		if ( 'wp-posts' === $this->get_active_admin_tab() ) {
			wp_enqueue_script(
				'choctaw-wp-security-posts-scan',
				CHOCTAW_WP_SECURITY_URL . 'assets/js/admin-posts-scan.js',
				array( 'choctaw-wp-security-admin-help', 'choctaw-wp-security-report-status', 'choctaw-wp-security-report-pagination' ),
				CHOCTAW_WP_SECURITY_VERSION,
				true
			);

			wp_localize_script(
				'choctaw-wp-security-posts-scan',
				'choctawWpSecurityPostsScan',
				array(
					'ajaxUrl'        => admin_url( 'admin-ajax.php' ),
					'nonce'          => wp_create_nonce( 'choctaw_wp_security_posts_scan_ajax' ),
					'scanType'       => 'wp-posts',
					'pageSize'       => $this->get_report_page_size(),
					'itemNoun'       => __( 'findings', 'choctaw-wp-security' ),
					'initialResult'  => $this->load_report_result(
						$this->get_posts_scan_result_transient_key(),
						Choctaw_Wp_Security_Utils::USER_META_POSTS_SCAN_RESULT
					),
					'categoryLabels' => Choctaw_Wp_Security_Posts_Scan_Patterns::get_category_labels(),
					'detailGuidance' => Choctaw_Wp_Security_Posts_Scan_Patterns::get_detail_guidance(),
					'strings'        => array(
						'scanButton'         => __( 'Scan Now', 'choctaw-wp-security' ),
						'rescanButton'       => __( 'Rescan', 'choctaw-wp-security' ),
						'refreshButton'      => __( 'Refresh', 'choctaw-wp-security' ),
						'scanning'           => __( 'Scanning posts table...', 'choctaw-wp-security' ),
						'resettingBaseline'  => __( 'Resetting baseline...', 'choctaw-wp-security' ),
						'scanError'          => __( 'The posts scan could not be completed.', 'choctaw-wp-security' ),
						'resetError'         => __( 'The posts scan baseline could not be reset.', 'choctaw-wp-security' ),
						'noFindings'         => __( 'No findings matched the current filters.', 'choctaw-wp-security' ),
						'noFlagged'          => __( 'No findings requiring review were found. Choose All risks, Safe, or Info to view inventory findings.', 'choctaw-wp-security' ),
						'sortAscending'      => __( 'Sort ascending', 'choctaw-wp-security' ),
						'sortDescending'     => __( 'Sort descending', 'choctaw-wp-security' ),
						'configuredTable'    => __( 'WordPress configured table: %s', 'choctaw-wp-security' ),
						'scanCompleteIssues' => __( 'Scan complete. %1$s critical, %2$s suspicious, %3$s safe, and %4$s informational findings.', 'choctaw-wp-security' ),
						'scanCompleteClean'  => __( 'Scan complete. No critical or suspicious findings. %1$s safe and %2$s informational item(s) reported.', 'choctaw-wp-security' ),
						'incomplete'         => __( 'The scan stopped early because it reached its time budget. Review the partial results below and run the scan again if needed.', 'choctaw-wp-security' ),
						'risk'               => __( 'Risk', 'choctaw-wp-security' ),
						'category'           => __( 'Category', 'choctaw-wp-security' ),
						'allRisks'           => __( 'All risks', 'choctaw-wp-security' ),
						'needsReview'        => __( 'Needs review', 'choctaw-wp-security' ),
						'allCategories'      => __( 'All categories', 'choctaw-wp-security' ),
						'riskCritical'       => __( 'Critical', 'choctaw-wp-security' ),
						'riskSuspicious'     => __( 'Suspicious', 'choctaw-wp-security' ),
						'riskSafe'           => __( 'Safe', 'choctaw-wp-security' ),
						'riskInfo'           => __( 'Info', 'choctaw-wp-security' ),
						'postId'             => __( 'Post ID', 'choctaw-wp-security' ),
						'userId'             => __( 'User ID', 'choctaw-wp-security' ),
						'userDisplayName'    => __( 'User Display Name', 'choctaw-wp-security' ),
						'title'              => __( 'Title', 'choctaw-wp-security' ),
						'type'               => __( 'Type', 'choctaw-wp-security' ),
						'status'             => __( 'Status', 'choctaw-wp-security' ),
						'size'               => __( 'Size', 'choctaw-wp-security' ),
						'detail'             => __( 'Detail', 'choctaw-wp-security' ),
						'excerpt'            => __( 'Excerpt', 'choctaw-wp-security' ),
						'actions'            => __( 'Action', 'choctaw-wp-security' ),
						'matchedSnippet'     => __( 'Matched Snippet', 'choctaw-wp-security' ),
						'infoPanel'          => __( 'Info', 'choctaw-wp-security' ),
						'whySeeingThis'      => __( 'Why you are seeing this', 'choctaw-wp-security' ),
						'howToProceed'       => __( 'How to proceed', 'choctaw-wp-security' ),
						'whySeeingThisFallback' => __( 'This post matched one of the wp_posts security checks. Review the Detail and Matched Snippet to understand why it was flagged.', 'choctaw-wp-security' ),
						'howToProceedFallback'  => __( 'Confirm whether the post content is expected. If it is not, clean or trash it using the editor or a trusted backup, then rescan. Sassh reports findings only — it does not modify posts automatically.', 'choctaw-wp-security' ),
						'viewDetails'        => __( 'View details', 'choctaw-wp-security' ),
						'hideDetails'        => __( 'Hide details', 'choctaw-wp-security' ),
						'userIdLabel'        => __( 'User ID %1$s (%2$s)', 'choctaw-wp-security' ),
					),
				)
			);
		}

		if ( 'wp-users' === $this->get_active_admin_tab() ) {
			wp_enqueue_script(
				'choctaw-wp-security-users-table',
				CHOCTAW_WP_SECURITY_URL . 'assets/js/admin-users-table.js',
				array( 'choctaw-wp-security-admin-help', 'choctaw-wp-security-report-status', 'choctaw-wp-security-report-pagination' ),
				CHOCTAW_WP_SECURITY_VERSION,
				true
			);

			wp_localize_script(
				'choctaw-wp-security-users-table',
				'choctawWpSecurityUsersTable',
				array(
					'ajaxUrl'       => admin_url( 'admin-ajax.php' ),
					'nonce'         => wp_create_nonce( 'choctaw_wp_security_users_table_ajax' ),
					'pageSize'      => $this->get_report_page_size(),
					'itemNoun'      => __( 'users', 'choctaw-wp-security' ),
					'activityItemNoun' => __( 'items', 'choctaw-wp-security' ),
					'usermetaItemNoun' => __( 'items', 'choctaw-wp-security' ),
					'fileActivityItemNoun' => __( 'matches', 'choctaw-wp-security' ),
					'initialResult' => $this->load_report_result(
						$this->get_users_table_result_transient_key(),
						Choctaw_Wp_Security_Utils::USER_META_USERS_TABLE_RESULT
					),
					'strings'       => array(
						'loadButton'           => __( 'Load Users', 'choctaw-wp-security' ),
						'reloadButton'         => __( 'Reload Selected Table', 'choctaw-wp-security' ),
						'loading'              => __( 'Loading users from the selected table...', 'choctaw-wp-security' ),
						'loadError'            => __( 'The users table could not be loaded.', 'choctaw-wp-security' ),
						'activityError'        => __( 'User activity could not be loaded.', 'choctaw-wp-security' ),
						'activityLoading'      => __( 'Loading user activity...', 'choctaw-wp-security' ),
						'viewActivity'         => __( 'View activity', 'choctaw-wp-security' ),
						'hideActivity'         => __( 'Hide activity', 'choctaw-wp-security' ),
						'viewDetails'          => __( 'View details', 'choctaw-wp-security' ),
						'hideDetails'          => __( 'Hide details', 'choctaw-wp-security' ),
						'noUsers'              => __( 'No users were found in the selected table.', 'choctaw-wp-security' ),
						'noActivity'           => __( 'No detectable activity was found for this user.', 'choctaw-wp-security' ),
						'activityLimitations'  => __( 'This scan reviews key WordPress database tables for records associated with this user and reconstructs a timeline of their content, media, comments, and other recorded activity.', 'choctaw-wp-security' ),
						'activityCapped'       => __( 'Showing the %s most recent activity items.', 'choctaw-wp-security' ),
						'tabDatabaseActivity'  => __( 'Database Activity', 'choctaw-wp-security' ),
						'tabUsermeta'          => __( 'Usermeta Table', 'choctaw-wp-security' ),
						'tabFileActivity'      => __( 'File Activity', 'choctaw-wp-security' ),
						'usermetaScope'        => __( 'This scan displays all usermeta records associated with this account, including roles, capabilities, preferences, plugin settings, and other user-specific metadata.', 'choctaw-wp-security' ),
						'usermetaLoading'      => __( 'Loading usermeta...', 'choctaw-wp-security' ),
						'usermetaError'        => __( 'Usermeta could not be loaded.', 'choctaw-wp-security' ),
						'noUsermeta'           => __( 'No usermeta rows were found for this user.', 'choctaw-wp-security' ),
						'usermetaCapped'       => __( 'Showing the first %s usermeta rows.', 'choctaw-wp-security' ),
						'metaKey'              => __( 'Meta Key', 'choctaw-wp-security' ),
						'metaValue'            => __( 'Meta Value', 'choctaw-wp-security' ),
						'fileActivityLoading'  => __( 'Searching code files for this user\'s login and email...', 'choctaw-wp-security' ),
						'fileActivityError'    => __( 'File activity could not be loaded.', 'choctaw-wp-security' ),
						'noFileActivity'       => __( 'No matching file references were found for this user\'s login or email.', 'choctaw-wp-security' ),
						'fileActivityCapped'   => __( 'Showing the first %s file matches.', 'choctaw-wp-security' ),
						'fileActivityIncomplete' => __( 'The file search stopped early because the time budget was reached. Results may be incomplete.', 'choctaw-wp-security' ),
						'fileActivityScope'    => __( 'This scan searches WordPress root files, plugins, themes, and mu-plugins for references to this user\'s login name and email address, helping identify code that may create, modify, or reference the account.', 'choctaw-wp-security' ),
						'filePath'             => __( 'Path', 'choctaw-wp-security' ),
						'fileFilename'         => __( 'Filename', 'choctaw-wp-security' ),
						'fileLineNumber'       => __( 'Line Number', 'choctaw-wp-security' ),
						'fileMatch'            => __( 'Match', 'choctaw-wp-security' ),
						'fileContents'         => __( 'Contents', 'choctaw-wp-security' ),
						'configuredTable'      => __( 'WordPress configured table: %s', 'choctaw-wp-security' ),
						'usersLoaded'          => __( '%s user(s) loaded.', 'choctaw-wp-security' ),
						'items'                => __( '%s items', 'choctaw-wp-security' ),
						'item'                 => __( '%s item', 'choctaw-wp-security' ),
						'sortAscending'        => __( 'Sort ascending', 'choctaw-wp-security' ),
						'sortDescending'       => __( 'Sort descending', 'choctaw-wp-security' ),
						'id'                   => __( 'ID', 'choctaw-wp-security' ),
						'userLogin'            => __( 'user_login', 'choctaw-wp-security' ),
						'userEmail'            => __( 'user_email', 'choctaw-wp-security' ),
						'userRegistered'       => __( 'user_registered', 'choctaw-wp-security' ),
						'userStatus'           => __( 'user_status', 'choctaw-wp-security' ),
						'displayName'          => __( 'display_name', 'choctaw-wp-security' ),
						'actions'              => __( 'Action', 'choctaw-wp-security' ),
						'allStatuses'         => __( 'All statuses', 'choctaw-wp-security' ),
						'activityDate'         => __( 'Date', 'choctaw-wp-security' ),
						'activityLabel'        => __( 'Activity', 'choctaw-wp-security' ),
						'activityType'         => __( 'Type', 'choctaw-wp-security' ),
						'activityTitle'        => __( 'Title', 'choctaw-wp-security' ),
						'activityDetail'       => __( 'Status/Detail', 'choctaw-wp-security' ),
					),
				)
			);
		}

		if ( 'file-changes' === $this->get_active_admin_tab() ) {
			wp_enqueue_script(
				'choctaw-wp-security-file-changes',
				CHOCTAW_WP_SECURITY_URL . 'assets/js/admin-file-changes.js',
				array( 'choctaw-wp-security-admin-help', 'choctaw-wp-security-report-status' ),
				CHOCTAW_WP_SECURITY_VERSION,
				true
			);

			wp_localize_script(
				'choctaw-wp-security-file-changes',
				'choctawWpSecurityFileChanges',
				array(
					'ajaxUrl' => admin_url( 'admin-ajax.php' ),
					'nonce'   => wp_create_nonce( 'choctaw_wp_security_file_changes_checksum_ajax' ),
					'paths'   => $this->get_core_file_change_checksum_paths(),
					'strings' => array(
						'checking'          => __( 'Checking…', 'choctaw-wp-security' ),
						'verified'          => __( 'Checksum verified', 'choctaw-wp-security' ),
						'failed'            => __( 'Checksum mismatch', 'choctaw-wp-security' ),
						'missing'           => __( 'File missing', 'choctaw-wp-security' ),
						'notApplicable'     => __( 'Not included in WordPress core checksums', 'choctaw-wp-security' ),
						'unavailable'       => __( 'Checksum unavailable', 'choctaw-wp-security' ),
						'scanError'         => __( 'Unable to verify checksums for these files.', 'choctaw-wp-security' ),
						'notApplicableAbbr' => __( 'N/A', 'choctaw-wp-security' ),
						'riskSafe'          => __( 'Safe', 'choctaw-wp-security' ),
						'riskCritical'      => __( 'Critical', 'choctaw-wp-security' ),
						'riskMissing'       => __( 'Missing', 'choctaw-wp-security' ),
						'riskNa'            => __( 'N/A', 'choctaw-wp-security' ),
						'riskExplainSafe'   => __( 'This file matches the official WordPress.org checksum for your installed version.', 'choctaw-wp-security' ),
						'riskExplainCritical' => __( 'This file does not match the official WordPress.org checksum, indicating it was modified after installation.', 'choctaw-wp-security' ),
						'riskExplainMissing' => __( 'Official WordPress core verification reports that this file is missing from disk.', 'choctaw-wp-security' ),
						'riskExplainNa'     => __( 'This file is not included in official WordPress core checksums. Site-specific files such as wp-config.php and .htaccess cannot be verified this way.', 'choctaw-wp-security' ),
						'riskExplainPending' => __( 'Checksum status is still being verified.', 'choctaw-wp-security' ),
						'riskExplainUnavailable' => __( 'Checksum status could not be determined for this file.', 'choctaw-wp-security' ),
					),
				)
			);
		}

		if ( 'exposed-files' === $this->get_active_admin_tab() ) {
			wp_enqueue_style(
				'choctaw-wp-security-exposed-files',
				CHOCTAW_WP_SECURITY_URL . 'assets/css/admin-exposed-files.css',
				array( 'choctaw-wp-security-report-risk' ),
				(string) filemtime( CHOCTAW_WP_SECURITY_PATH . 'assets/css/admin-exposed-files.css' )
			);

			wp_enqueue_script(
				'choctaw-wp-security-exposed-files',
				CHOCTAW_WP_SECURITY_URL . 'assets/js/admin-exposed-files.js',
				array( 'choctaw-wp-security-admin-help', 'choctaw-wp-security-report-status', 'choctaw-wp-security-report-pagination' ),
				(string) filemtime( CHOCTAW_WP_SECURITY_PATH . 'assets/js/admin-exposed-files.js' ),
				true
			);

			wp_localize_script(
				'choctaw-wp-security-exposed-files',
				'choctawWpSecurityExposedFiles',
				array(
					'ajaxUrl'        => admin_url( 'admin-ajax.php' ),
					'nonce'          => wp_create_nonce( 'choctaw_wp_security_exposed_files_ajax' ),
					'scanType'       => 'exposed-files',
					'pageSize'       => $this->get_report_page_size(),
					'itemNoun'       => __( 'findings', 'choctaw-wp-security' ),
					'initialResult'  => $this->load_report_result(
						$this->get_exposed_files_result_transient_key(),
						Choctaw_Wp_Security_Utils::USER_META_EXPOSED_FILES_RESULT
					),
					'categoryLabels' => Choctaw_Wp_Security_Exposed_Files_Scanner::get_category_labels(),
					'strings'        => array(
						'scanButton'            => __( 'Scan Now', 'choctaw-wp-security' ),
						'rescanButton'          => __( 'Rescan', 'choctaw-wp-security' ),
						'scanning'              => __( 'Scanning for exposed files...', 'choctaw-wp-security' ),
						'scanError'             => __( 'The exposed files scan could not be completed.', 'choctaw-wp-security' ),
						'noFindings'            => __( 'No findings matched the current filters.', 'choctaw-wp-security' ),
						'risk'                  => __( 'Risk', 'choctaw-wp-security' ),
						'category'              => __( 'Category', 'choctaw-wp-security' ),
						'allRisks'              => __( 'All risks', 'choctaw-wp-security' ),
						'allCategories'         => __( 'All categories', 'choctaw-wp-security' ),
						'riskCritical'          => __( 'Critical', 'choctaw-wp-security' ),
						'riskAlert'             => __( 'Alert', 'choctaw-wp-security' ),
						'riskWarning'           => __( 'Warning', 'choctaw-wp-security' ),
						'riskInfo'              => __( 'Info', 'choctaw-wp-security' ),
						'filename'              => __( 'Filename', 'choctaw-wp-security' ),
						'actions'               => __( 'Action', 'choctaw-wp-security' ),
						'infoPanel'             => __( 'Info', 'choctaw-wp-security' ),
						'contentsHeading'       => __( 'Contents', 'choctaw-wp-security' ),
						'modifiedDateTime'      => __( 'Modified Date/Time', 'choctaw-wp-security' ),
						'fileSize'              => __( 'File Size', 'choctaw-wp-security' ),
						'permissions'           => __( 'Permissions', 'choctaw-wp-security' ),
						'owner'                 => __( 'Owner', 'choctaw-wp-security' ),
						'whySeeingThis'         => __( 'Why you are seeing this', 'choctaw-wp-security' ),
						'howToProceed'          => __( 'How to proceed', 'choctaw-wp-security' ),
						'whySeeingThisFallback' => __( 'This file matches a pattern commonly left exposed in WordPress document roots.', 'choctaw-wp-security' ),
						'howToProceedFallback'  => __( 'Review the file carefully. Remove or relocate anything that should not be publicly accessible.', 'choctaw-wp-security' ),
						'viewDetails'           => __( 'View details', 'choctaw-wp-security' ),
						'hideDetails'           => __( 'Hide details', 'choctaw-wp-security' ),
						'search'                => __( 'Search', 'choctaw-wp-security' ),
						'searchPlaceholder'     => __( 'Search files…', 'choctaw-wp-security' ),
						'refresh'               => __( 'Refresh', 'choctaw-wp-security' ),
						'scanCompleteIssues'    => __( 'Scan complete. %1$s critical, %2$s alert, %3$s warning, and %4$s informational finding(s) among %5$s exposed file(s).', 'choctaw-wp-security' ),
						'scanCompleteClean'     => __( 'Scan complete. No exposed sensitive files were found in the WordPress root.', 'choctaw-wp-security' ),
					),
				)
			);
		}

		if ( 'uploads-folder' === $this->get_active_admin_tab() ) {
			wp_enqueue_script(
				'choctaw-wp-security-uploads-folder',
				CHOCTAW_WP_SECURITY_URL . 'assets/js/admin-uploads-folder.js',
				array( 'choctaw-wp-security-admin-help', 'choctaw-wp-security-report-status', 'choctaw-wp-security-report-related-findings', 'choctaw-wp-security-report-pagination' ),
				(string) filemtime( CHOCTAW_WP_SECURITY_PATH . 'assets/js/admin-uploads-folder.js' ),
				true
			);

			wp_localize_script(
				'choctaw-wp-security-uploads-folder',
				'choctawWpSecurityUploadsFolder',
				array(
					'ajaxUrl'        => admin_url( 'admin-ajax.php' ),
					'nonce'          => wp_create_nonce( 'choctaw_wp_security_uploads_folder_ajax' ),
					'scanType'       => 'uploads-folder',
					'pageSize'       => $this->get_report_page_size(),
					'itemNoun'       => __( 'findings', 'choctaw-wp-security' ),
					'initialResult'  => $this->load_report_result(
						$this->get_uploads_folder_result_transient_key(),
						Choctaw_Wp_Security_Utils::USER_META_UPLOADS_FOLDER_RESULT
					),
					'categoryLabels' => Choctaw_Wp_Security_Uploads_Folder_Scanner::get_category_labels(),
					'strings'        => array(
						'scanButton'            => __( 'Scan Now', 'choctaw-wp-security' ),
						'rescanButton'          => __( 'Rescan', 'choctaw-wp-security' ),
						'scanning'              => __( 'Scanning uploads folder...', 'choctaw-wp-security' ),
						'scanError'             => __( 'The uploads folder scan could not be completed.', 'choctaw-wp-security' ),
						'noFindings'            => __( 'No findings matched the current filters.', 'choctaw-wp-security' ),
						'risk'                  => __( 'Risk', 'choctaw-wp-security' ),
						'status'                => __( 'Status', 'choctaw-wp-security' ),
						'category'              => __( 'Category', 'choctaw-wp-security' ),
						'allRisks'              => __( 'All risks', 'choctaw-wp-security' ),
						'allCategories'         => __( 'All categories', 'choctaw-wp-security' ),
						'riskCritical'          => __( 'Critical', 'choctaw-wp-security' ),
						'riskWarning'           => __( 'Warning', 'choctaw-wp-security' ),
						'file'                  => __( 'File', 'choctaw-wp-security' ),
						'actions'               => __( 'Action', 'choctaw-wp-security' ),
						'infoPanel'             => __( 'Info', 'choctaw-wp-security' ),
						'contentsHeading'       => __( 'Contents', 'choctaw-wp-security' ),
						'lastModified'          => __( 'Last Modified', 'choctaw-wp-security' ),
						'fileSize'              => __( 'File Size', 'choctaw-wp-security' ),
						'permissions'           => __( 'Permissions', 'choctaw-wp-security' ),
						'owner'                 => __( 'Owner', 'choctaw-wp-security' ),
						'whySeeingThis'         => __( 'Why you are seeing this', 'choctaw-wp-security' ),
						'howToProceed'          => __( 'How to proceed', 'choctaw-wp-security' ),
						'whySeeingThisFallback' => __( 'PHP files in the uploads folder are unusual and often indicate a compromised upload path.', 'choctaw-wp-security' ),
						'howToProceedFallback'  => __( 'Review the file carefully. Remove unexpected PHP files and enable Disable PHP Execution in Uploads when possible.', 'choctaw-wp-security' ),
						'viewDetails'           => __( 'View details', 'choctaw-wp-security' ),
						'hideDetails'           => __( 'Hide details', 'choctaw-wp-security' ),
						'search'                => __( 'Search', 'choctaw-wp-security' ),
						'searchPlaceholder'     => __( 'Search files…', 'choctaw-wp-security' ),
						'scanCompleteIssues'    => __( 'Scan complete. %1$s warning finding(s) in the uploads folder.', 'choctaw-wp-security' ),
						'scanCompleteClean'     => __( 'Scan complete. No PHP executable files were found in the uploads folder.', 'choctaw-wp-security' ),
					),
				)
			);
		}

		if ( 'mu-plugins' === $this->get_active_admin_tab() ) {
			wp_enqueue_script(
				'choctaw-wp-security-mu-plugins',
				CHOCTAW_WP_SECURITY_URL . 'assets/js/admin-mu-plugins.js',
				array( 'choctaw-wp-security-admin-help', 'choctaw-wp-security-report-status', 'choctaw-wp-security-report-related-findings', 'choctaw-wp-security-report-pagination' ),
				(string) filemtime( CHOCTAW_WP_SECURITY_PATH . 'assets/js/admin-mu-plugins.js' ),
				true
			);

			wp_localize_script(
				'choctaw-wp-security-mu-plugins',
				'choctawWpSecurityMuPlugins',
				array(
					'ajaxUrl'        => admin_url( 'admin-ajax.php' ),
					'nonce'          => wp_create_nonce( 'choctaw_wp_security_mu_plugins_ajax' ),
					'scanType'       => 'mu-plugins',
					'pageSize'       => $this->get_report_page_size(),
					'itemNoun'       => __( 'findings', 'choctaw-wp-security' ),
					'initialResult'  => $this->load_report_result(
						$this->get_mu_plugins_result_transient_key(),
						Choctaw_Wp_Security_Utils::USER_META_MU_PLUGINS_RESULT
					),
					'categoryLabels' => Choctaw_Wp_Security_Mu_Plugins_Scanner::get_category_labels(),
					'strings'        => array(
						'scanButton'           => __( 'Scan Now', 'choctaw-wp-security' ),
						'rescanButton'         => __( 'Rescan', 'choctaw-wp-security' ),
						'scanning'             => __( 'Scanning must-use plugins...', 'choctaw-wp-security' ),
						'scanError'            => __( 'The MU-Plugins scan could not be completed.', 'choctaw-wp-security' ),
						'noFindings'           => __( 'No findings matched the current filters.', 'choctaw-wp-security' ),
						'risk'                 => __( 'Risk', 'choctaw-wp-security' ),
						'category'             => __( 'Category', 'choctaw-wp-security' ),
						'allRisks'             => __( 'All risks', 'choctaw-wp-security' ),
						'allCategories'        => __( 'All categories', 'choctaw-wp-security' ),
						'riskAlert'            => __( 'Alert', 'choctaw-wp-security' ),
						'file'                 => __( 'File', 'choctaw-wp-security' ),
						'actions'              => __( 'Action', 'choctaw-wp-security' ),
						'infoPanel'            => __( 'Info', 'choctaw-wp-security' ),
						'contentsHeading'      => __( 'Contents', 'choctaw-wp-security' ),
						'version'              => __( 'Version', 'choctaw-wp-security' ),
						'author'               => __( 'Author', 'choctaw-wp-security' ),
						'pluginUri'            => __( 'Plugin URI', 'choctaw-wp-security' ),
						'updateUri'            => __( 'Update URI', 'choctaw-wp-security' ),
						'description'          => __( 'Description', 'choctaw-wp-security' ),
						'fileSize'             => __( 'File size', 'choctaw-wp-security' ),
						'lastModified'         => __( 'Last modified', 'choctaw-wp-security' ),
						'whySeeingThis'        => __( 'Why you are seeing this', 'choctaw-wp-security' ),
						'howToProceed'         => __( 'How to proceed', 'choctaw-wp-security' ),
						'whySeeingThisFallback' => __( 'Must-use plugins load automatically and are hidden from the Plugins screen, so unexpected files deserve review.', 'choctaw-wp-security' ),
						'howToProceedFallback'  => __( 'Confirm each file belongs to software you recognize or to your hosting provider before removing anything.', 'choctaw-wp-security' ),
						'viewDetails'          => __( 'View details', 'choctaw-wp-security' ),
						'hideDetails'          => __( 'Hide details', 'choctaw-wp-security' ),
						'search'               => __( 'Search', 'choctaw-wp-security' ),
						'searchPlaceholder'    => __( 'Search files…', 'choctaw-wp-security' ),
						'riskSuspicious'       => __( 'Suspicious', 'choctaw-wp-security' ),
						'scanCompleteIssues'   => __( 'Scan complete. %1$s suspicious must-use plugin file(s) found for review.', 'choctaw-wp-security' ),
						'scanCompleteClean'    => __( 'Scan complete. No PHP-like files were found in the mu-plugins folder.', 'choctaw-wp-security' ),
					),
				)
			);
		}

		if ( 'exposed-folders' === $this->get_active_admin_tab() ) {
			wp_enqueue_script(
				'choctaw-wp-security-directory-browsing',
				CHOCTAW_WP_SECURITY_URL . 'assets/js/admin-directory-browsing.js',
				array( 'choctaw-wp-security-admin-help', 'choctaw-wp-security-report-status', 'choctaw-wp-security-report-pagination' ),
				(string) filemtime( CHOCTAW_WP_SECURITY_PATH . 'assets/js/admin-directory-browsing.js' ),
				true
			);

			wp_localize_script(
				'choctaw-wp-security-directory-browsing',
				'choctawWpSecurityDirectoryBrowsing',
				array(
					'ajaxUrl'       => admin_url( 'admin-ajax.php' ),
					'nonce'         => wp_create_nonce( 'choctaw_wp_security_directory_browsing_ajax' ),
					'scanType'      => 'directory-browsing',
					'pageSize'      => $this->get_report_page_size(),
					'itemNoun'      => __( 'findings', 'choctaw-wp-security' ),
					'initialResult' => $this->load_report_result(
						$this->get_exposed_folders_result_transient_key(),
						Choctaw_Wp_Security_Utils::USER_META_EXPOSED_FOLDERS_RESULT
					),
					'strings'       => array(
						'scanButton'            => __( 'Scan Now', 'choctaw-wp-security' ),
						'rescanButton'          => __( 'Rescan', 'choctaw-wp-security' ),
						'scanning'              => __( 'Scanning directory browsing settings...', 'choctaw-wp-security' ),
						'scanError'             => __( 'The directory browsing scan could not be completed.', 'choctaw-wp-security' ),
						'noFindings'            => __( 'No findings matched the current filters.', 'choctaw-wp-security' ),
						'risk'                  => __( 'Risk', 'choctaw-wp-security' ),
						'status'                => __( 'Status', 'choctaw-wp-security' ),
						'serverType'            => __( 'Server Type', 'choctaw-wp-security' ),
						'path'                  => __( 'Path', 'choctaw-wp-security' ),
						'directoryBrowsing'     => __( 'Directory Browsing', 'choctaw-wp-security' ),
						'actions'               => __( 'Action', 'choctaw-wp-security' ),
						'allRisks'              => __( 'All risks', 'choctaw-wp-security' ),
						'riskCritical'          => __( 'Critical', 'choctaw-wp-security' ),
						'riskReview'            => __( 'Review', 'choctaw-wp-security' ),
						'riskSafe'              => __( 'Safe', 'choctaw-wp-security' ),
						'riskInfo'              => __( 'Info', 'choctaw-wp-security' ),
						'infoPanel'             => __( 'Info', 'choctaw-wp-security' ),
						'testingMethod'         => __( 'Testing Method', 'choctaw-wp-security' ),
						'contentsHeading'       => __( 'Contents', 'choctaw-wp-security' ),
						'whySeeingThis'         => __( 'Why you are seeing this', 'choctaw-wp-security' ),
						'howToProceed'          => __( 'How to proceed', 'choctaw-wp-security' ),
						'whySeeingThisFallback' => __( 'This row reports directory browsing posture for the site root .htaccess file or a public folder root.', 'choctaw-wp-security' ),
						'howToProceedFallback'  => __( 'See the guidance box labeled “How to Turn Directory Browsing Off” for server-specific instructions.', 'choctaw-wp-security' ),
						'viewDetails'           => __( 'View details', 'choctaw-wp-security' ),
						'hideDetails'           => __( 'Hide details', 'choctaw-wp-security' ),
						'search'                => __( 'Search', 'choctaw-wp-security' ),
						'searchPlaceholder'     => __( 'Search path…', 'choctaw-wp-security' ),
						'scanCompleteIssues'    => __( 'Scan complete. %1$s critical, %2$s review, %3$s safe, and %4$s informational finding(s).', 'choctaw-wp-security' ),
						'scanCompleteClean'     => __( 'Scan complete. No critical or review findings. %1$s safe and %2$s informational item(s) reported.', 'choctaw-wp-security' ),
					),
				)
			);
		}

		if ( 'component-scan' === $this->get_active_admin_tab() ) {
			$component_result = false;

			if ( isset( $_GET['component_scan_run'] ) ) {
				$component_result = $this->load_report_result(
					$this->get_component_scan_result_transient_key(),
					Choctaw_Wp_Security_Utils::USER_META_COMPONENT_SCAN_RESULT
				);
			}

			$unrecognized_result = null;

			if ( is_array( $component_result ) ) {
				$unrecognized_result = array(
					'findings' => isset( $component_result['findings'] ) && is_array( $component_result['findings'] )
						? $component_result['findings']
						: array(),
				);
			}

			wp_enqueue_style(
				'choctaw-wp-security-unrecognized-components',
				CHOCTAW_WP_SECURITY_URL . 'assets/css/admin-unrecognized-components.css',
				array( 'choctaw-wp-security-report-risk' ),
				(string) filemtime( CHOCTAW_WP_SECURITY_PATH . 'assets/css/admin-unrecognized-components.css' )
			);

			wp_enqueue_script(
				'choctaw-wp-security-unrecognized-components',
				CHOCTAW_WP_SECURITY_URL . 'assets/js/admin-unrecognized-components.js',
				array( 'choctaw-wp-security-admin-help', 'choctaw-wp-security-report-status', 'choctaw-wp-security-report-pagination' ),
				(string) filemtime( CHOCTAW_WP_SECURITY_PATH . 'assets/js/admin-unrecognized-components.js' ),
				true
			);

			wp_localize_script(
				'choctaw-wp-security-unrecognized-components',
				'choctawWpSecurityUnrecognizedComponents',
				array(
					'scanType'      => 'unrecognized-components',
					'pageSize'      => $this->get_report_page_size(),
					'itemNoun'      => __( 'components', 'choctaw-wp-security' ),
					'initialResult' => $unrecognized_result,
					'strings'       => array(
						'noFindings'            => __( 'No unrecognized components matched the current filters.', 'choctaw-wp-security' ),
						'allRecognized'         => __( 'All installed plugins and themes were recognized by the API.', 'choctaw-wp-security' ),
						'risk'                  => __( 'Risk', 'choctaw-wp-security' ),
						'status'                => __( 'Status', 'choctaw-wp-security' ),
						'category'              => __( 'Category', 'choctaw-wp-security' ),
						'name'                  => __( 'Name', 'choctaw-wp-security' ),
						'state'                 => __( 'State', 'choctaw-wp-security' ),
						'actions'               => __( 'Action', 'choctaw-wp-security' ),
						'allRisks'              => __( 'All risks', 'choctaw-wp-security' ),
						'allCategories'         => __( 'All categories', 'choctaw-wp-security' ),
						'riskInfo'              => __( 'Info', 'choctaw-wp-security' ),
						'categoryPlugin'        => __( 'Plugin', 'choctaw-wp-security' ),
						'categoryTheme'         => __( 'Theme', 'choctaw-wp-security' ),
						'infoPanel'             => __( 'Info', 'choctaw-wp-security' ),
						'slug'                  => __( 'Slug', 'choctaw-wp-security' ),
						'version'               => __( 'Version', 'choctaw-wp-security' ),
						'contentsHeading'       => __( 'Contents', 'choctaw-wp-security' ),
						'whySeeingThis'         => __( 'Why you are seeing this', 'choctaw-wp-security' ),
						'howToProceed'          => __( 'How to proceed', 'choctaw-wp-security' ),
						'whySeeingThisFallback' => __( 'This component could not be identified by the WPVulnerability API.', 'choctaw-wp-security' ),
						'howToProceedFallback'  => __( 'Review this component and dismiss it if you believe it is safe.', 'choctaw-wp-security' ),
						'viewDetails'           => __( 'View details', 'choctaw-wp-security' ),
						'hideDetails'           => __( 'Hide details', 'choctaw-wp-security' ),
						'search'                => __( 'Search', 'choctaw-wp-security' ),
						'searchPlaceholder'     => __( 'Search name…', 'choctaw-wp-security' ),
					),
				)
			);
		}
	}

	/**
	 * Build the transient key used to store the latest scan result.
	 *
	 * @return string
	 */
	private function get_core_checksum_result_transient_key() {
		return 'cws_core_checksum_' . get_current_user_id();
	}

	/**
	 * Build the transient key used to store the latest component scan result.
	 *
	 * @return string
	 */
	private function get_component_scan_result_transient_key() {
		return 'cws_component_scan_' . get_current_user_id();
	}

	/**
	 * Build the transient key used to store the latest exposed folders scan result.
	 *
	 * @return string
	 */
	private function get_exposed_folders_result_transient_key() {
		return 'cws_exposed_folders_' . get_current_user_id();
	}

	/**
	 * Build the transient key used to store the latest database scan result.
	 *
	 * @return string
	 */
	private function get_database_scan_result_transient_key() {
		return 'cws_database_scan_' . get_current_user_id();
	}

	/**
	 * Build the transient key used to store the latest scheduled tasks scan result.
	 *
	 * @return string
	 */
	private function get_scheduled_tasks_result_transient_key() {
		return 'cws_scheduled_tasks_' . get_current_user_id();
	}

	/**
	 * Build the transient key used to store the latest posts scan result.
	 *
	 * @return string
	 */
	private function get_posts_scan_result_transient_key() {
		return 'cws_posts_scan_' . get_current_user_id();
	}

	/**
	 * Build the transient key for Exposed Files scan results.
	 *
	 * @return string
	 */
	private function get_exposed_files_result_transient_key() {
		return 'cws_exposed_files_' . get_current_user_id();
	}

	/**
	 * Build the transient key for Uploads Folder scan results.
	 *
	 * @return string
	 */
	private function get_uploads_folder_result_transient_key() {
		return 'cws_uploads_folder_' . get_current_user_id();
	}

	/**
	 * Build the transient key for MU-Plugins scan results.
	 *
	 * @return string
	 */
	private function get_mu_plugins_result_transient_key() {
		return 'cws_mu_plugins_' . get_current_user_id();
	}

	/**
	 * Build the transient key used to store the latest users table result.
	 *
	 * @return string
	 */
	private function get_users_table_result_transient_key() {
		return 'cws_users_table_' . get_current_user_id();
	}

	/**
	 * Retrieve how long stored scan reports should remain available.
	 *
	 * @return int
	 */
	private function get_report_result_ttl() {
		return (int) Choctaw_Wp_Security_Utils::REPORT_RESULT_TTL;
	}

	/**
	 * Persist a scan report for later pagination and review.
	 *
	 * Applies finding Status from the site-wide registry before storage, and returns
	 * that enriched payload so AJAX callers can send it to the browser.
	 *
	 * @param string               $transient_key Transient storage key.
	 * @param string               $user_meta_key User meta storage key.
	 * @param array<string, mixed> $result        Scan result payload.
	 * @return array<string, mixed>
	 */
	private function save_report_result( $transient_key, $user_meta_key, array $result ) {
		$user_id = get_current_user_id();

		if ( $user_id <= 0 ) {
			return $result;
		}

		$scan_type = $this->get_scan_type_for_report_meta( $user_meta_key );

		// Uploads Folder uses Sassh Findings; do not merge prototype status store.
		if ( '' !== $scan_type && 'uploads-folder' !== $scan_type ) {
			$result = Choctaw_Wp_Security_Finding_Status_Store::apply_to_result( $scan_type, $result );
		}

		set_transient( $transient_key, $result, $this->get_report_result_ttl() );
		update_user_meta( $user_id, $user_meta_key, $result );

		return $result;
	}

	/**
	 * Load a stored scan report and refresh its transient expiration.
	 *
	 * @param string $transient_key Transient storage key.
	 * @param string $user_meta_key User meta storage key.
	 * @return array<string, mixed>|false
	 */
	private function load_report_result( $transient_key, $user_meta_key ) {
		$user_id = get_current_user_id();

		if ( $user_id <= 0 ) {
			return false;
		}

		$result = get_transient( $transient_key );

		if ( false === $result ) {
			$result = get_user_meta( $user_id, $user_meta_key, true );
		}

		if ( ! is_array( $result ) || empty( $result ) ) {
			return false;
		}

		$result = $this->sanitize_loaded_report_result( $result, $user_meta_key );

		$scan_type = $this->get_scan_type_for_report_meta( $user_meta_key );

		if ( '' !== $scan_type && 'uploads-folder' !== $scan_type ) {
			$result = Choctaw_Wp_Security_Finding_Status_Store::apply_to_result( $scan_type, $result );
		}

		set_transient( $transient_key, $result, $this->get_report_result_ttl() );

		return $result;
	}

	/**
	 * Map a stored report user-meta key to a Status scan type.
	 *
	 * @param string $user_meta_key User meta key.
	 * @return string Empty when unsupported.
	 */
	private function get_scan_type_for_report_meta( $user_meta_key ) {
		$map = array(
			Choctaw_Wp_Security_Utils::USER_META_DATABASE_SCAN_RESULT   => 'database-scan',
			Choctaw_Wp_Security_Utils::USER_META_POSTS_SCAN_RESULT      => 'wp-posts',
			Choctaw_Wp_Security_Utils::USER_META_SCHEDULED_TASKS_RESULT => 'scheduled-tasks',
			Choctaw_Wp_Security_Utils::USER_META_EXPOSED_FILES_RESULT   => 'exposed-files',
			Choctaw_Wp_Security_Utils::USER_META_UPLOADS_FOLDER_RESULT  => 'uploads-folder',
			Choctaw_Wp_Security_Utils::USER_META_MU_PLUGINS_RESULT      => 'mu-plugins',
			Choctaw_Wp_Security_Utils::USER_META_CORE_CHECKSUM_RESULT   => 'verify-checksums',
			Choctaw_Wp_Security_Utils::USER_META_EXPOSED_FOLDERS_RESULT => 'directory-browsing',
			Choctaw_Wp_Security_Utils::USER_META_COMPONENT_SCAN_RESULT  => 'unrecognized-components',
		);

		$user_meta_key = (string) $user_meta_key;

		return isset( $map[ $user_meta_key ] ) ? $map[ $user_meta_key ] : '';
	}

	/**
	 * Resolve transient + user-meta storage keys for a Status scan type.
	 *
	 * @param string $scan_type Scan type key.
	 * @return array{transient:string,user_meta:string}|null
	 */
	private function get_report_storage_for_scan_type( $scan_type ) {
		$user_id = get_current_user_id();

		if ( $user_id <= 0 ) {
			return null;
		}

		$map = array(
			'database-scan'    => array(
				'transient' => $this->get_database_scan_result_transient_key(),
				'user_meta' => Choctaw_Wp_Security_Utils::USER_META_DATABASE_SCAN_RESULT,
			),
			'wp-posts'         => array(
				'transient' => $this->get_posts_scan_result_transient_key(),
				'user_meta' => Choctaw_Wp_Security_Utils::USER_META_POSTS_SCAN_RESULT,
			),
			'scheduled-tasks'  => array(
				'transient' => $this->get_scheduled_tasks_result_transient_key(),
				'user_meta' => Choctaw_Wp_Security_Utils::USER_META_SCHEDULED_TASKS_RESULT,
			),
			'exposed-files'    => array(
				'transient' => $this->get_exposed_files_result_transient_key(),
				'user_meta' => Choctaw_Wp_Security_Utils::USER_META_EXPOSED_FILES_RESULT,
			),
			'uploads-folder'   => array(
				'transient' => $this->get_uploads_folder_result_transient_key(),
				'user_meta' => Choctaw_Wp_Security_Utils::USER_META_UPLOADS_FOLDER_RESULT,
			),
			'mu-plugins'       => array(
				'transient' => $this->get_mu_plugins_result_transient_key(),
				'user_meta' => Choctaw_Wp_Security_Utils::USER_META_MU_PLUGINS_RESULT,
			),
			'verify-checksums' => array(
				'transient' => $this->get_core_checksum_result_transient_key(),
				'user_meta' => Choctaw_Wp_Security_Utils::USER_META_CORE_CHECKSUM_RESULT,
			),
			'directory-browsing' => array(
				'transient' => $this->get_exposed_folders_result_transient_key(),
				'user_meta' => Choctaw_Wp_Security_Utils::USER_META_EXPOSED_FOLDERS_RESULT,
			),
		);

		$scan_type = (string) $scan_type;

		return isset( $map[ $scan_type ] ) ? $map[ $scan_type ] : null;
	}

	/**
	 * Delete the current user's last report for a scan type.
	 *
	 * @param string $scan_type Scan type key.
	 * @return void
	 */
	private function clear_report_result_for_scan_type( $scan_type ) {
		$storage = $this->get_report_storage_for_scan_type( $scan_type );

		if ( null === $storage ) {
			return;
		}

		$user_id = get_current_user_id();

		delete_transient( $storage['transient'] );
		delete_user_meta( $user_id, $storage['user_meta'] );
	}

	/**
	 * AJAX: dismiss a finding.
	 *
	 * @return void
	 */
	public function ajax_finding_dismiss() {
		$this->handle_finding_status_ajax( 'dismiss' );
	}

	/**
	 * AJAX: undismiss a finding.
	 *
	 * @return void
	 */
	public function ajax_finding_undismiss() {
		$this->handle_finding_status_ajax( 'undismiss' );
	}

	/**
	 * AJAX: clear dismissal history for a scan type.
	 *
	 * @return void
	 */
	public function ajax_finding_clear_history() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to clear history.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_finding_status', 'nonce' );

		$scan_type = isset( $_POST['scan_type'] ) ? sanitize_key( wp_unslash( $_POST['scan_type'] ) ) : '';

		if ( in_array( $scan_type, array( 'uploads-folder', 'mu-plugins' ), true ) ) {
			wp_send_json_error(
				array(
					'message' => __( 'Clear History is not available for Sassh Findings-backed scans.', 'choctaw-wp-security' ),
				),
				400
			);
		}

		$result = Choctaw_Wp_Security_Finding_Status_Store::clear_scan( $scan_type );

		if ( is_wp_error( $result ) ) {
			wp_send_json_error(
				array(
					'message' => $result->get_error_message(),
				),
				400
			);
		}

		$this->clear_report_result_for_scan_type( $scan_type );

		wp_send_json_success(
			array(
				'scan_type' => $scan_type,
			)
		);
	}

	/**
	 * Shared dismiss/undismiss AJAX handler.
	 *
	 * @param string $mode dismiss|undismiss.
	 * @return void
	 */
	private function handle_finding_status_ajax( $mode ) {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to update finding status.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_finding_status', 'nonce' );

		$scan_type   = isset( $_POST['scan_type'] ) ? sanitize_text_field( wp_unslash( $_POST['scan_type'] ) ) : '';
		$fingerprint = isset( $_POST['fingerprint'] ) ? sanitize_text_field( wp_unslash( $_POST['fingerprint'] ) ) : '';

		if ( in_array( $scan_type, array( 'uploads-folder', 'mu-plugins' ), true ) ) {
			wp_send_json_error(
				array(
					'message' => __( 'These findings must be dismissed through Sassh Findings.', 'choctaw-wp-security' ),
				),
				400
			);
		}

		$result = ( 'undismiss' === $mode )
			? Choctaw_Wp_Security_Finding_Status_Store::undismiss( $scan_type, $fingerprint )
			: Choctaw_Wp_Security_Finding_Status_Store::dismiss( $scan_type, $fingerprint );

		if ( is_wp_error( $result ) ) {
			wp_send_json_error(
				array(
					'message' => $result->get_error_message(),
				),
				400
			);
		}

		$open_status = Choctaw_Wp_Security_Finding_Status_Store::STATUS_NEEDS_REVIEW;

		if ( 'undismiss' === $mode ) {
			$storage = $this->get_report_storage_for_scan_type( $scan_type );
			if ( is_array( $storage ) ) {
				$stored = $this->load_report_result( $storage['transient'], $storage['user_meta'] );
				if ( is_array( $stored ) && ! empty( $stored['findings'] ) && is_array( $stored['findings'] ) ) {
					foreach ( $stored['findings'] as $finding ) {
						if ( ! is_array( $finding ) ) {
							continue;
						}
						$fp = isset( $finding['fingerprint'] ) ? (string) $finding['fingerprint'] : ( isset( $finding['id'] ) ? (string) $finding['id'] : '' );
						if ( $fp === $fingerprint ) {
							$open_status = Choctaw_Wp_Security_Finding_Status_Store::open_status_for_finding( $finding );
							break;
						}
					}
				}
			}
		}

		wp_send_json_success(
			array(
				'scan_type'   => $scan_type,
				'fingerprint' => $fingerprint,
				'status'      => ( 'undismiss' === $mode )
					? $open_status
					: Choctaw_Wp_Security_Finding_Status_Store::STATUS_DISMISSED,
				'status_label' => Choctaw_Wp_Security_Finding_Status_Store::status_label(
					( 'undismiss' === $mode )
						? $open_status
						: Choctaw_Wp_Security_Finding_Status_Store::STATUS_DISMISSED
				),
			)
		);
	}

	/**
	 * AJAX: dismiss a Sassh Finding (fingerprint-gated).
	 *
	 * @return void
	 */
	public function ajax_sassh_finding_dismiss() {
		$this->handle_sassh_finding_status_ajax( 'dismiss' );
	}

	/**
	 * AJAX: undismiss a Sassh Finding.
	 *
	 * @return void
	 */
	public function ajax_sassh_finding_undismiss() {
		$this->handle_sassh_finding_status_ajax( 'undismiss' );
	}

	/**
	 * AJAX: related findings for a detail-panel expand (cap 10; capability-gated).
	 *
	 * @return void
	 */
	public function ajax_sassh_finding_related() {
		Sassh_Capabilities::require_manage_or_json_error(
			__( 'You do not have permission to view Sassh findings.', 'choctaw-wp-security' )
		);

		check_ajax_referer( 'sassh_finding_status', 'nonce' );

		$finding_id = isset( $_POST['finding_id'] ) ? sanitize_text_field( wp_unslash( $_POST['finding_id'] ) ) : '';

		if ( '' === $finding_id ) {
			wp_send_json_error(
				array(
					'message' => __( 'Missing finding id.', 'choctaw-wp-security' ),
				),
				400
			);
		}

		$service = new Sassh_Findings_Service();
		$related = $service->list_related_findings( $finding_id );
		$items   = array();

		foreach ( $related as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}

			$items[] = array(
				'finding_id'              => isset( $row['finding_id'] ) ? (string) $row['finding_id'] : '',
				'scanner_id'              => isset( $row['scanner_id'] ) ? (string) $row['scanner_id'] : '',
				'rule_id'                 => isset( $row['rule_id'] ) ? (string) $row['rule_id'] : '',
				'title'                   => isset( $row['title'] ) ? (string) $row['title'] : '',
				'object_key'              => isset( $row['object_key'] ) ? (string) $row['object_key'] : '',
				'risk_level'              => isset( $row['risk_level'] ) ? (string) $row['risk_level'] : '',
				'risk_label'              => isset( $row['risk_label'] ) ? (string) $row['risk_label'] : '',
				'effective_status'        => isset( $row['effective_status'] ) ? (string) $row['effective_status'] : '',
				'status_label'            => isset( $row['status_label'] ) ? (string) $row['status_label'] : '',
				'detection_state'         => isset( $row['detection_state'] ) ? (string) $row['detection_state'] : '',
				'object_fingerprint_comparison' => isset( $row['object_fingerprint_comparison'] ) ? (string) $row['object_fingerprint_comparison'] : 'unknown',
				'last_seen_at'                  => isset( $row['last_seen_at'] ) ? (string) $row['last_seen_at'] : '',
			);
		}

		wp_send_json_success(
			array(
				'finding_id'       => $finding_id,
				'related_findings' => $items,
			)
		);
	}

	/**
	 * Shared Sassh Findings dismiss/undismiss AJAX handler.
	 *
	 * @param string $mode dismiss|undismiss.
	 * @return void
	 */
	private function handle_sassh_finding_status_ajax( $mode ) {
		Sassh_Capabilities::require_manage_or_json_error(
			__( 'You do not have permission to update Sassh findings.', 'choctaw-wp-security' )
		);

		check_ajax_referer( 'sassh_finding_status', 'nonce' );

		$finding_id  = isset( $_POST['finding_id'] ) ? sanitize_text_field( wp_unslash( $_POST['finding_id'] ) ) : '';
		$fingerprint = isset( $_POST['fingerprint'] ) ? sanitize_text_field( wp_unslash( $_POST['fingerprint'] ) ) : '';

		if ( '' === $finding_id ) {
			wp_send_json_error(
				array(
					'message' => __( 'Missing finding id.', 'choctaw-wp-security' ),
				),
				400
			);
		}

		$service = new Sassh_Findings_Service();
		$result  = ( 'undismiss' === $mode )
			? $service->undismiss( $finding_id )
			: $service->dismiss( $finding_id, $fingerprint );

		if ( is_wp_error( $result ) ) {
			wp_send_json_error(
				array(
					'message' => $result->get_error_message(),
				),
				400
			);
		}

		$status = isset( $result['effective_status'] ) ? (string) $result['effective_status'] : 'needs_review';

		wp_send_json_success(
			array(
				'finding_id'          => $finding_id,
				'fingerprint'         => isset( $result['content_fingerprint'] ) ? (string) $result['content_fingerprint'] : $fingerprint,
				'content_fingerprint' => isset( $result['content_fingerprint'] ) ? (string) $result['content_fingerprint'] : $fingerprint,
				'status'              => $status,
				'status_label'        => Sassh_Findings_Service::status_label( $status ),
				'effective_status'    => $status,
			)
		);
	}

	/**
	 * Whether a finding matches the Needs Review status filter (actionable + not dismissed).
	 *
	 * @param array<string, mixed> $finding Finding row.
	 * @return bool
	 */
	private function finding_matches_needs_review_filter( array $finding ) {
		$status = isset( $finding['status'] ) ? (string) $finding['status'] : '';

		if ( '' === $status ) {
			$status = Choctaw_Wp_Security_Finding_Status_Store::open_status_for_finding( $finding );
		}

		return Choctaw_Wp_Security_Finding_Status_Store::STATUS_NEEDS_REVIEW === $status;
	}

	/**
	 * Render a Clear History button for a Status-enabled scan.
	 *
	 * @param string $scan_type Scan type key.
	 * @return void
	 */
	private function render_clear_history_button( $scan_type ) {
		?>
		<button
			type="button"
			class="button button-secondary"
			data-cws-clear-history="<?php echo esc_attr( (string) $scan_type ); ?>"
		>
			<?php esc_html_e( 'Clear History', 'choctaw-wp-security' ); ?>
		</button>
		<?php
	}

	/**
	 * Render Status badge cell.
	 *
	 * @param string $status Status key.
	 * @param string $label  Status label.
	 * @return void
	 */
	private function render_status_badge( $status, $label ) {
		unset( $status );
		?>
		<span class="cws-status-text"><?php echo esc_html( (string) $label ); ?></span>
		<?php
	}

	/**
	 * Render dismiss checkbox + Submit for PHP detail panels.
	 *
	 * @param string $scan_type   Scan type key.
	 * @param string $fingerprint Finding fingerprint.
	 * @param string $status      Current status.
	 * @return void
	 */
	private function render_dismiss_controls( $scan_type, $fingerprint, $status ) {
		$is_dismissed = Choctaw_Wp_Security_Finding_Status_Store::STATUS_DISMISSED === $status;
		?>
		<div
			class="cws-report-dismiss"
			data-cws-dismiss-block="1"
			data-scan-type="<?php echo esc_attr( (string) $scan_type ); ?>"
			data-fingerprint="<?php echo esc_attr( (string) $fingerprint ); ?>"
			data-status="<?php echo esc_attr( (string) $status ); ?>"
		>
			<label class="cws-report-dismiss-label">
				<input
					type="checkbox"
					class="cws-report-dismiss-checkbox"
					<?php checked( $is_dismissed ); ?>
				/>
				<?php esc_html_e( 'Dismiss this item', 'choctaw-wp-security' ); ?>
			</label>
			<button type="button" class="button button-secondary cws-report-dismiss-submit">
				<?php esc_html_e( 'Submit', 'choctaw-wp-security' ); ?>
			</button>
			<p class="cws-report-dismiss-error" hidden></p>
		</div>
		<?php
	}

	/**
	 * Drop obsolete sections from stored reports (e.g. Cron Events moved to WP-Cron).
	 *
	 * @param array<string, mixed> $result       Stored report payload.
	 * @param string               $user_meta_key User meta key identifying the report type.
	 * @return array<string, mixed>
	 */
	private function sanitize_loaded_report_result( array $result, $user_meta_key ) {
		if ( Choctaw_Wp_Security_Utils::USER_META_COMPONENT_SCAN_RESULT === $user_meta_key ) {
			if ( empty( $result['findings'] ) || ! is_array( $result['findings'] ) ) {
				$result['findings'] = Choctaw_Wp_Security_Component_Vulnerability_Scanner::build_unrecognized_findings( $result );
			}

			return $result;
		}

		if ( Choctaw_Wp_Security_Utils::USER_META_DATABASE_SCAN_RESULT !== $user_meta_key ) {
			return $result;
		}

		if ( empty( $result['sections'] ) || ! is_array( $result['sections'] ) ) {
			return $result;
		}

		$allowed = array_fill_keys( Choctaw_Wp_Security_Options_Scan_Patterns::$section_keys, true );
		$result['sections'] = array_intersect_key( $result['sections'], $allowed );

		return $result;
	}

	/**
	 * Render the Directory Browsing scan section.
	 *
	 * @return void
	 */
	private function render_exposed_folders_section() {
		$result          = false;
		$results_missing = false;

		if ( isset( $_GET['exposed_folders_run'] ) ) {
			$result = $this->load_report_result(
				$this->get_exposed_folders_result_transient_key(),
				Choctaw_Wp_Security_Utils::USER_META_EXPOSED_FOLDERS_RESULT
			);

			if ( false === $result ) {
				$results_missing = true;
			} elseif ( is_array( $result ) && empty( $result['findings'] ) ) {
				// Pre-migration payloads used server_level/rows; require a fresh scan.
				$result          = false;
				$results_missing = true;
			}
		}
		?>
		<div class="cws-admin-tab-panel cws-directory-browsing-panel">
			<div class="cws-report-section">
				<h2><?php esc_html_e( 'Directory Browsing', 'choctaw-wp-security' ); ?></h2>
				<?php Choctaw_Wp_Security_Admin_Help::render_tab_intro( 'exposed_folders' ); ?>

				<?php if ( $results_missing ) : ?>
					<div class="notice notice-warning">
						<p><?php esc_html_e( 'The previous directory browsing scan results are no longer available. Run Scan Now to generate a fresh report.', 'choctaw-wp-security' ); ?></p>
					</div>
				<?php endif; ?>

				<form method="post" class="cws-directory-browsing-form" id="cws-directory-browsing-form">
					<?php wp_nonce_field( 'choctaw_wp_security_exposed_folders_scan_form' ); ?>
					<input type="hidden" name="cws_tab" value="exposed-folders" />
					<?php submit_button( __( 'Scan Now', 'choctaw-wp-security' ), 'secondary', 'choctaw_wp_security_exposed_folders_scan', false ); ?>
					<?php $this->render_clear_history_button( 'directory-browsing' ); ?>
				</form>

				<div id="cws-directory-browsing-js-notices" aria-live="polite"></div>
				<div id="cws-directory-browsing-js-results"></div>

				<div id="cws-directory-browsing-fallback-results">
					<?php if ( is_array( $result ) ) : ?>
						<?php $this->render_exposed_folders_results( $result ); ?>
					<?php endif; ?>
				</div>
			</div>

			<div id="cws-directory-browsing-help-boxes" class="cws-help-boxes cws-directory-browsing-help-boxes"<?php echo is_array( $result ) ? '' : ' hidden'; ?>>
				<?php Choctaw_Wp_Security_Admin_Help::render_guidance_box( 'directory_browsing_fix' ); ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the core checksum scan section.
	 *
	 * @return void
	 */
	private function render_core_checksum_section() {
		$result = false;

		if ( isset( $_GET['core_checksum_run'] ) ) {
			$result = $this->load_report_result(
				$this->get_core_checksum_result_transient_key(),
				Choctaw_Wp_Security_Utils::USER_META_CORE_CHECKSUM_RESULT
			);
		}
		?>
		<div class="cws-admin-tab-panel">
			<div class="cws-report-section">
			<h2><?php esc_html_e( 'WP Core Verify-Checksums', 'choctaw-wp-security' ); ?></h2>
			<?php Choctaw_Wp_Security_Admin_Help::render_tab_intro( 'core_checksum' ); ?>

			<form method="post">
				<?php wp_nonce_field( 'choctaw_wp_security_core_checksum_scan' ); ?>
				<input type="hidden" name="choctaw_wp_security_core_checksum_scan" value="1" />
				<input type="hidden" name="cws_tab" value="verify-checksums" />
				<?php submit_button( __( 'Scan Now', 'choctaw-wp-security' ), 'secondary', 'submit', false ); ?>
				<?php $this->render_clear_history_button( 'verify-checksums' ); ?>
			</form>

			<?php if ( is_array( $result ) ) : ?>
				<?php $this->render_core_checksum_results( $result ); ?>
			<?php endif; ?>
			</div>

			<?php if ( is_array( $result ) ) : ?>
				<?php $this->render_core_checksum_category_reports( $result ); ?>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Render the component vulnerability scan section.
	 *
	 * @return void
	 */
	private function render_component_scan_section() {
		$result = false;

		if ( isset( $_GET['component_scan_run'] ) ) {
			$result = $this->load_report_result(
				$this->get_component_scan_result_transient_key(),
				Choctaw_Wp_Security_Utils::USER_META_COMPONENT_SCAN_RESULT
			);
		}
		?>
		<div class="cws-admin-tab-panel">
			<div class="cws-report-section">
				<h2><?php esc_html_e( 'Vulnerabilities', 'choctaw-wp-security' ); ?></h2>
				<?php Choctaw_Wp_Security_Admin_Help::render_tab_intro( 'component_scan' ); ?>

				<form method="post">
					<?php wp_nonce_field( 'choctaw_wp_security_component_scan' ); ?>
					<input type="hidden" name="choctaw_wp_security_component_scan" value="1" />
					<input type="hidden" name="cws_tab" value="component-scan" />
					<?php submit_button( __( 'Scan Now', 'choctaw-wp-security' ), 'secondary', 'submit', false ); ?>
				</form>

				<?php if ( is_array( $result ) ) : ?>
					<?php $this->render_component_scan_results( $result ); ?>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Render WPVulnerability attribution for the component scan tab.
	 *
	 * @param int|null $api_updated Optional API refresh timestamp.
	 * @return void
	 */
	private function render_component_scan_attribution( $api_updated = null ) {
		?>
		<p class="description cws-component-scan-attribution">
			<?php esc_html_e( 'Vulnerability data provided by', 'choctaw-wp-security' ); ?>
			<a href="https://www.wpvulnerability.com/" target="_blank" rel="noopener noreferrer">WPVulnerability</a>.
			<a href="https://docs.wpvulnerability.com/" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'API documentation', 'choctaw-wp-security' ); ?></a>.
			<?php if ( ! empty( $api_updated ) ) : ?>
				<?php
				echo ' ';
				echo esc_html(
					sprintf(
						/* translators: %s: formatted date/time */
						__( 'Database last updated: %s.', 'choctaw-wp-security' ),
						wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $api_updated )
					)
				);
				?>
			<?php endif; ?>
		</p>
		<?php
	}

	/**
	 * Render component scan results.
	 *
	 * @param array<string, mixed> $result Scan result payload.
	 * @return void
	 */
	private function render_component_scan_results( $result ) {
		$has_vulnerabilities = empty( $result['success'] );
		$panel_class         = $has_vulnerabilities ? 'cws-core-checksum-results is-error' : 'cws-core-checksum-results is-success';
		$summary             = isset( $result['summary'] ) && is_array( $result['summary'] ) ? $result['summary'] : array();
		?>
		<div class="<?php echo esc_attr( $panel_class ); ?>">
			<p class="cws-core-checksum-summary">
				<?php if ( $has_vulnerabilities ) : ?>
					<?php esc_html_e( 'Known vulnerabilities were found in one or more scanned components.', 'choctaw-wp-security' ); ?>
				<?php else : ?>
					<?php esc_html_e( 'No known vulnerabilities were found in the scanned components.', 'choctaw-wp-security' ); ?>
				<?php endif; ?>
			</p>

			<?php if ( ! empty( $result['scan_incomplete'] ) ) : ?>
				<p class="description">
					<?php esc_html_e( 'The scan stopped early because it reached its time budget. Review the partial results below and run the scan again if needed.', 'choctaw-wp-security' ); ?>
				</p>
			<?php endif; ?>

			<?php if ( ! empty( $result['errors'] ) && is_array( $result['errors'] ) ) : ?>
				<h3><?php esc_html_e( 'Errors', 'choctaw-wp-security' ); ?></h3>
				<ul class="cws-core-checksum-list">
					<?php foreach ( $result['errors'] as $error_message ) : ?>
						<li><?php echo esc_html( (string) $error_message ); ?></li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>
		</div>

		<div class="cws-report-section cws-component-scan-report">
			<h3><?php esc_html_e( 'WordPress Core', 'choctaw-wp-security' ); ?></h3>
			<?php
			if ( isset( $result['core'] ) && is_array( $result['core'] ) ) {
				$this->render_component_scan_component_details(
					array(
						'label'           => sprintf(
							/* translators: %s: WordPress version */
							__( 'WordPress %s', 'choctaw-wp-security' ),
							isset( $result['core']['version'] ) ? (string) $result['core']['version'] : ''
						),
						'status'          => isset( $result['core']['status'] ) ? (string) $result['core']['status'] : 'error',
						'vulnerabilities' => isset( $result['core']['vulnerabilities'] ) && is_array( $result['core']['vulnerabilities'] ) ? $result['core']['vulnerabilities'] : array(),
					)
				);
			}
			?>
		</div>

		<div class="cws-report-section cws-component-scan-report">
			<h3><?php esc_html_e( 'Active Theme', 'choctaw-wp-security' ); ?></h3>
			<?php if ( ! empty( $result['active_theme'] ) && is_array( $result['active_theme'] ) ) : ?>
				<?php
				$theme = $result['active_theme'];
				$this->render_component_scan_component_details(
					array(
						'label'           => sprintf(
							'%s (%s)',
							isset( $theme['name'] ) ? (string) $theme['name'] : '',
							isset( $theme['version'] ) ? (string) $theme['version'] : ''
						),
						'status'          => isset( $theme['status'] ) ? (string) $theme['status'] : 'error',
						'vulnerabilities' => isset( $theme['vulnerabilities'] ) && is_array( $theme['vulnerabilities'] ) ? $theme['vulnerabilities'] : array(),
					)
				);
				?>
				<?php if ( ! empty( $theme['via_child_theme'] ) ) : ?>
					<p class="description">
						<?php
						echo esc_html(
							sprintf(
								/* translators: %s: child theme name */
								__( 'Reported as active because the selected child theme “%s” uses this parent theme.', 'choctaw-wp-security' ),
								(string) $theme['via_child_theme']
							)
						);
						?>
					</p>
				<?php endif; ?>
			<?php else : ?>
				<p class="description">
					<?php esc_html_e( 'No API-recognized active theme was scanned. If your active theme (or its parent theme) is custom or unlisted, it appears in Unrecognized Components below.', 'choctaw-wp-security' ); ?>
				</p>
			<?php endif; ?>
		</div>

		<div class="cws-report-section cws-component-scan-report">
			<h3>
				<?php esc_html_e( 'Inactive Themes', 'choctaw-wp-security' ); ?>
				<span class="cws-component-scan-count">
					<?php
					echo esc_html(
						sprintf(
							/* translators: 1: number scanned, 2: number vulnerable */
							__( '(%1$d scanned, %2$d vulnerable)', 'choctaw-wp-security' ),
							isset( $summary['inactive_themes_scanned'] ) ? (int) $summary['inactive_themes_scanned'] : 0,
							isset( $summary['inactive_themes_vulnerable'] ) ? (int) $summary['inactive_themes_vulnerable'] : 0
						)
					);
					?>
				</span>
			</h3>
			<?php if ( ! empty( $result['inactive_themes'] ) && is_array( $result['inactive_themes'] ) ) : ?>
				<div class="cws-component-scan-list">
					<?php foreach ( $result['inactive_themes'] as $theme ) : ?>
						<?php
						$this->render_component_scan_component_details(
							array(
								'label'           => sprintf(
									'%s (%s)',
									isset( $theme['name'] ) ? (string) $theme['name'] : '',
									isset( $theme['version'] ) ? (string) $theme['version'] : ''
								),
								'status'          => isset( $theme['status'] ) ? (string) $theme['status'] : 'error',
								'vulnerabilities' => isset( $theme['vulnerabilities'] ) && is_array( $theme['vulnerabilities'] ) ? $theme['vulnerabilities'] : array(),
							)
						);
						?>
					<?php endforeach; ?>
				</div>
			<?php else : ?>
				<p class="description">
					<?php esc_html_e( 'No API-recognized inactive themes were scanned.', 'choctaw-wp-security' ); ?>
				</p>
			<?php endif; ?>
		</div>

		<div class="cws-report-section cws-component-scan-report">
			<h3>
				<?php esc_html_e( 'Active Plugins', 'choctaw-wp-security' ); ?>
				<span class="cws-component-scan-count">
					<?php
					echo esc_html(
						sprintf(
							/* translators: 1: number scanned, 2: number vulnerable */
							__( '(%1$d scanned, %2$d vulnerable)', 'choctaw-wp-security' ),
							isset( $summary['active_plugins_scanned'] ) ? (int) $summary['active_plugins_scanned'] : 0,
							isset( $summary['active_plugins_vulnerable'] ) ? (int) $summary['active_plugins_vulnerable'] : 0
						)
					);
					?>
				</span>
			</h3>
			<?php if ( ! empty( $result['active_plugins'] ) && is_array( $result['active_plugins'] ) ) : ?>
				<div class="cws-component-scan-list">
					<?php foreach ( $result['active_plugins'] as $plugin ) : ?>
						<?php
						$this->render_component_scan_component_details(
							array(
								'label'           => sprintf(
									'%s (%s)',
									isset( $plugin['name'] ) ? (string) $plugin['name'] : '',
									isset( $plugin['version'] ) ? (string) $plugin['version'] : ''
								),
								'status'          => isset( $plugin['status'] ) ? (string) $plugin['status'] : 'error',
								'vulnerabilities' => isset( $plugin['vulnerabilities'] ) && is_array( $plugin['vulnerabilities'] ) ? $plugin['vulnerabilities'] : array(),
							)
						);
						?>
					<?php endforeach; ?>
				</div>
			<?php else : ?>
				<p class="description">
					<?php esc_html_e( 'No API-recognized active plugins were scanned.', 'choctaw-wp-security' ); ?>
				</p>
			<?php endif; ?>
		</div>

		<div class="cws-report-section cws-component-scan-report">
			<h3>
				<?php esc_html_e( 'Inactive Plugins', 'choctaw-wp-security' ); ?>
				<span class="cws-component-scan-count">
					<?php
					echo esc_html(
						sprintf(
							/* translators: 1: number scanned, 2: number vulnerable */
							__( '(%1$d scanned, %2$d vulnerable)', 'choctaw-wp-security' ),
							isset( $summary['inactive_plugins_scanned'] ) ? (int) $summary['inactive_plugins_scanned'] : 0,
							isset( $summary['inactive_plugins_vulnerable'] ) ? (int) $summary['inactive_plugins_vulnerable'] : 0
						)
					);
					?>
				</span>
			</h3>
			<?php if ( ! empty( $result['inactive_plugins'] ) && is_array( $result['inactive_plugins'] ) ) : ?>
				<div class="cws-component-scan-list">
					<?php foreach ( $result['inactive_plugins'] as $plugin ) : ?>
						<?php
						$this->render_component_scan_component_details(
							array(
								'label'           => sprintf(
									'%s (%s)',
									isset( $plugin['name'] ) ? (string) $plugin['name'] : '',
									isset( $plugin['version'] ) ? (string) $plugin['version'] : ''
								),
								'status'          => isset( $plugin['status'] ) ? (string) $plugin['status'] : 'error',
								'vulnerabilities' => isset( $plugin['vulnerabilities'] ) && is_array( $plugin['vulnerabilities'] ) ? $plugin['vulnerabilities'] : array(),
							)
						);
						?>
					<?php endforeach; ?>
				</div>
			<?php else : ?>
				<p class="description">
					<?php esc_html_e( 'No API-recognized inactive plugins were scanned.', 'choctaw-wp-security' ); ?>
				</p>
			<?php endif; ?>
		</div>

		<div class="cws-report-section cws-component-scan-report cws-unrecognized-components-section">
			<div class="cws-unrecognized-components-heading">
				<h3>
					<?php esc_html_e( 'Unrecognized Components', 'choctaw-wp-security' ); ?>
					<span class="cws-component-scan-count">
						<?php
						echo esc_html(
							sprintf(
								/* translators: 1: plugin count, 2: theme count */
								__( '(%1$d plugins, %2$d themes)', 'choctaw-wp-security' ),
								isset( $summary['unrecognized_plugins'] ) ? (int) $summary['unrecognized_plugins'] : 0,
								isset( $summary['unrecognized_themes'] ) ? (int) $summary['unrecognized_themes'] : 0
							)
						);
						?>
					</span>
				</h3>
				<?php $this->render_clear_history_button( 'unrecognized-components' ); ?>
			</div>
			<p class="description">
				<?php esc_html_e( 'These installed plugins and themes are not in the WPVulnerability database, so no CVE report could be generated for them. This does not mean they are unsafe — only that the API has no record for their slug.', 'choctaw-wp-security' ); ?>
			</p>
			<div id="cws-unrecognized-components-js-results"></div>
			<div id="cws-unrecognized-components-fallback-results">
				<?php $this->render_component_scan_unrecognized_table( $result ); ?>
			</div>
		</div>

		<?php $this->render_component_scan_about( isset( $result['api_updated'] ) ? (int) $result['api_updated'] : null ); ?>
		<?php
	}

	/**
	 * Render the component scan "About this scan" note below report sections.
	 *
	 * @param int|null $api_updated Optional API refresh timestamp for attribution.
	 * @return void
	 */
	private function render_component_scan_about( $api_updated = null ) {
		?>
		<div class="cws-report-section cws-component-scan-report">
			<h3><?php echo esc_html( Choctaw_Wp_Security_Admin_Help::get_scan_about_label() ); ?></h3>
			<p class="description">
				<?php echo esc_html( Choctaw_Wp_Security_Admin_Help_Content::component_scan_about_text() ); ?>
			</p>
			<?php $this->render_component_scan_attribution( $api_updated ); ?>
		</div>
		<?php
	}

	/**
	 * Render one expandable component result row.
	 *
	 * @param array<string, mixed> $component Component result data.
	 * @return void
	 */
	private function render_component_scan_component_details( array $component ) {
		$status          = isset( $component['status'] ) ? (string) $component['status'] : 'error';
		$label           = isset( $component['label'] ) ? (string) $component['label'] : '';
		$vulnerabilities = isset( $component['vulnerabilities'] ) && is_array( $component['vulnerabilities'] ) ? $component['vulnerabilities'] : array();
		$status_class    = 'is-error';
		$status_label    = __( 'Error', 'choctaw-wp-security' );

		if ( 'clean' === $status ) {
			$status_class = 'is-clean';
			$status_label = __( 'No known vulnerabilities', 'choctaw-wp-security' );
		} elseif ( 'vulnerable' === $status ) {
			$status_class = 'is-vulnerable';
			$status_label = sprintf(
				/* translators: %d: vulnerability count */
				_n( '%d known vulnerability', '%d known vulnerabilities', count( $vulnerabilities ), 'choctaw-wp-security' ),
				count( $vulnerabilities )
			);
		} elseif ( 'unrecognized' === $status ) {
			$status_class = 'is-neutral';
			$status_label = __( 'Not recognized by API', 'choctaw-wp-security' );
		}

		$details_class = 'cws-component-status ' . $status_class;
		?>
		<details class="<?php echo esc_attr( $details_class ); ?>">
			<summary>
				<span class="cws-component-status-label"><?php echo esc_html( $label ); ?></span>
				<span class="cws-component-status-badge"><?php echo esc_html( $status_label ); ?></span>
			</summary>
			<div class="cws-component-status-body">
				<?php if ( 'clean' === $status ) : ?>
					<p><?php esc_html_e( 'No known vulnerabilities were reported for the installed version.', 'choctaw-wp-security' ); ?></p>
				<?php elseif ( 'vulnerable' === $status ) : ?>
					<?php $this->render_component_vulnerability_list( $vulnerabilities ); ?>
				<?php elseif ( 'unrecognized' === $status ) : ?>
					<p><?php esc_html_e( 'This component is not listed in the WPVulnerability database.', 'choctaw-wp-security' ); ?></p>
				<?php else : ?>
					<p><?php esc_html_e( 'This component could not be checked.', 'choctaw-wp-security' ); ?></p>
				<?php endif; ?>
			</div>
		</details>
		<?php
	}

	/**
	 * Render a list of vulnerability findings.
	 *
	 * @param array<int, array<string, mixed>> $vulnerabilities Vulnerability records.
	 * @return void
	 */
	private function render_component_vulnerability_list( array $vulnerabilities ) {
		if ( empty( $vulnerabilities ) ) {
			echo '<p>' . esc_html__( 'No vulnerability details were returned.', 'choctaw-wp-security' ) . '</p>';
			return;
		}
		?>
		<div class="cws-component-vulnerability-list">
			<?php foreach ( $vulnerabilities as $vulnerability ) : ?>
				<div class="cws-component-vulnerability-item">
					<h4><?php echo esc_html( isset( $vulnerability['name'] ) ? (string) $vulnerability['name'] : '' ); ?></h4>

					<?php if ( ! empty( $vulnerability['description'] ) ) : ?>
						<div class="cws-component-vulnerability-description">
							<?php echo wp_kses_post( (string) $vulnerability['description'] ); ?>
						</div>
					<?php endif; ?>

					<ul class="cws-core-checksum-list">
						<?php if ( ! empty( $vulnerability['version_range'] ) ) : ?>
							<li>
								<strong><?php esc_html_e( 'Affected versions:', 'choctaw-wp-security' ); ?></strong>
								<?php echo esc_html( (string) $vulnerability['version_range'] ); ?>
							</li>
						<?php endif; ?>
						<?php if ( ! empty( $vulnerability['severity'] ) || ! empty( $vulnerability['score'] ) ) : ?>
							<li>
								<strong><?php esc_html_e( 'Severity:', 'choctaw-wp-security' ); ?></strong>
								<?php
								echo esc_html(
									trim(
										( ! empty( $vulnerability['severity'] ) ? (string) $vulnerability['severity'] : '' ) .
										( ! empty( $vulnerability['score'] ) ? ' (' . (string) $vulnerability['score'] . '/10)' : '' )
									)
								);
								?>
							</li>
						<?php endif; ?>
						<?php if ( ! empty( $vulnerability['unfixed'] ) ) : ?>
							<li><?php esc_html_e( 'This vulnerability appears to be unpatched.', 'choctaw-wp-security' ); ?></li>
						<?php endif; ?>
						<?php if ( ! empty( $vulnerability['closed'] ) ) : ?>
							<li><?php esc_html_e( 'This plugin or theme may no longer be available (closed).', 'choctaw-wp-security' ); ?></li>
						<?php endif; ?>
					</ul>

					<?php if ( ! empty( $vulnerability['cwes'] ) && is_array( $vulnerability['cwes'] ) ) : ?>
						<p><strong><?php esc_html_e( 'Weakness classification:', 'choctaw-wp-security' ); ?></strong></p>
						<ul class="cws-core-checksum-list">
							<?php foreach ( $vulnerability['cwes'] as $cwe ) : ?>
								<li>
									<?php echo esc_html( isset( $cwe['name'] ) ? (string) $cwe['name'] : '' ); ?>
									<?php if ( ! empty( $cwe['description'] ) ) : ?>
										<?php echo esc_html( ' — ' . (string) $cwe['description'] ); ?>
									<?php endif; ?>
								</li>
							<?php endforeach; ?>
						</ul>
					<?php endif; ?>

					<?php if ( ! empty( $vulnerability['sources'] ) && is_array( $vulnerability['sources'] ) ) : ?>
						<p><strong><?php esc_html_e( 'References:', 'choctaw-wp-security' ); ?></strong></p>
						<ul class="cws-core-checksum-list">
							<?php foreach ( $vulnerability['sources'] as $source ) : ?>
								<li>
									<a href="<?php echo esc_url( isset( $source['link'] ) ? (string) $source['link'] : '' ); ?>" target="_blank" rel="noopener noreferrer">
										<?php echo esc_html( isset( $source['name'] ) ? (string) $source['name'] : __( 'Reference', 'choctaw-wp-security' ) ); ?>
									</a>
								</li>
							<?php endforeach; ?>
						</ul>
					<?php endif; ?>
				</div>
			<?php endforeach; ?>
		</div>
		<?php
	}

	/**
	 * Render unrecognized components results (no-JS fallback).
	 *
	 * @param array<string, mixed> $result Scan result payload.
	 * @return void
	 */
	private function render_component_scan_unrecognized_table( $result ) {
		$findings = isset( $result['findings'] ) && is_array( $result['findings'] )
			? $result['findings']
			: Choctaw_Wp_Security_Component_Vulnerability_Scanner::build_unrecognized_findings( $result );

		if ( empty( $findings ) ) {
			echo '<p>' . esc_html__( 'All installed plugins and themes were recognized by the API.', 'choctaw-wp-security' ) . '</p>';
			return;
		}

		$pagination = $this->paginate_report_items( $findings, $this->get_report_page_number( 'cws_unrecognized' ) );
		?>
		<table class="widefat striped cws-core-checksum-table cws-unrecognized-components-table">
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'Risk', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Status', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Category', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Name', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'State', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Action', 'choctaw-wp-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $pagination['items'] as $index => $finding ) : ?>
					<?php
					$row_id       = 'cws-unrecognized-fallback-' . (int) $index;
					$risk         = isset( $finding['risk'] ) ? (string) $finding['risk'] : 'info';
					$risk_label   = isset( $finding['risk_label'] ) ? (string) $finding['risk_label'] : __( 'Info', 'choctaw-wp-security' );
					$status       = isset( $finding['status'] ) ? (string) $finding['status'] : Choctaw_Wp_Security_Finding_Status_Store::STATUS_NEEDS_REVIEW;
					$status_label = isset( $finding['status_label'] ) ? (string) $finding['status_label'] : Choctaw_Wp_Security_Finding_Status_Store::status_label( $status );
					$fingerprint  = isset( $finding['fingerprint'] ) ? (string) $finding['fingerprint'] : ( isset( $finding['id'] ) ? (string) $finding['id'] : '' );
					?>
					<tr>
						<td><?php $this->render_risk_badge( $risk, $risk_label ); ?></td>
						<td><?php $this->render_status_badge( $status, $status_label ); ?></td>
						<td><span class="cws-report-pill"><?php echo esc_html( isset( $finding['category_label'] ) ? (string) $finding['category_label'] : '' ); ?></span></td>
						<td><?php echo esc_html( isset( $finding['name'] ) ? (string) $finding['name'] : '' ); ?></td>
						<td><?php echo esc_html( isset( $finding['state_label'] ) ? (string) $finding['state_label'] : '' ); ?></td>
						<td>
							<button type="button" class="cws-report-eye" data-expand-target="<?php echo esc_attr( $row_id ); ?>" aria-expanded="false" aria-label="<?php esc_attr_e( 'View details', 'choctaw-wp-security' ); ?>">
								<span class="dashicons dashicons-visibility" aria-hidden="true"></span>
							</button>
						</td>
					</tr>
					<tr class="cws-report-detail-row" id="<?php echo esc_attr( $row_id ); ?>" hidden>
						<td colspan="6">
							<div class="cws-report-detail-grid cws-unrecognized-components-detail-grid">
								<div class="cws-unrecognized-components-detail-left">
									<div class="cws-unrecognized-components-info-panel">
										<h4><?php esc_html_e( 'Info', 'choctaw-wp-security' ); ?></h4>
										<dl>
											<dt><?php esc_html_e( 'Slug', 'choctaw-wp-security' ); ?></dt>
											<dd><code class="cws-file-path"><?php echo esc_html( isset( $finding['slug'] ) ? (string) $finding['slug'] : '' ); ?></code></dd>
											<dt><?php esc_html_e( 'Version', 'choctaw-wp-security' ); ?></dt>
											<dd><?php echo esc_html( isset( $finding['version'] ) && '' !== (string) $finding['version'] ? (string) $finding['version'] : '—' ); ?></dd>
										</dl>
									</div>
									<div class="cws-unrecognized-components-contents">
										<h4><?php esc_html_e( 'Contents', 'choctaw-wp-security' ); ?></h4>
										<textarea class="cws-file-contents-textarea large-text code" rows="14" readonly><?php echo esc_textarea( isset( $finding['contents'] ) ? (string) $finding['contents'] : '' ); ?></textarea>
									</div>
								</div>
								<div class="cws-unrecognized-components-detail-right">
									<div>
										<h4><?php esc_html_e( 'Why you are seeing this', 'choctaw-wp-security' ); ?></h4>
										<p><?php echo esc_html( isset( $finding['why_seeing_this'] ) ? (string) $finding['why_seeing_this'] : '' ); ?></p>
									</div>
									<div>
										<h4><?php esc_html_e( 'How to proceed', 'choctaw-wp-security' ); ?></h4>
										<p><?php echo esc_html( isset( $finding['how_to_proceed'] ) ? (string) $finding['how_to_proceed'] : '' ); ?></p>
										<?php
										if ( '' !== $fingerprint ) {
											$this->render_dismiss_controls( 'unrecognized-components', $fingerprint, $status );
										}
										?>
									</div>
								</div>
							</div>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
		$this->render_report_pagination( 'cws_unrecognized', $pagination, __( 'components', 'choctaw-wp-security' ) );
	}

	/**
	 * Render the database scan section.
	 *
	 * @return void
	 */
	private function render_database_scan_section() {
		$result         = false;
		$results_missing = false;

		if ( isset( $_GET['database_scan_run'] ) ) {
			$result = $this->load_report_result(
				$this->get_database_scan_result_transient_key(),
				Choctaw_Wp_Security_Utils::USER_META_DATABASE_SCAN_RESULT
			);

			if ( false === $result ) {
				$results_missing = true;
			}
		}

		$baseline_reset = isset( $_GET['database_scan_baseline_reset'] );
		$resolved       = $this->get_resolved_scan_tables();
		?>
		<div class="cws-admin-tab-panel cws-database-scan-panel">
			<div class="cws-report-section">
				<h2><?php esc_html_e( 'wp_options', 'choctaw-wp-security' ); ?></h2>
				<?php Choctaw_Wp_Security_Admin_Help::render_tab_intro( 'database_scan' ); ?>

				<p class="description">
					<?php
					echo esc_html(
						sprintf(
							/* translators: %s: options table name */
							__( 'Scanning table: %s', 'choctaw-wp-security' ),
							(string) $resolved['options_table']
						)
					);
					?>
				</p>

				<?php if ( $results_missing ) : ?>
					<div class="notice notice-warning">
						<p><?php esc_html_e( 'The previous database scan results are no longer available. Run Scan Now to generate a fresh report.', 'choctaw-wp-security' ); ?></p>
					</div>
				<?php endif; ?>

				<?php if ( $baseline_reset ) : ?>
					<div class="notice notice-success is-dismissible">
						<p><?php esc_html_e( 'The database scan baseline was reset for the selected options table.', 'choctaw-wp-security' ); ?></p>
					</div>
				<?php endif; ?>

				<form method="post" class="cws-database-scan-form" id="cws-database-scan-form">
					<?php wp_nonce_field( 'choctaw_wp_security_database_scan_form' ); ?>
					<input type="hidden" name="cws_tab" value="database-scan" />

					<?php submit_button( __( 'Scan Now', 'choctaw-wp-security' ), 'secondary', 'choctaw_wp_security_database_scan', false ); ?>
					<?php
					submit_button(
						__( 'Reset Baseline', 'choctaw-wp-security' ),
						'secondary',
						'choctaw_wp_security_database_scan_baseline_reset',
						false,
						array(
							'onclick' => "return confirm('" . esc_js( __( 'Reset the baseline to the current options table snapshot?', 'choctaw-wp-security' ) ) . "');",
						)
					);
					?>
					<?php $this->render_clear_history_button( 'database-scan' ); ?>
				</form>

				<div id="cws-database-scan-js-notices" aria-live="polite"></div>
				<div id="cws-database-scan-js-results"></div>

				<div id="cws-database-scan-fallback-results">
					<?php if ( is_array( $result ) ) : ?>
						<?php $this->render_database_scan_results( $result ); ?>
					<?php endif; ?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render database scan results.
	 *
	 * @param array<string, mixed> $result Scan result payload.
	 * @return void
	 */
	private function render_database_scan_results( $result ) {
		$summary     = isset( $result['summary'] ) && is_array( $result['summary'] ) ? $result['summary'] : array();
		$critical    = isset( $summary['critical'] ) ? (int) $summary['critical'] : 0;
		$suspicious  = isset( $summary['suspicious'] ) ? (int) $summary['suspicious'] : ( isset( $summary['warning'] ) ? (int) $summary['warning'] : 0 );
		$safe        = isset( $summary['safe'] ) ? (int) $summary['safe'] : 0;
		$info        = isset( $summary['info'] ) ? (int) $summary['info'] : 0;
		$has_problems = ( $critical + $suspicious ) > 0;

		if ( $critical > 0 ) {
			$panel_class = 'cws-core-checksum-results is-error';
		} elseif ( $suspicious > 0 ) {
			$panel_class = 'cws-core-checksum-results is-warning';
		} else {
			$panel_class = 'cws-core-checksum-results is-success';
		}

		$findings = array();
		if ( ! empty( $result['findings'] ) && is_array( $result['findings'] ) ) {
			$findings = $result['findings'];
		} elseif ( ! empty( $result['sections'] ) && is_array( $result['sections'] ) ) {
			foreach ( Choctaw_Wp_Security_Options_Scan_Patterns::$section_keys as $section_key ) {
				if ( empty( $result['sections'][ $section_key ]['findings'] ) || ! is_array( $result['sections'][ $section_key ]['findings'] ) ) {
					continue;
				}
				foreach ( $result['sections'][ $section_key ]['findings'] as $finding ) {
					if ( empty( $finding['risk'] ) ) {
						$finding['risk'] = Choctaw_Wp_Security_Options_Scan_Patterns::map_severity_to_risk(
							isset( $finding['severity'] ) ? (string) $finding['severity'] : 'info',
							$section_key
						);
					}
					if ( empty( $finding['category_label'] ) ) {
						$labels = Choctaw_Wp_Security_Options_Scan_Patterns::get_category_labels();
						$finding['category_label'] = isset( $labels[ $section_key ] ) ? $labels[ $section_key ] : $section_key;
					}
					$findings[] = $finding;
				}
			}
		}

		// PHP fallback shows Needs Review list (actionable + not dismissed).
		$visible_findings = array_values(
			array_filter(
				$findings,
				function ( $finding ) {
					return is_array( $finding ) && $this->finding_matches_needs_review_filter( $finding );
				}
			)
		);

		usort(
			$visible_findings,
			static function ( $left, $right ) {
				return ( isset( $right['size'] ) ? (int) $right['size'] : 0 ) <=> ( isset( $left['size'] ) ? (int) $left['size'] : 0 );
			}
		);

		$pagination = $this->paginate_report_items( $visible_findings, $this->get_report_page_number( 'cws_dbscan_unified' ) );
		?>
		<div class="<?php echo esc_attr( $panel_class ); ?>">
			<p class="cws-core-checksum-summary">
				<?php if ( $has_problems ) : ?>
					<?php
					echo esc_html(
						sprintf(
							/* translators: 1: critical count, 2: suspicious count, 3: safe count, 4: info count */
							__( 'Scan complete. %1$d critical, %2$d suspicious, %3$d safe, and %4$d informational findings.', 'choctaw-wp-security' ),
							$critical,
							$suspicious,
							$safe,
							$info
						)
					);
					?>
				<?php else : ?>
					<?php
					echo esc_html(
						sprintf(
							/* translators: 1: safe count, 2: informational finding count */
							__( 'Scan complete. No critical or suspicious findings. %1$d safe and %2$d informational item(s) reported.', 'choctaw-wp-security' ),
							$safe,
							$info
						)
					);
					?>
				<?php endif; ?>
			</p>

			<?php if ( ! empty( $result['scan_incomplete'] ) ) : ?>
				<p><?php esc_html_e( 'The scan stopped early because it reached its time budget. Review the partial results below and run the scan again if needed.', 'choctaw-wp-security' ); ?></p>
			<?php endif; ?>

			<?php if ( ! empty( $result['wordpress_configured_table'] ) && ! empty( $result['options_table'] ) && $result['wordpress_configured_table'] !== $result['options_table'] ) : ?>
				<p>
					<?php
					echo esc_html(
						sprintf(
							/* translators: %s: WordPress configured options table */
							__( 'WordPress configured table: %s', 'choctaw-wp-security' ),
							(string) $result['wordpress_configured_table']
						)
					);
					?>
				</p>
			<?php endif; ?>
		</div>

		<div class="cws-report-section cws-database-scan-section">
			<?php if ( empty( $visible_findings ) ) : ?>
				<p><?php esc_html_e( 'No findings requiring review were found. Use Scan Now with JavaScript enabled to choose All risks, Safe, or Info.', 'choctaw-wp-security' ); ?></p>
			<?php else : ?>
				<table class="widefat striped cws-core-checksum-table cws-database-scan-table">
					<thead>
						<tr>
							<th scope="col"><?php esc_html_e( 'Risk', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Status', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Category', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Option ID', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Option', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Action', 'choctaw-wp-security' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $pagination['items'] as $finding ) : ?>
							<?php
							$risk         = isset( $finding['risk'] ) ? (string) $finding['risk'] : 'info';
							$status       = isset( $finding['status'] ) ? (string) $finding['status'] : Choctaw_Wp_Security_Finding_Status_Store::STATUS_NEEDS_REVIEW;
							$status_label = isset( $finding['status_label'] ) ? (string) $finding['status_label'] : Choctaw_Wp_Security_Finding_Status_Store::status_label( $status );
							?>
							<tr>
								<td>
									<div class="cws-risk is-<?php echo esc_attr( $risk ); ?>">
										<span class="cws-risk-label">
											<?php Choctaw_Wp_Security_Utils::render_coreguard_mark(); ?>
											<?php echo esc_html( $this->format_database_scan_risk( $risk ) ); ?>
										</span>
									</div>
								</td>
								<td><?php $this->render_status_badge( $status, $status_label ); ?></td>
								<td><span class="cws-report-pill"><?php echo esc_html( isset( $finding['category_label'] ) ? (string) $finding['category_label'] : '' ); ?></span></td>
								<td><?php echo esc_html( $this->format_database_scan_option_id( $finding ) ); ?></td>
								<td><code class="cws-file-path"><?php echo esc_html( isset( $finding['option_name'] ) ? (string) $finding['option_name'] : '' ); ?></code></td>
								<td><span class="description"><?php esc_html_e( 'Use Scan Now with JavaScript enabled for detail view.', 'choctaw-wp-security' ); ?></span></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
				<?php $this->render_report_pagination( 'cws_dbscan_unified', $pagination, __( 'findings', 'choctaw-wp-security' ) ); ?>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Format a database scan risk label.
	 *
	 * @param string $risk Risk key.
	 * @return string
	 */
	private function format_database_scan_risk( $risk ) {
		$map = array(
			'critical'   => __( 'Critical', 'choctaw-wp-security' ),
			'suspicious' => __( 'Suspicious', 'choctaw-wp-security' ),
			'alert'      => __( 'Alert', 'choctaw-wp-security' ),
			'safe'       => __( 'Safe', 'choctaw-wp-security' ),
			'info'       => __( 'Info', 'choctaw-wp-security' ),
			'missing'    => __( 'Missing', 'choctaw-wp-security' ),
			'na'         => __( 'N/A', 'choctaw-wp-security' ),
			'review'     => __( 'Review', 'choctaw-wp-security' ),
		);

		return isset( $map[ $risk ] ) ? $map[ $risk ] : $this->format_database_scan_severity( $risk );
	}

	/**
	 * Retrieve the page size used for paginated admin reports.
	 *
	 * @return int
	 */
	private function get_report_page_size() {
		return (int) Choctaw_Wp_Security_Utils::REPORT_PAGE_SIZE;
	}

	/**
	 * Read a requested report page number from the query string.
	 *
	 * @param string $param_name Query parameter name.
	 * @return int
	 */
	private function get_report_page_number( $param_name ) {
		$param_name = sanitize_key( (string) $param_name );

		if ( '' === $param_name || ! isset( $_GET[ $param_name ] ) ) {
			return 1;
		}

		return max( 1, (int) wp_unslash( $_GET[ $param_name ] ) );
	}

	/**
	 * Slice a report item list for the requested page.
	 *
	 * @param array<int, mixed> $items Report items.
	 * @param int               $page  Requested page number.
	 * @return array{items: array<int, mixed>, page: int, total: int, total_pages: int, per_page: int}
	 */
	private function paginate_report_items( array $items, $page ) {
		$per_page    = $this->get_report_page_size();
		$total       = count( $items );
		$total_pages = max( 1, (int) ceil( $total / $per_page ) );
		$page        = min( max( 1, (int) $page ), $total_pages );
		$offset      = ( $page - 1 ) * $per_page;

		return array(
			'items'       => array_slice( $items, $offset, $per_page ),
			'page'        => $page,
			'total'       => $total,
			'total_pages' => $total_pages,
			'per_page'    => $per_page,
		);
	}

	/**
	 * Build query args that should be preserved across report pagination links.
	 *
	 * @return array<string, string>
	 */
	private function get_report_page_preserve_args() {
		$args = array(
			'page' => 'sassh-scans',
		);

		if ( ! empty( $_GET['cws_tab'] ) ) {
			$args['cws_tab'] = sanitize_key( wp_unslash( $_GET['cws_tab'] ) );
		} elseif ( isset( $_GET['database_scan_run'] ) ) {
			$args['cws_tab'] = 'database-scan';
		} elseif ( isset( $_GET['scheduled_tasks_run'] ) ) {
			$args['cws_tab'] = 'scheduled-tasks';
		} elseif ( isset( $_GET['posts_scan_run'] ) ) {
			$args['cws_tab'] = 'wp-posts';
		} elseif ( isset( $_GET['core_checksum_run'] ) ) {
			$args['cws_tab'] = 'verify-checksums';
		} elseif ( isset( $_GET['component_scan_run'] ) ) {
			$args['cws_tab'] = 'component-scan';
		} elseif ( isset( $_GET['exposed_folders_run'] ) ) {
			$args['cws_tab'] = 'exposed-folders';
		} elseif ( isset( $_GET['exposed_files_run'] ) ) {
			$args['cws_tab'] = 'exposed-files';
		} elseif ( isset( $_GET['users_table_load'] ) ) {
			$args['cws_tab'] = 'wp-users';
		} elseif ( $this->has_report_pagination_request() ) {
			$args['cws_tab'] = $this->get_active_admin_tab();
		}

		foreach ( array( 'database_scan_run', 'database_scan_baseline_reset', 'scheduled_tasks_run', 'posts_scan_run', 'posts_scan_baseline_reset', 'core_checksum_run', 'component_scan_run', 'exposed_folders_run', 'exposed_files_run', 'uploads_folder_run', 'mu_plugins_run', 'users_table_load' ) as $flag ) {
			if ( isset( $_GET[ $flag ] ) ) {
				$args[ $flag ] = '1';
			}
		}

		return $args;
	}

	/**
	 * Determine whether the current request is paginating a report table.
	 *
	 * @return bool
	 */
	private function has_report_pagination_request() {
		foreach ( $_GET as $key => $value ) {
			if ( ! is_string( $key ) || 0 !== strpos( $key, 'cws_' ) || 'cws_tab' === $key || ! is_scalar( $value ) ) {
				continue;
			}

			if ( is_numeric( $value ) && (int) $value > 0 ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Build a paginated report URL for the settings screen.
	 *
	 * @param string               $param_name    Pagination query parameter.
	 * @param int                  $page          Target page number.
	 * @param array<string, string> $preserve_args Args to preserve in the URL.
	 * @return string
	 */
	private function build_report_page_url( $param_name, $page, array $preserve_args = array() ) {
		$param_name = sanitize_key( (string) $param_name );

		if ( empty( $preserve_args ) ) {
			$preserve_args = $this->get_report_page_preserve_args();
		}

		$args = $preserve_args;

		foreach ( $_GET as $key => $value ) {
			if ( ! is_string( $key ) || 0 !== strpos( $key, 'cws_' ) || $key === $param_name || ! is_scalar( $value ) ) {
				continue;
			}

			$args[ sanitize_key( $key ) ] = sanitize_text_field( wp_unslash( (string) $value ) );
		}

		if ( $page > 1 ) {
			$args[ $param_name ] = (string) (int) $page;
		} else {
			unset( $args[ $param_name ] );
		}

		return add_query_arg( $args, admin_url( 'admin.php' ) );
	}

	/**
	 * Render a shared Risk badge cell.
	 *
	 * @param string $risk  Risk key (critical, suspicious, alert, safe, info, missing, na, review).
	 * @param string $label Display label.
	 * @return void
	 */
	private function render_risk_badge( $risk, $label ) {
		?>
		<div class="cws-risk is-<?php echo esc_attr( (string) $risk ); ?>">
			<span class="cws-risk-label">
				<?php Choctaw_Wp_Security_Utils::render_coreguard_mark(); ?>
				<?php echo esc_html( (string) $label ); ?>
			</span>
		</div>
		<?php
	}

	/**
	 * Render pagination links below a report table.
	 *
	 * Always shows the footer when there is at least one row (grayed controls on a single page).
	 *
	 * @param string                             $param_name Pagination query parameter.
	 * @param array{items: array<int, mixed>, page: int, total: int, total_pages: int, per_page: int} $pagination Pagination state.
	 * @param string                             $item_label Plural noun for the range text (e.g. findings, users, lockouts).
	 * @return void
	 */
	private function render_report_pagination( $param_name, array $pagination, $item_label = '' ) {
		$total_items = (int) $pagination['total'];
		if ( $total_items <= 0 ) {
			return;
		}

		$current_page = (int) $pagination['page'];
		$total_pages  = max( 1, (int) $pagination['total_pages'] );
		$per_page     = (int) $pagination['per_page'];
		$from         = ( ( $current_page - 1 ) * $per_page ) + 1;
		$to           = min( $current_page * $per_page, $total_items );
		$item_label   = '' !== (string) $item_label ? (string) $item_label : __( 'findings', 'choctaw-wp-security' );
		?>
		<div class="cws-report-pagination-bar">
			<div class="cws-report-pagination-info">
				<?php
				echo esc_html(
					sprintf(
						/* translators: 1: first item number, 2: last item number, 3: total items, 4: item noun (findings, users, events, etc.) */
						__( 'Showing %1$s to %2$s of %3$s %4$s.', 'choctaw-wp-security' ),
						number_format_i18n( $from ),
						number_format_i18n( $to ),
						number_format_i18n( $total_items ),
						$item_label
					)
				);
				echo ' ';
				echo esc_html(
					sprintf(
						/* translators: 1: current page number, 2: total pages */
						__( 'Page %1$s of %2$s', 'choctaw-wp-security' ),
						number_format_i18n( $current_page ),
						number_format_i18n( $total_pages )
					)
				);
				?>
			</div>
			<div class="cws-report-pagination-controls">
				<?php if ( $current_page > 1 ) : ?>
					<a class="button button-small" href="<?php echo esc_url( $this->build_report_page_url( $param_name, 1 ) ); ?>">
						<span class="screen-reader-text"><?php esc_html_e( 'First page', 'choctaw-wp-security' ); ?></span>
						<span aria-hidden="true">&laquo;</span>
					</a>
					<a class="button button-small" href="<?php echo esc_url( $this->build_report_page_url( $param_name, $current_page - 1 ) ); ?>">
						<span class="screen-reader-text"><?php esc_html_e( 'Previous page', 'choctaw-wp-security' ); ?></span>
						<span aria-hidden="true">&lsaquo;</span>
					</a>
				<?php else : ?>
					<button type="button" class="button button-small" disabled aria-hidden="true">&laquo;</button>
					<button type="button" class="button button-small" disabled aria-hidden="true">&lsaquo;</button>
				<?php endif; ?>

				<?php if ( $current_page < $total_pages ) : ?>
					<a class="button button-small" href="<?php echo esc_url( $this->build_report_page_url( $param_name, $current_page + 1 ) ); ?>">
						<span class="screen-reader-text"><?php esc_html_e( 'Next page', 'choctaw-wp-security' ); ?></span>
						<span aria-hidden="true">&rsaquo;</span>
					</a>
					<a class="button button-small" href="<?php echo esc_url( $this->build_report_page_url( $param_name, $total_pages ) ); ?>">
						<span class="screen-reader-text"><?php esc_html_e( 'Last page', 'choctaw-wp-security' ); ?></span>
						<span aria-hidden="true">&raquo;</span>
					</a>
				<?php else : ?>
					<button type="button" class="button button-small" disabled aria-hidden="true">&rsaquo;</button>
					<button type="button" class="button button-small" disabled aria-hidden="true">&raquo;</button>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Append the end-of / truncated marker for a Contents textarea value.
	 *
	 * @param string $contents  Preview contents.
	 * @param bool   $truncated Whether contents were truncated to the report limit.
	 * @param string $noun      Content noun (File, Arguments, Snippet, Option Value).
	 * @return string
	 */
	private function with_report_contents_footer( $contents, $truncated, $noun = '' ) {
		return Choctaw_Wp_Security_Utils::with_report_contents_footer( $contents, $truncated, $noun );
	}

	/**
	 * Build the pagination query parameter for a database scan section.
	 *
	 * @param string $section_key Section identifier.
	 * @return string
	 */
	private function get_database_scan_page_param( $section_key ) {
		return 'cws_dbscan_' . sanitize_key( (string) $section_key );
	}

	/**
	 * Render one database scan report section.
	 *
	 * @param array<string, mixed> $section     Section payload.
	 * @param string               $section_key Section identifier.
	 * @return void
	 */
	private function render_database_scan_section_results( $section, $section_key = '' ) {
		$findings     = isset( $section['findings'] ) && is_array( $section['findings'] ) ? $section['findings'] : array();
		$info_message = isset( $section['info_message'] ) ? (string) $section['info_message'] : '';
		$title        = isset( $section['title'] ) ? (string) $section['title'] : '';
		$guidance     = isset( $section['guidance'] ) ? (string) $section['guidance'] : '';
		$page_param   = $this->get_database_scan_page_param( $section_key );
		$pagination   = $this->paginate_report_items( $findings, $this->get_report_page_number( $page_param ) );
		$visible      = $pagination['items'];
		$section_class = 'cws-report-section cws-database-scan-section';

		if ( 'large_autoload' === $section_key ) {
			$section_class .= ' cws-database-scan-section-full-width';
		}
		?>
		<div class="<?php echo esc_attr( $section_class ); ?>">
			<h3>
				<?php echo esc_html( $title ); ?>
				<span class="cws-database-scan-count">(<?php echo esc_html( (string) count( $findings ) ); ?>)</span>
			</h3>
			<?php
			$guidance_detail = Choctaw_Wp_Security_Admin_Help_Content::get_scan_section_detail( (string) $section_key );
			Choctaw_Wp_Security_Admin_Help::render_scan_guidance( $guidance, (string) $section_key, $guidance_detail );
			?>

			<?php if ( '' !== $info_message ) : ?>
				<div class="cws-core-checksum-results is-success">
					<p class="cws-core-checksum-summary"><?php echo esc_html( $info_message ); ?></p>
				</div>
			<?php elseif ( empty( $findings ) ) : ?>
				<p><?php esc_html_e( 'No findings in this section.', 'choctaw-wp-security' ); ?></p>
			<?php else : ?>
				<table class="widefat striped cws-core-checksum-table">
					<thead>
						<tr>
							<th scope="col"><?php esc_html_e( 'Severity', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Option ID', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Option', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Size', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Detail', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Excerpt', 'choctaw-wp-security' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $visible as $finding ) : ?>
							<tr>
								<td><?php echo esc_html( $this->format_database_scan_severity( isset( $finding['severity'] ) ? (string) $finding['severity'] : 'info' ) ); ?></td>
								<td><?php echo esc_html( $this->format_database_scan_option_id( $finding ) ); ?></td>
								<td><code class="cws-file-path"><?php echo esc_html( isset( $finding['option_name'] ) ? (string) $finding['option_name'] : '' ); ?></code></td>
								<td><?php echo esc_html( size_format( isset( $finding['size'] ) ? (int) $finding['size'] : 0 ) ); ?></td>
								<td><?php echo esc_html( isset( $finding['detail'] ) ? (string) $finding['detail'] : '' ); ?></td>
								<td class="<?php echo 'large_autoload' === $section_key ? 'cws-database-scan-excerpt' : ''; ?>"><?php echo esc_html( isset( $finding['excerpt'] ) ? (string) $finding['excerpt'] : '' ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>

				<?php $this->render_report_pagination( $page_param, $pagination, __( 'findings', 'choctaw-wp-security' ) ); ?>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Format a database scan severity label.
	 *
	 * @param string $severity Severity key.
	 * @return string
	 */
	private function format_database_scan_severity( $severity ) {
		if ( 'critical' === $severity ) {
			return __( 'Critical', 'choctaw-wp-security' );
		}

		if ( 'warning' === $severity ) {
			return __( 'Warning', 'choctaw-wp-security' );
		}

		return __( 'Info', 'choctaw-wp-security' );
	}

	/**
	 * Format an option_id value for database scan results.
	 *
	 * @param array<string, mixed> $finding Finding payload.
	 * @return string
	 */
	private function format_database_scan_option_id( $finding ) {
		if ( ! empty( $finding['option_id_label'] ) ) {
			return (string) $finding['option_id_label'];
		}

		$option_id = isset( $finding['option_id'] ) ? (int) $finding['option_id'] : 0;

		if ( $option_id > 0 ) {
			return (string) $option_id;
		}

		return '-';
	}


	/**
	 * Format a table timestamp for display.
	 *
	 * @param string $timestamp Raw timestamp value.
	 * @return string
	 */
	private function format_database_scan_table_timestamp( $timestamp ) {
		if ( '' === $timestamp || '0000-00-00 00:00:00' === $timestamp ) {
			return __( 'Not available (InnoDB)', 'choctaw-wp-security' );
		}

		return $timestamp;
	}

	/**
	 * Render the WP-Cron scan section.
	 *
	 * @return void
	 */
	private function render_scheduled_tasks_section() {
		$result          = false;
		$results_missing = false;

		if ( isset( $_GET['scheduled_tasks_run'] ) ) {
			$result = $this->load_report_result(
				$this->get_scheduled_tasks_result_transient_key(),
				Choctaw_Wp_Security_Utils::USER_META_SCHEDULED_TASKS_RESULT
			);

			if ( false === $result ) {
				$results_missing = true;
			}
		}

		$resolved = $this->get_resolved_scan_tables();
		?>
		<div class="cws-admin-tab-panel">
			<div class="cws-report-section cws-scheduled-tasks-panel">
				<h2><?php esc_html_e( 'WP-Cron', 'choctaw-wp-security' ); ?></h2>
				<?php Choctaw_Wp_Security_Admin_Help::render_tab_intro( 'scheduled_tasks' ); ?>

				<p class="description">
					<?php
					echo esc_html(
						sprintf(
							/* translators: %s: options table name */
							__( 'Scanning table: %s', 'choctaw-wp-security' ),
							(string) $resolved['options_table']
						)
					);
					?>
				</p>

				<?php if ( $results_missing ) : ?>
					<div class="notice notice-warning">
						<p><?php esc_html_e( 'The previous WP-Cron scan results are no longer available. Run Scan Now to generate a fresh report.', 'choctaw-wp-security' ); ?></p>
					</div>
				<?php endif; ?>

				<form method="post" class="cws-scheduled-tasks-form" id="cws-scheduled-tasks-form">
					<?php wp_nonce_field( 'choctaw_wp_security_scheduled_tasks_form' ); ?>
					<input type="hidden" name="cws_tab" value="scheduled-tasks" />

					<?php submit_button( __( 'Scan Now', 'choctaw-wp-security' ), 'secondary', 'choctaw_wp_security_scheduled_tasks_scan', false ); ?>
					<?php $this->render_clear_history_button( 'scheduled-tasks' ); ?>
				</form>

				<div id="cws-scheduled-tasks-js-notices" aria-live="polite"></div>
				<div id="cws-scheduled-tasks-js-results"></div>

				<div id="cws-scheduled-tasks-fallback-results">
					<?php if ( is_array( $result ) ) : ?>
						<?php $this->render_scheduled_tasks_results( $result ); ?>
					<?php endif; ?>
				</div>

				<div
					id="cws-scheduled-tasks-help-boxes"
					class="cws-help-boxes cws-scheduled-tasks-help-boxes"
					<?php echo is_array( $result ) ? '' : ' hidden'; ?>
				>
					<?php
					Choctaw_Wp_Security_Admin_Help::render_info_box( 'scheduled_tasks_categories' );
					Choctaw_Wp_Security_Admin_Help::render_guidance_box( 'scheduled_tasks_remove' );
					?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render scheduled tasks scan results (PHP fallback).
	 *
	 * @param array<string, mixed> $result Scan result payload.
	 * @return void
	 */
	private function render_scheduled_tasks_results( $result ) {
		$summary      = isset( $result['summary'] ) && is_array( $result['summary'] ) ? $result['summary'] : array();
		$critical     = isset( $summary['critical'] ) ? (int) $summary['critical'] : 0;
		$suspicious   = isset( $summary['suspicious'] ) ? (int) $summary['suspicious'] : 0;
		$review       = isset( $summary['review'] ) ? (int) $summary['review'] : 0;
		$info         = isset( $summary['info'] ) ? (int) $summary['info'] : 0;
		$flagged      = isset( $summary['flagged'] ) ? (int) $summary['flagged'] : 0;
		$has_problems = ( $critical + $suspicious ) > 0;

		if ( $critical > 0 ) {
			$panel_class = 'cws-core-checksum-results is-error';
		} elseif ( $suspicious > 0 ) {
			$panel_class = 'cws-core-checksum-results is-warning';
		} else {
			$panel_class = 'cws-core-checksum-results is-success';
		}

		$findings = isset( $result['findings'] ) && is_array( $result['findings'] ) ? $result['findings'] : array();
		$visible  = array();

		foreach ( $findings as $finding ) {
			if ( ! is_array( $finding ) ) {
				continue;
			}

			if ( $this->finding_matches_needs_review_filter( $finding ) ) {
				$visible[] = $finding;
			}
		}

		$page_param = 'cws_scheduled_tasks';
		$pagination = $this->paginate_report_items( $visible, $this->get_report_page_number( $page_param ) );
		$rows       = $pagination['items'];
		?>
		<div class="<?php echo esc_attr( $panel_class ); ?>">
			<p class="cws-core-checksum-summary">
				<?php if ( $has_problems ) : ?>
					<?php
					echo esc_html(
						sprintf(
							/* translators: 1: critical count, 2: suspicious count, 3: review count, 4: info count, 5: flagged count */
							__( 'Scan complete. %1$d critical, %2$d suspicious, %3$d review, and %4$d informational findings. %5$d flagged for review.', 'choctaw-wp-security' ),
							$critical,
							$suspicious,
							$review,
							$info,
							$flagged
						)
					);
					?>
				<?php else : ?>
					<?php
					echo esc_html(
						sprintf(
							/* translators: 1: review count, 2: info count, 3: flagged count */
							__( 'Scan complete. No critical or suspicious findings. %1$d review and %2$d informational item(s) reported. %3$d flagged for review.', 'choctaw-wp-security' ),
							$review,
							$info,
							$flagged
						)
					);
					?>
				<?php endif; ?>
			</p>

			<?php if ( ! empty( $result['wordpress_configured_table'] ) && ! empty( $result['options_table'] ) && $result['wordpress_configured_table'] !== $result['options_table'] ) : ?>
				<p>
					<?php
					echo esc_html(
						sprintf(
							/* translators: %s: WordPress configured options table */
							__( 'WordPress configured table: %s', 'choctaw-wp-security' ),
							(string) $result['wordpress_configured_table']
						)
					);
					?>
				</p>
			<?php endif; ?>
		</div>

		<div class="cws-report-section cws-scheduled-tasks-section">
			<h3>
				<?php esc_html_e( 'Flagged WP-Cron Events', 'choctaw-wp-security' ); ?>
				<span class="cws-database-scan-count">(<?php echo esc_html( (string) count( $visible ) ); ?>)</span>
			</h3>

			<?php if ( empty( $visible ) ) : ?>
				<p><?php esc_html_e( 'No non-recognized WP-Cron events were found.', 'choctaw-wp-security' ); ?></p>
			<?php else : ?>
				<table class="widefat striped cws-core-checksum-table cws-scheduled-tasks-table">
					<thead>
						<tr>
							<th scope="col"><?php esc_html_e( 'Risk', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Category', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Hook', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Action', 'choctaw-wp-security' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $rows as $finding ) : ?>
							<?php
							$risk_label = isset( $finding['risk_label'] ) ? (string) $finding['risk_label'] : $this->format_scheduled_tasks_risk( isset( $finding['risk'] ) ? (string) $finding['risk'] : 'info' );
							$categories = isset( $finding['category_labels'] ) && is_array( $finding['category_labels'] ) ? $finding['category_labels'] : array();
							?>
							<tr>
								<td><?php echo esc_html( $risk_label ); ?></td>
								<td><?php echo esc_html( implode( ', ', array_map( 'strval', $categories ) ) ); ?></td>
								<td><code class="cws-file-path"><?php echo esc_html( isset( $finding['hook'] ) ? (string) $finding['hook'] : '' ); ?></code></td>
								<td><span class="description"><?php esc_html_e( 'Use Scan Now with JavaScript enabled for detail view.', 'choctaw-wp-security' ); ?></span></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>

				<?php $this->render_report_pagination( $page_param, $pagination, __( 'events', 'choctaw-wp-security' ) ); ?>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Format a scheduled tasks risk label.
	 *
	 * @param string $risk Risk key.
	 * @return string
	 */
	private function format_scheduled_tasks_risk( $risk ) {
		$map = array(
			'critical'   => __( 'Critical', 'choctaw-wp-security' ),
			'suspicious' => __( 'Suspicious', 'choctaw-wp-security' ),
			'review'     => __( 'Review', 'choctaw-wp-security' ),
			'info'       => __( 'Info', 'choctaw-wp-security' ),
		);

		return isset( $map[ $risk ] ) ? $map[ $risk ] : $map['info'];
	}


	/**
	 * Render the wp_posts scan section.
	 *
	 * @return void
	 */
	private function render_posts_scan_section() {
		$result          = false;
		$results_missing = false;

		if ( isset( $_GET['posts_scan_run'] ) ) {
			$result = $this->load_report_result(
				$this->get_posts_scan_result_transient_key(),
				Choctaw_Wp_Security_Utils::USER_META_POSTS_SCAN_RESULT
			);

			if ( false === $result ) {
				$results_missing = true;
			}
		}

		$baseline_reset = isset( $_GET['posts_scan_baseline_reset'] );
		$resolved       = $this->get_resolved_scan_tables();
		?>
		<div class="cws-admin-tab-panel cws-posts-scan-panel">
			<div class="cws-report-section">
				<h2><?php esc_html_e( 'wp_posts', 'choctaw-wp-security' ); ?></h2>
				<?php Choctaw_Wp_Security_Admin_Help::render_tab_intro( 'posts_scan' ); ?>

				<p class="description">
					<?php
					echo esc_html(
						sprintf(
							/* translators: %s: posts table name */
							__( 'Scanning table: %s', 'choctaw-wp-security' ),
							(string) $resolved['posts_table']
						)
					);
					?>
				</p>

				<?php if ( $results_missing ) : ?>
					<div class="notice notice-warning">
						<p><?php esc_html_e( 'The previous posts scan results are no longer available. Run Scan Now to generate a fresh report.', 'choctaw-wp-security' ); ?></p>
					</div>
				<?php endif; ?>

				<?php if ( $baseline_reset ) : ?>
					<div class="notice notice-success is-dismissible">
						<p><?php esc_html_e( 'The posts scan baseline was reset for the selected posts table.', 'choctaw-wp-security' ); ?></p>
					</div>
				<?php endif; ?>

				<form method="post" class="cws-posts-scan-form" id="cws-posts-scan-form">
					<?php wp_nonce_field( 'choctaw_wp_security_posts_scan_form' ); ?>
					<input type="hidden" name="cws_tab" value="wp-posts" />

					<?php submit_button( __( 'Scan Now', 'choctaw-wp-security' ), 'secondary', 'choctaw_wp_security_posts_scan', false ); ?>
					<?php
					submit_button(
						__( 'Reset Baseline', 'choctaw-wp-security' ),
						'secondary',
						'choctaw_wp_security_posts_scan_baseline_reset',
						false,
						array(
							'onclick' => "return confirm('" . esc_js( __( 'Reset the baseline to the current posts table snapshot?', 'choctaw-wp-security' ) ) . "');",
						)
					);
					?>
					<?php $this->render_clear_history_button( 'wp-posts' ); ?>
				</form>

				<div id="cws-posts-scan-js-notices" aria-live="polite"></div>
				<div id="cws-posts-scan-js-results"></div>

				<div id="cws-posts-scan-fallback-results">
					<?php if ( is_array( $result ) ) : ?>
						<?php $this->render_posts_scan_results( $result ); ?>
					<?php endif; ?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render wp_posts scan results.
	 *
	 * @param array<string, mixed> $result Scan result payload.
	 * @return void
	 */
	private function render_posts_scan_results( $result ) {
		$summary     = isset( $result['summary'] ) && is_array( $result['summary'] ) ? $result['summary'] : array();
		$critical    = isset( $summary['critical'] ) ? (int) $summary['critical'] : 0;
		$suspicious  = isset( $summary['suspicious'] ) ? (int) $summary['suspicious'] : ( isset( $summary['warning'] ) ? (int) $summary['warning'] : 0 );
		$safe        = isset( $summary['safe'] ) ? (int) $summary['safe'] : 0;
		$info        = isset( $summary['info'] ) ? (int) $summary['info'] : 0;
		$has_problems = ( $critical + $suspicious ) > 0;

		if ( $critical > 0 ) {
			$panel_class = 'cws-core-checksum-results is-error';
		} elseif ( $suspicious > 0 ) {
			$panel_class = 'cws-core-checksum-results is-warning';
		} else {
			$panel_class = 'cws-core-checksum-results is-success';
		}

		$findings = array();
		if ( ! empty( $result['findings'] ) && is_array( $result['findings'] ) ) {
			$findings = $result['findings'];
		} elseif ( ! empty( $result['sections'] ) && is_array( $result['sections'] ) ) {
			$labels = Choctaw_Wp_Security_Posts_Scan_Patterns::get_category_labels();
			foreach ( Choctaw_Wp_Security_Posts_Scan_Patterns::$section_keys as $section_key ) {
				if ( empty( $result['sections'][ $section_key ]['findings'] ) || ! is_array( $result['sections'][ $section_key ]['findings'] ) ) {
					continue;
				}
				foreach ( $result['sections'][ $section_key ]['findings'] as $finding ) {
					if ( empty( $finding['risk'] ) ) {
						$finding['risk'] = Choctaw_Wp_Security_Posts_Scan_Patterns::map_severity_to_risk(
							isset( $finding['severity'] ) ? (string) $finding['severity'] : 'info',
							$section_key
						);
					}
					if ( empty( $finding['category'] ) ) {
						$finding['category'] = $section_key;
					}
					if ( empty( $finding['category_label'] ) ) {
						$finding['category_label'] = isset( $labels[ $section_key ] ) ? $labels[ $section_key ] : $section_key;
					}
					$findings[] = $finding;
				}
			}
		}

		$visible_findings = array_values(
			array_filter(
				$findings,
				function ( $finding ) {
					return is_array( $finding ) && $this->finding_matches_needs_review_filter( $finding );
				}
			)
		);

		usort(
			$visible_findings,
			static function ( $left, $right ) {
				$order = array( 'critical' => 3, 'suspicious' => 2, 'safe' => 1, 'info' => 0 );
				$left_risk  = isset( $left['risk'] ) ? (string) $left['risk'] : 'info';
				$right_risk = isset( $right['risk'] ) ? (string) $right['risk'] : 'info';
				$cmp = ( isset( $order[ $right_risk ] ) ? $order[ $right_risk ] : 0 ) <=> ( isset( $order[ $left_risk ] ) ? $order[ $left_risk ] : 0 );
				if ( 0 !== $cmp ) {
					return $cmp;
				}
				return ( isset( $right['size'] ) ? (int) $right['size'] : 0 ) <=> ( isset( $left['size'] ) ? (int) $left['size'] : 0 );
			}
		);

		$pagination = $this->paginate_report_items( $visible_findings, $this->get_report_page_number( 'cws_postsscan_unified' ) );
		?>
		<div class="<?php echo esc_attr( $panel_class ); ?>">
			<p class="cws-core-checksum-summary">
				<?php if ( $has_problems ) : ?>
					<?php
					echo esc_html(
						sprintf(
							/* translators: 1: critical count, 2: suspicious count, 3: safe count, 4: info count */
							__( 'Scan complete. %1$d critical, %2$d suspicious, %3$d safe, and %4$d informational findings.', 'choctaw-wp-security' ),
							$critical,
							$suspicious,
							$safe,
							$info
						)
					);
					?>
				<?php else : ?>
					<?php
					echo esc_html(
						sprintf(
							/* translators: 1: safe count, 2: informational finding count */
							__( 'Scan complete. No critical or suspicious findings. %1$d safe and %2$d informational item(s) reported.', 'choctaw-wp-security' ),
							$safe,
							$info
						)
					);
					?>
				<?php endif; ?>
			</p>

			<?php if ( ! empty( $result['scan_incomplete'] ) ) : ?>
				<p><?php esc_html_e( 'The scan stopped early because it reached its time budget. Review the partial results below and run the scan again if needed.', 'choctaw-wp-security' ); ?></p>
			<?php endif; ?>

			<?php if ( ! empty( $result['wordpress_configured_table'] ) && ! empty( $result['posts_table'] ) && $result['wordpress_configured_table'] !== $result['posts_table'] ) : ?>
				<p>
					<?php
					echo esc_html(
						sprintf(
							/* translators: %s: WordPress configured posts table */
							__( 'WordPress configured table: %s', 'choctaw-wp-security' ),
							(string) $result['wordpress_configured_table']
						)
					);
					?>
				</p>
			<?php endif; ?>
		</div>

		<div class="cws-report-section cws-posts-scan-section">
			<?php if ( empty( $visible_findings ) ) : ?>
				<p><?php esc_html_e( 'No findings requiring review were found. Use Scan Now with JavaScript enabled to choose All risks, Safe, or Info.', 'choctaw-wp-security' ); ?></p>
			<?php else : ?>
				<table class="widefat striped cws-core-checksum-table cws-posts-scan-table">
					<thead>
						<tr>
							<th scope="col"><?php esc_html_e( 'Risk', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Status', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Category', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Post ID', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Title', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Type', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Action', 'choctaw-wp-security' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $pagination['items'] as $finding ) : ?>
							<?php
							$risk         = isset( $finding['risk'] ) ? (string) $finding['risk'] : 'info';
							$status       = isset( $finding['status'] ) ? (string) $finding['status'] : Choctaw_Wp_Security_Finding_Status_Store::STATUS_NEEDS_REVIEW;
							$status_label = isset( $finding['status_label'] ) ? (string) $finding['status_label'] : Choctaw_Wp_Security_Finding_Status_Store::status_label( $status );
							?>
							<tr>
								<td><?php $this->render_risk_badge( $risk, $this->format_database_scan_risk( $risk ) ); ?></td>
								<td><?php $this->render_status_badge( $status, $status_label ); ?></td>
								<td><span class="cws-report-pill"><?php echo esc_html( isset( $finding['category_label'] ) ? (string) $finding['category_label'] : '' ); ?></span></td>
								<td><?php echo wp_kses_post( $this->get_posts_scan_post_id_markup( $finding ) ); ?></td>
								<td><?php echo esc_html( isset( $finding['post_title'] ) ? (string) $finding['post_title'] : '' ); ?></td>
								<td><?php echo esc_html( isset( $finding['post_type'] ) ? (string) $finding['post_type'] : '' ); ?></td>
								<td><span class="description"><?php esc_html_e( 'Use Scan Now with JavaScript enabled for detail view.', 'choctaw-wp-security' ); ?></span></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
				<?php $this->render_report_pagination( 'cws_postsscan_unified', $pagination, __( 'findings', 'choctaw-wp-security' ) ); ?>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Build post ID markup for posts scan results.
	 *
	 * @param array<string, mixed> $finding Finding payload.
	 * @return string
	 */
	private function get_posts_scan_post_id_markup( $finding ) {
		$post_id = isset( $finding['post_id'] ) ? (int) $finding['post_id'] : 0;

		if ( $post_id <= 0 ) {
			return '-';
		}

		$edit_url = get_edit_post_link( $post_id, 'raw' );

		if ( ! is_string( $edit_url ) || '' === $edit_url ) {
			return esc_html( (string) $post_id );
		}

		return sprintf(
			'<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>',
			esc_url( $edit_url ),
			esc_html( (string) $post_id )
		);
	}

	/**
	 * Build user ID markup for posts scan results.
	 *
	 * @param array<string, mixed> $finding Finding payload.
	 * @return string
	 */
	private function get_posts_scan_user_id_markup( $finding ) {
		$user_id      = isset( $finding['user_id'] ) ? (int) $finding['user_id'] : 0;
		$display_name = isset( $finding['user_display_name'] ) ? (string) $finding['user_display_name'] : '';

		if ( $user_id <= 0 ) {
			return esc_html( '0' );
		}

		$edit_url = admin_url( 'user-edit.php?user_id=' . $user_id );
		$label    = esc_html( (string) $user_id );
		$title    = '' !== $display_name ? $display_name : '';
		$aria     = '' !== $display_name
			? sprintf(
				/* translators: 1: user ID, 2: display name */
				__( 'User ID %1$s (%2$s)', 'choctaw-wp-security' ),
				$user_id,
				$display_name
			)
			: (string) $user_id;

		return sprintf(
			'<a href="%s" target="_blank" rel="noopener noreferrer"%s aria-label="%s">%s</a>',
			esc_url( $edit_url ),
			'' !== $title ? ' title="' . esc_attr( $title ) . '"' : '',
			esc_attr( $aria ),
			$label
		);
	}


	/**
	 * Render core checksum scan results.
	 *
	 * @param array<string, mixed> $result Scan result payload.
	 * @return void
	 */
	private function render_core_checksum_results( $result ) {
		$has_problems = empty( $result['success'] );
		$panel_class  = $has_problems ? 'cws-core-checksum-results is-error' : 'cws-core-checksum-results is-success';
		?>
		<div class="<?php echo esc_attr( $panel_class ); ?>">
			<?php if ( ! $has_problems ) : ?>
				<p class="cws-core-checksum-summary">
					<?php
					echo esc_html(
						sprintf(
							/* translators: 1: WordPress version, 2: locale, 3: number of files checked */
							__( 'All checked WordPress core files match official checksums for version %1$s (%2$s). %3$d files verified.', 'choctaw-wp-security' ),
							isset( $result['version'] ) ? (string) $result['version'] : '',
							isset( $result['locale'] ) ? (string) $result['locale'] : '',
							isset( $result['checked'] ) ? (int) $result['checked'] : 0
						)
					);
					?>
				</p>
			<?php else : ?>
				<p class="cws-core-checksum-summary">
					<?php
					echo esc_html(
						sprintf(
							/* translators: 1: WordPress version, 2: locale, 3: number of files checked */
							__( 'Problems were found while comparing WordPress %1$s (%2$s). %3$d core files were checked.', 'choctaw-wp-security' ),
							isset( $result['version'] ) ? (string) $result['version'] : '',
							isset( $result['locale'] ) ? (string) $result['locale'] : '',
							isset( $result['checked'] ) ? (int) $result['checked'] : 0
						)
					);
					?>
				</p>

				<?php if ( ! empty( $result['errors'] ) ) : ?>
					<h3><?php esc_html_e( 'Errors', 'choctaw-wp-security' ); ?></h3>
					<ul class="cws-core-checksum-list">
						<?php foreach ( $result['errors'] as $error_message ) : ?>
							<li><?php echo esc_html( (string) $error_message ); ?></li>
						<?php endforeach; ?>
					</ul>
				<?php endif; ?>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Render the three checksum finding category reports as one unified table.
	 *
	 * @param array<string, mixed> $result Scan result payload.
	 * @return void
	 */
	private function render_core_checksum_category_reports( $result ) {
		$modified = isset( $result['modified'] ) && is_array( $result['modified'] ) ? $result['modified'] : array();
		$missing  = isset( $result['missing'] ) && is_array( $result['missing'] ) ? $result['missing'] : array();
		$unknown  = isset( $result['unknown'] ) && is_array( $result['unknown'] ) ? $result['unknown'] : array();

		$findings = array();

		foreach ( $modified as $file_path ) {
			$path        = (string) $file_path;
			$fingerprint = Choctaw_Wp_Security_Finding_Status_Store::fingerprint_checksum( $path, 'modified' );
			$findings[]  = $this->build_checksum_finding_row( $path, 'critical', 'modified', $fingerprint );
		}
		foreach ( $missing as $file_path ) {
			$path        = (string) $file_path;
			$fingerprint = Choctaw_Wp_Security_Finding_Status_Store::fingerprint_checksum( $path, 'missing' );
			$findings[]  = $this->build_checksum_finding_row( $path, 'critical', 'missing', $fingerprint );
		}
		foreach ( $unknown as $file_path ) {
			$path        = (string) $file_path;
			$fingerprint = Choctaw_Wp_Security_Finding_Status_Store::fingerprint_checksum( $path, 'unknown' );
			$findings[]  = $this->build_checksum_finding_row( $path, 'suspicious', 'unknown', $fingerprint );
		}

		$findings = Choctaw_Wp_Security_Finding_Status_Store::apply( 'verify-checksums', $findings );

		$risk_filter     = isset( $_GET['cws_checksum_risk'] ) ? sanitize_key( wp_unslash( $_GET['cws_checksum_risk'] ) ) : '';
		$status_filter   = isset( $_GET['cws_checksum_status'] ) ? sanitize_key( wp_unslash( $_GET['cws_checksum_status'] ) ) : 'needs_review';
		$category_filter = isset( $_GET['cws_checksum_category'] ) ? sanitize_key( wp_unslash( $_GET['cws_checksum_category'] ) ) : '';

		if ( ! in_array( $status_filter, array( 'needs_review', 'no_action_needed', 'dismissed', '' ), true ) ) {
			$status_filter = 'needs_review';
		}

		if ( in_array( $risk_filter, array( 'critical', 'suspicious' ), true ) ) {
			$findings = array_values(
				array_filter(
					$findings,
					static function ( $finding ) use ( $risk_filter ) {
						return $risk_filter === $finding['risk'];
					}
				)
			);
		}

		if ( 'needs_review' === $status_filter ) {
			$findings = array_values(
				array_filter(
					$findings,
					function ( $finding ) {
						return is_array( $finding ) && $this->finding_matches_needs_review_filter( $finding );
					}
				)
			);
		} elseif ( 'dismissed' === $status_filter ) {
			$findings = array_values(
				array_filter(
					$findings,
					static function ( $finding ) {
						return isset( $finding['status'] ) && Choctaw_Wp_Security_Finding_Status_Store::STATUS_DISMISSED === $finding['status'];
					}
				)
			);
		} elseif ( 'no_action_needed' === $status_filter ) {
			$findings = array_values(
				array_filter(
					$findings,
					static function ( $finding ) {
						return isset( $finding['status'] ) && Choctaw_Wp_Security_Finding_Status_Store::STATUS_NO_ACTION_NEEDED === $finding['status'];
					}
				)
			);
		}

		if ( in_array( $category_filter, array( 'modified', 'missing', 'unknown' ), true ) ) {
			$findings = array_values(
				array_filter(
					$findings,
					static function ( $finding ) use ( $category_filter ) {
						return $category_filter === $finding['category'];
					}
				)
			);
		}

		$category_labels = array(
			'modified' => __( 'Modified Files', 'choctaw-wp-security' ),
			'missing'  => __( 'Missing Files', 'choctaw-wp-security' ),
			'unknown'  => __( 'Not Part of Core', 'choctaw-wp-security' ),
		);
		$why_copy        = array(
			'modified' => __( 'This file does not match the official WordPress core checksum, indicating that it was modified by something. Because plugins and themes do not modify core files, this was highly likely the result of an attacker.', 'choctaw-wp-security' ),
			'missing'  => __( 'Official WordPress core verification reports that this file is missing. It is highly unlikely it was deleted by a plugin or theme.', 'choctaw-wp-security' ),
			'unknown'  => __( 'Official WordPress core verification reports that it does not recognize this file.', 'choctaw-wp-security' ),
		);
		?>
		<div class="cws-report-section cws-core-checksum-category-report">
			<h3><?php esc_html_e( 'Checksum Findings', 'choctaw-wp-security' ); ?></h3>

			<?php if ( empty( $modified ) && empty( $missing ) && empty( $unknown ) ) : ?>
				<p><?php esc_html_e( 'No files reported.', 'choctaw-wp-security' ); ?></p>
			<?php else : ?>
				<form method="get" class="cws-report-toolbar" action="">
					<input type="hidden" name="page" value="sassh-scans" />
					<input type="hidden" name="cws_tab" value="verify-checksums" />
					<input type="hidden" name="core_checksum_run" value="1" />
					<label>
						<span class="screen-reader-text"><?php esc_html_e( 'Risk', 'choctaw-wp-security' ); ?></span>
						<select name="cws_checksum_risk" onchange="this.form.submit()">
							<option value=""><?php esc_html_e( 'All risks', 'choctaw-wp-security' ); ?></option>
							<option value="critical" <?php selected( $risk_filter, 'critical' ); ?>><?php esc_html_e( 'Critical', 'choctaw-wp-security' ); ?></option>
							<option value="suspicious" <?php selected( $risk_filter, 'suspicious' ); ?>><?php esc_html_e( 'Suspicious', 'choctaw-wp-security' ); ?></option>
						</select>
					</label>
					<label>
						<span class="screen-reader-text"><?php esc_html_e( 'Status', 'choctaw-wp-security' ); ?></span>
						<select name="cws_checksum_status" onchange="this.form.submit()">
							<option value="needs_review" <?php selected( $status_filter, 'needs_review' ); ?>><?php esc_html_e( 'Needs Review', 'choctaw-wp-security' ); ?></option>
							<option value="no_action_needed" <?php selected( $status_filter, 'no_action_needed' ); ?>><?php esc_html_e( 'Review Not Needed', 'choctaw-wp-security' ); ?></option>
							<option value="dismissed" <?php selected( $status_filter, 'dismissed' ); ?>><?php esc_html_e( 'Dismissed', 'choctaw-wp-security' ); ?></option>
							<option value="" <?php selected( $status_filter, '' ); ?>><?php esc_html_e( 'All statuses', 'choctaw-wp-security' ); ?></option>
						</select>
					</label>
					<label>
						<span class="screen-reader-text"><?php esc_html_e( 'Category', 'choctaw-wp-security' ); ?></span>
						<select name="cws_checksum_category" onchange="this.form.submit()">
							<option value=""><?php esc_html_e( 'All categories', 'choctaw-wp-security' ); ?></option>
							<option value="modified" <?php selected( $category_filter, 'modified' ); ?>><?php esc_html_e( 'Modified Files', 'choctaw-wp-security' ); ?></option>
							<option value="missing" <?php selected( $category_filter, 'missing' ); ?>><?php esc_html_e( 'Missing Files', 'choctaw-wp-security' ); ?></option>
							<option value="unknown" <?php selected( $category_filter, 'unknown' ); ?>><?php esc_html_e( 'Not Part of Core', 'choctaw-wp-security' ); ?></option>
						</select>
					</label>
				</form>

				<?php if ( empty( $findings ) ) : ?>
					<p><?php esc_html_e( 'No findings matched the current filters.', 'choctaw-wp-security' ); ?></p>
				<?php else : ?>
					<?php
					$pagination = $this->paginate_report_items( $findings, $this->get_report_page_number( 'cws_checksum_unified' ) );
					?>
					<table class="widefat striped cws-core-checksum-table">
						<thead>
							<tr>
								<th scope="col"><?php esc_html_e( 'Risk', 'choctaw-wp-security' ); ?></th>
								<th scope="col"><?php esc_html_e( 'Status', 'choctaw-wp-security' ); ?></th>
								<th scope="col"><?php esc_html_e( 'Category', 'choctaw-wp-security' ); ?></th>
								<th scope="col"><?php esc_html_e( 'Path', 'choctaw-wp-security' ); ?></th>
								<th scope="col"><?php esc_html_e( 'File', 'choctaw-wp-security' ); ?></th>
								<th scope="col"><?php esc_html_e( 'Action', 'choctaw-wp-security' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $pagination['items'] as $index => $finding ) : ?>
								<?php
								$category    = $finding['category'];
								$row_id      = 'cws-checksum-' . $category . '-' . (int) $index;
								$risk_lbl    = 'suspicious' === $finding['risk']
									? __( 'Suspicious', 'choctaw-wp-security' )
									: __( 'Critical', 'choctaw-wp-security' );
								$status      = isset( $finding['status'] ) ? (string) $finding['status'] : Choctaw_Wp_Security_Finding_Status_Store::STATUS_NEEDS_REVIEW;
								$status_lbl  = isset( $finding['status_label'] ) ? (string) $finding['status_label'] : Choctaw_Wp_Security_Finding_Status_Store::status_label( $status );
								$fingerprint = isset( $finding['fingerprint'] ) ? (string) $finding['fingerprint'] : '';
								?>
								<tr>
									<td><?php $this->render_risk_badge( $finding['risk'], $risk_lbl ); ?></td>
									<td><?php $this->render_status_badge( $status, $status_lbl ); ?></td>
									<td><span class="cws-report-pill"><?php echo esc_html( $category_labels[ $category ] ); ?></span></td>
									<td><?php $this->render_file_path( $this->get_core_file_directory_path( $finding['path'] ) ); ?></td>
									<td><?php $this->render_file_path( $this->get_core_file_basename( $finding['path'] ) ); ?></td>
									<td>
										<button
											type="button"
											class="cws-report-eye"
											data-expand-target="<?php echo esc_attr( $row_id ); ?>"
											aria-expanded="false"
											aria-label="<?php esc_attr_e( 'View details', 'choctaw-wp-security' ); ?>"
										>
											<span class="dashicons dashicons-visibility" aria-hidden="true"></span>
										</button>
									</td>
								</tr>
								<tr class="cws-report-detail-row" id="<?php echo esc_attr( $row_id ); ?>" hidden>
									<td colspan="6">
										<div class="cws-report-detail-grid cws-report-detail-standard">
											<div class="cws-report-detail-left">
												<div class="cws-report-info-panel">
													<h4><?php esc_html_e( 'Info', 'choctaw-wp-security' ); ?></h4>
													<dl>
														<dt><?php esc_html_e( 'Modified Date/Time', 'choctaw-wp-security' ); ?></dt>
														<dd><?php echo esc_html( $this->display_or_em_dash( isset( $finding['modified_label'] ) ? (string) $finding['modified_label'] : '' ) ); ?></dd>
														<dt><?php esc_html_e( 'File Size', 'choctaw-wp-security' ); ?></dt>
														<dd><?php echo esc_html( $this->display_or_em_dash( isset( $finding['size_label'] ) ? (string) $finding['size_label'] : '' ) ); ?></dd>
														<dt><?php esc_html_e( 'Permissions', 'choctaw-wp-security' ); ?></dt>
														<dd><?php echo esc_html( $this->display_or_em_dash( isset( $finding['permissions'] ) ? (string) $finding['permissions'] : '' ) ); ?></dd>
														<dt><?php esc_html_e( 'Owner', 'choctaw-wp-security' ); ?></dt>
														<dd><?php echo esc_html( $this->display_or_em_dash( isset( $finding['owner'] ) ? (string) $finding['owner'] : '' ) ); ?></dd>
													</dl>
												</div>
												<div class="cws-report-contents">
													<h4><?php esc_html_e( 'Contents', 'choctaw-wp-security' ); ?></h4>
													<textarea class="cws-file-contents-textarea large-text code" rows="14" readonly><?php echo esc_textarea( $this->with_report_contents_footer( isset( $finding['contents'] ) ? (string) $finding['contents'] : '', ! empty( $finding['contents_truncated'] ), __( 'File', 'choctaw-wp-security' ) ) ); ?></textarea>
												</div>
											</div>
											<div class="cws-report-detail-right">
												<div>
													<h4><?php esc_html_e( 'Why you are seeing this', 'choctaw-wp-security' ); ?></h4>
													<p><?php echo esc_html( $why_copy[ $category ] ); ?></p>
												</div>
												<div>
													<h4><?php esc_html_e( 'How to proceed', 'choctaw-wp-security' ); ?></h4>
													<?php echo wp_kses_post( $this->get_checksum_how_to_proceed_html( $category ) ); ?>
													<?php $this->render_dismiss_controls( 'verify-checksums', $fingerprint, $status ); ?>
												</div>
											</div>
										</div>
									</td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
					<?php $this->render_report_pagination( 'cws_checksum_unified', $pagination, __( 'findings', 'choctaw-wp-security' ) ); ?>
				<?php endif; ?>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Build one Verify Checksums finding row with Info/Contents metadata.
	 *
	 * @param string $relative_path Relative WordPress path.
	 * @param string $risk          Risk key.
	 * @param string $category      Category key.
	 * @param string $fingerprint   Finding fingerprint.
	 * @return array<string, mixed>
	 */
	private function build_checksum_finding_row( $relative_path, $risk, $category, $fingerprint ) {
		$absolute = wp_normalize_path( ABSPATH . ltrim( wp_normalize_path( (string) $relative_path ), '/' ) );
		$meta     = Choctaw_Wp_Security_Utils::get_file_preview_meta( $absolute );

		return array(
			'id'              => $fingerprint,
			'fingerprint'     => $fingerprint,
			'path'            => (string) $relative_path,
			'risk'            => $risk,
			'category'        => $category,
			'size'            => $meta['size'],
			'size_label'      => $meta['size_label'],
			'modified'        => $meta['modified'],
			'modified_label'  => $meta['modified_label'],
			'permissions'     => $meta['permissions'],
			'owner'           => $meta['owner'],
			'contents'        => $meta['contents'],
			'contents_truncated' => ! empty( $meta['contents_truncated'] ),
		);
	}

	/**
	 * Build How to proceed HTML for a checksum category from guidance content.
	 *
	 * @param string $category modified|missing|unknown.
	 * @return string
	 */
	private function get_checksum_how_to_proceed_html( $category ) {
		$guidance_id = 'checksum_' . sanitize_key( (string) $category );
		$guidance    = Choctaw_Wp_Security_Admin_Help_Content::get_guidance( $guidance_id );

		if ( empty( $guidance ) ) {
			return '';
		}

		$html = '';

		if ( ! empty( $guidance['intro'] ) ) {
			$html .= '<p>' . esc_html( (string) $guidance['intro'] ) . '</p>';
		}

		if ( ! empty( $guidance['steps'] ) && is_array( $guidance['steps'] ) ) {
			$html .= '<ol>';
			foreach ( $guidance['steps'] as $step ) {
				$html .= '<li>' . wp_kses_post( (string) $step ) . '</li>';
			}
			$html .= '</ol>';
		}

		return $html;
	}

	/**
	 * Render Directory Browsing scan results (no-JS fallback).
	 *
	 * @param array<string, mixed> $result Scan result payload.
	 * @return void
	 */
	private function render_exposed_folders_results( $result ) {
		$findings = isset( $result['findings'] ) && is_array( $result['findings'] ) ? $result['findings'] : array();
		$summary  = isset( $result['summary'] ) && is_array( $result['summary'] ) ? $result['summary'] : array();
		$critical = isset( $summary['critical'] ) ? (int) $summary['critical'] : 0;
		$review   = isset( $summary['review'] ) ? (int) $summary['review'] : 0;
		$safe     = isset( $summary['safe'] ) ? (int) $summary['safe'] : 0;
		$info     = isset( $summary['info'] ) ? (int) $summary['info'] : 0;
		$panel    = ( $critical > 0 || $review > 0 ) ? 'cws-core-checksum-results is-error' : 'cws-core-checksum-results is-success';
		?>
		<div class="<?php echo esc_attr( $panel ); ?>">
			<p class="cws-core-checksum-summary">
				<?php
				if ( $critical > 0 || $review > 0 ) {
					echo esc_html(
						sprintf(
							/* translators: 1: critical count, 2: review count, 3: safe count, 4: info count */
							__( 'Scan complete. %1$s critical, %2$s review, %3$s safe, and %4$s informational finding(s).', 'choctaw-wp-security' ),
							number_format_i18n( $critical ),
							number_format_i18n( $review ),
							number_format_i18n( $safe ),
							number_format_i18n( $info )
						)
					);
				} else {
					echo esc_html(
						sprintf(
							/* translators: 1: safe count, 2: info count */
							__( 'Scan complete. No critical or review findings. %1$s safe and %2$s informational item(s) reported.', 'choctaw-wp-security' ),
							number_format_i18n( $safe ),
							number_format_i18n( $info )
						)
					);
				}
				?>
			</p>
		</div>
		<?php if ( empty( $findings ) ) : ?>
			<p><?php esc_html_e( 'No directory browsing findings were returned.', 'choctaw-wp-security' ); ?></p>
			<?php
			return;
		endif;

		$pagination = $this->paginate_report_items( $findings, $this->get_report_page_number( 'cws_directory_browsing' ) );
		?>
		<table class="widefat striped cws-core-checksum-table cws-directory-browsing-table">
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'Risk', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Status', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Server Type', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Path', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Directory Browsing', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Action', 'choctaw-wp-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $pagination['items'] as $index => $finding ) : ?>
					<?php
					if ( ! is_array( $finding ) ) {
						continue;
					}

					$row_id       = 'cws-directory-browsing-fallback-' . (int) $index;
					$risk         = isset( $finding['risk'] ) ? (string) $finding['risk'] : 'info';
					$risk_label   = isset( $finding['risk_label'] ) ? (string) $finding['risk_label'] : $risk;
					$status       = isset( $finding['status'] ) ? (string) $finding['status'] : Choctaw_Wp_Security_Finding_Status_Store::STATUS_NEEDS_REVIEW;
					$status_label = isset( $finding['status_label'] ) ? (string) $finding['status_label'] : Choctaw_Wp_Security_Finding_Status_Store::status_label( $status );
					$path         = isset( $finding['path'] ) ? (string) $finding['path'] : '';
					$info_path    = ! empty( $finding['test_url'] ) ? (string) $finding['test_url'] : $path;
					$browsing     = isset( $finding['browsing'] ) ? (string) $finding['browsing'] : Choctaw_Wp_Security_Directory_Browsing_Scanner::BROWSING_UNKNOWN;
					?>
					<tr>
						<td><?php $this->render_risk_badge( $risk, $risk_label ); ?></td>
						<td><?php $this->render_status_badge( $status, $status_label ); ?></td>
						<td><?php echo esc_html( isset( $finding['server_type_label'] ) ? (string) $finding['server_type_label'] : '—' ); ?></td>
						<td><?php $this->render_file_path( $path ); ?></td>
						<td><?php $this->render_directory_browsing_state( $browsing, isset( $finding['browsing_label'] ) ? (string) $finding['browsing_label'] : '' ); ?></td>
						<td>
							<button type="button" class="cws-report-eye" data-expand-target="<?php echo esc_attr( $row_id ); ?>" aria-expanded="false" aria-label="<?php esc_attr_e( 'View details', 'choctaw-wp-security' ); ?>">
								<span class="dashicons dashicons-visibility" aria-hidden="true"></span>
							</button>
						</td>
					</tr>
					<tr class="cws-report-detail-row" id="<?php echo esc_attr( $row_id ); ?>" hidden>
						<td colspan="6">
							<div class="cws-report-detail-grid cws-directory-browsing-detail-grid">
								<div class="cws-directory-browsing-detail-left">
									<div class="cws-directory-browsing-info-panel">
										<h4><?php esc_html_e( 'Info', 'choctaw-wp-security' ); ?></h4>
										<dl>
											<dt><?php esc_html_e( 'Testing Method', 'choctaw-wp-security' ); ?></dt>
											<dd><?php echo esc_html( isset( $finding['testing_method'] ) ? (string) $finding['testing_method'] : '—' ); ?></dd>
											<dt><?php esc_html_e( 'Path', 'choctaw-wp-security' ); ?></dt>
											<dd><?php echo esc_html( '' !== $info_path ? $info_path : '—' ); ?></dd>
										</dl>
									</div>
									<div class="cws-directory-browsing-contents">
										<h4><?php esc_html_e( 'Contents', 'choctaw-wp-security' ); ?></h4>
										<textarea class="cws-file-contents-textarea large-text code" rows="14" readonly><?php echo esc_textarea( $this->with_report_contents_footer( isset( $finding['contents'] ) ? (string) $finding['contents'] : '', ! empty( $finding['contents_truncated'] ) ) ); ?></textarea>
									</div>
								</div>
								<div class="cws-directory-browsing-detail-right">
									<div>
										<h4><?php esc_html_e( 'Why you are seeing this', 'choctaw-wp-security' ); ?></h4>
										<p><?php echo esc_html( isset( $finding['why_seeing_this'] ) ? (string) $finding['why_seeing_this'] : '' ); ?></p>
									</div>
									<div>
										<h4><?php esc_html_e( 'How to proceed', 'choctaw-wp-security' ); ?></h4>
										<p><?php echo esc_html( isset( $finding['how_to_proceed'] ) ? (string) $finding['how_to_proceed'] : '' ); ?></p>
										<?php
										$fingerprint = isset( $finding['fingerprint'] ) ? (string) $finding['fingerprint'] : '';
										if ( '' !== $fingerprint ) {
											$this->render_dismiss_controls( 'directory-browsing', $fingerprint, $status );
										}
										?>
									</div>
								</div>
							</div>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
		$this->render_report_pagination( 'cws_directory_browsing', $pagination, __( 'findings', 'choctaw-wp-security' ) );
	}

	/**
	 * Render Directory Browsing Blocked / Not Blocked / Unknown cell.
	 *
	 * @param string $state Browsing state key.
	 * @param string $label Display label.
	 * @return void
	 */
	private function render_directory_browsing_state( $state, $label = '' ) {
		$state = (string) $state;
		if ( '' === $label ) {
			$label = Choctaw_Wp_Security_Directory_Browsing_Scanner::browsing_label( $state );
		}
		?>
		<span class="cws-browsing-status is-<?php echo esc_attr( $state ); ?>">
			<span class="cws-browsing-status-label"><?php echo esc_html( $label ); ?></span>
		</span>
		<?php
	}

	/**
	 * Render the Disable XML-RPC section description.
	 *
	 * @return void
	 */
	public function render_xmlrpc_section() {
		echo '<div class="cws-section-help-intro">';
		Choctaw_Wp_Security_Admin_Help::render_disclosure_block(
			'xmlrpc-section',
			Choctaw_Wp_Security_Admin_Help_Content::xmlrpc_blocking_detail_html(),
			Choctaw_Wp_Security_Admin_Help_Content::xmlrpc_section_summary(),
			'',
			array( 'summary_class' => 'cws-section-summary' )
		);
		echo '</div>';
	}

	/**
	 * Render the Disable PHP Execution in Uploads section description.
	 *
	 * @return void
	 */
	public function render_uploads_php_section() {
		$lockdown = new Choctaw_Wp_Security_Uploads_Php_Lockdown();
		$server   = $lockdown->get_server_type();
		$detail   = Choctaw_Wp_Security_Uploads_Php_Lockdown::SERVER_NGINX === $server
			? Choctaw_Wp_Security_Admin_Help_Content::uploads_php_lockdown_nginx_detail_html()
			: Choctaw_Wp_Security_Admin_Help_Content::uploads_php_lockdown_apache_detail_html();

		echo '<div class="cws-section-help-intro">';
		Choctaw_Wp_Security_Admin_Help::render_disclosure_block(
			'uploads-php-section',
			$detail,
			Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_summary_html(),
			'',
			array(
				'summary_is_html' => true,
				'summary_class'   => 'cws-section-summary',
			)
		);
		echo '</div>';
	}

	/**
	 * Render the policy section description.
	 *
	 * @return void
	 */
	public function render_policy_section() {
		// Section layout is handled by render_security_feature_field() and render_policy_number_field().
	}

	/**
	 * Render the username discovery section description.
	 *
	 * @return void
	 */
	public function render_username_discovery_section() {
		echo '<div class="cws-section-help-intro">';
		Choctaw_Wp_Security_Admin_Help::render_disclosure_block(
			'username-discovery-section',
			Choctaw_Wp_Security_Admin_Help_Content::username_discovery_section_detail_html(),
			Choctaw_Wp_Security_Admin_Help_Content::username_discovery_section_summary()
		);
		echo '</div>';
	}

	/**
	 * Render the WordPress Tables section description.
	 *
	 * @return void
	 */
	public function render_table_prefix_section() {
		echo '<div class="cws-section-help-intro cws-table-prefix-section-intro">';
		Choctaw_Wp_Security_Admin_Help::render_disclosure_block(
			'table-prefix-section',
			Choctaw_Wp_Security_Admin_Help_Content::table_prefix_section_detail_html(),
			Choctaw_Wp_Security_Admin_Help_Content::table_prefix_section_summary()
		);
		echo '<p class="description">';
		esc_html_e( 'Choose which leftover WordPress install set database scans should use. Auto uses the live WordPress-configured prefix from wp-config.php.', 'choctaw-wp-security' );
		echo '</p>';
		echo '</div>';
	}

	/**
	 * Render the WordPress Tables prefix picker field.
	 *
	 * @param array<string, string> $args Field arguments.
	 * @return void
	 */
	public function render_table_prefix_field( $args ) {
		unset( $args );

		$discovery       = new Choctaw_Wp_Security_Table_Prefix_Discovery();
		$prefixes_meta   = $discovery->get_prefixes_with_metadata();
		$mismatch_warn   = $discovery->get_mismatch_warning( $prefixes_meta );
		$resolved        = $discovery->resolve_configured_tables();
		$selected_prefix = (string) $resolved['prefix'];
		$single_prefix   = 1 === count( $prefixes_meta );
		$field_name      = Choctaw_Wp_Security_Utils::OPTION_KEY . '[database_scan_table_prefix]';

		if ( '' !== $mismatch_warn ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html( $mismatch_warn ) . '</p></div>';
		}

		if ( empty( $prefixes_meta ) ) {
			echo '<p>' . esc_html__( 'No WordPress table prefixes were discovered in this database.', 'choctaw-wp-security' ) . '</p>';
			return;
		}
		?>
		<div class="cws-database-scan-table-picker<?php echo $single_prefix ? ' is-disabled' : ''; ?>">
			<?php if ( $single_prefix ) : ?>
				<p class="description">
					<?php esc_html_e( 'Only one WordPress table prefix was found. Scans use this prefix automatically.', 'choctaw-wp-security' ); ?>
				</p>
			<?php endif; ?>
			<table class="widefat striped cws-database-scan-table-picker-table">
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'Select', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Prefix', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Status', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Rows', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'siteurl Host', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Last Updated', 'choctaw-wp-security' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $prefixes_meta as $prefix_meta ) : ?>
						<?php
						$prefix      = isset( $prefix_meta['prefix'] ) ? (string) $prefix_meta['prefix'] : '';
						$is_selected = $prefix === $selected_prefix;
						$badges      = array();

						if ( ! empty( $prefix_meta['is_wordpress_configured'] ) ) {
							$badges[] = __( 'WordPress configured', 'choctaw-wp-security' );
						}

						if ( ! empty( $prefix_meta['url_matches_site'] ) ) {
							$badges[] = __( 'URL matches site', 'choctaw-wp-security' );
						}
						?>
						<tr>
							<td>
								<input
									type="radio"
									name="<?php echo esc_attr( $field_name ); ?>"
									id="<?php echo esc_attr( 'database_scan_table_prefix_' . $prefix ); ?>"
									value="<?php echo esc_attr( $prefix ); ?>"
									<?php checked( $is_selected ); ?>
									<?php disabled( $single_prefix ); ?>
								/>
							</td>
							<td><code class="cws-file-path"><?php echo esc_html( $prefix ); ?></code></td>
							<td><?php echo esc_html( implode( '; ', $badges ) ); ?></td>
							<td><?php echo esc_html( number_format_i18n( isset( $prefix_meta['row_count'] ) ? (int) $prefix_meta['row_count'] : 0 ) ); ?></td>
							<td><?php echo esc_html( isset( $prefix_meta['siteurl_host'] ) ? (string) $prefix_meta['siteurl_host'] : '' ); ?></td>
							<td><?php echo esc_html( $this->format_database_scan_table_timestamp( isset( $prefix_meta['update_time'] ) ? (string) $prefix_meta['update_time'] : '' ) ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
			<?php if ( $single_prefix ) : ?>
				<input type="hidden" name="<?php echo esc_attr( $field_name ); ?>" value="<?php echo esc_attr( $selected_prefix ); ?>" />
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Resolve options/posts/users tables from the Settings prefix selection.
	 *
	 * @return array{prefix: string, is_override: bool, options_table: string, posts_table: string, users_table: string}
	 */
	private function get_resolved_scan_tables() {
		$discovery = new Choctaw_Wp_Security_Table_Prefix_Discovery();

		return $discovery->resolve_configured_tables();
	}

	/**
	 * Render a consolidated security feature checkbox row.
	 *
	 * @param array<string, string> $args Field arguments.
	 * @return void
	 */
	public function render_security_feature_field( $args ) {
		$options = Choctaw_Wp_Security_Utils::get_options();
		$option  = $args['option'];
		$value   = ! empty( $options[ $option ] );
		$help_id = ! empty( $args['help_id'] ) ? (string) $args['help_id'] : '';
		?>
		<div class="cws-feature-setting">
			<div class="cws-feature-setting-header">
				<input
					type="checkbox"
					id="<?php echo esc_attr( $args['label_for'] ); ?>"
					name="<?php echo esc_attr( Choctaw_Wp_Security_Utils::OPTION_KEY . '[' . $option . ']' ); ?>"
					value="1"
					<?php checked( $value ); ?>
				/>
				<label class="cws-feature-setting-title" for="<?php echo esc_attr( $args['label_for'] ); ?>">
					<?php echo esc_html( $args['label'] ); ?>
				</label>
				<?php if ( '' !== $help_id && Choctaw_Wp_Security_Admin_Help::shows_recommendation( $help_id ) ) : ?>
					<span class="cws-help-recommendation"><?php echo esc_html( Choctaw_Wp_Security_Admin_Help::get_recommendation_label() ); ?></span>
				<?php endif; ?>
			</div>
			<?php
			if ( '' !== $help_id ) {
				Choctaw_Wp_Security_Admin_Help::render_feature_summary( $help_id );
			}
			?>
		</div>
		<?php
	}

	/**
	 * Render the XML-RPC blocking checkbox with live Active/Disabled status.
	 *
	 * @param array<string, string> $args Field arguments.
	 * @return void
	 */
	public function render_xmlrpc_blocking_field( $args ) {
		$options = Choctaw_Wp_Security_Utils::get_options();
		$option  = $args['option'];
		$enabled = ! empty( $options[ $option ] );
		$variant = $enabled ? 'is-active' : 'is-disabled-risk';
		$icon    = $enabled ? 'dashicons-yes-alt' : 'dashicons-warning';
		$title   = $enabled
			? Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_active_status_label()
			: Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_disabled_status_label();
		?>
		<div class="cws-feature-setting cws-xmlrpc-setting">
			<div class="cws-feature-setting-header">
				<input
					type="checkbox"
					id="<?php echo esc_attr( $args['label_for'] ); ?>"
					name="<?php echo esc_attr( Choctaw_Wp_Security_Utils::OPTION_KEY . '[' . $option . ']' ); ?>"
					value="1"
					<?php checked( $enabled ); ?>
				/>
				<label class="cws-feature-setting-title" for="<?php echo esc_attr( $args['label_for'] ); ?>">
					<?php echo esc_html( $args['label'] ); ?>
				</label>
				<?php if ( Choctaw_Wp_Security_Admin_Help::shows_recommendation( 'xmlrpc_blocking' ) ) : ?>
					<span class="cws-help-recommendation"><?php echo esc_html( Choctaw_Wp_Security_Admin_Help::get_recommendation_label() ); ?></span>
				<?php endif; ?>
			</div>
			<?php
			$this->render_feature_status_banner(
				$variant,
				$icon,
				$title,
				'',
				array(
					'id'             => 'cws-xmlrpc-status',
					'live'           => true,
					'checkbox_id'    => 'xmlrpc_blocking_enabled',
					'active_label'   => Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_active_status_label(),
					'disabled_label' => Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_disabled_status_label(),
				)
			);
			?>
		</div>
		<?php
	}

	/**
	 * Render a checkbox settings field.
	 *
	 * @param array<string, string> $args Field arguments.
	 * @return void
	 */
	public function render_checkbox_field( $args ) {
		$options = Choctaw_Wp_Security_Utils::get_options();
		$option  = $args['option'];
		$value   = ! empty( $options[ $option ] );
		?>
		<label for="<?php echo esc_attr( $args['label_for'] ); ?>">
			<input
				type="checkbox"
				id="<?php echo esc_attr( $args['label_for'] ); ?>"
				name="<?php echo esc_attr( Choctaw_Wp_Security_Utils::OPTION_KEY . '[' . $option . ']' ); ?>"
				value="1"
				<?php checked( $value ); ?>
			/>
			<?php echo esc_html( $args['label'] ); ?>
		</label>
		<?php
		if ( ! empty( $args['help_id'] ) ) {
			Choctaw_Wp_Security_Admin_Help::render_field_description( (string) $args['help_id'] );
		} elseif ( ! empty( $args['description_html'] ) ) {
			echo '<p class="description">' . wp_kses( $args['description_html'], $this->get_allowed_file_path_markup() ) . '</p>';
		} elseif ( ! empty( $args['description'] ) ) {
			echo '<p class="description">' . esc_html( $args['description'] ) . '</p>';
		}
	}

	/**
	 * Render the uploads PHP lockdown field with server-aware UI.
	 *
	 * @param array<string, string> $args Field arguments.
	 * @return void
	 */
	public function render_uploads_lockdown_field( $args ) {
		$lockdown = new Choctaw_Wp_Security_Uploads_Php_Lockdown();
		$server   = $lockdown->get_server_type();

		if ( Choctaw_Wp_Security_Uploads_Php_Lockdown::SERVER_NGINX === $server ) {
			$this->render_nginx_uploads_lockdown_setting( $args );
			return;
		}

		if ( Choctaw_Wp_Security_Uploads_Php_Lockdown::SERVER_UNKNOWN === $server ) {
			$this->render_unknown_uploads_lockdown_setting( $args );
			return;
		}

		$this->render_apache_uploads_lockdown_setting( $args );
	}

	/**
	 * Render uploads lockdown for Apache and LiteSpeed servers.
	 *
	 * @param array<string, string> $args Field arguments.
	 * @return void
	 */
	private function render_apache_uploads_lockdown_setting( $args ) {
		$options = Choctaw_Wp_Security_Utils::get_options();
		$option  = $args['option'];
		$enabled = ! empty( $options[ $option ] );
		$variant = $enabled ? 'is-active' : 'is-disabled-risk';
		$icon    = $enabled ? 'dashicons-yes-alt' : 'dashicons-warning';
		$title   = $enabled
			? Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_active_status_label()
			: Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_disabled_status_label();
		?>
		<div class="cws-feature-setting cws-uploads-lockdown-setting">
			<div class="cws-uploads-lockdown-control">
				<div class="cws-feature-setting-header">
					<input
						type="checkbox"
						id="<?php echo esc_attr( $args['label_for'] ); ?>"
						name="<?php echo esc_attr( Choctaw_Wp_Security_Utils::OPTION_KEY . '[' . $option . ']' ); ?>"
						value="1"
						<?php checked( $enabled ); ?>
					/>
					<label class="cws-feature-setting-title" for="<?php echo esc_attr( $args['label_for'] ); ?>">
						<?php echo esc_html( Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_enable_label() ); ?>
					</label>
				</div>
			</div>
			<?php
			$this->render_feature_status_banner(
				$variant,
				$icon,
				$title,
				'',
				array(
					'id'             => 'cws-uploads-lockdown-apache-status',
					'live'           => true,
					'checkbox_id'    => 'uploads_php_lockdown_enabled',
					'active_label'   => Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_active_status_label(),
					'disabled_label' => Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_disabled_status_label(),
				)
			);
			?>
			<p class="description cws-uploads-lockdown-subtext">
				<?php echo wp_kses( Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_htaccess_subtext_html(), Choctaw_Wp_Security_Admin_Help::get_allowed_detail_markup() ); ?>
			</p>
		</div>
		<?php
	}

	/**
	 * Render uploads lockdown for Nginx servers.
	 *
	 * @param array<string, string> $args Field arguments.
	 * @return void
	 */
	private function render_nginx_uploads_lockdown_setting( $args ) {
		unset( $args );
		?>
		<div class="cws-feature-setting cws-uploads-lockdown-setting">
			<?php
			$this->render_feature_status_banner(
				'is-manual',
				'dashicons-admin-generic',
				Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_manual_config_title()
			);
			?>
			<p class="description cws-uploads-lockdown-explanation">
				<?php echo esc_html( Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_nginx_explanation() ); ?>
			</p>
			<div class="cws-uploads-lockdown-actions">
				<h4 class="cws-uploads-lockdown-action-heading">
					<?php echo esc_html( Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_nginx_action_heading() ); ?>
				</h4>
				<p class="description cws-uploads-lockdown-action-instruction">
					<?php echo esc_html( Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_nginx_action_instruction() ); ?>
				</p>
				<?php
				Choctaw_Wp_Security_Admin_Help::render_guidance_disclosure(
					'uploads-php-lockdown-nginx-snippet',
					'uploads_php_nginx',
					Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_nginx_snippet_toggle_label()
				);
				?>
			</div>
		</div>
		<?php
	}

	/**
	 * Render uploads lockdown when the server type cannot be confirmed.
	 *
	 * @param array<string, string> $args Field arguments.
	 * @return void
	 */
	private function render_unknown_uploads_lockdown_setting( $args ) {
		$options = Choctaw_Wp_Security_Utils::get_options();
		$option  = $args['option'];
		$enabled = ! empty( $options[ $option ] );
		?>
		<div class="cws-feature-setting cws-uploads-lockdown-setting">
			<?php
			$this->render_feature_status_banner(
				'is-unknown',
				'dashicons-warning',
				Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_unknown_banner_title(),
				Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_unknown_banner_subtitle()
			);
			?>
			<p class="description cws-uploads-lockdown-explanation">
				<?php echo wp_kses( Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_unknown_guidance_html(), Choctaw_Wp_Security_Admin_Help::get_allowed_detail_markup() ); ?>
			</p>
			<div class="cws-uploads-lockdown-control">
				<div class="cws-feature-setting-header">
					<input
						type="checkbox"
						id="<?php echo esc_attr( $args['label_for'] ); ?>"
						name="<?php echo esc_attr( Choctaw_Wp_Security_Utils::OPTION_KEY . '[' . $option . ']' ); ?>"
						value="1"
						<?php checked( $enabled ); ?>
					/>
					<label class="cws-feature-setting-title" for="<?php echo esc_attr( $args['label_for'] ); ?>">
						<?php echo esc_html( Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_enable_label() ); ?>
					</label>
				</div>
				<p class="description cws-uploads-lockdown-subtext">
					<?php echo wp_kses( Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_htaccess_subtext_html(), Choctaw_Wp_Security_Admin_Help::get_allowed_detail_markup() ); ?>
				</p>
			</div>
			<div class="cws-feature-setting-notes">
				<?php
				Choctaw_Wp_Security_Admin_Help::render_guidance_disclosure(
					'uploads-php-lockdown-unknown-snippet',
					'uploads_php_nginx',
					Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_nginx_snippet_toggle_label()
				);
				?>
			</div>
		</div>
		<?php
	}

	/**
	 * Render a shared Active/Disabled/Manual status banner.
	 *
	 * @param string               $variant  CSS variant class (is-active, is-disabled-risk, is-manual, is-unknown).
	 * @param string               $icon     Dashicon class name.
	 * @param string               $title    Banner title.
	 * @param string               $subtitle Optional subtitle.
	 * @param array<string, mixed> $args     Optional live-toggle attributes.
	 * @return void
	 */
	private function render_feature_status_banner( $variant, $icon, $title, $subtitle = '', array $args = array() ) {
		$classes = array( 'cws-server-status-banner', sanitize_html_class( (string) $variant ) );
		$id_attr = ! empty( $args['id'] ) ? (string) $args['id'] : '';
		$live    = ! empty( $args['live'] );
		?>
		<div
			class="<?php echo esc_attr( implode( ' ', $classes ) ); ?>"
			<?php if ( '' !== $id_attr ) : ?>
				id="<?php echo esc_attr( $id_attr ); ?>"
			<?php endif; ?>
			<?php if ( $live ) : ?>
				data-cws-feature-status="1"
				data-checkbox-id="<?php echo esc_attr( (string) $args['checkbox_id'] ); ?>"
				data-active-label="<?php echo esc_attr( (string) $args['active_label'] ); ?>"
				data-disabled-label="<?php echo esc_attr( (string) $args['disabled_label'] ); ?>"
				data-active-icon="dashicons-yes-alt"
				data-disabled-icon="dashicons-warning"
			<?php endif; ?>
		>
			<span class="dashicons <?php echo esc_attr( $icon ); ?>" aria-hidden="true"></span>
			<div class="cws-server-status-banner-text">
				<p class="cws-server-status-banner-title"><?php echo esc_html( $title ); ?></p>
				<?php if ( '' !== trim( (string) $subtitle ) ) : ?>
					<p class="cws-server-status-banner-subtitle"><?php echo esc_html( $subtitle ); ?></p>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Render an indented numeric field within the login rate limit policy group.
	 *
	 * @param array<string, int|string> $args Field arguments.
	 * @return void
	 */
	public function render_policy_number_field( $args ) {
		$options            = Choctaw_Wp_Security_Utils::get_options();
		$option             = $args['option'];
		$help_id            = ! empty( $args['help_id'] ) ? (string) $args['help_id'] : '';
		$rate_limit_enabled = ! empty( $options['login_rate_limit_enabled'] );
		$field_class        = 'cws-rate-limit-policy-field';

		if ( ! $rate_limit_enabled ) {
			$field_class .= ' cws-rate-limit-policy-field-is-disabled';
		}
		?>
		<div class="<?php echo esc_attr( $field_class ); ?>">
			<div class="cws-rate-limit-policy-field-header">
				<label class="cws-rate-limit-policy-label" for="<?php echo esc_attr( $args['label_for'] ); ?>">
					<?php echo esc_html( $args['label'] ); ?>
				</label>
				<input
					type="number"
					class="small-text"
					id="<?php echo esc_attr( $args['label_for'] ); ?>"
					name="<?php echo esc_attr( Choctaw_Wp_Security_Utils::OPTION_KEY . '[' . $option . ']' ); ?>"
					value="<?php echo esc_attr( (string) $options[ $option ] ); ?>"
					min="<?php echo esc_attr( (string) $args['min'] ); ?>"
					max="<?php echo esc_attr( (string) $args['max'] ); ?>"
					step="<?php echo esc_attr( (string) $args['step'] ); ?>"
					<?php disabled( ! $rate_limit_enabled ); ?>
				/>
			</div>
			<?php
			if ( '' !== $help_id ) {
				Choctaw_Wp_Security_Admin_Help::render_feature_summary( $help_id, array( 'summary_class' => 'cws-rate-limit-policy-summary' ) );
			}
			?>
		</div>
		<?php
	}

	/**
	 * Render a numeric settings field.
	 *
	 * @param array<string, int|string> $args Field arguments.
	 * @return void
	 */
	public function render_number_field( $args ) {
		$options = Choctaw_Wp_Security_Utils::get_options();
		$option  = $args['option'];
		?>
		<input
			type="number"
			class="small-text"
			id="<?php echo esc_attr( $args['label_for'] ); ?>"
			name="<?php echo esc_attr( Choctaw_Wp_Security_Utils::OPTION_KEY . '[' . $option . ']' ); ?>"
			value="<?php echo esc_attr( (string) $options[ $option ] ); ?>"
			min="<?php echo esc_attr( (string) $args['min'] ); ?>"
			max="<?php echo esc_attr( (string) $args['max'] ); ?>"
			step="<?php echo esc_attr( (string) $args['step'] ); ?>"
		/>
		<?php
		if ( ! empty( $args['help_id'] ) ) {
			Choctaw_Wp_Security_Admin_Help::render_field_description( (string) $args['help_id'] );
		} elseif ( ! empty( $args['description'] ) ) {
			echo '<p class="description">' . esc_html( $args['description'] ) . '</p>';
		}
	}

	/**
	 * Convert a boolean status into a readable label.
	 *
	 * @param bool $enabled Whether the feature is enabled.
	 * @return string
	 */
	private function status_label( $enabled ) {
		return $enabled
			? __( 'Enabled', 'choctaw-wp-security' )
			: __( 'Disabled', 'choctaw-wp-security' );
	}

	/**
	 * Build the status label for username discovery protections.
	 *
	 * @param array<string, mixed> $options Plugin options.
	 * @return string
	 */
	private function username_discovery_status_label( $options ) {
		$keys = array(
			'block_user_rest_api_enabled',
			'block_author_query_enabled',
			'block_author_archives_enabled',
			'normalize_login_errors_enabled',
		);

		$enabled_count = 0;

		foreach ( $keys as $key ) {
			if ( ! empty( $options[ $key ] ) ) {
				++$enabled_count;
			}
		}

		$total = count( $keys );

		if ( 0 === $enabled_count ) {
			return __( 'Disabled', 'choctaw-wp-security' );
		}

		if ( $enabled_count === $total ) {
			return __( 'Enabled (4/4)', 'choctaw-wp-security' );
		}

		return sprintf(
			/* translators: 1: enabled count, 2: total count */
			__( 'Partial (%1$d/%2$d)', 'choctaw-wp-security' ),
			$enabled_count,
			$total
		);
	}

	/**
	 * Retrieve modification details for stable WordPress files commonly targeted by attackers.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private function get_core_file_changes() {
		$changes = array();

		foreach ( $this->get_monitored_core_file_map() as $label => $path ) {
			$meta = Choctaw_Wp_Security_Utils::get_file_preview_meta( $path );

			$changes[] = array(
				'label'           => $label,
				'checksum_path'   => $label,
				'modified'        => $this->format_file_modified_time( $path ),
				'modified_label'  => $meta['modified_label'],
				'size_label'      => $meta['size_label'],
				'permissions'     => $meta['permissions'],
				'owner'           => $meta['owner'],
				'contents'        => $meta['contents'],
				'contents_truncated' => ! empty( $meta['contents_truncated'] ),
			);
		}

		return $changes;
	}

	/**
	 * Map monitored core file labels to absolute paths.
	 *
	 * @return array<string, string>
	 */
	private function get_monitored_core_file_map() {
		return array(
			'wp-config.php'                     => $this->get_wp_config_path(),
			'.htaccess'                         => ABSPATH . '.htaccess',
			'index.php'                         => ABSPATH . 'index.php',
			'wp-login.php'                      => ABSPATH . 'wp-login.php',
			'xmlrpc.php'                        => ABSPATH . 'xmlrpc.php',
			'wp-cron.php'                       => ABSPATH . 'wp-cron.php',
			'wp-load.php'                       => ABSPATH . 'wp-load.php',
			'wp-settings.php'                   => ABSPATH . 'wp-settings.php',
			'wp-blog-header.php'                => ABSPATH . 'wp-blog-header.php',
			'wp-admin/admin.php'                => ABSPATH . 'wp-admin/admin.php',
			'wp-admin/includes/file.php'        => ABSPATH . 'wp-admin/includes/file.php',
			'wp-admin/includes/plugin.php'      => ABSPATH . 'wp-admin/includes/plugin.php',
			'wp-admin/includes/update.php'      => ABSPATH . 'wp-admin/includes/update.php',
			'wp-includes/load.php'              => ABSPATH . WPINC . '/load.php',
			'wp-includes/plugin.php'            => ABSPATH . WPINC . '/plugin.php',
			'wp-includes/pluggable.php'         => ABSPATH . WPINC . '/pluggable.php',
			'wp-includes/functions.php'         => ABSPATH . WPINC . '/functions.php',
			'wp-includes/default-filters.php'   => ABSPATH . WPINC . '/default-filters.php',
			'wp-includes/class-wp-hook.php'     => ABSPATH . WPINC . '/class-wp-hook.php',
			'wp-includes/version.php'           => ABSPATH . WPINC . '/version.php',
		);
	}

	/**
	 * Relative paths used for Recent File Changes checksum verification.
	 *
	 * @return array<int, string>
	 */
	private function get_core_file_change_checksum_paths() {
		return array_keys( $this->get_monitored_core_file_map() );
	}

	/**
	 * Locate wp-config.php, including the supported parent-directory location.
	 *
	 * @return string
	 */
	private function get_wp_config_path() {
		$root_config   = ABSPATH . 'wp-config.php';
		$parent_config = dirname( ABSPATH ) . '/wp-config.php';

		if ( file_exists( $root_config ) ) {
			return $root_config;
		}

		return $parent_config;
	}

	/**
	 * Format a file modification timestamp for display.
	 *
	 * @param string $path File path.
	 * @return string
	 */
	private function format_file_modified_time( $path ) {
		if ( '' === $path || ! file_exists( $path ) ) {
			return __( 'File not found', 'choctaw-wp-security' );
		}

		$modified = filemtime( $path );

		if ( false === $modified ) {
			return __( 'Unavailable', 'choctaw-wp-security' );
		}

		return $this->format_timestamp( $modified );
	}

	/**
	 * Format a path relative to the WordPress root when possible.
	 *
	 * @param string $path File path.
	 * @return string
	 */
	private function format_display_path( $path ) {
		$normalized_path = wp_normalize_path( $path );
		$root            = trailingslashit( wp_normalize_path( ABSPATH ) );

		if ( 0 === strpos( $normalized_path, $root ) ) {
			return ltrim( substr( $normalized_path, strlen( $root ) ), '/' );
		}

		return $normalized_path;
	}

	/**
	 * Derive the WordPress root-relative directory path for a core file.
	 *
	 * Root-level files return "/". Nested files return the directory path with a trailing slash.
	 *
	 * @param string $relative_path WordPress-relative file path.
	 * @return string
	 */
	private function get_core_file_directory_path( $relative_path ) {
		$relative_path = wp_normalize_path( (string) $relative_path );
		$directory     = dirname( $relative_path );

		if ( '.' === $directory ) {
			return '/';
		}

		return trailingslashit( $directory );
	}

	/**
	 * Derive the filename portion of a WordPress root-relative core file path.
	 *
	 * @param string $relative_path WordPress-relative file path.
	 * @return string
	 */
	private function get_core_file_basename( $relative_path ) {
		return basename( wp_normalize_path( (string) $relative_path ) );
	}

	/**
	 * Render a file or folder path in monospace.
	 *
	 * @param string $path Path to display.
	 * @return void
	 */
	private function render_file_path( $path ) {
		echo '<code class="cws-file-path">' . esc_html( (string) $path ) . '</code>';
	}

	/**
	 * Allowed HTML for status notes that include file path markup.
	 *
	 * @return array<string, array<string, bool>>
	 */
	private function get_allowed_file_path_markup() {
		return array(
			'code' => array(
				'class' => true,
			),
		);
	}

	/**
	 * Build a public URL for a display path relative to the WordPress root.
	 *
	 * @param string $path Display path.
	 * @return string
	 */
	private function get_public_url_for_display_path( $path ) {
		return trailingslashit( site_url( ltrim( $path, '/' ) ) );
	}

	/**
	 * Format a lockout timestamp for display.
	 *
	 * @param int $timestamp Unix timestamp.
	 * @return string
	 */
	private function format_scope( $scope ) {
		if ( 'ip' === $scope ) {
			return __( 'IP only', 'choctaw-wp-security' );
		}

		if ( 'ip_user' === $scope ) {
			return __( 'IP + username', 'choctaw-wp-security' );
		}

		return '-';
	}

	/**
	 * Format a lockout timestamp for display.
	 *
	 * @param int $timestamp Unix timestamp.
	 * @return string
	 */
	private function format_timestamp( $timestamp ) {
		if ( $timestamp <= 0 ) {
			return '-';
		}

		return wp_date(
			get_option( 'date_format' ) . ' ' . get_option( 'time_format' ),
			$timestamp
		);
	}

	/**
	 * Handle a manual users table load request.
	 *
	 * @return void
	 */
	public function handle_users_table_load() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			return;
		}

		if ( empty( $_POST['choctaw_wp_security_users_table_load'] ) ) {
			return;
		}

		check_admin_referer( 'choctaw_wp_security_users_table_form' );

		$resolved    = $this->get_resolved_scan_tables();
		$users_table = $resolved['users_table'];
		$discovery   = new Choctaw_Wp_Security_Users_Table_Discovery();

		$reader = new Choctaw_Wp_Security_Users_Table_Reader( $discovery );
		$result = $reader->fetch_users( $users_table );

		$this->save_report_result(
			$this->get_users_table_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_USERS_TABLE_RESULT,
			$result
		);

		wp_safe_redirect(
			$this->get_scans_page_url(
				'wp-users',
				array(
					'users_table_load' => '1',
				)
			)
		);
		exit;
	}

	/**
	 * Handle an AJAX users table load request.
	 *
	 * @return void
	 */
	public function ajax_users_table_load() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to load users tables.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_users_table_ajax', 'nonce' );

		$resolved    = $this->get_resolved_scan_tables();
		$users_table = $resolved['users_table'];
		$discovery   = new Choctaw_Wp_Security_Users_Table_Discovery();

		$reader = new Choctaw_Wp_Security_Users_Table_Reader( $discovery );
		$result = $reader->fetch_users( $users_table );

		if ( empty( $result['success'] ) ) {
			wp_send_json_error(
				array(
					'message' => isset( $result['message'] ) ? (string) $result['message'] : __( 'The users table could not be loaded.', 'choctaw-wp-security' ),
				),
				400
			);
		}

		$result = $this->save_report_result(
			$this->get_users_table_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_USERS_TABLE_RESULT,
			$result
		);

		wp_send_json_success(
			array(
				'result' => $result,
			)
		);
	}

	/**
	 * Handle an AJAX user activity load request.
	 *
	 * @return void
	 */
	public function ajax_user_activity_load() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to load user activity.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_users_table_ajax', 'nonce' );

		$resolved    = $this->get_resolved_scan_tables();
		$users_table = $resolved['users_table'];
		$user_id     = isset( $_POST['user_id'] ) ? (int) wp_unslash( $_POST['user_id'] ) : 0;
		$discovery   = new Choctaw_Wp_Security_Users_Table_Discovery();
		$reader      = new Choctaw_Wp_Security_User_Activity_Reader( $discovery );
		$result      = $reader->fetch_user_activity( $users_table, $user_id );

		if ( empty( $result['success'] ) ) {
			wp_send_json_error(
				array(
					'message' => isset( $result['message'] ) ? (string) $result['message'] : __( 'User activity could not be loaded.', 'choctaw-wp-security' ),
				),
				400
			);
		}

		wp_send_json_success( $result );
	}

	/**
	 * Handle an AJAX user usermeta load request.
	 *
	 * @return void
	 */
	public function ajax_user_usermeta_load() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to load usermeta.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_users_table_ajax', 'nonce' );

		$resolved    = $this->get_resolved_scan_tables();
		$users_table = $resolved['users_table'];
		$user_id     = isset( $_POST['user_id'] ) ? (int) wp_unslash( $_POST['user_id'] ) : 0;
		$discovery   = new Choctaw_Wp_Security_Users_Table_Discovery();
		$reader      = new Choctaw_Wp_Security_User_Usermeta_Reader( $discovery );
		$result      = $reader->fetch_user_usermeta( $users_table, $user_id );

		if ( empty( $result['success'] ) ) {
			wp_send_json_error(
				array(
					'message' => isset( $result['message'] ) ? (string) $result['message'] : __( 'Usermeta could not be loaded.', 'choctaw-wp-security' ),
				),
				400
			);
		}

		wp_send_json_success( $result );
	}

	/**
	 * Handle an AJAX user file activity load request.
	 *
	 * @return void
	 */
	public function ajax_user_file_activity_load() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to load file activity.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_users_table_ajax', 'nonce' );

		$resolved    = $this->get_resolved_scan_tables();
		$users_table = $resolved['users_table'];
		$user_id     = isset( $_POST['user_id'] ) ? (int) wp_unslash( $_POST['user_id'] ) : 0;
		$discovery   = new Choctaw_Wp_Security_Users_Table_Discovery();
		$scanner     = new Choctaw_Wp_Security_User_File_Activity_Scanner( $discovery );
		$result      = $scanner->scan_user_file_activity( $users_table, $user_id );

		if ( empty( $result['success'] ) ) {
			wp_send_json_error(
				array(
					'message' => isset( $result['message'] ) ? (string) $result['message'] : __( 'File activity could not be loaded.', 'choctaw-wp-security' ),
				),
				400
			);
		}

		wp_send_json_success( $result );
	}

	/**
	 * Verify checksum status for the Recent File Changes table via AJAX.
	 *
	 * @return void
	 */
	public function ajax_file_changes_checksum() {
		if ( ! Sassh_Capabilities::current_user_can_manage() ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to verify core checksums.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_file_changes_checksum_ajax', 'nonce' );

		$scanner = new Choctaw_Wp_Security_Core_Checksum_Scanner();
		$result  = $scanner->verify_paths( $this->get_core_file_change_checksum_paths() );

		wp_send_json_success( $result );
	}

	/**
	 * Render the wp_users section.
	 *
	 * @return void
	 */
	private function render_users_table_section() {
		$result          = false;
		$results_missing = false;

		if ( isset( $_GET['users_table_load'] ) ) {
			$result = $this->load_report_result(
				$this->get_users_table_result_transient_key(),
				Choctaw_Wp_Security_Utils::USER_META_USERS_TABLE_RESULT
			);

			if ( false === $result ) {
				$results_missing = true;
			}
		}

		$resolved = $this->get_resolved_scan_tables();
		?>
		<div class="cws-admin-tab-panel">
			<div class="cws-report-section">
				<h2><?php esc_html_e( 'wp_users', 'choctaw-wp-security' ); ?></h2>
				<?php Choctaw_Wp_Security_Admin_Help::render_tab_intro( 'users_table' ); ?>

				<p class="description">
					<?php
					echo esc_html(
						sprintf(
							/* translators: %s: users table name */
							__( 'Loading table: %s', 'choctaw-wp-security' ),
							(string) $resolved['users_table']
						)
					);
					?>
				</p>

				<?php if ( $results_missing ) : ?>
					<div class="notice notice-warning">
						<p><?php esc_html_e( 'The previous users table results are no longer available. Click Load Users to generate a fresh report.', 'choctaw-wp-security' ); ?></p>
					</div>
				<?php endif; ?>

				<form method="post" class="cws-database-scan-form" id="cws-users-table-form">
					<?php wp_nonce_field( 'choctaw_wp_security_users_table_form' ); ?>
					<input type="hidden" name="cws_tab" value="wp-users" />

					<?php submit_button( __( 'Load Users', 'choctaw-wp-security' ), 'secondary', 'choctaw_wp_security_users_table_load', false ); ?>
				</form>

				<div id="cws-users-table-js-notices" aria-live="polite"></div>
				<div id="cws-users-table-js-results"></div>

				<div id="cws-users-table-fallback-results">
					<?php if ( is_array( $result ) ) : ?>
						<?php $this->render_users_table_results( $result ); ?>
					<?php endif; ?>
				</div>

				<div
					id="cws-users-table-help-boxes"
					class="cws-help-boxes cws-users-table-help-boxes"
					<?php echo is_array( $result ) ? '' : ' hidden'; ?>
				>
					<?php Choctaw_Wp_Security_Admin_Help::render_guidance_box( 'remove_user_account' ); ?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render users table results for the PHP fallback.
	 *
	 * @param array<string, mixed> $result Users table payload.
	 * @return void
	 */
	private function render_users_table_results( array $result ) {
		$users = isset( $result['users'] ) && is_array( $result['users'] ) ? $result['users'] : array();

		if ( empty( $users ) ) {
			?>
			<p><?php esc_html_e( 'No users were found in the selected table.', 'choctaw-wp-security' ); ?></p>
			<?php
			return;
		}

		$pagination = $this->paginate_report_items( $users, $this->get_report_page_number( 'cws_users_table' ) );
		?>
		<table class="widefat striped cws-core-checksum-table">
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'ID', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'user_login', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'user_email', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'user_registered', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'user_status', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'display_name', 'choctaw-wp-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $pagination['items'] as $user ) : ?>
					<tr>
						<td><?php echo esc_html( isset( $user['ID'] ) ? (string) $user['ID'] : '' ); ?></td>
						<td><code class="cws-file-path"><?php echo esc_html( isset( $user['user_login'] ) ? (string) $user['user_login'] : '' ); ?></code></td>
						<td><?php echo esc_html( isset( $user['user_email'] ) ? (string) $user['user_email'] : '' ); ?></td>
						<td><?php echo esc_html( isset( $user['user_registered'] ) ? (string) $user['user_registered'] : '' ); ?></td>
						<td><?php echo esc_html( isset( $user['user_status'] ) ? (string) $user['user_status'] : '' ); ?></td>
						<td><?php echo esc_html( isset( $user['display_name'] ) ? (string) $user['display_name'] : '' ); ?></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
		$this->render_report_pagination( 'cws_users_table', $pagination, __( 'users', 'choctaw-wp-security' ) );
	}

}
