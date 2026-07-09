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
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'load-settings_page_choctaw-wp-security', array( $this, 'handle_core_checksum_scan' ) );
		add_action( 'load-settings_page_choctaw-wp-security', array( $this, 'handle_component_scan' ) );
		add_action( 'load-settings_page_choctaw-wp-security', array( $this, 'handle_exposed_folders_scan' ) );
		add_action( 'load-settings_page_choctaw-wp-security', array( $this, 'handle_database_scan' ) );
		add_action( 'load-settings_page_choctaw-wp-security', array( $this, 'handle_database_scan_baseline_reset' ) );
		add_action( 'load-settings_page_choctaw-wp-security', array( $this, 'handle_posts_scan' ) );
		add_action( 'load-settings_page_choctaw-wp-security', array( $this, 'handle_posts_scan_baseline_reset' ) );
		add_action( 'load-settings_page_choctaw-wp-security', array( $this, 'handle_users_table_load' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
		add_action( 'wp_ajax_choctaw_wp_security_database_scan', array( $this, 'ajax_database_scan' ) );
		add_action( 'wp_ajax_choctaw_wp_security_database_scan_baseline_reset', array( $this, 'ajax_database_scan_baseline_reset' ) );
		add_action( 'wp_ajax_choctaw_wp_security_posts_scan', array( $this, 'ajax_posts_scan' ) );
		add_action( 'wp_ajax_choctaw_wp_security_posts_scan_baseline_reset', array( $this, 'ajax_posts_scan_baseline_reset' ) );
		add_action( 'wp_ajax_choctaw_wp_security_users_table_load', array( $this, 'ajax_users_table_load' ) );
		add_action( 'wp_ajax_choctaw_wp_security_user_activity_load', array( $this, 'ajax_user_activity_load' ) );
		add_action( 'wp_ajax_choctaw_wp_security_user_usermeta_load', array( $this, 'ajax_user_usermeta_load' ) );
		add_action( 'wp_ajax_choctaw_wp_security_user_file_activity_load', array( $this, 'ajax_user_file_activity_load' ) );
		add_action( 'wp_ajax_choctaw_wp_security_file_changes_checksum', array( $this, 'ajax_file_changes_checksum' ) );
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
			'choctaw_wp_security_features',
			__( 'Security Features', 'choctaw-wp-security' ),
			array( $this, 'render_features_section' ),
			'choctaw-wp-security'
		);

		add_settings_field(
			'xmlrpc_blocking_enabled',
			'',
			array( $this, 'render_security_feature_field' ),
			'choctaw-wp-security',
			'choctaw_wp_security_features',
			array(
				'label_for' => 'xmlrpc_blocking_enabled',
				'option'    => 'xmlrpc_blocking_enabled',
				'label'     => __( 'Block XML-RPC requests', 'choctaw-wp-security' ),
				'help_id'   => 'xmlrpc_blocking',
			)
		);

		add_settings_field(
			'uploads_php_lockdown_enabled',
			'',
			array( $this, 'render_uploads_lockdown_field' ),
			'choctaw-wp-security',
			'choctaw_wp_security_features',
			array(
				'label_for' => 'uploads_php_lockdown_enabled',
				'option'    => 'uploads_php_lockdown_enabled',
				'label'     => __( 'Disable PHP execution in uploads', 'choctaw-wp-security' ),
				'help_id'   => 'uploads_php_lockdown',
			)
		);

		add_settings_section(
			'choctaw_wp_security_username_discovery',
			__( 'Reduce Username Exposure', 'choctaw-wp-security' ),
			array( $this, 'render_username_discovery_section' ),
			'choctaw-wp-security'
		);

		add_settings_field(
			'block_user_rest_api_enabled',
			'',
			array( $this, 'render_security_feature_field' ),
			'choctaw-wp-security',
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
			'choctaw-wp-security',
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
			'choctaw-wp-security',
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
			'choctaw-wp-security',
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
			'choctaw-wp-security'
		);

		add_settings_field(
			'login_rate_limit_enabled',
			'',
			array( $this, 'render_security_feature_field' ),
			'choctaw-wp-security',
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
			'choctaw-wp-security',
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
			'choctaw-wp-security',
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
			'choctaw-wp-security',
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
	}

	/**
	 * Add the settings page under Settings.
	 *
	 * @return void
	 */
	public function register_menu() {
		add_options_page(
			__( 'Choctaw WP Security', 'choctaw-wp-security' ),
			__( 'Choctaw WP Security', 'choctaw-wp-security' ),
			'manage_options',
			'choctaw-wp-security',
			array( $this, 'render_page' )
		);
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

		$sanitized = array(
			'xmlrpc_blocking_enabled'      => ! empty( $input['xmlrpc_blocking_enabled'] ),
			'login_rate_limit_enabled'     => ! empty( $input['login_rate_limit_enabled'] ),
			'uploads_php_lockdown_enabled' => $this->sanitize_uploads_php_lockdown_enabled( $input ),
			'block_user_rest_api_enabled' => ! empty( $input['block_user_rest_api_enabled'] ),
			'block_author_query_enabled' => ! empty( $input['block_author_query_enabled'] ),
			'block_author_archives_enabled' => ! empty( $input['block_author_archives_enabled'] ),
			'normalize_login_errors_enabled' => ! empty( $input['normalize_login_errors_enabled'] ),
			'allowed_failed_attempts'        => $this->clamp_int( $input, 'allowed_failed_attempts', 1, 100, (int) $existing['allowed_failed_attempts'] ),
			'failure_window_minutes'   => $this->clamp_int( $input, 'failure_window_minutes', 1, 1440, (int) $existing['failure_window_minutes'] ),
			'lockout_duration_minutes' => $this->clamp_int( $input, 'lockout_duration_minutes', 1, 1440, (int) $existing['lockout_duration_minutes'] ),
		);

		return $sanitized;
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
	 * Render the settings page.
	 *
	 * @return void
	 */
	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$active_tab = $this->get_active_admin_tab();
		?>
		<div class="wrap">
			<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>

			<?php
			$this->render_admin_tabs( $active_tab );
			$this->render_active_admin_tab( $active_tab );
			?>
		</div>
		<?php
	}

	/**
	 * Get admin page tabs.
	 *
	 * @return array<string, string>
	 */
	private function get_admin_tabs() {
		return array(
			'main'                 => __( 'Main', 'choctaw-wp-security' ),
			'file-changes-uploads' => __( 'Files Changes/Uploads', 'choctaw-wp-security' ),
			'exposed-folders'      => __( 'Directory Browsing', 'choctaw-wp-security' ),
			'verify-checksums'     => __( 'Verify Checksums', 'choctaw-wp-security' ),
			'component-scan'       => __( 'Vulnerabilities', 'choctaw-wp-security' ),
			'database-scan'        => __( 'wp_options', 'choctaw-wp-security' ),
			'wp-posts'             => __( 'wp_posts', 'choctaw-wp-security' ),
			'wp-users'             => __( 'wp_users', 'choctaw-wp-security' ),
			'about-this-plugin'    => __( 'About This Plugin', 'choctaw-wp-security' ),
		);
	}

	/**
	 * Get the current admin tab, defaulting to Main.
	 *
	 * @return string
	 */
	private function get_active_admin_tab() {
		$tabs = $this->get_admin_tabs();
		$tab  = isset( $_GET['cws_tab'] ) ? sanitize_key( wp_unslash( $_GET['cws_tab'] ) ) : 'main';

		if ( ! isset( $tabs[ $tab ] ) ) {
			return 'main';
		}

		return $tab;
	}

	/**
	 * Render WordPress admin tabs.
	 *
	 * @param string $active_tab Active tab key.
	 * @return void
	 */
	private function render_admin_tabs( $active_tab ) {
		?>
		<nav class="nav-tab-wrapper cws-admin-tabs" aria-label="<?php esc_attr_e( 'Choctaw WP Security sections', 'choctaw-wp-security' ); ?>">
			<?php foreach ( $this->get_admin_tabs() as $tab_key => $tab_label ) : ?>
				<a
					class="nav-tab <?php echo esc_attr( $active_tab === $tab_key ? 'nav-tab-active' : '' ); ?>"
					href="<?php echo esc_url( add_query_arg( array( 'page' => 'choctaw-wp-security', 'cws_tab' => $tab_key ), admin_url( 'options-general.php' ) ) ); ?>"
					<?php echo $active_tab === $tab_key ? 'aria-current="page"' : ''; ?>
				>
					<?php echo esc_html( $tab_label ); ?>
				</a>
			<?php endforeach; ?>
		</nav>
		<?php
	}

	/**
	 * Render the active admin tab.
	 *
	 * @param string $active_tab Active tab key.
	 * @return void
	 */
	private function render_active_admin_tab( $active_tab ) {
		if ( 'file-changes-uploads' === $active_tab ) {
			$this->render_file_changes_uploads_tab();
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

		if ( 'wp-posts' === $active_tab ) {
			$this->render_posts_scan_section();
			return;
		}

		if ( 'wp-users' === $active_tab ) {
			$this->render_users_table_section();
			return;
		}

		if ( 'about-this-plugin' === $active_tab ) {
			$this->render_about_this_plugin_tab();
			return;
		}

		$this->render_main_tab();
	}

	/**
	 * Render the Main tab.
	 *
	 * @return void
	 */
	private function render_main_tab() {
		$options        = Choctaw_Wp_Security_Utils::get_options();
		$events         = Choctaw_Wp_Security_Utils::get_lockout_log();
		$uploads_status = ( new Choctaw_Wp_Security_Uploads_Php_Lockdown() )->get_status();
		?>
		<div class="cws-admin-tab-panel">
			<form action="options.php" method="post">
				<?php
				settings_fields( 'choctaw_wp_security' );
				do_settings_sections( 'choctaw-wp-security' );
				submit_button();
				?>
			</form>

			<hr>

			<?php
			$this->render_status_section( $options, $uploads_status );
			$this->render_recent_lockouts_section( $events );
			?>
		</div>
		<?php
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
		?>
		<div class="cws-report-section">
		<h2><?php esc_html_e( 'Recent Lockouts', 'choctaw-wp-security' ); ?></h2>
		<?php Choctaw_Wp_Security_Admin_Help::render_field_description( 'recent_lockouts' ); ?>
		<table class="widefat striped">
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'Time', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'IP Address', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Attempted Username', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Scope', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Lockout Duration', 'choctaw-wp-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $events as $event ) : ?>
					<tr>
						<td><?php echo esc_html( $this->format_timestamp( isset( $event['timestamp'] ) ? (int) $event['timestamp'] : 0 ) ); ?></td>
						<td><?php echo esc_html( isset( $event['ip'] ) ? (string) $event['ip'] : '' ); ?></td>
						<td><?php echo esc_html( isset( $event['username'] ) ? (string) $event['username'] : '' ); ?></td>
						<td><?php echo esc_html( $this->format_scope( isset( $event['scope'] ) ? (string) $event['scope'] : '' ) ); ?></td>
						<td>
							<?php
							$duration_seconds = isset( $event['lockout_duration'] ) ? (int) $event['lockout_duration'] : 0;
							echo esc_html(
								sprintf(
									/* translators: %d: lockout duration in minutes */
									__( '%d minutes', 'choctaw-wp-security' ),
									max( 1, (int) round( $duration_seconds / MINUTE_IN_SECONDS ) )
								)
							);
							?>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		</div>
		<?php
	}

	/**
	 * Render the Files Changes/Uploads tab.
	 *
	 * @return void
	 */
	private function render_file_changes_uploads_tab() {
		$core_file_changes      = $this->get_core_file_changes();
		$content_php_files      = $this->get_content_php_files();
		$uploads_plugin_folders = $this->get_non_media_uploads_folders();
		?>
		<div class="cws-admin-tab-panel">

			<div class="cws-report-section">
			<h2><?php esc_html_e( 'Recent File Changes', 'choctaw-wp-security' ); ?></h2>
			<?php Choctaw_Wp_Security_Admin_Help::render_field_description( 'file_changes_recent' ); ?>
			<table id="cws-core-file-changes-table" class="widefat striped">
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'File', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Last Modified', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Checksum Verified', 'choctaw-wp-security' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $core_file_changes as $file_change ) : ?>
						<?php
						$file_help_id    = Choctaw_Wp_Security_Admin_Help_Content::get_core_file_change_help_id( $file_change['checksum_path'] );
						$file_help_detail = Choctaw_Wp_Security_Admin_Help_Content::get_core_file_change_detail( $file_change['checksum_path'] );
						?>
						<tr data-checksum-path="<?php echo esc_attr( $file_change['checksum_path'] ); ?>">
							<td class="cws-core-file-cell">
								<div class="cws-core-file-cell-inner">
									<?php $this->render_file_path( $file_change['label'] ); ?>
									<?php if ( '' !== $file_help_detail ) : ?>
										<?php Choctaw_Wp_Security_Admin_Help::render_disclosure_toggle( $file_help_id ); ?>
									<?php endif; ?>
								</div>
							</td>
							<td><?php echo esc_html( $file_change['modified'] ); ?></td>
							<td class="cws-checksum-verified-cell">
								<span class="cws-checksum-status is-pending"><?php esc_html_e( 'Checking…', 'choctaw-wp-security' ); ?></span>
							</td>
						</tr>
						<?php if ( '' !== $file_help_detail ) : ?>
							<?php Choctaw_Wp_Security_Admin_Help::render_table_disclosure_row( $file_help_id, $file_help_detail, 3 ); ?>
						<?php endif; ?>
					<?php endforeach; ?>
				</tbody>
			</table>
			<div id="cws-core-file-changes-checksum-status" class="cws-checksum-scan-status" hidden></div>
			</div>

			<div class="cws-report-section">
			<h2><?php esc_html_e( 'PHP Files in Uploads and Must-Use Plugins', 'choctaw-wp-security' ); ?></h2>
			<?php Choctaw_Wp_Security_Admin_Help::render_field_description( 'file_changes_php_uploads' ); ?>
			<?php if ( ! empty( $content_php_files ) ) : ?>
				<?php
				$php_files_pagination = $this->paginate_report_items(
					$content_php_files,
					$this->get_report_page_number( 'cws_php_files' )
				);
				?>
				<table class="widefat striped">
					<thead>
						<tr>
							<th scope="col"><?php esc_html_e( 'Location', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'File', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Last Modified', 'choctaw-wp-security' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $php_files_pagination['items'] as $php_file ) : ?>
							<tr>
								<td><?php echo esc_html( $php_file['location'] ); ?></td>
								<td><?php $this->render_file_path( $php_file['path'] ); ?></td>
								<td><?php echo esc_html( $php_file['modified'] ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
				<?php $this->render_report_pagination( 'cws_php_files', $php_files_pagination ); ?>
			<?php else : ?>
				<p>
					<?php esc_html_e( 'No PHP files were found in the', 'choctaw-wp-security' ); ?>
					<?php $this->render_file_path( 'uploads' ); ?>
					<?php esc_html_e( 'or', 'choctaw-wp-security' ); ?>
					<?php $this->render_file_path( 'mu-plugins' ); ?>
					<?php esc_html_e( 'folders.', 'choctaw-wp-security' ); ?>
				</p>
			<?php endif; ?>
			</div>

			<div class="cws-report-section">
			<h2><?php esc_html_e( 'Plugins Found Inside Uploads Folder', 'choctaw-wp-security' ); ?></h2>
			<?php Choctaw_Wp_Security_Admin_Help::render_field_description( 'file_changes_uploads_plugins' ); ?>
			<p><strong><?php esc_html_e( 'IMPORTANT: Do not delete folders from active plugins, only those from plugins that were uninstalled.', 'choctaw-wp-security' ); ?></strong></p>
			<?php if ( ! empty( $uploads_plugin_folders['errors'] ) ) : ?>
				<?php foreach ( $uploads_plugin_folders['errors'] as $error_message ) : ?>
					<p class="description"><?php echo esc_html( $error_message ); ?></p>
				<?php endforeach; ?>
			<?php endif; ?>
			<?php if ( ! empty( $uploads_plugin_folders['folders'] ) ) : ?>
				<?php
				$uploads_folders_pagination = $this->paginate_report_items(
					$uploads_plugin_folders['folders'],
					$this->get_report_page_number( 'cws_uploads_folders' )
				);
				?>
				<table class="widefat striped">
					<thead>
						<tr>
							<th scope="col"><?php esc_html_e( 'Folder', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Last Modified', 'choctaw-wp-security' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $uploads_folders_pagination['items'] as $folder ) : ?>
							<tr>
								<td><?php $this->render_file_path( $folder['path'] ); ?></td>
								<td><?php echo esc_html( $folder['modified'] ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
				<?php $this->render_report_pagination( 'cws_uploads_folders', $uploads_folders_pagination ); ?>
			<?php elseif ( empty( $uploads_plugin_folders['errors'] ) ) : ?>
				<p>
					<?php esc_html_e( 'No non-Media Library folders were found in the', 'choctaw-wp-security' ); ?>
					<?php $this->render_file_path( 'uploads' ); ?>
					<?php esc_html_e( 'directory.', 'choctaw-wp-security' ); ?>
				</p>
			<?php endif; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the About This Plugin tab.
	 *
	 * @return void
	 */
	private function render_about_this_plugin_tab() {
		?>
		<div class="cws-admin-tab-panel cws-about-plugin">
			<div class="cws-about-logo-wrap">
				<?php $this->render_choctaw_websites_logo(); ?>
			</div>

			<div class="cws-about-content">
				<h2><?php esc_html_e( 'About This Plugin', 'choctaw-wp-security' ); ?></h2>
				<p><?php esc_html_e( 'Choctaw WP Security is 100% free to use.', 'choctaw-wp-security' ); ?></p>

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
					<?php esc_html_e( 'Choctaw WP Security was created by Steve Johnson, Lead Developer, Choctaw Websites.', 'choctaw-wp-security' ); ?>
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
	 * Render the Choctaw Websites logo.
	 *
	 * @return void
	 */
	private function render_choctaw_websites_logo() {
		?>
		<svg class="cws-about-logo" preserveAspectRatio="xMidYMid meet" viewBox="0 0 300.000000 301.000000" height="301.000000pt" width="300.000000pt" xmlns="http://www.w3.org/2000/svg" version="1.0" role="img" aria-label="<?php esc_attr_e( 'Choctaw Websites logo', 'choctaw-wp-security' ); ?>">
			<g stroke="none" transform="translate(0.000000,301.000000) scale(0.100000,-0.100000)">
				<path d="M567 2949 c-178 -26 -361 -158 -441 -318 -76 -149 -71 -77 -71 -1131 l0 -945 28 -80 c38 -107 83 -179 159 -251 74 -71 131 -106 231 -143 l72 -26 926 -3 c1040 -3 1008 -5 1157 68 110 55 202 146 261 258 73 141 71 108 71 1123 0 612 -4 925 -11 965 -20 111 -98 250 -183 327 -60 55 -150 108 -230 135 l-81 27 -915 1 c-503 1 -941 -2 -973 -7z m2003 -136 c130 -64 222 -164 272 -298 21 -57 22 -77 26 -414 l3 -354 -218 -219 -218 -218 -232 232 -233 233 -233 -233 -232 -232 -233 232 -232 233 -238 -238 -237 -237 -208 208 -208 208 1 362 c0 330 2 367 20 425 48 156 179 287 338 338 54 17 110 18 1017 16 l960 -2 85 -42z m-154 -1922 l-455 -455 -216 222 c-141 144 -224 222 -237 222 -13 0 -105 -82 -250 -222 l-229 -222 -439 439 -439 439 -3 133 c-2 73 -1 133 2 133 3 0 202 -197 442 -437 l437 -437 198 191 c109 105 216 210 238 233 l40 41 227 -233 227 -233 453 453 453 452 3 -132 3 -132 -455 -455z m444 -321 c-16 -95 -71 -201 -138 -268 -66 -66 -121 -101 -212 -134 l-65 -23 -895 -3 c-605 -2 -918 1 -965 8 -186 29 -339 157 -413 344 -13 34 -17 99 -22 364 -3 177 -3 322 0 322 3 0 201 -196 442 -437 l436 -436 239 232 238 232 227 -233 228 -233 452 453 453 452 3 -287 c2 -177 -1 -313 -8 -353z"></path>
				<path d="M1376 2655 c-130 -36 -260 -131 -323 -236 -101 -168 -77 -379 56 -501 95 -87 211 -128 364 -128 102 0 178 19 271 68 79 41 196 150 196 181 0 41 -23 31 -95 -38 -54 -53 -94 -81 -152 -108 -71 -33 -88 -37 -185 -41 -88 -4 -118 -1 -175 16 -230 70 -320 278 -210 485 95 180 361 272 563 195 58 -22 109 -71 120 -114 18 -73 -68 -172 -170 -195 -70 -15 -121 -5 -159 32 -24 24 -28 35 -23 60 3 17 15 42 26 56 36 46 21 93 -30 93 -32 0 -52 -20 -79 -80 -54 -120 9 -231 148 -261 140 -30 307 47 368 169 12 25 18 59 18 104 0 58 -4 72 -30 109 -73 103 -182 150 -349 148 -55 0 -123 -7 -150 -14z"></path>
			</g>
		</svg>
		<?php
	}

	/**
	 * Handle a manual core checksum scan request.
	 *
	 * @return void
	 */
	public function handle_core_checksum_scan() {
		if ( ! current_user_can( 'manage_options' ) ) {
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
			add_query_arg(
				array(
					'page'              => 'choctaw-wp-security',
					'cws_tab'           => 'verify-checksums',
					'core_checksum_run' => '1',
				),
				admin_url( 'options-general.php' )
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
		if ( ! current_user_can( 'manage_options' ) ) {
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
			add_query_arg(
				array(
					'page'               => 'choctaw-wp-security',
					'cws_tab'            => 'component-scan',
					'component_scan_run' => '1',
				),
				admin_url( 'options-general.php' )
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
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		if ( empty( $_POST['choctaw_wp_security_exposed_folders_scan'] ) ) {
			return;
		}

		check_admin_referer( 'choctaw_wp_security_exposed_folders_scan' );

		$result = $this->scan_exposed_folders();

		$this->save_report_result(
			$this->get_exposed_folders_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_EXPOSED_FOLDERS_RESULT,
			$result
		);

		wp_safe_redirect(
			add_query_arg(
				array(
					'page'                => 'choctaw-wp-security',
					'cws_tab'             => 'exposed-folders',
					'exposed_folders_run' => '1',
				),
				admin_url( 'options-general.php' )
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
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		if ( empty( $_POST['choctaw_wp_security_database_scan'] ) ) {
			return;
		}

		check_admin_referer( 'choctaw_wp_security_database_scan_form' );

		$requested_table = isset( $_POST['database_scan_options_table'] ) ? wp_unslash( $_POST['database_scan_options_table'] ) : '';
		$discovery       = new Choctaw_Wp_Security_Options_Table_Discovery();
		$options_table   = $discovery->resolve_scan_table( (string) $requested_table );

		Choctaw_Wp_Security_Utils::save_database_scan_options_table( $options_table );

		$scanner = new Choctaw_Wp_Security_Options_Table_Scanner( $options_table );
		$result  = $scanner->scan();

		$this->save_report_result(
			$this->get_database_scan_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_DATABASE_SCAN_RESULT,
			$result
		);

		wp_safe_redirect(
			add_query_arg(
				array(
					'page'              => 'choctaw-wp-security',
					'cws_tab'           => 'database-scan',
					'database_scan_run' => '1',
				),
				admin_url( 'options-general.php' )
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
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		if ( empty( $_POST['choctaw_wp_security_database_scan_baseline_reset'] ) ) {
			return;
		}

		check_admin_referer( 'choctaw_wp_security_database_scan_form' );

		$requested_table = isset( $_POST['database_scan_options_table'] ) ? wp_unslash( $_POST['database_scan_options_table'] ) : '';
		$discovery       = new Choctaw_Wp_Security_Options_Table_Discovery();
		$options_table   = $discovery->resolve_scan_table( (string) $requested_table );

		Choctaw_Wp_Security_Utils::save_database_scan_options_table( $options_table );

		Choctaw_Wp_Security_Options_Table_Scanner::reset_baseline( $options_table );

		wp_safe_redirect(
			add_query_arg(
				array(
					'page'                        => 'choctaw-wp-security',
					'cws_tab'                     => 'database-scan',
					'database_scan_baseline_reset' => '1',
				),
				admin_url( 'options-general.php' )
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
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to run database scans.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_database_scan_ajax', 'nonce' );

		$requested_table = isset( $_POST['database_scan_options_table'] ) ? wp_unslash( $_POST['database_scan_options_table'] ) : '';
		$discovery       = new Choctaw_Wp_Security_Options_Table_Discovery();
		$options_table   = $discovery->resolve_scan_table( (string) $requested_table );

		Choctaw_Wp_Security_Utils::save_database_scan_options_table( $options_table );

		$scanner = new Choctaw_Wp_Security_Options_Table_Scanner( $options_table );
		$result  = $scanner->scan();

		$this->save_report_result(
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
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to reset the database scan baseline.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_database_scan_ajax', 'nonce' );

		$requested_table = isset( $_POST['database_scan_options_table'] ) ? wp_unslash( $_POST['database_scan_options_table'] ) : '';
		$discovery       = new Choctaw_Wp_Security_Options_Table_Discovery();
		$options_table   = $discovery->resolve_scan_table( (string) $requested_table );

		Choctaw_Wp_Security_Utils::save_database_scan_options_table( $options_table );
		Choctaw_Wp_Security_Options_Table_Scanner::reset_baseline( $options_table );

		wp_send_json_success(
			array(
				'message'       => __( 'The database scan baseline was reset for the selected options table.', 'choctaw-wp-security' ),
				'options_table' => $options_table,
			)
		);
	}

	/**
	 * Handle a manual wp_posts scan request.
	 *
	 * @return void
	 */
	public function handle_posts_scan() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		if ( empty( $_POST['choctaw_wp_security_posts_scan'] ) ) {
			return;
		}

		check_admin_referer( 'choctaw_wp_security_posts_scan_form' );

		$requested_table = isset( $_POST['database_scan_posts_table'] ) ? wp_unslash( $_POST['database_scan_posts_table'] ) : '';
		$discovery       = new Choctaw_Wp_Security_Posts_Table_Discovery();
		$posts_table     = $discovery->resolve_scan_table( (string) $requested_table );

		Choctaw_Wp_Security_Utils::save_database_scan_posts_table( $posts_table );

		$scanner = new Choctaw_Wp_Security_Posts_Table_Scanner( $posts_table );
		$result  = $scanner->scan();

		$this->save_report_result(
			$this->get_posts_scan_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_POSTS_SCAN_RESULT,
			$result
		);

		wp_safe_redirect(
			add_query_arg(
				array(
					'page'           => 'choctaw-wp-security',
					'cws_tab'        => 'wp-posts',
					'posts_scan_run' => '1',
				),
				admin_url( 'options-general.php' )
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
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		if ( empty( $_POST['choctaw_wp_security_posts_scan_baseline_reset'] ) ) {
			return;
		}

		check_admin_referer( 'choctaw_wp_security_posts_scan_form' );

		$requested_table = isset( $_POST['database_scan_posts_table'] ) ? wp_unslash( $_POST['database_scan_posts_table'] ) : '';
		$discovery       = new Choctaw_Wp_Security_Posts_Table_Discovery();
		$posts_table     = $discovery->resolve_scan_table( (string) $requested_table );

		Choctaw_Wp_Security_Utils::save_database_scan_posts_table( $posts_table );

		Choctaw_Wp_Security_Posts_Table_Scanner::reset_baseline( $posts_table );

		wp_safe_redirect(
			add_query_arg(
				array(
					'page'                      => 'choctaw-wp-security',
					'cws_tab'                   => 'wp-posts',
					'posts_scan_baseline_reset' => '1',
				),
				admin_url( 'options-general.php' )
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
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to run posts scans.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_posts_scan_ajax', 'nonce' );

		$requested_table = isset( $_POST['database_scan_posts_table'] ) ? wp_unslash( $_POST['database_scan_posts_table'] ) : '';
		$discovery       = new Choctaw_Wp_Security_Posts_Table_Discovery();
		$posts_table     = $discovery->resolve_scan_table( (string) $requested_table );

		Choctaw_Wp_Security_Utils::save_database_scan_posts_table( $posts_table );

		$scanner = new Choctaw_Wp_Security_Posts_Table_Scanner( $posts_table );
		$result  = $scanner->scan();

		$this->save_report_result(
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
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to reset the posts scan baseline.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_posts_scan_ajax', 'nonce' );

		$requested_table = isset( $_POST['database_scan_posts_table'] ) ? wp_unslash( $_POST['database_scan_posts_table'] ) : '';
		$discovery       = new Choctaw_Wp_Security_Posts_Table_Discovery();
		$posts_table     = $discovery->resolve_scan_table( (string) $requested_table );

		Choctaw_Wp_Security_Utils::save_database_scan_posts_table( $posts_table );
		Choctaw_Wp_Security_Posts_Table_Scanner::reset_baseline( $posts_table );

		wp_send_json_success(
			array(
				'message'     => __( 'The posts scan baseline was reset for the selected posts table.', 'choctaw-wp-security' ),
				'posts_table' => $posts_table,
			)
		);
	}

	/**
	 * Enqueue admin assets for the settings page.
	 *
	 * @param string $hook_suffix Current admin page hook suffix.
	 * @return void
	 */
	public function enqueue_admin_assets( $hook_suffix ) {
		if ( 'settings_page_choctaw-wp-security' !== $hook_suffix ) {
			return;
		}

		wp_enqueue_style(
			'choctaw-wp-security-admin',
			CHOCTAW_WP_SECURITY_URL . 'assets/css/admin-core-checksum.css',
			array(),
			CHOCTAW_WP_SECURITY_VERSION
		);

		Choctaw_Wp_Security_Admin_Help::enqueue_assets();

		if ( 'database-scan' === $this->get_active_admin_tab() ) {
			wp_enqueue_script(
				'choctaw-wp-security-database-scan',
				CHOCTAW_WP_SECURITY_URL . 'assets/js/admin-database-scan.js',
				array( 'choctaw-wp-security-admin-help' ),
				CHOCTAW_WP_SECURITY_VERSION,
				true
			);

			wp_localize_script(
				'choctaw-wp-security-database-scan',
				'choctawWpSecurityDatabaseScan',
				array(
					'ajaxUrl'       => admin_url( 'admin-ajax.php' ),
					'nonce'         => wp_create_nonce( 'choctaw_wp_security_database_scan_ajax' ),
					'pageSize'      => $this->get_report_page_size(),
					'initialResult' => $this->load_report_result(
						$this->get_database_scan_result_transient_key(),
						Choctaw_Wp_Security_Utils::USER_META_DATABASE_SCAN_RESULT
					),
					'strings'       => array(
						'scanButton'         => __( 'Scan Now', 'choctaw-wp-security' ),
						'rescanButton'       => __( 'Rescan Selected Table', 'choctaw-wp-security' ),
						'scanning'           => __( 'Scanning selected options table...', 'choctaw-wp-security' ),
						'resettingBaseline'  => __( 'Resetting baseline...', 'choctaw-wp-security' ),
						'scanError'          => __( 'The database scan could not be completed.', 'choctaw-wp-security' ),
						'resetError'         => __( 'The database scan baseline could not be reset.', 'choctaw-wp-security' ),
						'noFindings'         => __( 'No findings in this section.', 'choctaw-wp-security' ),
						'pageOf'             => __( 'Page %1$s of %2$s', 'choctaw-wp-security' ),
						'items'              => __( '%s items', 'choctaw-wp-security' ),
						'item'               => __( '%s item', 'choctaw-wp-security' ),
						'sortAscending'      => __( 'Sort ascending', 'choctaw-wp-security' ),
						'sortDescending'     => __( 'Sort descending', 'choctaw-wp-security' ),
						'scannedTable'       => __( 'Scanned table: %s', 'choctaw-wp-security' ),
						'configuredTable'    => __( 'WordPress configured table: %s', 'choctaw-wp-security' ),
						'scanCompleteIssues' => __( 'Scan complete. %1$s critical, %2$s warning, and %3$s informational findings worth investigating.', 'choctaw-wp-security' ),
						'scanCompleteClean'  => __( 'Scan complete. No critical or warning findings. %s informational item(s) reported.', 'choctaw-wp-security' ),
						'incomplete'         => __( 'The scan stopped early because it reached its time budget. Review the partial results below and run the scan again if needed.', 'choctaw-wp-security' ),
						'severity'           => __( 'Severity', 'choctaw-wp-security' ),
						'optionId'           => __( 'Option ID', 'choctaw-wp-security' ),
						'option'             => __( 'Option', 'choctaw-wp-security' ),
						'size'               => __( 'Size', 'choctaw-wp-security' ),
						'detail'             => __( 'Detail', 'choctaw-wp-security' ),
						'excerpt'            => __( 'Excerpt', 'choctaw-wp-security' ),
						'firstPage'          => __( 'First page', 'choctaw-wp-security' ),
						'previousPage'       => __( 'Previous page', 'choctaw-wp-security' ),
						'nextPage'           => __( 'Next page', 'choctaw-wp-security' ),
						'lastPage'           => __( 'Last page', 'choctaw-wp-security' ),
						'whyThisMatters'     => Choctaw_Wp_Security_Admin_Help::get_toggle_label(),
					),
				)
			);
		}

		if ( 'wp-posts' === $this->get_active_admin_tab() ) {
			wp_enqueue_script(
				'choctaw-wp-security-posts-scan',
				CHOCTAW_WP_SECURITY_URL . 'assets/js/admin-posts-scan.js',
				array( 'choctaw-wp-security-admin-help' ),
				CHOCTAW_WP_SECURITY_VERSION,
				true
			);

			wp_localize_script(
				'choctaw-wp-security-posts-scan',
				'choctawWpSecurityPostsScan',
				array(
					'ajaxUrl'       => admin_url( 'admin-ajax.php' ),
					'nonce'         => wp_create_nonce( 'choctaw_wp_security_posts_scan_ajax' ),
					'pageSize'      => $this->get_report_page_size(),
					'initialResult' => $this->load_report_result(
						$this->get_posts_scan_result_transient_key(),
						Choctaw_Wp_Security_Utils::USER_META_POSTS_SCAN_RESULT
					),
					'strings'       => array(
						'scanButton'         => __( 'Scan Now', 'choctaw-wp-security' ),
						'rescanButton'       => __( 'Rescan Selected Table', 'choctaw-wp-security' ),
						'scanning'           => __( 'Scanning selected posts table...', 'choctaw-wp-security' ),
						'resettingBaseline'  => __( 'Resetting baseline...', 'choctaw-wp-security' ),
						'scanError'          => __( 'The posts scan could not be completed.', 'choctaw-wp-security' ),
						'resetError'         => __( 'The posts scan baseline could not be reset.', 'choctaw-wp-security' ),
						'noFindings'         => __( 'No findings in this section.', 'choctaw-wp-security' ),
						'pageOf'             => __( 'Page %1$s of %2$s', 'choctaw-wp-security' ),
						'items'              => __( '%s items', 'choctaw-wp-security' ),
						'item'               => __( '%s item', 'choctaw-wp-security' ),
						'sortAscending'      => __( 'Sort ascending', 'choctaw-wp-security' ),
						'sortDescending'     => __( 'Sort descending', 'choctaw-wp-security' ),
						'scannedTable'       => __( 'Scanned table: %s', 'choctaw-wp-security' ),
						'configuredTable'    => __( 'WordPress configured table: %s', 'choctaw-wp-security' ),
						'scanCompleteIssues' => __( 'Scan complete. %1$s critical, %2$s warning, and %3$s informational findings worth investigating.', 'choctaw-wp-security' ),
						'scanCompleteClean'  => __( 'Scan complete. No critical or warning findings. %s informational item(s) reported.', 'choctaw-wp-security' ),
						'incomplete'         => __( 'The scan stopped early because it reached its time budget. Review the partial results below and run the scan again if needed.', 'choctaw-wp-security' ),
						'severity'           => __( 'Severity', 'choctaw-wp-security' ),
						'postId'             => __( 'Post ID', 'choctaw-wp-security' ),
						'userId'             => __( 'User ID', 'choctaw-wp-security' ),
						'title'              => __( 'Title', 'choctaw-wp-security' ),
						'type'               => __( 'Type', 'choctaw-wp-security' ),
						'status'             => __( 'Status', 'choctaw-wp-security' ),
						'size'               => __( 'Size', 'choctaw-wp-security' ),
						'detail'             => __( 'Detail', 'choctaw-wp-security' ),
						'excerpt'            => __( 'Excerpt', 'choctaw-wp-security' ),
						'firstPage'          => __( 'First page', 'choctaw-wp-security' ),
						'previousPage'       => __( 'Previous page', 'choctaw-wp-security' ),
						'nextPage'           => __( 'Next page', 'choctaw-wp-security' ),
						'lastPage'           => __( 'Last page', 'choctaw-wp-security' ),
						'userIdLabel'        => __( 'User ID %1$s (%2$s)', 'choctaw-wp-security' ),
						'whyThisMatters'     => Choctaw_Wp_Security_Admin_Help::get_toggle_label(),
					),
				)
			);
		}

		if ( 'wp-users' === $this->get_active_admin_tab() ) {
			wp_enqueue_script(
				'choctaw-wp-security-users-table',
				CHOCTAW_WP_SECURITY_URL . 'assets/js/admin-users-table.js',
				array( 'choctaw-wp-security-admin-help' ),
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
						'loadedTable'          => __( 'Loaded table: %s', 'choctaw-wp-security' ),
						'configuredTable'      => __( 'WordPress configured table: %s', 'choctaw-wp-security' ),
						'usersLoaded'          => __( '%s user(s) loaded.', 'choctaw-wp-security' ),
						'pageOf'               => __( 'Page %1$s of %2$s', 'choctaw-wp-security' ),
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
						'actions'              => __( 'Actions', 'choctaw-wp-security' ),
						'activityDate'         => __( 'Date', 'choctaw-wp-security' ),
						'activityLabel'        => __( 'Activity', 'choctaw-wp-security' ),
						'activityType'         => __( 'Type', 'choctaw-wp-security' ),
						'activityTitle'        => __( 'Title', 'choctaw-wp-security' ),
						'activityDetail'       => __( 'Status/Detail', 'choctaw-wp-security' ),
						'firstPage'            => __( 'First page', 'choctaw-wp-security' ),
						'previousPage'         => __( 'Previous page', 'choctaw-wp-security' ),
						'nextPage'             => __( 'Next page', 'choctaw-wp-security' ),
						'lastPage'             => __( 'Last page', 'choctaw-wp-security' ),
					),
				)
			);
		}

		if ( 'file-changes-uploads' === $this->get_active_admin_tab() ) {
			wp_enqueue_script(
				'choctaw-wp-security-file-changes',
				CHOCTAW_WP_SECURITY_URL . 'assets/js/admin-file-changes.js',
				array( 'choctaw-wp-security-admin-help' ),
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
						'checking'        => __( 'Checking…', 'choctaw-wp-security' ),
						'verified'        => __( 'Checksum verified', 'choctaw-wp-security' ),
						'failed'          => __( 'Checksum mismatch', 'choctaw-wp-security' ),
						'missing'         => __( 'File missing', 'choctaw-wp-security' ),
						'notApplicable'   => __( 'Not included in WordPress core checksums', 'choctaw-wp-security' ),
						'unavailable'     => __( 'Checksum unavailable', 'choctaw-wp-security' ),
						'scanError'       => __( 'Unable to verify checksums for these files.', 'choctaw-wp-security' ),
						'notApplicableAbbr' => __( 'N/A', 'choctaw-wp-security' ),
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
	 * Build the transient key used to store the latest posts scan result.
	 *
	 * @return string
	 */
	private function get_posts_scan_result_transient_key() {
		return 'cws_posts_scan_' . get_current_user_id();
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
	 * @param string               $transient_key Transient storage key.
	 * @param string               $user_meta_key User meta storage key.
	 * @param array<string, mixed> $result        Scan result payload.
	 * @return void
	 */
	private function save_report_result( $transient_key, $user_meta_key, array $result ) {
		$user_id = get_current_user_id();

		if ( $user_id <= 0 ) {
			return;
		}

		set_transient( $transient_key, $result, $this->get_report_result_ttl() );
		update_user_meta( $user_id, $user_meta_key, $result );
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

		set_transient( $transient_key, $result, $this->get_report_result_ttl() );

		return $result;
	}

	/**
	 * Render the exposed folders scan section.
	 *
	 * @return void
	 */
	private function render_exposed_folders_section() {
		$result = false;

		if ( isset( $_GET['exposed_folders_run'] ) ) {
			$result = $this->load_report_result(
				$this->get_exposed_folders_result_transient_key(),
				Choctaw_Wp_Security_Utils::USER_META_EXPOSED_FOLDERS_RESULT
			);
		}
		?>
		<div class="cws-admin-tab-panel">
			<div class="cws-report-section">
			<h2><?php esc_html_e( 'Directory Browsing', 'choctaw-wp-security' ); ?></h2>
			<?php Choctaw_Wp_Security_Admin_Help::render_tab_intro( 'exposed_folders' ); ?>

			<form method="post">
				<?php wp_nonce_field( 'choctaw_wp_security_exposed_folders_scan' ); ?>
				<input type="hidden" name="choctaw_wp_security_exposed_folders_scan" value="1" />
				<input type="hidden" name="cws_tab" value="exposed-folders" />
				<?php submit_button( __( 'Scan Now', 'choctaw-wp-security' ), 'secondary', 'submit', false ); ?>
			</form>

			<?php if ( is_array( $result ) ) : ?>
				<?php $this->render_exposed_folders_results( $result ); ?>
			<?php endif; ?>
			</div>

			<?php if ( is_array( $result ) ) : ?>
				<?php $this->render_exposed_folders_guidance(); ?>
			<?php endif; ?>
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
					<?php esc_html_e( 'No known vulnerabilities were found in the scanned active components.', 'choctaw-wp-security' ); ?>
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

			<?php $this->render_component_scan_attribution( isset( $result['api_updated'] ) ? (int) $result['api_updated'] : null ); ?>
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
			<?php else : ?>
				<p class="description">
					<?php esc_html_e( 'No API-recognized active theme was scanned. If your active theme is custom or unlisted, it appears in Unrecognized Components below.', 'choctaw-wp-security' ); ?>
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
			<p class="description">
				<?php esc_html_e( 'These installed plugins and themes are not in the WPVulnerability database, so no CVE report could be generated for them. This does not mean they are unsafe — only that the API has no record for their slug.', 'choctaw-wp-security' ); ?>
			</p>
			<?php $this->render_component_scan_unrecognized_table( $result ); ?>
		</div>

		<?php $this->render_component_scan_about(); ?>
		<?php
	}

	/**
	 * Render the component scan "About this scan" note below report sections.
	 *
	 * @return void
	 */
	private function render_component_scan_about() {
		?>
		<div class="cws-report-section cws-component-scan-report">
			<h3><?php echo esc_html( Choctaw_Wp_Security_Admin_Help::get_scan_about_label() ); ?></h3>
			<p class="description">
				<?php echo esc_html( Choctaw_Wp_Security_Admin_Help_Content::component_scan_about_text() ); ?>
			</p>
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
	 * Render the unrecognized components table.
	 *
	 * @param array<string, mixed> $result Scan result payload.
	 * @return void
	 */
	private function render_component_scan_unrecognized_table( $result ) {
		$unrecognized = isset( $result['unrecognized'] ) && is_array( $result['unrecognized'] ) ? $result['unrecognized'] : array();
		$plugins      = isset( $unrecognized['plugins'] ) && is_array( $unrecognized['plugins'] ) ? $unrecognized['plugins'] : array();
		$themes       = isset( $unrecognized['themes'] ) && is_array( $unrecognized['themes'] ) ? $unrecognized['themes'] : array();

		if ( empty( $plugins ) && empty( $themes ) ) {
			echo '<p>' . esc_html__( 'All installed plugins and themes were recognized by the API.', 'choctaw-wp-security' ) . '</p>';
			return;
		}
		?>
		<table class="widefat striped cws-core-checksum-table">
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'Type', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Name', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Slug', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Version', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Status', 'choctaw-wp-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $plugins as $plugin ) : ?>
					<tr>
						<td><?php esc_html_e( 'Plugin', 'choctaw-wp-security' ); ?></td>
						<td><?php echo esc_html( isset( $plugin['name'] ) ? (string) $plugin['name'] : '' ); ?></td>
						<td><code class="cws-file-path"><?php echo esc_html( isset( $plugin['slug'] ) ? (string) $plugin['slug'] : '' ); ?></code></td>
						<td><?php echo esc_html( isset( $plugin['version'] ) ? (string) $plugin['version'] : '' ); ?></td>
						<td><?php echo ! empty( $plugin['active'] ) ? esc_html__( 'Active', 'choctaw-wp-security' ) : esc_html__( 'Inactive', 'choctaw-wp-security' ); ?></td>
					</tr>
				<?php endforeach; ?>
				<?php foreach ( $themes as $theme ) : ?>
					<tr>
						<td><?php esc_html_e( 'Theme', 'choctaw-wp-security' ); ?></td>
						<td><?php echo esc_html( isset( $theme['name'] ) ? (string) $theme['name'] : '' ); ?></td>
						<td><code class="cws-file-path"><?php echo esc_html( isset( $theme['slug'] ) ? (string) $theme['slug'] : '' ); ?></code></td>
						<td><?php echo esc_html( isset( $theme['version'] ) ? (string) $theme['version'] : '' ); ?></td>
						<td><?php echo ! empty( $theme['active'] ) ? esc_html__( 'Active', 'choctaw-wp-security' ) : esc_html__( 'Inactive', 'choctaw-wp-security' ); ?></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
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
		$discovery      = new Choctaw_Wp_Security_Options_Table_Discovery();
		$selected_table = $discovery->resolve_scan_table( '' );
		$tables_meta    = $discovery->get_tables_with_metadata();
		$mismatch_warn  = $discovery->get_mismatch_warning( $tables_meta );
		?>
		<div class="cws-admin-tab-panel">
			<div class="cws-report-section">
				<h2><?php esc_html_e( 'wp_options', 'choctaw-wp-security' ); ?></h2>
				<?php Choctaw_Wp_Security_Admin_Help::render_tab_intro( 'database_scan' ); ?>

				<?php if ( '' !== $mismatch_warn ) : ?>
					<div class="notice notice-warning">
						<p><?php echo esc_html( $mismatch_warn ); ?></p>
					</div>
				<?php endif; ?>

				<?php
				if ( is_array( $result ) && ! empty( $result['options_table'] ) ) {
					$selected_table = (string) $result['options_table'];
				}
				?>

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

					<?php $this->render_database_scan_table_picker( $tables_meta, $selected_table ); ?>

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
		$summary       = isset( $result['summary'] ) && is_array( $result['summary'] ) ? $result['summary'] : array();
		$critical      = isset( $summary['critical'] ) ? (int) $summary['critical'] : 0;
		$warning       = isset( $summary['warning'] ) ? (int) $summary['warning'] : 0;
		$info          = isset( $summary['info'] ) ? (int) $summary['info'] : 0;
		$has_problems = ( $critical + $warning ) > 0;

		if ( $critical > 0 ) {
			$panel_class = 'cws-core-checksum-results is-error';
		} elseif ( $warning > 0 ) {
			$panel_class = 'cws-core-checksum-results is-warning';
		} else {
			$panel_class = 'cws-core-checksum-results is-success';
		}

		?>
		<div class="<?php echo esc_attr( $panel_class ); ?>">
			<p class="cws-core-checksum-summary">
				<?php if ( $has_problems ) : ?>
					<?php
					echo esc_html(
						sprintf(
							/* translators: 1: critical count, 2: warning count, 3: info count */
							__( 'Scan complete. %1$d critical, %2$d warning, and %3$d informational findings worth investigating.', 'choctaw-wp-security' ),
							$critical,
							$warning,
							$info
						)
					);
					?>
				<?php else : ?>
					<?php
					echo esc_html(
						sprintf(
							/* translators: %d: informational finding count */
							__( 'Scan complete. No critical or warning findings. %d informational item(s) reported.', 'choctaw-wp-security' ),
							$info
						)
					);
					?>
				<?php endif; ?>
			</p>

			<?php if ( ! empty( $result['scan_incomplete'] ) ) : ?>
				<p><?php esc_html_e( 'The scan stopped early because it reached its time budget. Review the partial results below and run the scan again if needed.', 'choctaw-wp-security' ); ?></p>
			<?php endif; ?>

			<?php if ( ! empty( $result['options_table'] ) ) : ?>
				<p>
					<?php
					echo esc_html(
						sprintf(
							/* translators: %s: options table name */
							__( 'Scanned table: %s', 'choctaw-wp-security' ),
							(string) $result['options_table']
						)
					);
					?>
				</p>
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

		<?php
		if ( empty( $result['sections'] ) || ! is_array( $result['sections'] ) ) {
			return;
		}

		foreach ( Choctaw_Wp_Security_Options_Scan_Patterns::$section_keys as $section_key ) {
			if ( empty( $result['sections'][ $section_key ] ) || ! is_array( $result['sections'][ $section_key ] ) ) {
				continue;
			}

			$this->render_database_scan_section_results( $result['sections'][ $section_key ], $section_key );
		}
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
			'page' => 'choctaw-wp-security',
		);

		if ( ! empty( $_GET['cws_tab'] ) ) {
			$args['cws_tab'] = sanitize_key( wp_unslash( $_GET['cws_tab'] ) );
		} elseif ( isset( $_GET['database_scan_run'] ) ) {
			$args['cws_tab'] = 'database-scan';
		} elseif ( isset( $_GET['posts_scan_run'] ) ) {
			$args['cws_tab'] = 'wp-posts';
		} elseif ( isset( $_GET['core_checksum_run'] ) ) {
			$args['cws_tab'] = 'verify-checksums';
		} elseif ( isset( $_GET['component_scan_run'] ) ) {
			$args['cws_tab'] = 'component-scan';
		} elseif ( isset( $_GET['exposed_folders_run'] ) ) {
			$args['cws_tab'] = 'exposed-folders';
		} elseif ( isset( $_GET['users_table_load'] ) ) {
			$args['cws_tab'] = 'wp-users';
		} elseif ( $this->has_report_pagination_request() ) {
			$args['cws_tab'] = $this->get_active_admin_tab();
		}

		foreach ( array( 'database_scan_run', 'database_scan_baseline_reset', 'posts_scan_run', 'posts_scan_baseline_reset', 'core_checksum_run', 'component_scan_run', 'exposed_folders_run', 'users_table_load' ) as $flag ) {
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

		return add_query_arg( $args, admin_url( 'options-general.php' ) );
	}

	/**
	 * Render pagination links below a report table.
	 *
	 * @param string                             $param_name Pagination query parameter.
	 * @param array{items: array<int, mixed>, page: int, total: int, total_pages: int, per_page: int} $pagination Pagination state.
	 * @return void
	 */
	private function render_report_pagination( $param_name, array $pagination ) {
		if ( $pagination['total_pages'] <= 1 ) {
			return;
		}

		$current_page = (int) $pagination['page'];
		$total_pages  = (int) $pagination['total_pages'];
		$total_items  = (int) $pagination['total'];
		?>
		<div class="tablenav bottom cws-report-pagination">
			<div class="tablenav-pages">
				<span class="displaying-num">
					<?php
					echo esc_html(
						sprintf(
							/* translators: %s: number of items */
							_n( '%s item', '%s items', $total_items, 'choctaw-wp-security' ),
							number_format_i18n( $total_items )
						)
					);
					?>
				</span>
				<span class="pagination-links">
					<?php if ( $current_page > 1 ) : ?>
						<a class="first-page button" href="<?php echo esc_url( $this->build_report_page_url( $param_name, 1 ) ); ?>">
							<span class="screen-reader-text"><?php esc_html_e( 'First page', 'choctaw-wp-security' ); ?></span>
							<span aria-hidden="true">&laquo;</span>
						</a>
						<a class="prev-page button" href="<?php echo esc_url( $this->build_report_page_url( $param_name, $current_page - 1 ) ); ?>">
							<span class="screen-reader-text"><?php esc_html_e( 'Previous page', 'choctaw-wp-security' ); ?></span>
							<span aria-hidden="true">&lsaquo;</span>
						</a>
					<?php else : ?>
						<span class="tablenav-pages-navspan button disabled" aria-hidden="true">&laquo;</span>
						<span class="tablenav-pages-navspan button disabled" aria-hidden="true">&lsaquo;</span>
					<?php endif; ?>

					<span class="paging-input">
						<span class="tablenav-paging-text">
							<?php
							echo esc_html(
								sprintf(
									/* translators: 1: current page number, 2: total pages */
									__( 'Page %1$s of %2$s', 'choctaw-wp-security' ),
									number_format_i18n( $current_page ),
									number_format_i18n( $total_pages )
								)
							);
							?>
						</span>
					</span>

					<?php if ( $current_page < $total_pages ) : ?>
						<a class="next-page button" href="<?php echo esc_url( $this->build_report_page_url( $param_name, $current_page + 1 ) ); ?>">
							<span class="screen-reader-text"><?php esc_html_e( 'Next page', 'choctaw-wp-security' ); ?></span>
							<span aria-hidden="true">&rsaquo;</span>
						</a>
						<a class="last-page button" href="<?php echo esc_url( $this->build_report_page_url( $param_name, $total_pages ) ); ?>">
							<span class="screen-reader-text"><?php esc_html_e( 'Last page', 'choctaw-wp-security' ); ?></span>
							<span aria-hidden="true">&raquo;</span>
						</a>
					<?php else : ?>
						<span class="tablenav-pages-navspan button disabled" aria-hidden="true">&rsaquo;</span>
						<span class="tablenav-pages-navspan button disabled" aria-hidden="true">&raquo;</span>
					<?php endif; ?>
				</span>
			</div>
		</div>
		<?php
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

				<?php $this->render_report_pagination( $page_param, $pagination ); ?>
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
	 * Render the options table picker for database scans.
	 *
	 * @param array<int, array<string, mixed>> $tables_metadata Discovered table metadata.
	 * @param string                           $selected_table  Selected table name.
	 * @return void
	 */
	private function render_database_scan_table_picker( array $tables_metadata, $selected_table ) {
		if ( empty( $tables_metadata ) ) {
			?>
			<p><?php esc_html_e( 'No options tables were discovered in this database.', 'choctaw-wp-security' ); ?></p>
			<?php
			return;
		}
		?>
		<div class="cws-database-scan-table-picker">
			<h3><?php esc_html_e( 'Options Table', 'choctaw-wp-security' ); ?></h3>
			<table class="widefat striped cws-database-scan-table-picker-table">
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'Select', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Table', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Status', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Rows', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Data Size', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'siteurl Host', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'home Host', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Last Updated', 'choctaw-wp-security' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $tables_metadata as $table_meta ) : ?>
						<?php
						$table_name = isset( $table_meta['table_name'] ) ? (string) $table_meta['table_name'] : '';
						$is_selected = $table_name === $selected_table;
						$badges = array();

						if ( ! empty( $table_meta['is_wordpress_configured'] ) ) {
							$badges[] = __( 'WordPress configured', 'choctaw-wp-security' );
						}

						if ( ! empty( $table_meta['url_matches_site'] ) ) {
							$badges[] = __( 'URL matches site', 'choctaw-wp-security' );
						}
						?>
						<tr>
							<td>
								<input
									type="radio"
									name="database_scan_options_table"
									class="cws-database-scan-table-choice"
									value="<?php echo esc_attr( $table_name ); ?>"
									<?php checked( $is_selected ); ?>
								/>
							</td>
							<td><code class="cws-file-path"><?php echo esc_html( $table_name ); ?></code></td>
							<td><?php echo esc_html( implode( '; ', $badges ) ); ?></td>
							<td><?php echo esc_html( number_format_i18n( isset( $table_meta['row_count'] ) ? (int) $table_meta['row_count'] : 0 ) ); ?></td>
							<td><?php echo esc_html( size_format( isset( $table_meta['data_size'] ) ? (int) $table_meta['data_size'] : 0 ) ); ?></td>
							<td><?php echo esc_html( isset( $table_meta['siteurl_host'] ) ? (string) $table_meta['siteurl_host'] : '' ); ?></td>
							<td><?php echo esc_html( isset( $table_meta['home_host'] ) ? (string) $table_meta['home_host'] : '' ); ?></td>
							<td><?php echo esc_html( $this->format_database_scan_table_timestamp( isset( $table_meta['update_time'] ) ? (string) $table_meta['update_time'] : '' ) ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
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
		$discovery      = new Choctaw_Wp_Security_Posts_Table_Discovery();
		$selected_table = $discovery->resolve_scan_table( '' );
		$tables_meta    = $discovery->get_tables_with_metadata();
		?>
		<div class="cws-admin-tab-panel">
			<div class="cws-report-section">
				<h2><?php esc_html_e( 'wp_posts', 'choctaw-wp-security' ); ?></h2>
				<?php Choctaw_Wp_Security_Admin_Help::render_tab_intro( 'posts_scan' ); ?>

				<?php
				if ( is_array( $result ) && ! empty( $result['posts_table'] ) ) {
					$selected_table = (string) $result['posts_table'];
				}
				?>

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

					<?php $this->render_posts_scan_table_picker( $tables_meta, $selected_table ); ?>

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
		$summary      = isset( $result['summary'] ) && is_array( $result['summary'] ) ? $result['summary'] : array();
		$critical     = isset( $summary['critical'] ) ? (int) $summary['critical'] : 0;
		$warning      = isset( $summary['warning'] ) ? (int) $summary['warning'] : 0;
		$info         = isset( $summary['info'] ) ? (int) $summary['info'] : 0;
		$has_problems = ( $critical + $warning ) > 0;

		if ( $critical > 0 ) {
			$panel_class = 'cws-core-checksum-results is-error';
		} elseif ( $warning > 0 ) {
			$panel_class = 'cws-core-checksum-results is-warning';
		} else {
			$panel_class = 'cws-core-checksum-results is-success';
		}

		?>
		<div class="<?php echo esc_attr( $panel_class ); ?>">
			<p class="cws-core-checksum-summary">
				<?php if ( $has_problems ) : ?>
					<?php
					echo esc_html(
						sprintf(
							/* translators: 1: critical count, 2: warning count, 3: info count */
							__( 'Scan complete. %1$d critical, %2$d warning, and %3$d informational findings worth investigating.', 'choctaw-wp-security' ),
							$critical,
							$warning,
							$info
						)
					);
					?>
				<?php else : ?>
					<?php
					echo esc_html(
						sprintf(
							/* translators: %d: informational finding count */
							__( 'Scan complete. No critical or warning findings. %d informational item(s) reported.', 'choctaw-wp-security' ),
							$info
						)
					);
					?>
				<?php endif; ?>
			</p>

			<?php if ( ! empty( $result['scan_incomplete'] ) ) : ?>
				<p><?php esc_html_e( 'The scan stopped early because it reached its time budget. Review the partial results below and run the scan again if needed.', 'choctaw-wp-security' ); ?></p>
			<?php endif; ?>

			<?php if ( ! empty( $result['posts_table'] ) ) : ?>
				<p>
					<?php
					echo esc_html(
						sprintf(
							/* translators: %s: posts table name */
							__( 'Scanned table: %s', 'choctaw-wp-security' ),
							(string) $result['posts_table']
						)
					);
					?>
				</p>
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

		<?php
		if ( empty( $result['sections'] ) || ! is_array( $result['sections'] ) ) {
			return;
		}

		foreach ( Choctaw_Wp_Security_Posts_Scan_Patterns::$section_keys as $section_key ) {
			if ( empty( $result['sections'][ $section_key ] ) || ! is_array( $result['sections'][ $section_key ] ) ) {
				continue;
			}

			$this->render_posts_scan_section_results( $result['sections'][ $section_key ], $section_key );
		}
	}

	/**
	 * Build the pagination query parameter for a posts scan section.
	 *
	 * @param string $section_key Section identifier.
	 * @return string
	 */
	private function get_posts_scan_page_param( $section_key ) {
		return 'cws_postsscan_' . sanitize_key( (string) $section_key );
	}

	/**
	 * Render one wp_posts scan report section.
	 *
	 * @param array<string, mixed> $section     Section payload.
	 * @param string               $section_key Section identifier.
	 * @return void
	 */
	private function render_posts_scan_section_results( $section, $section_key = '' ) {
		$findings     = isset( $section['findings'] ) && is_array( $section['findings'] ) ? $section['findings'] : array();
		$info_message = isset( $section['info_message'] ) ? (string) $section['info_message'] : '';
		$title        = isset( $section['title'] ) ? (string) $section['title'] : '';
		$guidance     = isset( $section['guidance'] ) ? (string) $section['guidance'] : '';
		$page_param   = $this->get_posts_scan_page_param( $section_key );
		$pagination   = $this->paginate_report_items( $findings, $this->get_report_page_number( $page_param ) );
		$visible      = $pagination['items'];
		$section_class = 'cws-report-section cws-posts-scan-section';

		if ( 'large_post_content' === $section_key ) {
			$section_class .= ' cws-posts-scan-section-full-width';
		}
		?>
		<div class="<?php echo esc_attr( $section_class ); ?>">
			<h3>
				<?php echo esc_html( $title ); ?>
				<span class="cws-posts-scan-count">(<?php echo esc_html( (string) count( $findings ) ); ?>)</span>
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
							<th scope="col"><?php esc_html_e( 'Post ID', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'User ID', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Title', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Type', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Status', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Size', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Detail', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Excerpt', 'choctaw-wp-security' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $visible as $finding ) : ?>
							<tr>
								<td><?php echo esc_html( $this->format_database_scan_severity( isset( $finding['severity'] ) ? (string) $finding['severity'] : 'info' ) ); ?></td>
								<td><?php echo wp_kses_post( $this->get_posts_scan_post_id_markup( $finding ) ); ?></td>
								<td><?php echo wp_kses_post( $this->get_posts_scan_user_id_markup( $finding ) ); ?></td>
								<td><?php echo esc_html( isset( $finding['post_title'] ) ? (string) $finding['post_title'] : '' ); ?></td>
								<td><?php echo esc_html( isset( $finding['post_type'] ) ? (string) $finding['post_type'] : '' ); ?></td>
								<td><?php echo esc_html( isset( $finding['post_status'] ) ? (string) $finding['post_status'] : '' ); ?></td>
								<td><?php echo esc_html( size_format( isset( $finding['size'] ) ? (int) $finding['size'] : 0 ) ); ?></td>
								<td><?php echo esc_html( isset( $finding['detail'] ) ? (string) $finding['detail'] : '' ); ?></td>
								<td class="<?php echo 'large_post_content' === $section_key ? 'cws-posts-scan-excerpt' : ''; ?>"><?php echo esc_html( isset( $finding['excerpt'] ) ? (string) $finding['excerpt'] : '' ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>

				<?php $this->render_report_pagination( $page_param, $pagination ); ?>
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
			'<a href="%s">%s</a>',
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

		if ( '' === $display_name ) {
			return esc_html( (string) $user_id );
		}

		return sprintf(
			'<span class="cws-posts-scan-user-id" title="%s" aria-label="%s">%s</span>',
			esc_attr( $display_name ),
			esc_attr(
				sprintf(
					/* translators: 1: user ID, 2: display name */
					__( 'User ID %1$s (%2$s)', 'choctaw-wp-security' ),
					$user_id,
					$display_name
				)
			),
			esc_html( (string) $user_id )
		);
	}

	/**
	 * Render the posts table picker for wp_posts scans.
	 *
	 * @param array<int, array<string, mixed>> $tables_metadata Discovered table metadata.
	 * @param string                           $selected_table  Selected table name.
	 * @return void
	 */
	private function render_posts_scan_table_picker( array $tables_metadata, $selected_table ) {
		if ( empty( $tables_metadata ) ) {
			?>
			<p><?php esc_html_e( 'No posts tables were discovered in this database.', 'choctaw-wp-security' ); ?></p>
			<?php
			return;
		}
		?>
		<div class="cws-posts-scan-table-picker">
			<h3><?php esc_html_e( 'Posts Table', 'choctaw-wp-security' ); ?></h3>
			<table class="widefat striped cws-posts-scan-table-picker-table">
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'Select', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Table', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Status', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Rows', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Data Size', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Last Updated', 'choctaw-wp-security' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $tables_metadata as $table_meta ) : ?>
						<?php
						$table_name  = isset( $table_meta['table_name'] ) ? (string) $table_meta['table_name'] : '';
						$is_selected = $table_name === $selected_table;
						$badges      = array();

						if ( ! empty( $table_meta['is_wordpress_configured'] ) ) {
							$badges[] = __( 'WordPress configured', 'choctaw-wp-security' );
						}
						?>
						<tr>
							<td>
								<input
									type="radio"
									name="database_scan_posts_table"
									class="cws-posts-scan-table-choice"
									value="<?php echo esc_attr( $table_name ); ?>"
									<?php checked( $is_selected ); ?>
								/>
							</td>
							<td><code class="cws-file-path"><?php echo esc_html( $table_name ); ?></code></td>
							<td><?php echo esc_html( implode( '; ', $badges ) ); ?></td>
							<td><?php echo esc_html( number_format_i18n( isset( $table_meta['row_count'] ) ? (int) $table_meta['row_count'] : 0 ) ); ?></td>
							<td><?php echo esc_html( size_format( isset( $table_meta['data_size'] ) ? (int) $table_meta['data_size'] : 0 ) ); ?></td>
							<td><?php echo esc_html( $this->format_database_scan_table_timestamp( isset( $table_meta['update_time'] ) ? (string) $table_meta['update_time'] : '' ) ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
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
	 * Render the three checksum finding category reports.
	 *
	 * @param array<string, mixed> $result Scan result payload.
	 * @return void
	 */
	private function render_core_checksum_category_reports( $result ) {
		$modified = isset( $result['modified'] ) && is_array( $result['modified'] ) ? $result['modified'] : array();
		$missing  = isset( $result['missing'] ) && is_array( $result['missing'] ) ? $result['missing'] : array();
		$unknown  = isset( $result['unknown'] ) && is_array( $result['unknown'] ) ? $result['unknown'] : array();

		$this->render_checksum_category_section(
			__( 'Modified Files', 'choctaw-wp-security' ),
			'modified',
			$modified,
			'cws_checksum_modified'
		);
		$this->render_checksum_category_section(
			__( 'Missing Files', 'choctaw-wp-security' ),
			'missing',
			$missing,
			'cws_checksum_missing'
		);
		$this->render_checksum_category_section(
			__( 'Not Part of Core', 'choctaw-wp-security' ),
			'unknown',
			$unknown,
			'cws_checksum_unknown'
		);
	}

	/**
	 * Render exposed folders scan results.
	 *
	 * @param array<string, mixed> $result Scan result payload.
	 * @return void
	 */
	private function render_exposed_folders_results( $result ) {
		$server_level = isset( $result['server_level'] ) && is_array( $result['server_level'] ) ? $result['server_level'] : array();
		$errors       = isset( $result['errors'] ) && is_array( $result['errors'] ) ? $result['errors'] : array();
		?>
		<div class="cws-exposed-folders-results">
			<h3><?php esc_html_e( 'Scan Results', 'choctaw-wp-security' ); ?></h3>

			<?php $this->render_exposed_folders_server_level_table( $server_level ); ?>

			<?php if ( ! empty( $errors ) ) : ?>
				<h4><?php esc_html_e( 'Scan Notes', 'choctaw-wp-security' ); ?></h4>
				<ul class="cws-core-checksum-list">
					<?php foreach ( $errors as $error_message ) : ?>
						<li><?php echo esc_html( (string) $error_message ); ?></li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Render the server-level directory browsing results table.
	 *
	 * @param array<string, mixed> $server_level Server-level scan payload.
	 * @return void
	 */
	private function render_exposed_folders_server_level_table( $server_level ) {
		$rows = isset( $server_level['rows'] ) && is_array( $server_level['rows'] ) ? $server_level['rows'] : array();

		if ( empty( $rows ) ) {
			return;
		}

		$has_conflict = false;

		foreach ( $rows as $row ) {
			if ( ! empty( $row['conflict'] ) ) {
				$has_conflict = true;
				break;
			}
		}
		?>
		<?php if ( $has_conflict ) : ?>
			<p class="description">
				<?php esc_html_e( 'The .htaccess analysis and directory listing test returned different on/off results. Review each row for details.', 'choctaw-wp-security' ); ?>
			</p>
		<?php endif; ?>

		<table class="widefat striped cws-core-checksum-table">
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'Server Type', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Directory Browsing', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Detection Method', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Details', 'choctaw-wp-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $rows as $index => $row ) : ?>
					<?php
					if ( ! is_array( $row ) ) {
						continue;
					}

					$row_id       = 'directory-browsing-' . sanitize_key( (string) ( isset( $row['method'] ) ? $row['method'] : 'row' ) ) . '-' . (int) $index;
					$detail_html  = Choctaw_Wp_Security_Admin_Help_Content::get_directory_browsing_row_detail_html( $row );
					$server_type  = isset( $row['server_type'] ) ? (string) $row['server_type'] : Choctaw_Wp_Security_Directory_Browsing_Scanner::SERVER_UNKNOWN;
					$status       = isset( $row['status'] ) ? (string) $row['status'] : Choctaw_Wp_Security_Directory_Browsing_Scanner::STATUS_UNKNOWN;
					$method       = isset( $row['method'] ) ? (string) $row['method'] : '';
					?>
					<tr>
						<td><?php echo esc_html( $this->get_directory_browsing_server_type_label( $server_type ) ); ?></td>
						<td class="cws-directory-browsing-status-cell">
							<?php $this->render_directory_browsing_status_indicator( $status ); ?>
						</td>
						<td><?php echo esc_html( $this->get_directory_browsing_method_label( $method ) ); ?></td>
						<td>
							<?php if ( '' !== $detail_html ) : ?>
								<?php Choctaw_Wp_Security_Admin_Help::render_disclosure_toggle( $row_id, Choctaw_Wp_Security_Admin_Help::get_more_info_label() ); ?>
							<?php else : ?>
								<?php echo esc_html( '—' ); ?>
							<?php endif; ?>
						</td>
					</tr>
					<?php if ( '' !== $detail_html ) : ?>
						<?php Choctaw_Wp_Security_Admin_Help::render_table_disclosure_row( $row_id, $detail_html, 4 ); ?>
					<?php endif; ?>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	/**
	 * Translate a detected server type for display.
	 *
	 * @param string $server_type Server type key.
	 * @return string
	 */
	private function get_directory_browsing_server_type_label( $server_type ) {
		switch ( $server_type ) {
			case Choctaw_Wp_Security_Directory_Browsing_Scanner::SERVER_APACHE:
				return __( 'Apache', 'choctaw-wp-security' );
			case Choctaw_Wp_Security_Directory_Browsing_Scanner::SERVER_LITESPEED:
				return __( 'LiteSpeed', 'choctaw-wp-security' );
			case Choctaw_Wp_Security_Directory_Browsing_Scanner::SERVER_NGINX:
				return __( 'Nginx', 'choctaw-wp-security' );
			default:
				return __( 'Unknown', 'choctaw-wp-security' );
		}
	}

	/**
	 * Render a directory browsing status indicator with dashicons.
	 *
	 * @param string $status Status key.
	 * @return void
	 */
	private function render_directory_browsing_status_indicator( $status ) {
		$label = $this->get_directory_browsing_status_label( $status );

		switch ( $status ) {
			case Choctaw_Wp_Security_Directory_Browsing_Scanner::STATUS_OFF:
				$status_class = 'is-verified';
				$icon_class   = 'dashicons-yes-alt';
				break;
			case Choctaw_Wp_Security_Directory_Browsing_Scanner::STATUS_ON:
				$status_class = 'is-failed';
				$icon_class   = 'dashicons-dismiss';
				break;
			default:
				$status_class = 'is-unknown';
				$icon_class   = 'dashicons-editor-help';
				break;
		}
		?>
		<span class="cws-checksum-status cws-directory-browsing-status <?php echo esc_attr( $status_class ); ?>">
			<span class="cws-directory-browsing-status-label"><?php echo esc_html( $label ); ?></span>
			<span class="dashicons <?php echo esc_attr( $icon_class ); ?>" aria-hidden="true"></span>
		</span>
		<?php
	}

	/**
	 * Translate a directory browsing status for display.
	 *
	 * @param string $status Status key.
	 * @return string
	 */
	private function get_directory_browsing_status_label( $status ) {
		switch ( $status ) {
			case Choctaw_Wp_Security_Directory_Browsing_Scanner::STATUS_ON:
				return __( 'On', 'choctaw-wp-security' );
			case Choctaw_Wp_Security_Directory_Browsing_Scanner::STATUS_OFF:
				return __( 'Off', 'choctaw-wp-security' );
			default:
				return __( 'Unknown', 'choctaw-wp-security' );
		}
	}

	/**
	 * Translate a detection method key for display.
	 *
	 * @param string $method Detection method key.
	 * @return string
	 */
	private function get_directory_browsing_method_label( $method ) {
		switch ( $method ) {
			case Choctaw_Wp_Security_Directory_Browsing_Scanner::METHOD_HTACCESS:
				return __( '.htaccess', 'choctaw-wp-security' );
			case Choctaw_Wp_Security_Directory_Browsing_Scanner::METHOD_DIRECTORY_TEST:
				return __( 'Directory Test', 'choctaw-wp-security' );
			default:
				return __( 'Other', 'choctaw-wp-security' );
		}
	}

	/**
	 * Render one checksum finding category report.
	 *
	 * @param string             $heading    Section heading.
	 * @param string             $category   Finding category: modified, missing, or unknown.
	 * @param array<int, string> $file_paths File paths to display.
	 * @param string             $page_param Pagination query parameter.
	 * @return void
	 */
	private function render_checksum_category_section( $heading, $category, array $file_paths, $page_param ) {
		?>
		<div class="cws-report-section cws-core-checksum-category-report">
			<h3><?php echo esc_html( $heading ); ?></h3>

			<?php if ( empty( $file_paths ) ) : ?>
				<p><?php esc_html_e( 'No files reported.', 'choctaw-wp-security' ); ?></p>
			<?php else : ?>
				<?php
				$page_number = $this->get_report_page_number( $page_param );
				$pagination  = $this->paginate_report_items( $file_paths, $page_number );
				?>
				<table class="widefat striped cws-core-checksum-table">
					<thead>
						<tr>
							<th scope="col"><?php esc_html_e( 'Path', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'File', 'choctaw-wp-security' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $pagination['items'] as $file_path ) : ?>
							<tr>
								<td><?php $this->render_file_path( $this->get_core_file_directory_path( (string) $file_path ) ); ?></td>
								<td><?php $this->render_file_path( $this->get_core_file_basename( (string) $file_path ) ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
				<?php $this->render_report_pagination( $page_param, $pagination ); ?>

				<?php Choctaw_Wp_Security_Admin_Help::render_guidance_box( 'checksum_' . sanitize_key( $category ) ); ?>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Render educational guidance for disabling directory browsing.
	 *
	 * @return void
	 */
	private function render_exposed_folders_guidance() {
		?>
		<div class="cws-report-section">
			<?php Choctaw_Wp_Security_Admin_Help::render_guidance_box( 'directory_browsing_fix' ); ?>
		</div>
		<?php
	}

	/**
	 * Render the features section description.
	 *
	 * @return void
	 */
	public function render_features_section() {
		echo '<p>' . esc_html__( 'Enable or disable individual security modules.', 'choctaw-wp-security' ) . '</p>';
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
	 * Render the uploads PHP lockdown checkbox with server-aware guidance.
	 *
	 * @param array<string, string> $args Field arguments.
	 * @return void
	 */
	public function render_uploads_lockdown_field( $args ) {
		$lockdown = new Choctaw_Wp_Security_Uploads_Php_Lockdown();
		$server   = $lockdown->get_server_type();

		if ( Choctaw_Wp_Security_Uploads_Php_Lockdown::SERVER_NGINX === $server ) {
			$this->render_nginx_uploads_lockdown_setting( $args, $lockdown );
			return;
		}

		$this->render_security_feature_field( $args );

		if ( Choctaw_Wp_Security_Uploads_Php_Lockdown::SERVER_UNKNOWN === $server ) {
			echo '<div class="cws-feature-setting-notes">';
			echo '<p class="description">';
			esc_html_e( 'When enabled, the plugin will attempt to install a managed', 'choctaw-wp-security' );
			echo ' ';
			$this->render_file_path( '.htaccess' );
			echo ' ';
			esc_html_e( 'block in', 'choctaw-wp-security' );
			echo ' ';
			$this->render_file_path( 'wp-content/uploads' );
			echo ', ';
			esc_html_e( 'but server support cannot be guaranteed.', 'choctaw-wp-security' );
			echo '</p>';
			echo '</div>';
		}
	}

	/**
	 * Render the uploads lockdown setting for Nginx servers.
	 *
	 * @param array<string, string>                  $args     Field arguments.
	 * @param Choctaw_Wp_Security_Uploads_Php_Lockdown $lockdown Uploads lockdown service.
	 * @return void
	 */
	private function render_nginx_uploads_lockdown_setting( $args, $lockdown ) {
		?>
		<div class="cws-feature-setting cws-feature-setting-is-disabled">
			<div class="cws-feature-setting-header">
				<input
					type="checkbox"
					id="<?php echo esc_attr( $args['label_for'] ); ?>"
					disabled="disabled"
					aria-disabled="true"
				/>
				<span class="cws-feature-setting-title"><?php echo esc_html( $args['label'] ); ?></span>
			</div>
			<p class="description cws-feature-setting-summary">
				<?php echo wp_kses( Choctaw_Wp_Security_Admin_Help_Content::uploads_lockdown_nginx_unavailable_summary_html(), Choctaw_Wp_Security_Admin_Help::get_allowed_detail_markup() ); ?>
			</p>
			<div class="cws-uploads-lockdown-snippet">
				<textarea readonly rows="5" class="large-text code"><?php echo esc_textarea( $lockdown->get_nginx_snippet() ); ?></textarea>
			</div>
			<div class="cws-feature-setting-notes">
				<?php
				Choctaw_Wp_Security_Admin_Help::render_disclosure_block(
					'uploads-php-lockdown-nginx',
					Choctaw_Wp_Security_Admin_Help_Content::uploads_php_lockdown_nginx_detail_html()
				);
				?>
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
	 * @return array<int, array{label: string, checksum_path: string, modified: string}>
	 */
	private function get_core_file_changes() {
		$changes = array();

		foreach ( $this->get_monitored_core_file_map() as $label => $path ) {
			$changes[] = array(
				'label'         => $label,
				'checksum_path' => $label,
				'modified'      => $this->format_file_modified_time( $path ),
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
	 * Retrieve PHP files found in uploads and must-use plugins directories.
	 *
	 * @return array<int, array{location: string, path: string, modified: string}>
	 */
	private function get_content_php_files() {
		$uploads = wp_get_upload_dir();
		$folders = array(
			__( 'Uploads', 'choctaw-wp-security' ) => isset( $uploads['basedir'] ) ? $uploads['basedir'] : '',
			__( 'Must-Use Plugins', 'choctaw-wp-security' ) => defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins',
		);

		$files = array();

		foreach ( $folders as $location => $folder ) {
			foreach ( $this->find_php_files( $folder ) as $path ) {
				$files[] = array(
					'location' => $location,
					'path'     => $this->format_display_path( $path ),
					'modified' => $this->format_file_modified_time( $path ),
				);
			}
		}

		usort(
			$files,
			function ( $a, $b ) {
				return strcmp( $a['path'], $b['path'] );
			}
		);

		return $files;
	}

	/**
	 * Retrieve top-level uploads folders that are not part of the Media Library.
	 *
	 * @return array{folders: array<int, array{path: string, modified: string}>, errors: array<int, string>}
	 */
	private function get_non_media_uploads_folders() {
		$result = array(
			'folders' => array(),
			'errors'  => array(),
		);

		$uploads = wp_get_upload_dir();
		$basedir = isset( $uploads['basedir'] ) ? (string) $uploads['basedir'] : '';

		if ( '' === $basedir || ! is_dir( $basedir ) ) {
			$result['errors'][] = __( 'Uploads directory not found.', 'choctaw-wp-security' );
			return $result;
		}

		if ( ! is_readable( $basedir ) ) {
			$result['errors'][] = __( 'Uploads directory is not readable by WordPress.', 'choctaw-wp-security' );
			return $result;
		}

		try {
			$iterator = new DirectoryIterator( $basedir );

			foreach ( $iterator as $file ) {
				if ( $file->isDot() || ! $file->isDir() ) {
					continue;
				}

				$name = $file->getFilename();

				if ( $this->is_media_library_upload_folder_name( $name ) ) {
					continue;
				}

				$path = $file->getPathname();

				$result['folders'][] = array(
					'path'     => $this->format_display_path( $path ),
					'modified' => $this->format_file_modified_time( $path ),
				);
			}
		} catch ( Exception $exception ) {
			$result['errors'][] = __( 'Scan stopped because the uploads directory could not be read.', 'choctaw-wp-security' );
			return $result;
		}

		usort(
			$result['folders'],
			function ( $a, $b ) {
				return strcmp( $a['path'], $b['path'] );
			}
		);

		return $result;
	}

	/**
	 * Determine whether a folder name matches WordPress Media Library date organization.
	 *
	 * @param string $name Folder basename.
	 * @return bool
	 */
	private function is_media_library_upload_folder_name( $name ) {
		// WordPress stores Media Library uploads in year-based folders (e.g. 2024, 2025).
		return (bool) preg_match( '/^\d{4}$/', $name );
	}

	/**
	 * Find PHP-like files in a directory.
	 *
	 * @param string $folder Directory path.
	 * @return array<int, string>
	 */
	private function find_php_files( $folder ) {
		$folder = (string) $folder;

		if ( '' === $folder || ! is_dir( $folder ) || ! is_readable( $folder ) ) {
			return array();
		}

		$matches    = array();
		$extensions = array( 'php', 'phtml', 'phar', 'php3', 'php4', 'php5', 'php7' );
		$limit      = 200;

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $folder, FilesystemIterator::SKIP_DOTS )
			);

			foreach ( $iterator as $file ) {
				if ( count( $matches ) >= $limit ) {
					break;
				}

				if ( ! $file->isFile() ) {
					continue;
				}

				$extension = strtolower( $file->getExtension() );

				if ( in_array( $extension, $extensions, true ) ) {
					$matches[] = $file->getPathname();
				}
			}
		} catch ( Exception $exception ) {
			return $matches;
		}

		return $matches;
	}

	/**
	 * Scan server-level directory browsing status.
	 *
	 * @return array<string, mixed>
	 */
	private function scan_exposed_folders() {
		$result = array(
			'server_level' => array(
				'server_type' => Choctaw_Wp_Security_Directory_Browsing_Scanner::SERVER_UNKNOWN,
				'rows'        => array(),
			),
			'errors'       => array(),
		);

		$sources = array(
			'plugins' => array(
				'label' => __( 'Plugins', 'choctaw-wp-security' ),
				'path'  => defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR : WP_CONTENT_DIR . '/plugins',
			),
			'themes'  => array(
				'label' => __( 'Themes', 'choctaw-wp-security' ),
				'path'  => get_theme_root(),
			),
		);

		$plugin_folders = array();
		$theme_folders  = array();

		foreach ( $sources as $key => $source ) {
			$scan = $this->find_top_level_folders_missing_index_files( $source['path'], 1 );

			if ( 'plugins' === $key ) {
				$plugin_folders = $scan['folders'];
			} else {
				$theme_folders = $scan['folders'];
			}

			if ( ! empty( $scan['errors'] ) ) {
				foreach ( $scan['errors'] as $error_message ) {
					$result['errors'][] = sprintf(
						/* translators: 1: source label, 2: scan note */
						__( '%1$s: %2$s', 'choctaw-wp-security' ),
						$source['label'],
						$error_message
					);
				}
			}
		}

		$scanner                  = new Choctaw_Wp_Security_Directory_Browsing_Scanner();
		$result['server_level'] = $scanner->scan( $plugin_folders, $theme_folders );

		return $result;
	}

	/**
	 * Find immediate child directories missing common index files.
	 *
	 * @param string $folder Root folder to inspect.
	 * @param int    $limit  Maximum folders to return.
	 * @return array{folders: array<int, string>, errors: array<int, string>, truncated: bool}
	 */
	private function find_top_level_folders_missing_index_files( $folder, $limit ) {
		$folder = (string) $folder;

		$result = array(
			'folders'   => array(),
			'errors'    => array(),
			'truncated' => false,
		);

		if ( '' === $folder || ! is_dir( $folder ) ) {
			$result['errors'][] = __( 'Directory not found.', 'choctaw-wp-security' );
			return $result;
		}

		if ( ! is_readable( $folder ) ) {
			$result['errors'][] = __( 'Directory is not readable by WordPress.', 'choctaw-wp-security' );
			return $result;
		}

		try {
			$iterator = new DirectoryIterator( $folder );

			foreach ( $iterator as $file ) {
				if ( $file->isDot() || ! $file->isDir() ) {
					continue;
				}

				$path = $file->getPathname();

				if ( $this->directory_has_index_file( $path ) ) {
					continue;
				}

				if ( count( $result['folders'] ) >= $limit ) {
					$result['truncated'] = true;
					break;
				}

				$result['folders'][] = $this->format_display_path( $path );
			}
		} catch ( Exception $exception ) {
			$result['errors'][] = __( 'Scan stopped because the directory could not be read.', 'choctaw-wp-security' );
		}

		sort( $result['folders'] );

		return $result;
	}

	/**
	 * Determine whether a directory contains a common index file.
	 *
	 * @param string $path Directory path.
	 * @return bool
	 */
	private function directory_has_index_file( $path ) {
		$index_files = array( 'index.php', 'index.html', 'index.htm' );

		foreach ( $index_files as $index_file ) {
			if ( file_exists( trailingslashit( $path ) . $index_file ) ) {
				return true;
			}
		}

		return false;
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
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		if ( empty( $_POST['choctaw_wp_security_users_table_load'] ) ) {
			return;
		}

		check_admin_referer( 'choctaw_wp_security_users_table_form' );

		$requested_table = isset( $_POST['database_scan_users_table'] ) ? wp_unslash( $_POST['database_scan_users_table'] ) : '';
		$discovery       = new Choctaw_Wp_Security_Users_Table_Discovery();
		$users_table     = $discovery->resolve_scan_table( (string) $requested_table );

		Choctaw_Wp_Security_Utils::save_database_scan_users_table( $users_table );

		$reader = new Choctaw_Wp_Security_Users_Table_Reader( $discovery );
		$result = $reader->fetch_users( $users_table );

		$this->save_report_result(
			$this->get_users_table_result_transient_key(),
			Choctaw_Wp_Security_Utils::USER_META_USERS_TABLE_RESULT,
			$result
		);

		wp_safe_redirect(
			add_query_arg(
				array(
					'page'             => 'choctaw-wp-security',
					'cws_tab'          => 'wp-users',
					'users_table_load' => '1',
				),
				admin_url( 'options-general.php' )
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
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to load users tables.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_users_table_ajax', 'nonce' );

		$requested_table = isset( $_POST['database_scan_users_table'] ) ? wp_unslash( $_POST['database_scan_users_table'] ) : '';
		$discovery       = new Choctaw_Wp_Security_Users_Table_Discovery();
		$users_table     = $discovery->resolve_scan_table( (string) $requested_table );

		Choctaw_Wp_Security_Utils::save_database_scan_users_table( $users_table );

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

		$this->save_report_result(
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
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to load user activity.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_users_table_ajax', 'nonce' );

		$requested_table = isset( $_POST['database_scan_users_table'] ) ? wp_unslash( $_POST['database_scan_users_table'] ) : '';
		$user_id         = isset( $_POST['user_id'] ) ? (int) wp_unslash( $_POST['user_id'] ) : 0;
		$discovery       = new Choctaw_Wp_Security_Users_Table_Discovery();
		$users_table     = $discovery->resolve_scan_table( (string) $requested_table );
		$reader          = new Choctaw_Wp_Security_User_Activity_Reader( $discovery );
		$result          = $reader->fetch_user_activity( $users_table, $user_id );

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
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to load usermeta.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_users_table_ajax', 'nonce' );

		$requested_table = isset( $_POST['database_scan_users_table'] ) ? wp_unslash( $_POST['database_scan_users_table'] ) : '';
		$user_id         = isset( $_POST['user_id'] ) ? (int) wp_unslash( $_POST['user_id'] ) : 0;
		$discovery       = new Choctaw_Wp_Security_Users_Table_Discovery();
		$users_table     = $discovery->resolve_scan_table( (string) $requested_table );
		$reader          = new Choctaw_Wp_Security_User_Usermeta_Reader( $discovery );
		$result          = $reader->fetch_user_usermeta( $users_table, $user_id );

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
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array(
					'message' => __( 'You do not have permission to load file activity.', 'choctaw-wp-security' ),
				),
				403
			);
		}

		check_ajax_referer( 'choctaw_wp_security_users_table_ajax', 'nonce' );

		$requested_table = isset( $_POST['database_scan_users_table'] ) ? wp_unslash( $_POST['database_scan_users_table'] ) : '';
		$user_id         = isset( $_POST['user_id'] ) ? (int) wp_unslash( $_POST['user_id'] ) : 0;
		$discovery       = new Choctaw_Wp_Security_Users_Table_Discovery();
		$users_table     = $discovery->resolve_scan_table( (string) $requested_table );
		$scanner         = new Choctaw_Wp_Security_User_File_Activity_Scanner( $discovery );
		$result          = $scanner->scan_user_file_activity( $users_table, $user_id );

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
		if ( ! current_user_can( 'manage_options' ) ) {
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

		$discovery      = new Choctaw_Wp_Security_Users_Table_Discovery();
		$selected_table = $discovery->resolve_scan_table( '' );
		$tables_meta    = $discovery->get_tables_with_metadata();
		?>
		<div class="cws-admin-tab-panel">
			<div class="cws-report-section">
				<h2><?php esc_html_e( 'wp_users', 'choctaw-wp-security' ); ?></h2>
				<?php Choctaw_Wp_Security_Admin_Help::render_tab_intro( 'users_table' ); ?>

				<?php
				if ( is_array( $result ) && ! empty( $result['users_table'] ) ) {
					$selected_table = (string) $result['users_table'];
				}
				?>

				<?php if ( $results_missing ) : ?>
					<div class="notice notice-warning">
						<p><?php esc_html_e( 'The previous users table results are no longer available. Click Load Users to generate a fresh report.', 'choctaw-wp-security' ); ?></p>
					</div>
				<?php endif; ?>

				<form method="post" class="cws-database-scan-form" id="cws-users-table-form">
					<?php wp_nonce_field( 'choctaw_wp_security_users_table_form' ); ?>
					<input type="hidden" name="cws_tab" value="wp-users" />

					<?php $this->render_users_table_picker( $tables_meta, $selected_table ); ?>

					<?php submit_button( __( 'Load Users', 'choctaw-wp-security' ), 'secondary', 'choctaw_wp_security_users_table_load', false ); ?>
				</form>

				<div id="cws-users-table-js-notices" aria-live="polite"></div>
				<div id="cws-users-table-js-results"></div>

				<div id="cws-users-table-fallback-results">
					<?php if ( is_array( $result ) ) : ?>
						<?php $this->render_users_table_results( $result ); ?>
					<?php endif; ?>
				</div>

				<?php Choctaw_Wp_Security_Admin_Help::render_guidance_box( 'remove_user_account' ); ?>
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

		if ( ! empty( $result['users_table'] ) ) {
			?>
			<p><?php echo esc_html( sprintf( __( 'Loaded table: %s', 'choctaw-wp-security' ), (string) $result['users_table'] ) ); ?></p>
			<?php
		}

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
		$this->render_report_pagination( 'cws_users_table', $pagination );
	}

	/**
	 * Render the users table picker.
	 *
	 * @param array<int, array<string, mixed>> $tables_metadata Discovered table metadata.
	 * @param string                           $selected_table  Selected table name.
	 * @return void
	 */
	private function render_users_table_picker( array $tables_metadata, $selected_table ) {
		if ( empty( $tables_metadata ) ) {
			?>
			<p><?php esc_html_e( 'No users tables were discovered in this database.', 'choctaw-wp-security' ); ?></p>
			<?php
			return;
		}
		?>
		<div class="cws-database-scan-table-picker">
			<h3><?php esc_html_e( 'Users Table', 'choctaw-wp-security' ); ?></h3>
			<table class="widefat striped cws-database-scan-table-picker-table">
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'Select', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Table', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Status', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Rows', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Data Size', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Last Updated', 'choctaw-wp-security' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $tables_metadata as $table_meta ) : ?>
						<?php
						$table_name  = isset( $table_meta['table_name'] ) ? (string) $table_meta['table_name'] : '';
						$is_selected = $table_name === $selected_table;
						$badges      = array();

						if ( ! empty( $table_meta['is_wordpress_configured'] ) ) {
							$badges[] = __( 'WordPress configured', 'choctaw-wp-security' );
						}
						?>
						<tr>
							<td>
								<input
									type="radio"
									name="database_scan_users_table"
									class="cws-users-table-choice"
									value="<?php echo esc_attr( $table_name ); ?>"
									<?php checked( $is_selected ); ?>
								/>
							</td>
							<td><code class="cws-file-path"><?php echo esc_html( $table_name ); ?></code></td>
							<td><?php echo esc_html( implode( '; ', $badges ) ); ?></td>
							<td><?php echo esc_html( number_format_i18n( isset( $table_meta['row_count'] ) ? (int) $table_meta['row_count'] : 0 ) ); ?></td>
							<td><?php echo esc_html( size_format( isset( $table_meta['data_size'] ) ? (int) $table_meta['data_size'] : 0 ) ); ?></td>
							<td><?php echo esc_html( $this->format_database_scan_table_timestamp( isset( $table_meta['update_time'] ) ? (string) $table_meta['update_time'] : '' ) ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
	}
}
