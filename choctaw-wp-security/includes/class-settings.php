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
		add_action( 'load-settings_page_choctaw-wp-security', array( $this, 'handle_exposed_folders_scan' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
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
			__( 'XML-RPC Blocking', 'choctaw-wp-security' ),
			array( $this, 'render_checkbox_field' ),
			'choctaw-wp-security',
			'choctaw_wp_security_features',
			array(
				'label_for' => 'xmlrpc_blocking_enabled',
				'option'    => 'xmlrpc_blocking_enabled',
				'label'     => __( 'Block XML-RPC requests', 'choctaw-wp-security' ),
			)
		);

		add_settings_field(
			'login_rate_limit_enabled',
			__( 'Login Rate Limiting', 'choctaw-wp-security' ),
			array( $this, 'render_checkbox_field' ),
			'choctaw-wp-security',
			'choctaw_wp_security_features',
			array(
				'label_for' => 'login_rate_limit_enabled',
				'option'    => 'login_rate_limit_enabled',
				'label'     => __( 'Enable login rate limiting', 'choctaw-wp-security' ),
			)
		);

		add_settings_field(
			'uploads_php_lockdown_enabled',
			__( 'Uploads PHP Lockdown', 'choctaw-wp-security' ),
			array( $this, 'render_uploads_lockdown_field' ),
			'choctaw-wp-security',
			'choctaw_wp_security_features',
			array(
				'label_for' => 'uploads_php_lockdown_enabled',
				'option'    => 'uploads_php_lockdown_enabled',
				'label'     => __( 'Disable PHP execution in uploads', 'choctaw-wp-security' ),
			)
		);

		add_settings_section(
			'choctaw_wp_security_policy',
			__( 'Login Rate Limit Policy', 'choctaw-wp-security' ),
			array( $this, 'render_policy_section' ),
			'choctaw-wp-security'
		);

		add_settings_field(
			'allowed_failed_attempts',
			__( 'Allowed Failed Attempts', 'choctaw-wp-security' ),
			array( $this, 'render_number_field' ),
			'choctaw-wp-security',
			'choctaw_wp_security_policy',
			array(
				'label_for' => 'allowed_failed_attempts',
				'option'    => 'allowed_failed_attempts',
				'min'       => 1,
				'max'       => 100,
				'step'      => 1,
			)
		);

		add_settings_field(
			'failure_window_minutes',
			__( 'Failure Window (minutes)', 'choctaw-wp-security' ),
			array( $this, 'render_number_field' ),
			'choctaw-wp-security',
			'choctaw_wp_security_policy',
			array(
				'label_for' => 'failure_window_minutes',
				'option'    => 'failure_window_minutes',
				'min'       => 1,
				'max'       => 1440,
				'step'      => 1,
			)
		);

		add_settings_field(
			'lockout_duration_minutes',
			__( 'Lockout Duration (minutes)', 'choctaw-wp-security' ),
			array( $this, 'render_number_field' ),
			'choctaw-wp-security',
			'choctaw_wp_security_policy',
			array(
				'label_for' => 'lockout_duration_minutes',
				'option'    => 'lockout_duration_minutes',
				'min'       => 1,
				'max'       => 1440,
				'step'      => 1,
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
		$defaults = Choctaw_Wp_Security_Utils::default_options();
		$input    = is_array( $input ) ? $input : array();

		$sanitized = array(
			'xmlrpc_blocking_enabled'      => ! empty( $input['xmlrpc_blocking_enabled'] ),
			'login_rate_limit_enabled'     => ! empty( $input['login_rate_limit_enabled'] ),
			'uploads_php_lockdown_enabled' => ! empty( $input['uploads_php_lockdown_enabled'] ),
			'allowed_failed_attempts'        => $this->clamp_int( $input, 'allowed_failed_attempts', 1, 100, $defaults['allowed_failed_attempts'] ),
			'failure_window_minutes'   => $this->clamp_int( $input, 'failure_window_minutes', 1, 1440, $defaults['failure_window_minutes'] ),
			'lockout_duration_minutes' => $this->clamp_int( $input, 'lockout_duration_minutes', 1, 1440, $defaults['lockout_duration_minutes'] ),
		);

		return $sanitized;
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
			'exposed-folders'      => __( 'Exposed Folders', 'choctaw-wp-security' ),
			'verify-checksums'     => __( 'Verify Checksums', 'choctaw-wp-security' ),
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

		if ( 'exposed-folders' === $active_tab ) {
			$this->render_exposed_folders_section();
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
		$options          = Choctaw_Wp_Security_Utils::get_options();
		$events           = Choctaw_Wp_Security_Utils::get_lockout_log();
		$uploads_lockdown = new Choctaw_Wp_Security_Uploads_Php_Lockdown();
		$uploads_status   = $uploads_lockdown->get_status();
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
			$this->render_nginx_uploads_lockdown_section( $uploads_lockdown, $uploads_status );
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
		<h2><?php esc_html_e( 'Status', 'choctaw-wp-security' ); ?></h2>
		<table class="widefat striped" style="max-width: 720px;">
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
							<p class="description"><?php echo esc_html( $uploads_status['note'] ); ?></p>
						<?php endif; ?>
					</td>
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
		<?php
	}

	/**
	 * Render Nginx upload lockdown guidance when required.
	 *
	 * @param Choctaw_Wp_Security_Uploads_Php_Lockdown $uploads_lockdown Uploads lockdown service.
	 * @param array<string, mixed>                     $uploads_status   Uploads lockdown status.
	 * @return void
	 */
	private function render_nginx_uploads_lockdown_section( $uploads_lockdown, $uploads_status ) {
		if ( Choctaw_Wp_Security_Uploads_Php_Lockdown::STATUS_NGINX_MANUAL !== $uploads_status['key'] ) {
			return;
		}
		?>
		<h2><?php esc_html_e( 'Nginx Uploads PHP Lockdown', 'choctaw-wp-security' ); ?></h2>
		<p><?php esc_html_e( 'Add this snippet to your site server block, then reload Nginx. The plugin cannot apply this rule automatically on Nginx.', 'choctaw-wp-security' ); ?></p>
		<textarea readonly rows="5" class="large-text code" style="max-width: 960px;"><?php echo esc_textarea( $uploads_lockdown->get_nginx_snippet() ); ?></textarea>
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
		<h2><?php esc_html_e( 'Recent Lockouts', 'choctaw-wp-security' ); ?></h2>
		<p><?php esc_html_e( 'Shared IP addresses (NAT/office networks) may cause IP-only lockouts to affect other users temporarily.', 'choctaw-wp-security' ); ?></p>
		<table class="widefat striped" style="max-width: 960px;">
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
		<?php
	}

	/**
	 * Render the Files Changes/Uploads tab.
	 *
	 * @return void
	 */
	private function render_file_changes_uploads_tab() {
		$core_file_changes = $this->get_core_file_changes();
		$content_php_files = $this->get_content_php_files();
		?>
		<div class="cws-admin-tab-panel">
			<h2><?php esc_html_e( 'Recent File Changes', 'choctaw-wp-security' ); ?></h2>
			<p><?php esc_html_e( 'These stable WordPress files should usually only change during core updates or deliberate server configuration changes.', 'choctaw-wp-security' ); ?></p>
			<table class="widefat striped" style="max-width: 960px;">
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'File', 'choctaw-wp-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Last Modified', 'choctaw-wp-security' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $core_file_changes as $file_change ) : ?>
						<tr>
							<td><?php echo esc_html( $file_change['label'] ); ?></td>
							<td><?php echo esc_html( $file_change['modified'] ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>

			<h2><?php esc_html_e( 'PHP Files in Uploads and Must-Use Plugins', 'choctaw-wp-security' ); ?></h2>
			<p><?php esc_html_e( 'PHP files in uploads are suspicious. Must-use plugins may be legitimate, but are worth reviewing because they load automatically.', 'choctaw-wp-security' ); ?></p>
			<?php if ( ! empty( $content_php_files ) ) : ?>
				<table class="widefat striped" style="max-width: 960px;">
					<thead>
						<tr>
							<th scope="col"><?php esc_html_e( 'Location', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'File', 'choctaw-wp-security' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Last Modified', 'choctaw-wp-security' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $content_php_files as $php_file ) : ?>
							<tr>
								<td><?php echo esc_html( $php_file['location'] ); ?></td>
								<td><?php echo esc_html( $php_file['path'] ); ?></td>
								<td><?php echo esc_html( $php_file['modified'] ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php else : ?>
				<p><?php esc_html_e( 'No PHP files were found in the uploads or must-use plugins folders.', 'choctaw-wp-security' ); ?></p>
			<?php endif; ?>
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
				<p>
					<?php esc_html_e( 'Please submit feature requests, bugs, and inquiries to its official Github Repository at:', 'choctaw-wp-security' ); ?>
					<a href="https://github.com/steve31266/Choctaw-WP-Security" target="_blank" rel="noopener noreferrer">https://github.com/steve31266/Choctaw-WP-Security</a>
				</p>
				<p>
					<?php esc_html_e( 'Choctaw WP Security was created by Steve Johnson, Lead Developer, Choctaw Websites.', 'choctaw-wp-security' ); ?>
					<a href="https://www.choctawwebsites.com" target="_blank" rel="noopener noreferrer">https://www.choctawwebsites.com</a>
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

		set_transient( $this->get_core_checksum_result_transient_key(), $result, MINUTE_IN_SECONDS );

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

		set_transient( $this->get_exposed_folders_result_transient_key(), $result, MINUTE_IN_SECONDS );

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
	 * Build the transient key used to store the latest exposed folders scan result.
	 *
	 * @return string
	 */
	private function get_exposed_folders_result_transient_key() {
		return 'cws_exposed_folders_' . get_current_user_id();
	}

	/**
	 * Render the exposed folders scan section.
	 *
	 * @return void
	 */
	private function render_exposed_folders_section() {
		$result = false;

		if ( isset( $_GET['exposed_folders_run'] ) ) {
			$result = get_transient( $this->get_exposed_folders_result_transient_key() );
		}
		?>
		<div class="cws-admin-tab-panel">
			<h2><?php esc_html_e( 'Exposed Folders', 'choctaw-wp-security' ); ?></h2>
			<p>
				<?php esc_html_e( 'Run this scan to identify folders within the', 'choctaw-wp-security' ); ?>
				<code>wp-content/themes/</code>
				<?php esc_html_e( 'and', 'choctaw-wp-security' ); ?>
				<code>wp-content/plugins/</code>
				<?php esc_html_e( 'directories that are missing', 'choctaw-wp-security' ); ?>
				<code>/index.php</code>
				<?php esc_html_e( 'files.', 'choctaw-wp-security' ); ?>
			</p>
			<p>
				<strong><?php esc_html_e( 'NOTE:', 'choctaw-wp-security' ); ?></strong>
				<?php esc_html_e( 'If your server already disables directory browsing, then this report is moot. If it does not, then you should either disable directory browsing at the server level, or add', 'choctaw-wp-security' ); ?>
				<code>index.php</code>
				<?php esc_html_e( 'files to each of the exposed folders.', 'choctaw-wp-security' ); ?>
			</p>

			<form method="post">
				<?php wp_nonce_field( 'choctaw_wp_security_exposed_folders_scan' ); ?>
				<input type="hidden" name="choctaw_wp_security_exposed_folders_scan" value="1" />
				<input type="hidden" name="cws_tab" value="exposed-folders" />
				<?php submit_button( __( 'Scan Now', 'choctaw-wp-security' ), 'secondary', 'submit', false ); ?>
			</form>

			<?php if ( is_array( $result ) ) : ?>
				<?php $this->render_exposed_folders_results( $result ); ?>
			<?php endif; ?>

			<?php $this->render_exposed_folders_guidance(); ?>
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
			$result = get_transient( $this->get_core_checksum_result_transient_key() );
		}
		?>
		<h2><?php esc_html_e( 'WP Core Verify-Checksums', 'choctaw-wp-security' ); ?></h2>
		<p>
			<?php esc_html_e( 'WP Core Verify-Checksums compares your installed WordPress core files against official WordPress.org checksums for your current WordPress version and locale. It does not scan plugins, themes, uploads, mu-plugins, or wp-config.php.', 'choctaw-wp-security' ); ?>
		</p>

		<form method="post">
			<?php wp_nonce_field( 'choctaw_wp_security_core_checksum_scan' ); ?>
			<input type="hidden" name="choctaw_wp_security_core_checksum_scan" value="1" />
			<input type="hidden" name="cws_tab" value="verify-checksums" />
			<?php submit_button( __( 'Scan Now', 'choctaw-wp-security' ), 'secondary', 'submit', false ); ?>
		</form>

		<?php if ( is_array( $result ) ) : ?>
			<?php $this->render_core_checksum_results( $result ); ?>
		<?php endif; ?>
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

				<?php if ( ! empty( $result['modified'] ) ) : ?>
					<h3><?php esc_html_e( 'Modified Files', 'choctaw-wp-security' ); ?></h3>
					<table class="widefat striped cws-core-checksum-table">
						<thead>
							<tr>
								<th scope="col"><?php esc_html_e( 'File', 'choctaw-wp-security' ); ?></th>
								<th scope="col"><?php esc_html_e( 'Problem', 'choctaw-wp-security' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $result['modified'] as $file_path ) : ?>
								<tr>
									<td><?php echo esc_html( (string) $file_path ); ?></td>
									<td><?php esc_html_e( 'Checksum mismatch', 'choctaw-wp-security' ); ?></td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>

				<?php if ( ! empty( $result['missing'] ) ) : ?>
					<h3><?php esc_html_e( 'Missing Files', 'choctaw-wp-security' ); ?></h3>
					<table class="widefat striped cws-core-checksum-table">
						<thead>
							<tr>
								<th scope="col"><?php esc_html_e( 'File', 'choctaw-wp-security' ); ?></th>
								<th scope="col"><?php esc_html_e( 'Problem', 'choctaw-wp-security' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $result['missing'] as $file_path ) : ?>
								<tr>
									<td><?php echo esc_html( (string) $file_path ); ?></td>
									<td><?php esc_html_e( 'File not found', 'choctaw-wp-security' ); ?></td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>

				<?php if ( ! empty( $result['unknown'] ) ) : ?>
					<h3><?php esc_html_e( 'Unknown Files', 'choctaw-wp-security' ); ?></h3>
					<p class="description">
						<?php esc_html_e( 'Some hosts and local development tools place extra files in the WordPress root or core directories. Review these files carefully rather than assuming every unknown file is malware.', 'choctaw-wp-security' ); ?>
					</p>
					<table class="widefat striped cws-core-checksum-table">
						<thead>
							<tr>
								<th scope="col"><?php esc_html_e( 'File', 'choctaw-wp-security' ); ?></th>
								<th scope="col"><?php esc_html_e( 'Problem', 'choctaw-wp-security' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $result['unknown'] as $file_path ) : ?>
								<tr>
									<td><?php echo esc_html( (string) $file_path ); ?></td>
									<td><?php esc_html_e( 'Not listed in official checksums', 'choctaw-wp-security' ); ?></td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
					<?php if ( ! empty( $result['unknown_truncated'] ) ) : ?>
						<p class="description">
							<?php
							echo esc_html(
								sprintf(
									/* translators: %d: number of additional unknown files not shown */
									__( '%d additional unknown files were found but are not displayed.', 'choctaw-wp-security' ),
									(int) $result['unknown_truncated']
								)
							);
							?>
						</p>
					<?php endif; ?>
				<?php endif; ?>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Render exposed folders scan results.
	 *
	 * @param array<string, mixed> $result Scan result payload.
	 * @return void
	 */
	private function render_exposed_folders_results( $result ) {
		$plugins   = isset( $result['plugins'] ) && is_array( $result['plugins'] ) ? $result['plugins'] : array();
		$themes    = isset( $result['themes'] ) && is_array( $result['themes'] ) ? $result['themes'] : array();
		$errors    = isset( $result['errors'] ) && is_array( $result['errors'] ) ? $result['errors'] : array();
		$total     = count( $plugins ) + count( $themes );
		$truncated = ! empty( $result['truncated'] );
		?>
		<div class="cws-exposed-folders-results">
			<h3><?php esc_html_e( 'Scan Results', 'choctaw-wp-security' ); ?></h3>
			<p class="cws-core-checksum-summary">
				<?php
				echo esc_html(
					sprintf(
						/* translators: 1: total possible exposed folders, 2: plugin folders count, 3: theme folders count */
						__( '%1$d potentially exposed folders found: %2$d in plugins and %3$d in themes.', 'choctaw-wp-security' ),
						$total,
						count( $plugins ),
						count( $themes )
					)
				);
				?>
			</p>

			<?php if ( 0 === $total ) : ?>
				<p><?php esc_html_e( 'No plugin or theme folders missing directory index files were found.', 'choctaw-wp-security' ); ?></p>
			<?php else : ?>
				<?php $this->render_exposed_folders_table( __( 'Plugin Folders', 'choctaw-wp-security' ), $plugins ); ?>
				<?php $this->render_exposed_folders_table( __( 'Theme Folders', 'choctaw-wp-security' ), $themes ); ?>
			<?php endif; ?>

			<?php if ( $truncated ) : ?>
				<p class="description">
					<?php esc_html_e( 'Additional folders were found but not displayed because the scan reached its result limit.', 'choctaw-wp-security' ); ?>
				</p>
			<?php endif; ?>

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
	 * Render one exposed folders result table.
	 *
	 * @param string             $heading Section heading.
	 * @param array<int, string> $folders Folders missing index files.
	 * @return void
	 */
	private function render_exposed_folders_table( $heading, $folders ) {
		if ( empty( $folders ) ) {
			return;
		}
		?>
		<h4><?php echo esc_html( $heading ); ?></h4>
		<table class="widefat striped cws-core-checksum-table" style="max-width: 960px;">
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'Folder', 'choctaw-wp-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Finding', 'choctaw-wp-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $folders as $folder ) : ?>
					<?php $folder_url = $this->get_public_url_for_display_path( (string) $folder ); ?>
					<tr>
						<td>
							<a href="<?php echo esc_url( $folder_url ); ?>" target="_blank" rel="noopener noreferrer">
								<?php echo esc_html( (string) $folder ); ?>
								<span class="dashicons dashicons-external" style="font-size: 14px; height: 14px; line-height: 14px; vertical-align: super;" aria-hidden="true"></span>
								<span class="screen-reader-text"><?php esc_html_e( 'Opens in a new window', 'choctaw-wp-security' ); ?></span>
							</a>
						</td>
						<td><?php esc_html_e( 'No directory index file found', 'choctaw-wp-security' ); ?></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	/**
	 * Render educational guidance for disabling directory browsing.
	 *
	 * @return void
	 */
	private function render_exposed_folders_guidance() {
		?>
		<div class="cws-exposed-folders-guidance">
			<h3><?php esc_html_e( 'How to Turn Directory Browsing Off', 'choctaw-wp-security' ); ?></h3>

			<h4><?php esc_html_e( 'Apache & LiteSpeed', 'choctaw-wp-security' ); ?></h4>
			<p><?php esc_html_e( 'At the server or virtual host level, disable directory indexes for the site. On hosts that allow Options in .htaccess, this can also be placed in the site root .htaccess file:', 'choctaw-wp-security' ); ?></p>
			<textarea readonly rows="2" class="large-text code" style="max-width: 960px;"><?php echo esc_textarea( 'Options -Indexes' ); ?></textarea>

			<h4><?php esc_html_e( 'Nginx', 'choctaw-wp-security' ); ?></h4>
			<p><?php esc_html_e( 'Nginx does not use .htaccess files. Disable autoindex in the site server block or a more specific location block, then reload Nginx:', 'choctaw-wp-security' ); ?></p>
			<textarea readonly rows="2" class="large-text code" style="max-width: 960px;"><?php echo esc_textarea( 'autoindex off;' ); ?></textarea>

			<h4><?php esc_html_e( 'Folder-Level Fallback', 'choctaw-wp-security' ); ?></h4>
			<p><?php esc_html_e( 'Adding a small index.php file to an individual folder usually prevents that folder from displaying a file listing, even when server-level directory browsing is enabled. Plugin and theme updates may remove manually added files, so server-level configuration is preferred when available.', 'choctaw-wp-security' ); ?></p>
			<textarea readonly rows="3" class="large-text code" style="max-width: 960px;"><?php echo esc_textarea( "<?php\n// Silence is golden.\n" ); ?></textarea>
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
		echo '<p>' . esc_html__( 'Configure login failure thresholds. Both IP-only and IP-plus-username scopes are tracked.', 'choctaw-wp-security' ) . '</p>';
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
	}

	/**
	 * Render the uploads PHP lockdown checkbox with server-aware guidance.
	 *
	 * @param array<string, string> $args Field arguments.
	 * @return void
	 */
	public function render_uploads_lockdown_field( $args ) {
		$this->render_checkbox_field( $args );

		$lockdown = new Choctaw_Wp_Security_Uploads_Php_Lockdown();
		$server   = $lockdown->get_server_type();

		if ( Choctaw_Wp_Security_Uploads_Php_Lockdown::SERVER_NGINX === $server ) {
			echo '<p class="description">' . esc_html__( 'This setting stays enabled to reflect your security policy. On Nginx, enforcement requires manual server configuration shown in the Status section below.', 'choctaw-wp-security' ) . '</p>';
			return;
		}

		if ( Choctaw_Wp_Security_Uploads_Php_Lockdown::SERVER_UNKNOWN === $server ) {
			echo '<p class="description">' . esc_html__( 'When enabled, the plugin will attempt to install a managed .htaccess block in wp-content/uploads, but server support cannot be guaranteed.', 'choctaw-wp-security' ) . '</p>';
		}
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
	 * Retrieve modification details for stable WordPress files commonly targeted by attackers.
	 *
	 * @return array<int, array{label: string, modified: string}>
	 */
	private function get_core_file_changes() {
		$files = array(
			'wp-config.php'               => $this->get_wp_config_path(),
			'.htaccess'                   => ABSPATH . '.htaccess',
			'index.php'                   => ABSPATH . 'index.php',
			'wp-settings.php'             => ABSPATH . 'wp-settings.php',
			'wp-load.php'                 => ABSPATH . 'wp-load.php',
			'wp-blog-header.php'          => ABSPATH . 'wp-blog-header.php',
			'wp-login.php'                => ABSPATH . 'wp-login.php',
			'xmlrpc.php'                  => ABSPATH . 'xmlrpc.php',
			'wp-cron.php'                 => ABSPATH . 'wp-cron.php',
			'wp-includes/functions.php'   => ABSPATH . WPINC . '/functions.php',
			'wp-includes/plugin.php'      => ABSPATH . WPINC . '/plugin.php',
			'wp-admin/admin.php'          => ABSPATH . 'wp-admin/admin.php',
			'wp-admin/includes/file.php'  => ABSPATH . 'wp-admin/includes/file.php',
		);

		$changes = array();

		foreach ( $files as $label => $path ) {
			$changes[] = array(
				'label'    => $label,
				'modified' => $this->format_file_modified_time( $path ),
			);
		}

		return $changes;
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
	 * Scan top-level plugin and theme folders for directories missing index files.
	 *
	 * @return array<string, mixed>
	 */
	private function scan_exposed_folders() {
		$result = array(
			'plugins'   => array(),
			'themes'    => array(),
			'errors'    => array(),
			'truncated' => false,
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

		$limit = 300;

		foreach ( $sources as $key => $source ) {
			$scan = $this->find_top_level_folders_missing_index_files( $source['path'], $limit );

			$result[ $key ] = $scan['folders'];

			if ( ! empty( $scan['truncated'] ) ) {
				$result['truncated'] = true;
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
}
