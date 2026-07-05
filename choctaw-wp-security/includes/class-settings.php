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
			'xmlrpc_blocking_enabled'  => ! empty( $input['xmlrpc_blocking_enabled'] ),
			'login_rate_limit_enabled' => ! empty( $input['login_rate_limit_enabled'] ),
			'allowed_failed_attempts'  => $this->clamp_int( $input, 'allowed_failed_attempts', 1, 100, $defaults['allowed_failed_attempts'] ),
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

		$options = Choctaw_Wp_Security_Utils::get_options();
		$events  = Choctaw_Wp_Security_Utils::get_lockout_log();
		?>
		<div class="wrap">
			<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>

			<form action="options.php" method="post">
				<?php
				settings_fields( 'choctaw_wp_security' );
				do_settings_sections( 'choctaw-wp-security' );
				submit_button();
				?>
			</form>

			<hr>

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

			<?php if ( ! empty( $events ) ) : ?>
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
			<?php endif; ?>
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
