<?php
/**
 * Login rate limiting module.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Tracks failed logins and applies transient-based lockouts.
 */
class Choctaw_Wp_Security_Login_Rate_Limiter {

	const LOCKOUT_ERROR_CODE   = 'choctaw_wp_security_too_many_attempts';
	const LOCKOUT_QUERY_ARG    = 'cws_lockout';
	const LOCKOUT_NOTICE_COOKIE = 'cws_lockout_notice';

	/**
	 * Register module hooks.
	 *
	 * @return void
	 */
	public function register_hooks() {
		if ( ! $this->is_enabled() ) {
			return;
		}

		add_action( 'login_init', array( $this, 'maybe_intercept_locked_out_login' ), 1 );
		add_filter( 'authenticate', array( $this, 'maybe_block_locked_out_user' ), 1, 3 );
		add_action( 'wp_login_failed', array( $this, 'handle_failed_login' ), 10, 2 );
		add_action( 'wp_login', array( $this, 'handle_successful_login' ), 10, 2 );
		add_filter( 'wp_login_errors', array( $this, 'add_lockout_login_error' ), 10, 2 );
		add_filter( 'login_message', array( $this, 'add_lockout_login_message' ) );
		add_filter( 'login_body_class', array( $this, 'add_lockout_body_class' ), 10, 1 );
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_login_styles' ) );
	}

	/**
	 * Determine whether login rate limiting is enabled.
	 *
	 * @return bool
	 */
	private function is_enabled() {
		return Choctaw_Wp_Security_Utils::is_enabled( 'login_rate_limit_enabled' );
	}

	/**
	 * Retrieve current rate-limit policy values.
	 *
	 * @return array<string, int>
	 */
	private function get_policy() {
		$options = Choctaw_Wp_Security_Utils::get_options();

		return array(
			'allowed_failed_attempts'  => max( 1, (int) $options['allowed_failed_attempts'] ),
			'failure_window_seconds'   => Choctaw_Wp_Security_Utils::minutes_to_seconds( (int) $options['failure_window_minutes'] ),
			'lockout_duration_seconds' => Choctaw_Wp_Security_Utils::minutes_to_seconds( (int) $options['lockout_duration_minutes'] ),
		);
	}

	/**
	 * Redirect locked-out POST requests before WordPress runs the login pipeline.
	 *
	 * Avoids sending blocked attempts through wp_signon(), which can trigger
	 * host-level errors on some shared hosting environments.
	 *
	 * @return void
	 */
	public function maybe_intercept_locked_out_login() {
		if ( 'POST' !== $_SERVER['REQUEST_METHOD'] ) {
			return;
		}

		if ( empty( $_POST['log'] ) ) {
			return;
		}

		$ip       = Choctaw_Wp_Security_Utils::get_client_ip();
		$username = Choctaw_Wp_Security_Utils::normalize_username( wp_unslash( $_POST['log'] ) );

		if ( ! $this->is_locked_out( $ip, $username ) ) {
			return;
		}

		$this->flag_lockout_notice();
		wp_safe_redirect( $this->get_lockout_redirect_url() );
		exit;
	}

	/**
	 * Block authentication when either lockout scope is active.
	 *
	 * @param WP_User|WP_Error|null $user     Existing auth result.
	 * @param string                $username Attempted username.
	 * @param string                $password Attempted password.
	 * @return WP_User|WP_Error|null
	 */
	public function maybe_block_locked_out_user( $user, $username, $password ) {
		unset( $password );

		$ip       = Choctaw_Wp_Security_Utils::get_client_ip();
		$username = Choctaw_Wp_Security_Utils::normalize_username( $username );

		if ( $this->is_locked_out( $ip, $username ) ) {
			return $this->lockout_error();
		}

		return $user;
	}

	/**
	 * Increment failure counters and create lockouts when thresholds are reached.
	 *
	 * @param string   $username Attempted username.
	 * @param WP_Error $error    Login failure error.
	 * @return void
	 */
	public function handle_failed_login( $username, $error ) {
		unset( $error );

		$ip       = Choctaw_Wp_Security_Utils::get_client_ip();
		$username = Choctaw_Wp_Security_Utils::normalize_username( $username );
		$policy   = $this->get_policy();

		if ( $this->is_locked_out( $ip, $username ) ) {
			$this->flag_lockout_notice();
			return;
		}

		$lockout_created = false;

		$lockout_created = $this->increment_failures_and_maybe_lock(
			Choctaw_Wp_Security_Utils::failure_key_ip( $ip ),
			Choctaw_Wp_Security_Utils::lockout_key_ip( $ip ),
			$policy,
			$ip,
			$username,
			'ip'
		) || $lockout_created;

		$lockout_created = $this->increment_failures_and_maybe_lock(
			Choctaw_Wp_Security_Utils::failure_key_ip_user( $ip, $username ),
			Choctaw_Wp_Security_Utils::lockout_key_ip_user( $ip, $username ),
			$policy,
			$ip,
			$username,
			'ip_user'
		) || $lockout_created;

		if ( $lockout_created ) {
			$this->flag_lockout_notice();
		}
	}

	/**
	 * Clear IP-plus-username failures after a successful login.
	 *
	 * @param string  $user_login Successful username.
	 * @param WP_User $user       Authenticated user object.
	 * @return void
	 */
	public function handle_successful_login( $user_login, $user ) {
		unset( $user );

		$ip       = Choctaw_Wp_Security_Utils::get_client_ip();
		$username = Choctaw_Wp_Security_Utils::normalize_username( $user_login );

		delete_transient( Choctaw_Wp_Security_Utils::failure_key_ip_user( $ip, $username ) );
		$this->clear_lockout_notice_flag();
	}

	/**
	 * Replace generic login errors with the lockout message when appropriate.
	 *
	 * @param WP_Error $errors      Login page errors.
	 * @param string   $redirect_to Redirect target.
	 * @return WP_Error
	 */
	public function add_lockout_login_error( $errors, $redirect_to ) {
		unset( $redirect_to );

		if ( ! $this->should_display_lockout_notice() ) {
			return $errors;
		}

		$this->clear_lockout_notice_flag();

		return new WP_Error();
	}

	/**
	 * Render a styled lockout notice above the login form.
	 *
	 * @param string $message Existing login message HTML.
	 * @return string
	 */
	public function add_lockout_login_message( $message ) {
		if ( ! $this->should_display_lockout_notice() ) {
			return $message;
		}

		$notice  = '<div class="cws-lockout-notice" role="alert">';
		$notice .= '<p class="cws-lockout-notice__title">' . esc_html__( 'Login temporarily unavailable', 'choctaw-wp-security' ) . '</p>';
		$notice .= '<p class="cws-lockout-notice__message">' . esc_html( $this->get_lockout_message() ) . '</p>';
		$notice .= '</div>';

		return $message . $notice;
	}

	/**
	 * Add a body class so lockout styles can be scoped to the login screen.
	 *
	 * @param array<int, string> $classes Existing body classes.
	 * @return array<int, string>
	 */
	public function add_lockout_body_class( $classes ) {
		if ( $this->should_display_lockout_notice() ) {
			$classes[] = 'cws-lockout-active';
		}

		return $classes;
	}

	/**
	 * Enqueue login screen styles for lockout messaging.
	 *
	 * @return void
	 */
	public function enqueue_login_styles() {
		if ( ! $this->should_display_lockout_notice() ) {
			return;
		}

		wp_enqueue_style(
			'choctaw-wp-security-login-lockout',
			CHOCTAW_WP_SECURITY_URL . 'assets/css/login-lockout.css',
			array( 'login' ),
			CHOCTAW_WP_SECURITY_VERSION
		);
	}

	/**
	 * Determine whether either lockout scope is active.
	 *
	 * @param string $ip       Client IP address.
	 * @param string $username Normalized username.
	 * @return bool
	 */
	private function is_locked_out( $ip, $username ) {
		return (bool) get_transient( Choctaw_Wp_Security_Utils::lockout_key_ip( $ip ) )
			|| (bool) get_transient( Choctaw_Wp_Security_Utils::lockout_key_ip_user( $ip, $username ) );
	}

	/**
	 * Increment a failure counter and create a lockout when needed.
	 *
	 * @param string             $failure_key Failure transient key.
	 * @param string             $lockout_key Lockout transient key.
	 * @param array<string, int> $policy      Rate-limit policy values.
	 * @param string             $ip          Client IP address.
	 * @param string             $username    Normalized username.
	 * @param string             $scope       Lockout scope identifier.
	 * @return bool Whether a new lockout was created.
	 */
	private function increment_failures_and_maybe_lock( $failure_key, $lockout_key, $policy, $ip, $username, $scope ) {
		if ( get_transient( $lockout_key ) ) {
			return false;
		}

		$failures = get_transient( $failure_key );

		if ( false === $failures ) {
			$failures = 0;
		}

		$failures = (int) $failures + 1;

		set_transient( $failure_key, $failures, $policy['failure_window_seconds'] );

		if ( $failures < $policy['allowed_failed_attempts'] ) {
			return false;
		}

		$created = set_transient( $lockout_key, 1, $policy['lockout_duration_seconds'] );

		if ( $created ) {
			$this->log_lockout( $ip, $username, $policy['lockout_duration_seconds'], $scope );
		}

		return (bool) $created;
	}

	/**
	 * Record a lockout event in the recent log.
	 *
	 * @param string $ip               Client IP address.
	 * @param string $username         Attempted username.
	 * @param int    $lockout_duration Lockout duration in seconds.
	 * @param string $scope            Lockout scope identifier.
	 * @return void
	 */
	private function log_lockout( $ip, $username, $lockout_duration, $scope ) {
		$display_username = ( Choctaw_Wp_Security_Utils::EMPTY_USERNAME_KEY === $username ) ? '(empty)' : $username;

		Choctaw_Wp_Security_Utils::log_lockout_event(
			$ip,
			$display_username,
			$lockout_duration,
			$scope
		);
	}

	/**
	 * Determine whether the login screen should show lockout messaging.
	 *
	 * @return bool
	 */
	private function should_display_lockout_notice() {
		if ( isset( $_GET[ self::LOCKOUT_QUERY_ARG ] ) && '1' === $_GET[ self::LOCKOUT_QUERY_ARG ] ) {
			return true;
		}

		if ( isset( $_COOKIE[ self::LOCKOUT_NOTICE_COOKIE ] ) && '1' === $_COOKIE[ self::LOCKOUT_NOTICE_COOKIE ] ) {
			return true;
		}

		if ( 'POST' === $_SERVER['REQUEST_METHOD'] ) {
			return false;
		}

		$ip       = Choctaw_Wp_Security_Utils::get_client_ip();
		$username = '';

		if ( isset( $_REQUEST['log'] ) ) {
			$username = Choctaw_Wp_Security_Utils::normalize_username( wp_unslash( $_REQUEST['log'] ) );
		}

		return $this->is_locked_out( $ip, $username );
	}

	/**
	 * Build the login URL used after a blocked attempt.
	 *
	 * @return string
	 */
	private function get_lockout_redirect_url() {
		$redirect_to = '';

		if ( isset( $_REQUEST['redirect_to'] ) ) {
			$redirect_to = wp_unslash( $_REQUEST['redirect_to'] );
		}

		$login_url = wp_login_url( $redirect_to, true );

		return add_query_arg( self::LOCKOUT_QUERY_ARG, '1', $login_url );
	}

	/**
	 * Persist a short-lived flag so the next login page load shows the notice.
	 *
	 * @return void
	 */
	private function flag_lockout_notice() {
		if ( headers_sent() ) {
			return;
		}

		setcookie(
			self::LOCKOUT_NOTICE_COOKIE,
			'1',
			time() + MINUTE_IN_SECONDS,
			COOKIEPATH,
			COOKIE_DOMAIN,
			is_ssl(),
			true
		);

		$_COOKIE[ self::LOCKOUT_NOTICE_COOKIE ] = '1';
	}

	/**
	 * Clear the short-lived lockout notice cookie.
	 *
	 * @return void
	 */
	private function clear_lockout_notice_flag() {
		if ( headers_sent() ) {
			return;
		}

		setcookie(
			self::LOCKOUT_NOTICE_COOKIE,
			'',
			time() - YEAR_IN_SECONDS,
			COOKIEPATH,
			COOKIE_DOMAIN,
			is_ssl(),
			true
		);

		unset( $_COOKIE[ self::LOCKOUT_NOTICE_COOKIE ] );
	}

	/**
	 * Build the generic lockout error response.
	 *
	 * @return WP_Error
	 */
	private function lockout_error() {
		return new WP_Error(
			self::LOCKOUT_ERROR_CODE,
			$this->get_lockout_message()
		);
	}

	/**
	 * Return the public lockout message shown to visitors.
	 *
	 * @return string
	 */
	private function get_lockout_message() {
		return __( 'Too many failed login attempts. Please try again later.', 'choctaw-wp-security' );
	}
}
