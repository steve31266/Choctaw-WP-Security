<?php
/**
 * Username discovery protection module.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Blocks common username discovery vectors for anonymous visitors.
 */
class Choctaw_Wp_Security_Username_Discovery_Protection {

	const REST_USERS_ROUTE_PATTERN = '#^/wp/v2/users(?:/|\z)#';

	/**
	 * Register module hooks.
	 *
	 * @return void
	 */
	public function register_hooks() {
		if ( Choctaw_Wp_Security_Utils::is_enabled( 'block_user_rest_api_enabled' ) ) {
			add_filter( 'rest_pre_dispatch', array( $this, 'maybe_block_users_rest_route' ), 10, 3 );
		}

		if ( Choctaw_Wp_Security_Utils::is_enabled( 'block_author_query_enabled' )
			|| Choctaw_Wp_Security_Utils::is_enabled( 'block_author_archives_enabled' ) ) {
			add_action( 'template_redirect', array( $this, 'maybe_block_author_discovery' ), 0 );
		}

		if ( Choctaw_Wp_Security_Utils::is_enabled( 'normalize_login_errors_enabled' ) ) {
			add_filter( 'login_errors', array( $this, 'normalize_login_errors' ) );
		}
	}

	/**
	 * Block anonymous access to the users REST API routes.
	 *
	 * @param mixed                 $result  Response to replace the requested version with.
	 * @param WP_REST_Server        $server  Server instance.
	 * @param WP_REST_Request       $request Request used to generate the response.
	 * @return mixed
	 */
	public function maybe_block_users_rest_route( $result, $server, $request ) {
		unset( $server );

		if ( is_user_logged_in() ) {
			return $result;
		}

		$route = (string) $request->get_route();

		if ( ! preg_match( self::REST_USERS_ROUTE_PATTERN, $route ) ) {
			return $result;
		}

		return new WP_Error(
			'rest_forbidden',
			__( 'Sorry, you are not allowed to do that.', 'choctaw-wp-security' ),
			array( 'status' => 403 )
		);
	}

	/**
	 * Block anonymous author query and author archive discovery routes.
	 *
	 * @return void
	 */
	public function maybe_block_author_discovery() {
		if ( is_user_logged_in() ) {
			return;
		}

		if ( Choctaw_Wp_Security_Utils::is_enabled( 'block_author_query_enabled' )
			&& isset( $_GET['author'] )
			&& ctype_digit( (string) wp_unslash( $_GET['author'] ) ) ) {
			$this->send_forbidden_response();
		}

		if ( Choctaw_Wp_Security_Utils::is_enabled( 'block_author_archives_enabled' ) && is_author() ) {
			$this->send_forbidden_response();
		}
	}

	/**
	 * Replace distinct login failure messages with a single generic message.
	 *
	 * @param string $error Existing login error HTML.
	 * @return string
	 */
	public function normalize_login_errors( $error ) {
		$error = trim( (string) $error );

		if ( '' === $error ) {
			return $error;
		}

		$lockout_message = __( 'Too many failed login attempts. Please try again later.', 'choctaw-wp-security' );

		if ( false !== stripos( $error, $lockout_message ) ) {
			return $error;
		}

		return esc_html__( 'Failed login, please try again.', 'choctaw-wp-security' );
	}

	/**
	 * Send a 403 response using the theme template when available.
	 *
	 * @return void
	 */
	private function send_forbidden_response() {
		status_header( 403 );
		nocache_headers();

		$template = get_query_template( '403' );

		if ( $template ) {
			include $template;
			exit;
		}

		wp_die( '', '', array( 'response' => 403 ) );
	}
}
