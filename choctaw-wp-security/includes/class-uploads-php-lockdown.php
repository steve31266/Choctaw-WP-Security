<?php
/**
 * Uploads PHP execution lockdown module.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Manages server-aware PHP execution blocking in the uploads directory.
 */
class Choctaw_Wp_Security_Uploads_Php_Lockdown {

	const MARKER_BEGIN = '# BEGIN Choctaw WP Security';
	const MARKER_END   = '# END Choctaw WP Security';

	const SERVER_APACHE   = 'apache';
	const SERVER_NGINX      = 'nginx';
	const SERVER_UNKNOWN    = 'unknown';

	const STATUS_PROTECTED           = 'protected';
	const STATUS_NGINX_MANUAL        = 'nginx_manual';
	const STATUS_UNKNOWN_INSTALLED   = 'unknown_installed';
	const STATUS_UNABLE_TO_WRITE     = 'unable_to_write';
	const STATUS_DISABLED            = 'disabled';

	/**
	 * Register module hooks.
	 *
	 * @return void
	 */
	public function register_hooks() {
		add_action( 'update_option_' . Choctaw_Wp_Security_Utils::OPTION_KEY, array( $this, 'apply_policy' ), 10, 0 );
	}

	/**
	 * Apply the uploads PHP lockdown policy based on current settings and server.
	 *
	 * @return void
	 */
	public function apply_policy() {
		if ( ! Choctaw_Wp_Security_Utils::is_enabled( 'uploads_php_lockdown_enabled' ) ) {
			$this->remove_managed_block();
			return;
		}

		$server = $this->get_server_type();

		if ( self::SERVER_NGINX === $server ) {
			return;
		}

		if ( self::SERVER_APACHE === $server || self::SERVER_UNKNOWN === $server ) {
			$this->install_managed_block();
		}
	}

	/**
	 * Detect the web server type from SERVER_SOFTWARE.
	 *
	 * @return string One of SERVER_APACHE, SERVER_NGINX, or SERVER_UNKNOWN.
	 */
	public function get_server_type() {
		$software = isset( $_SERVER['SERVER_SOFTWARE'] )
			? strtolower( (string) wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) )
			: '';

		if ( '' === $software ) {
			return self::SERVER_UNKNOWN;
		}

		if ( false !== strpos( $software, 'nginx' ) ) {
			return self::SERVER_NGINX;
		}

		if (
			false !== strpos( $software, 'apache' )
			|| false !== strpos( $software, 'litespeed' )
			|| false !== strpos( $software, 'openlitespeed' )
		) {
			return self::SERVER_APACHE;
		}

		return self::SERVER_UNKNOWN;
	}

	/**
	 * Retrieve the managed marker block content.
	 *
	 * @return string
	 */
	public function get_marker_block() {
		return self::MARKER_BEGIN . "\n\n"
			. '<FilesMatch "\.(php|phtml|php3|php4|php5|php7|php8|phar)$">' . "\n"
			. "Require all denied\n"
			. "</FilesMatch>\n\n"
			. self::MARKER_END;
	}

	/**
	 * Retrieve the copyable Nginx configuration snippet.
	 *
	 * @return string
	 */
	public function get_nginx_snippet() {
		return "location ~* ^/wp-content/uploads/.*\\.(php|phtml|php3|php4|php5|php7|php8|phar)$ {\n"
			. "    deny all;\n"
			. "    return 403;\n"
			. '}';
	}

	/**
	 * Resolve the uploads .htaccess file path.
	 *
	 * @return string
	 */
	public function get_uploads_htaccess_path() {
		$uploads = wp_get_upload_dir();

		if ( empty( $uploads['basedir'] ) ) {
			return '';
		}

		return trailingslashit( $uploads['basedir'] ) . '.htaccess';
	}

	/**
	 * Determine whether the plugin-managed marker block is present.
	 *
	 * @return bool
	 */
	public function has_managed_block() {
		$path = $this->get_uploads_htaccess_path();

		if ( '' === $path || ! file_exists( $path ) ) {
			return false;
		}

		$contents = file_get_contents( $path );

		if ( false === $contents ) {
			return false;
		}

		return $this->content_has_managed_block( $contents );
	}

	/**
	 * Install or update the managed marker block in uploads .htaccess.
	 *
	 * @return bool Whether the managed block is present after the attempt.
	 */
	public function install_managed_block() {
		$path = $this->get_uploads_htaccess_path();

		if ( '' === $path ) {
			return false;
		}

		$uploads_dir = dirname( $path );

		if ( ! is_dir( $uploads_dir ) || ! is_writable( $uploads_dir ) ) {
			return false;
		}

		$existing = '';

		if ( file_exists( $path ) ) {
			if ( ! is_writable( $path ) ) {
				return false;
			}

			$existing = file_get_contents( $path );

			if ( false === $existing ) {
				return false;
			}
		}

		$updated = $this->replace_managed_block( $existing, $this->get_marker_block() );
		$result  = file_put_contents( $path, $updated, LOCK_EX );

		return false !== $result && $this->has_managed_block();
	}

	/**
	 * Remove the plugin-managed marker block from uploads .htaccess.
	 *
	 * @return bool
	 */
	public function remove_managed_block() {
		$path = $this->get_uploads_htaccess_path();

		if ( '' === $path || ! file_exists( $path ) || ! is_writable( $path ) ) {
			return true;
		}

		$existing = file_get_contents( $path );

		if ( false === $existing ) {
			return false;
		}

		if ( ! $this->content_has_managed_block( $existing ) ) {
			return true;
		}

		$updated = $this->replace_managed_block( $existing, '' );
		$updated = trim( $updated );

		if ( '' === $updated ) {
			return unlink( $path );
		}

		return false !== file_put_contents( $path, $updated . "\n", LOCK_EX );
	}

	/**
	 * Retrieve the current enforcement status for admin display.
	 *
	 * @return array{key: string, label: string, note: string}
	 */
	public function get_status() {
		if ( ! Choctaw_Wp_Security_Utils::is_enabled( 'uploads_php_lockdown_enabled' ) ) {
			return array(
				'key'   => self::STATUS_DISABLED,
				'label' => __( 'Disabled', 'choctaw-wp-security' ),
				'note'  => '',
			);
		}

		$server = $this->get_server_type();

		if ( self::SERVER_NGINX === $server ) {
			return array(
				'key'   => self::STATUS_NGINX_MANUAL,
				'label' => __( 'Manual Nginx configuration required', 'choctaw-wp-security' ),
				'note'  => __( 'This plugin cannot enforce uploads PHP blocking on Nginx. Add the server configuration snippet below to your site block.', 'choctaw-wp-security' ),
			);
		}

		if ( $this->has_managed_block() ) {
			if ( self::SERVER_UNKNOWN === $server ) {
				return array(
					'key'   => self::STATUS_UNKNOWN_INSTALLED,
					'label' => __( 'Managed .htaccess block installed; server support unknown', 'choctaw-wp-security' ),
					'note'  => __( 'The managed block was written, but this server may not honor <code class="cws-file-path">.htaccess</code> files. Verify enforcement separately if possible.', 'choctaw-wp-security' ),
				);
			}

			return array(
				'key'   => self::STATUS_PROTECTED,
				'label' => __( 'Protected by managed .htaccess block', 'choctaw-wp-security' ),
				'note'  => __( 'The plugin installed its managed block in <code class="cws-file-path">wp-content/uploads/.htaccess</code>. This indicates the rule is in place, not that PHP execution has been independently verified.', 'choctaw-wp-security' ),
			);
		}

		return array(
			'key'   => self::STATUS_UNABLE_TO_WRITE,
			'label' => __( 'Unable to write uploads .htaccess', 'choctaw-wp-security' ),
			'note'  => __( 'The uploads directory or <code class="cws-file-path">.htaccess</code> file is missing or not writable by WordPress.', 'choctaw-wp-security' ),
		);
	}

	/**
	 * Determine whether content contains the managed marker block.
	 *
	 * @param string $contents File contents.
	 * @return bool
	 */
	private function content_has_managed_block( $contents ) {
		return false !== strpos( $contents, self::MARKER_BEGIN )
			&& false !== strpos( $contents, self::MARKER_END );
	}

	/**
	 * Replace or remove the managed marker block within .htaccess content.
	 *
	 * @param string $contents Existing file contents.
	 * @param string $block    Managed block to insert, or empty string to remove.
	 * @return string
	 */
	private function replace_managed_block( $contents, $block ) {
		$pattern = '/\s*' . preg_quote( self::MARKER_BEGIN, '/' ) . '.*?'
			. preg_quote( self::MARKER_END, '/' ) . '\s*/s';

		$updated = preg_replace( $pattern, "\n", $contents );

		if ( null === $updated ) {
			$updated = $contents;
		}

		$updated = trim( $updated );

		if ( '' === $block ) {
			return $updated;
		}

		if ( '' !== $updated ) {
			return $updated . "\n\n" . trim( $block ) . "\n";
		}

		return trim( $block ) . "\n";
	}
}
