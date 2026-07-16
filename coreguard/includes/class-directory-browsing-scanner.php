<?php
/**
 * Directory browsing detection (site root .htaccess + public folder roots).
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Detects directory browsing posture and returns standard report findings.
 */
class Choctaw_Wp_Security_Directory_Browsing_Scanner {

	const BROWSING_BLOCKED     = 'blocked';
	const BROWSING_NOT_BLOCKED = 'not_blocked';
	const BROWSING_UNKNOWN     = 'unknown';

	const METHOD_HTACCESS       = 'htaccess';
	const METHOD_DIRECTORY_TEST = 'directory_test';

	const SERVER_APACHE    = 'apache';
	const SERVER_LITESPEED = 'litespeed';
	const SERVER_NGINX     = 'nginx';
	const SERVER_UNKNOWN   = 'unknown';

	const HTTP_TIMEOUT = 10;

	const FOLDER_PLUGINS = 'plugins';
	const FOLDER_THEMES  = 'themes';
	const FOLDER_UPLOADS = 'uploads';

	/**
	 * Run directory browsing checks.
	 *
	 * @return array<string, mixed>
	 */
	public function scan() {
		$server_type = $this->get_server_type();
		$htaccess    = $this->analyze_htaccess( $server_type );
		$folders     = array();

		foreach ( $this->get_folder_targets() as $folder_key => $target ) {
			$folders[] = $this->probe_folder( $folder_key, $target, $server_type );
		}

		$findings = array();

		if ( ! empty( $htaccess['include_finding'] ) ) {
			$findings[] = $this->build_htaccess_finding( $htaccess, $folders, $server_type );
		}

		$htaccess_blocks = ! empty( $htaccess['blocks'] );

		foreach ( $folders as $folder ) {
			$findings[] = $this->build_folder_finding( $folder, $htaccess_blocks, $server_type );
		}

		$summary = $this->build_summary( $findings );

		return array(
			'success'     => true,
			'findings'    => $findings,
			'summary'     => $summary,
			'server_type' => $server_type,
			'scanned_at'  => time(),
		);
	}

	/**
	 * Category labels for UI filters (Testing Method).
	 *
	 * @return array<string, string>
	 */
	public static function get_category_labels() {
		return array(
			self::METHOD_HTACCESS       => __( '.htaccess', 'choctaw-wp-security' ),
			self::METHOD_DIRECTORY_TEST => __( 'Directory Test', 'choctaw-wp-security' ),
		);
	}

	/**
	 * Label for a browsing state key.
	 *
	 * @param string $state blocked|not_blocked|unknown.
	 * @return string
	 */
	public static function browsing_label( $state ) {
		switch ( (string) $state ) {
			case self::BROWSING_BLOCKED:
				return __( 'Blocked', 'choctaw-wp-security' );
			case self::BROWSING_NOT_BLOCKED:
				return __( 'Not Blocked', 'choctaw-wp-security' );
			default:
				return __( 'Unknown', 'choctaw-wp-security' );
		}
	}

	/**
	 * Label for a server type key.
	 *
	 * @param string $server_type Server type.
	 * @return string
	 */
	public static function server_type_label( $server_type ) {
		switch ( (string) $server_type ) {
			case self::SERVER_APACHE:
				return __( 'Apache', 'choctaw-wp-security' );
			case self::SERVER_LITESPEED:
				return __( 'LiteSpeed', 'choctaw-wp-security' );
			case self::SERVER_NGINX:
				return __( 'Nginx', 'choctaw-wp-security' );
			default:
				return __( 'Unknown', 'choctaw-wp-security' );
		}
	}

	/**
	 * Detect the web server type from SERVER_SOFTWARE.
	 *
	 * @return string One of the SERVER_* constants.
	 */
	public function get_server_type() {
		$software = isset( $_SERVER['SERVER_SOFTWARE'] )
			? strtolower( (string) wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) )
			: '';

		if ( '' === $software ) {
			return self::SERVER_UNKNOWN;
		}

		if (
			false !== strpos( $software, 'litespeed' )
			|| false !== strpos( $software, 'openlitespeed' )
		) {
			return self::SERVER_LITESPEED;
		}

		if ( false !== strpos( $software, 'nginx' ) ) {
			return self::SERVER_NGINX;
		}

		if ( false !== strpos( $software, 'apache' ) ) {
			return self::SERVER_APACHE;
		}

		return self::SERVER_UNKNOWN;
	}

	/**
	 * Folder roots to HTTP-test.
	 *
	 * @return array<string, array{label: string, absolute_path: string, display_path: string}>
	 */
	private function get_folder_targets() {
		$plugins = defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR : WP_CONTENT_DIR . '/plugins';
		$themes  = get_theme_root();
		$uploads = wp_get_upload_dir();
		$upload_basedir = isset( $uploads['basedir'] ) ? (string) $uploads['basedir'] : ( WP_CONTENT_DIR . '/uploads' );

		return array(
			self::FOLDER_PLUGINS => array(
				'label'         => __( 'Plugins', 'choctaw-wp-security' ),
				'absolute_path' => $plugins,
				'display_path'  => $this->format_display_path( $plugins ),
			),
			self::FOLDER_THEMES  => array(
				'label'         => __( 'Themes', 'choctaw-wp-security' ),
				'absolute_path' => $themes,
				'display_path'  => $this->format_display_path( $themes ),
			),
			self::FOLDER_UPLOADS => array(
				'label'         => __( 'Uploads', 'choctaw-wp-security' ),
				'absolute_path' => $upload_basedir,
				'display_path'  => $this->format_display_path( $upload_basedir ),
			),
		);
	}

	/**
	 * Analyze site-root .htaccess.
	 *
	 * @param string $server_type Detected server type.
	 * @return array<string, mixed>
	 */
	private function analyze_htaccess( $server_type ) {
		$path = trailingslashit( ABSPATH ) . '.htaccess';
		$result = array(
			'include_finding'   => false,
			'exists'            => false,
			'readable'          => false,
			'blocks'            => false,
			'indexes_state'     => null,
			'browsing'          => self::BROWSING_UNKNOWN,
			'contents'          => '',
			'contents_truncated' => false,
			'absolute_path'     => $path,
			'display_path'      => '.htaccess',
			'unknown_reason'    => 'not_found',
		);

		$exists = file_exists( $path );

		if ( self::SERVER_NGINX === $server_type ) {
			if ( ! $exists ) {
				return $result;
			}

			$result['include_finding'] = true;
			$result['exists']          = true;
			$result['browsing']        = self::BROWSING_UNKNOWN;
			$result['unknown_reason']  = 'nginx_ignores';

			if ( is_readable( $path ) ) {
				$result['readable'] = true;
				$preview            = Choctaw_Wp_Security_Utils::read_file_contents_preview_result( $path );
				$result['contents'] = isset( $preview['contents'] ) ? (string) $preview['contents'] : '';
				$result['contents_truncated'] = ! empty( $preview['truncated'] );
			} else {
				$result['unknown_reason'] = 'unreadable';
			}

			return $result;
		}

		// Apache, LiteSpeed, or unknown: always report .htaccess posture.
		$result['include_finding'] = true;

		if ( ! $exists ) {
			$result['unknown_reason'] = 'not_found';
			$result['browsing']       = self::BROWSING_UNKNOWN;
			return $result;
		}

		$result['exists'] = true;

		if ( ! is_readable( $path ) ) {
			$result['unknown_reason'] = 'unreadable';
			$result['browsing']       = self::BROWSING_UNKNOWN;
			return $result;
		}

		$result['readable'] = true;
		$preview            = Choctaw_Wp_Security_Utils::read_file_contents_preview_result( $path );
		$result['contents'] = isset( $preview['contents'] ) ? (string) $preview['contents'] : '';
		$result['contents_truncated'] = ! empty( $preview['truncated'] );

		if ( '' === trim( $result['contents'] ) && empty( $result['contents_truncated'] ) ) {
			$result['unknown_reason'] = 'not_found';
			$result['browsing']       = self::BROWSING_UNKNOWN;
			return $result;
		}

		$indexes_state = $this->parse_htaccess_indexes_state( $result['contents'] );
		$result['indexes_state'] = $indexes_state;

		if ( 'off' === $indexes_state ) {
			$result['blocks']         = true;
			$result['browsing']       = self::BROWSING_BLOCKED;
			$result['unknown_reason'] = '';
		} elseif ( 'on' === $indexes_state ) {
			$result['blocks']         = false;
			$result['browsing']       = self::BROWSING_NOT_BLOCKED;
			$result['unknown_reason'] = '';
		} else {
			$result['blocks']         = false;
			$result['browsing']       = self::BROWSING_UNKNOWN;
			$result['unknown_reason'] = 'inconclusive';
		}

		return $result;
	}

	/**
	 * Parse .htaccess content for Options +/-Indexes directives.
	 *
	 * @param string $content .htaccess file contents.
	 * @return string|null off, on, or null when inconclusive.
	 */
	private function parse_htaccess_indexes_state( $content ) {
		$lines = preg_split( '/\R/', (string) $content );

		if ( ! is_array( $lines ) ) {
			return null;
		}

		$indexes_enabled  = null;
		$indexes_disabled = false;

		foreach ( $lines as $line ) {
			$line = trim( (string) $line );

			if ( '' === $line || 0 === strpos( $line, '#' ) ) {
				continue;
			}

			if ( ! preg_match( '/^\s*Options\b(.+)$/i', $line, $matches ) ) {
				continue;
			}

			$tokens = preg_split( '/\s+/', trim( (string) $matches[1] ) );

			if ( ! is_array( $tokens ) ) {
				continue;
			}

			foreach ( $tokens as $token ) {
				$token = trim( (string) $token );

				if ( '' === $token || 0 === strpos( $token, '#' ) ) {
					continue;
				}

				if ( preg_match( '/^([+-]?)Indexes$/i', $token, $option_match ) ) {
					$sign = strtolower( (string) $option_match[1] );

					if ( '-' === $sign ) {
						$indexes_disabled = true;
					} elseif ( '+' === $sign || '' === $sign ) {
						$indexes_enabled = true;
					}
				} elseif ( preg_match( '/^([+-]?)All$/i', $token, $all_match ) ) {
					$sign = strtolower( (string) $all_match[1] );

					if ( '-' === $sign ) {
						$indexes_disabled = true;
					} elseif ( '+' === $sign || '' === $sign ) {
						$indexes_enabled = true;
					}
				}
			}
		}

		if ( $indexes_disabled && ! $indexes_enabled ) {
			return 'off';
		}

		if ( $indexes_enabled && ! $indexes_disabled ) {
			return 'on';
		}

		return null;
	}

	/**
	 * Probe one public folder root.
	 *
	 * @param string               $folder_key  Folder key.
	 * @param array<string, string> $target     Target metadata.
	 * @param string               $server_type Server type.
	 * @return array<string, mixed>
	 */
	private function probe_folder( $folder_key, array $target, $server_type ) {
		$absolute = isset( $target['absolute_path'] ) ? (string) $target['absolute_path'] : '';
		$display  = isset( $target['display_path'] ) ? (string) $target['display_path'] : '';
		$index    = $this->find_index_file( $absolute );
		$url      = trailingslashit( site_url( ltrim( $display, '/' ) ) );
		$http     = $this->request_directory( $url );

		$browsing = self::BROWSING_UNKNOWN;

		if ( 'listing' === $http['classification'] ) {
			$browsing = self::BROWSING_NOT_BLOCKED;
		} elseif ( 'non_listing' === $http['classification'] ) {
			$browsing = self::BROWSING_BLOCKED;
		}

		$contents          = '';
		$contents_truncated = false;

		if ( self::BROWSING_NOT_BLOCKED === $browsing ) {
			$contents = '';
		} elseif ( self::BROWSING_BLOCKED === $browsing && $http['status_code'] > 0 ) {
			$contents = sprintf(
				/* translators: %d: HTTP status code */
				__( 'HTTP %d Response', 'choctaw-wp-security' ),
				(int) $http['status_code']
			);
		} elseif ( '' !== $index['path'] ) {
			$preview           = Choctaw_Wp_Security_Utils::read_file_contents_preview_result( $index['path'] );
			$contents          = isset( $preview['contents'] ) ? (string) $preview['contents'] : '';
			$contents_truncated = ! empty( $preview['truncated'] );
		}

		return array(
			'folder_key'        => $folder_key,
			'label'             => isset( $target['label'] ) ? (string) $target['label'] : $folder_key,
			'absolute_path'     => $absolute,
			'display_path'      => $display,
			'test_url'          => $url,
			'has_index'         => '' !== $index['path'],
			'index_name'        => $index['name'],
			'index_path'        => $index['path'],
			'http_status'       => (int) $http['status_code'],
			'http_class'        => (string) $http['classification'],
			'browsing'          => $browsing,
			'contents'          => $contents,
			'contents_truncated' => $contents_truncated,
			'server_type'       => $server_type,
		);
	}

	/**
	 * Locate a common index file in a directory.
	 *
	 * @param string $directory Absolute directory path.
	 * @return array{path: string, name: string}
	 */
	private function find_index_file( $directory ) {
		$directory = (string) $directory;
		$empty     = array(
			'path' => '',
			'name' => '',
		);

		if ( '' === $directory || ! is_dir( $directory ) ) {
			return $empty;
		}

		foreach ( array( 'index.php', 'index.html', 'index.htm' ) as $name ) {
			$path = trailingslashit( $directory ) . $name;

			if ( file_exists( $path ) ) {
				return array(
					'path' => $path,
					'name' => $name,
				);
			}
		}

		return $empty;
	}

	/**
	 * Request a folder URL and classify the response.
	 *
	 * @param string $url Public folder URL.
	 * @return array{classification: string, status_code: int}
	 */
	private function request_directory( $url ) {
		$response = wp_remote_get(
			$url,
			array(
				'timeout'     => self::HTTP_TIMEOUT,
				'redirection' => 2,
				'headers'     => array(
					'Accept' => 'text/html,application/xhtml+xml',
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return array(
				'classification' => 'failed',
				'status_code'    => 0,
			);
		}

		$status_code = (int) wp_remote_retrieve_response_code( $response );
		$body        = (string) wp_remote_retrieve_body( $response );

		if ( $this->response_body_looks_like_directory_listing( $body ) ) {
			return array(
				'classification' => 'listing',
				'status_code'    => $status_code,
			);
		}

		if ( in_array( $status_code, array( 401, 403, 404, 410 ), true ) ) {
			return array(
				'classification' => 'non_listing',
				'status_code'    => $status_code,
			);
		}

		if ( $status_code >= 200 && $status_code < 300 ) {
			return array(
				'classification' => 'non_listing',
				'status_code'    => $status_code,
			);
		}

		if ( $status_code >= 500 ) {
			return array(
				'classification' => 'failed',
				'status_code'    => $status_code,
			);
		}

		return array(
			'classification' => 'inconclusive',
			'status_code'    => $status_code,
		);
	}

	/**
	 * Determine whether an HTTP response body resembles a directory listing page.
	 *
	 * @param string $body Response body.
	 * @return bool
	 */
	private function response_body_looks_like_directory_listing( $body ) {
		if ( '' === trim( (string) $body ) ) {
			return false;
		}

		$markers = array(
			'Index of /',
			'Index of ',
			'<title>Index of',
			'Parent Directory',
			'Directory Listing',
		);

		foreach ( $markers as $marker ) {
			if ( false !== stripos( (string) $body, $marker ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Build the .htaccess finding.
	 *
	 * @param array<string, mixed>             $htaccess    Htaccess analysis.
	 * @param array<int, array<string, mixed>> $folders     Folder probe results.
	 * @param string                           $server_type Server type.
	 * @return array<string, mixed>
	 */
	private function build_htaccess_finding( array $htaccess, array $folders, $server_type ) {
		$fingerprint = Choctaw_Wp_Security_Finding_Status_Store::fingerprint_directory_browsing( 'htaccess', '.htaccess' );
		$labels      = self::get_category_labels();
		$browsing    = isset( $htaccess['browsing'] ) ? (string) $htaccess['browsing'] : self::BROWSING_UNKNOWN;

		if ( self::SERVER_NGINX === $server_type ) {
			$risk = 'info';
			$why  = __( 'An .htaccess file was found in the WordPress root, but Nginx does not read .htaccess files. Files like this are often left behind after a site is migrated from Apache or LiteSpeed.', 'choctaw-wp-security' );
			$how  = __( 'No action is needed for this .htaccess file. Leave it in place; it does not control directory browsing on Nginx. Use Nginx configuration (for example autoindex off;) or per-folder index files if you need to change browsing behavior.', 'choctaw-wp-security' );
		} else {
			$all_folders_block = $this->all_folders_block( $folders );
			$blocks            = ! empty( $htaccess['blocks'] );

			if ( $blocks ) {
				$risk = 'safe';
				$why  = __( 'The site root .htaccess file contains Options -Indexes, which instructs Apache or LiteSpeed to disable directory listings for directories covered by this configuration.', 'choctaw-wp-security' );
				$how  = __( 'No action is needed for the .htaccess file. Site-wide directory browsing appears to be disabled at the .htaccess level.', 'choctaw-wp-security' );
			} elseif ( self::BROWSING_UNKNOWN === $browsing ) {
				$risk = 'review';
				$reason = isset( $htaccess['unknown_reason'] ) ? (string) $htaccess['unknown_reason'] : '';

				if ( 'not_found' === $reason ) {
					$why = __( 'The site root .htaccess file could not be found or was empty, so this scan could not confirm whether Options -Indexes is configured.', 'choctaw-wp-security' );
				} elseif ( 'unreadable' === $reason ) {
					$why = __( 'The site root .htaccess file exists but could not be read by WordPress, so this scan could not confirm whether Options -Indexes is configured.', 'choctaw-wp-security' );
				} else {
					$why = __( 'The site root .htaccess file did not contain a clear Options directive related to directory indexes, so this method could not confirm browsing protection.', 'choctaw-wp-security' );
				}

				$how = __( 'Review the Directory Test rows for each public folder. Prefer adding Options -Indexes to the site root .htaccess when your host allows it. See the guidance box labeled “How to Turn Directory Browsing Off”.', 'choctaw-wp-security' );
			} elseif ( $all_folders_block ) {
				$risk = 'info';
				$why  = __( 'The site root .htaccess file does not disable directory indexes, but each tested public folder currently blocks directory listing on its own (via an index file or an HTTP response that does not return a listing).', 'choctaw-wp-security' );
				$how  = __( 'No immediate folder-level action is required. Prefer adding Options -Indexes in .htaccess for site-wide protection so browsing does not depend on individual folders. See “How to Turn Directory Browsing Off”.', 'choctaw-wp-security' );
			} else {
				$risk = 'critical';
				$why  = __( 'The site root .htaccess file does not disable directory indexes, and one or more tested public folders also do not block directory listing. Visitors may be able to view file and folder names.', 'choctaw-wp-security' );
				$how  = __( 'Disable directory browsing site-wide by adding Options -Indexes to the site root .htaccess (when allowed), or fix each unprotected folder. See the guidance box labeled “How to Turn Directory Browsing Off”.', 'choctaw-wp-security' );
			}
		}

		return array(
			'id'                 => $fingerprint,
			'fingerprint'        => $fingerprint,
			'path'               => (string) $htaccess['display_path'],
			'absolute_path'      => (string) $htaccess['absolute_path'],
			'test_url'           => '',
			'risk'               => $risk,
			'risk_label'         => $this->risk_label( $risk ),
			'category'           => self::METHOD_HTACCESS,
			'category_label'     => $labels[ self::METHOD_HTACCESS ],
			'testing_method'     => $labels[ self::METHOD_HTACCESS ],
			'server_type'        => $server_type,
			'server_type_label'  => self::server_type_label( $server_type ),
			'browsing'           => $browsing,
			'browsing_label'     => self::browsing_label( $browsing ),
			'contents'           => (string) $htaccess['contents'],
			'contents_truncated'  => ! empty( $htaccess['contents_truncated'] ),
			'why_seeing_this'    => $why,
			'how_to_proceed'     => $how,
		);
	}

	/**
	 * Build a folder Directory Test finding.
	 *
	 * @param array<string, mixed> $folder          Folder probe payload.
	 * @param bool                 $htaccess_blocks Whether Apache/LS .htaccess blocks indexes.
	 * @param string               $server_type     Server type.
	 * @return array<string, mixed>
	 */
	private function build_folder_finding( array $folder, $htaccess_blocks, $server_type ) {
		$display     = isset( $folder['display_path'] ) ? (string) $folder['display_path'] : '';
		$fingerprint = Choctaw_Wp_Security_Finding_Status_Store::fingerprint_directory_browsing( 'folder', $display );
		$labels      = self::get_category_labels();
		$browsing    = isset( $folder['browsing'] ) ? (string) $folder['browsing'] : self::BROWSING_UNKNOWN;
		$http_status = isset( $folder['http_status'] ) ? (int) $folder['http_status'] : 0;
		$has_index   = ! empty( $folder['has_index'] );
		$is_nginx    = self::SERVER_NGINX === $server_type;

		if ( self::BROWSING_NOT_BLOCKED === $browsing ) {
			$risk = $is_nginx ? 'review' : 'critical';
			$why  = __( 'Requesting this folder URL returned a directory listing. Visitors may be able to view file and folder names without knowing exact paths, which can aid reconnaissance.', 'choctaw-wp-security' );

			if ( $is_nginx ) {
				$how = __( 'Disable autoindex in the Nginx server or location block (autoindex off;), reload Nginx, or add a blank index.php in this folder as a temporary fallback. See “How to Turn Directory Browsing Off”.', 'choctaw-wp-security' );
			} else {
				$how = __( 'Prefer disabling indexes site-wide with Options -Indexes in .htaccess when allowed, or add a blank index file in this folder as a fallback. See “How to Turn Directory Browsing Off”.', 'choctaw-wp-security' );
			}
		} elseif ( self::BROWSING_BLOCKED === $browsing ) {
			$risk = 'safe';
			$why  = $this->why_folder_blocked( $server_type, $http_status, $has_index, $htaccess_blocks );
			$how  = __( 'Nothing needs to be done for this path at this time.', 'choctaw-wp-security' );
		} else {
			$risk = 'review';
			$why  = __( 'This scan could not determine whether directory listing is blocked for this folder. The HTTP request failed, timed out, or returned a response that could not be classified.', 'choctaw-wp-security' );
			$how  = __( 'Verify the folder URL manually in a browser, confirm the site allows loopback HTTP requests, and review server directory-listing settings using “How to Turn Directory Browsing Off”.', 'choctaw-wp-security' );
		}

		return array(
			'id'                 => $fingerprint,
			'fingerprint'        => $fingerprint,
			'path'               => $display,
			'absolute_path'      => isset( $folder['absolute_path'] ) ? (string) $folder['absolute_path'] : '',
			'test_url'           => isset( $folder['test_url'] ) ? (string) $folder['test_url'] : '',
			'risk'               => $risk,
			'risk_label'         => $this->risk_label( $risk ),
			'category'           => self::METHOD_DIRECTORY_TEST,
			'category_label'     => $labels[ self::METHOD_DIRECTORY_TEST ],
			'testing_method'     => $labels[ self::METHOD_DIRECTORY_TEST ],
			'server_type'        => $server_type,
			'server_type_label'  => self::server_type_label( $server_type ),
			'browsing'           => $browsing,
			'browsing_label'     => self::browsing_label( $browsing ),
			'contents'           => isset( $folder['contents'] ) ? (string) $folder['contents'] : '',
			'contents_truncated'  => ! empty( $folder['contents_truncated'] ),
			'why_seeing_this'    => $why,
			'how_to_proceed'     => $how,
		);
	}

	/**
	 * Why text when a folder Directory Test is Blocked.
	 *
	 * @param string $server_type     Server type.
	 * @param int    $http_status     HTTP status code.
	 * @param bool   $has_index       Whether an index file exists.
	 * @param bool   $htaccess_blocks Whether .htaccess blocks indexes.
	 * @return string
	 */
	private function why_folder_blocked( $server_type, $http_status, $has_index, $htaccess_blocks ) {
		$status_note = '';

		if ( $http_status > 0 ) {
			$status_note = ' ' . sprintf(
				/* translators: %d: HTTP status code */
				__( 'The server responded with HTTP %d instead of a directory listing.', 'choctaw-wp-security' ),
				(int) $http_status
			);
		}

		if ( self::SERVER_NGINX === $server_type ) {
			$why = __( 'Directory listing appears blocked for this path. On Nginx that usually means autoindex is off (or an equivalent deny rule is in place).', 'choctaw-wp-security' );
		} elseif ( $htaccess_blocks ) {
			$why = __( 'Directory listing appears blocked for this path. That usually means the site root .htaccess (or server configuration) has disabled indexes.', 'choctaw-wp-security' );
		} else {
			$why = __( 'Directory listing appears blocked for this path. Protection may come from server configuration, an index-file fallback, or another rule.', 'choctaw-wp-security' );
		}

		if ( $has_index ) {
			$why .= ' ' . __( 'This folder also contains a common index file, which helps prevent listings even when server-level browsing is enabled.', 'choctaw-wp-security' );
		}

		return $why . $status_note;
	}

	/**
	 * Whether every folder probe currently blocks browsing.
	 *
	 * @param array<int, array<string, mixed>> $folders Folder probes.
	 * @return bool
	 */
	private function all_folders_block( array $folders ) {
		if ( empty( $folders ) ) {
			return false;
		}

		foreach ( $folders as $folder ) {
			if ( self::BROWSING_BLOCKED !== ( isset( $folder['browsing'] ) ? $folder['browsing'] : '' ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Risk label helper.
	 *
	 * @param string $risk Risk key.
	 * @return string
	 */
	private function risk_label( $risk ) {
		$map = array(
			'critical' => __( 'Critical', 'choctaw-wp-security' ),
			'review'   => __( 'Review', 'choctaw-wp-security' ),
			'safe'     => __( 'Safe', 'choctaw-wp-security' ),
			'info'     => __( 'Info', 'choctaw-wp-security' ),
		);

		return isset( $map[ $risk ] ) ? $map[ $risk ] : $risk;
	}

	/**
	 * Build summary counts.
	 *
	 * @param array<int, array<string, mixed>> $findings Findings.
	 * @return array<string, int>
	 */
	private function build_summary( array $findings ) {
		$summary = array(
			'critical'   => 0,
			'review'     => 0,
			'safe'       => 0,
			'info'       => 0,
			'suspicious' => 0,
			'alert'      => 0,
			'total'      => count( $findings ),
			'flagged'    => 0,
		);

		foreach ( $findings as $finding ) {
			$risk = isset( $finding['risk'] ) ? (string) $finding['risk'] : '';

			if ( isset( $summary[ $risk ] ) ) {
				++$summary[ $risk ];
			}

			if ( in_array( $risk, array( 'critical', 'review', 'alert', 'suspicious' ), true ) ) {
				++$summary['flagged'];
			}
		}

		return $summary;
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
}
