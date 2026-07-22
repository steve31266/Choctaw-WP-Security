<?php
/**
 * Directory browsing detection (site root .htaccess + public folder roots).
 * Sassh Findings producer (Phase 3.6).
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Detects directory browsing posture and persists via Sassh Findings.
 */
class Choctaw_Wp_Security_Directory_Browsing_Scanner {

	const SCANNER_ID = 'directory-browsing';

	const BROWSING_OPEN         = 'open';
	const BROWSING_NOT_OBSERVED = 'not_observed';
	const BROWSING_UNKNOWN      = 'unknown';
	const BROWSING_DISABLED     = 'disabled';
	const BROWSING_ENABLED      = 'enabled';

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
	 * Run directory browsing checks and persist via Sassh Findings.
	 *
	 * @return array<string, mixed>
	 */
	public function scan() {
		Sassh_Findings_Schema::maybe_upgrade();

		$scope_key    = Sassh_Findings_Service::directory_browsing_scope_key();
		$service      = new Sassh_Findings_Service();
		$server_type  = $this->get_server_type();
		$uploads      = wp_get_upload_dir();
		$upload_basedir = isset( $uploads['basedir'] ) ? (string) $uploads['basedir'] : '';

		$execution_id = $service->begin_scanner_execution(
			self::SCANNER_ID,
			array(
				'scope_key'  => $scope_key,
				'run_type'   => 'individual',
				'run_source' => 'wordpress_admin',
				'meta'       => array(
					'server_type'          => $server_type,
					'probed_blog_id'       => function_exists( 'get_current_blog_id' ) ? (int) get_current_blog_id() : 1,
					'uploads_basedir'      => $upload_basedir,
					'uploads_display_path' => $this->format_display_path( $upload_basedir ),
				),
			)
		);

		$root = wp_normalize_path( ABSPATH );

		if ( '' === $root || ! is_dir( $root ) ) {
			$service->finalize_scanner_execution( $execution_id, 'failed' );

			return $this->build_report_from_findings(
				$service,
				$execution_id,
				array(
					'completion_status' => 'failed',
					'scan_incomplete'   => true,
					'server_type'       => $server_type,
					'errors'            => array(
						__( 'WordPress root is not available, so directory browsing could not be evaluated.', 'choctaw-wp-security' ),
					),
				)
			);
		}

		$htaccess      = $this->analyze_htaccess( $server_type );
		$folder_results = array();
		$folder_bands   = array();
		$partial        = false;
		$errors         = array();

		if ( ! empty( $htaccess['unreadable'] ) ) {
			$partial  = true;
			$errors[] = __( 'The site root .htaccess file exists but could not be read. Previously confirmed .htaccess findings were not replaced.', 'choctaw-wp-security' );
		}

		foreach ( $this->get_folder_targets() as $folder_key => $target ) {
			$folder = $this->probe_folder( $folder_key, $target, $server_type );
			$folder_results[] = $folder;
			$band = isset( $folder['browsing'] ) ? (string) $folder['browsing'] : self::BROWSING_UNKNOWN;
			$folder_bands[ $folder_key ] = $band;

			if ( self::BROWSING_UNKNOWN === $band || ! empty( $folder['unevaluable'] ) ) {
				$partial = true;
			}
		}

		if ( $partial && empty( $errors ) ) {
			$errors[] = __( 'One or more directory browsing targets could not be conclusively evaluated. Previously confirmed findings were not cleared.', 'choctaw-wp-security' );
		}

		$observations = array();

		$htaccess_obs = $this->build_htaccess_observation( $htaccess, $folder_bands, $server_type );
		if ( null !== $htaccess_obs ) {
			$observations[] = $htaccess_obs;
		}

		foreach ( $folder_results as $folder ) {
			$obs = $this->build_folder_observation( $folder, $server_type, $htaccess );
			if ( null !== $obs ) {
				$observations[] = $obs;
			}
		}

		$service->record_observations( $execution_id, $observations );

		$completion = $partial ? 'partial' : 'success';
		$ok         = $service->finalize_scanner_execution( $execution_id, $completion );

		if ( ! $ok && 'success' === $completion ) {
			$completion = 'failed';
			$partial    = true;
			$errors[]   = __( 'Directory browsing findings could not be finalized.', 'choctaw-wp-security' );
		}

		return $this->build_report_from_findings(
			$service,
			$execution_id,
			array(
				'completion_status' => $completion,
				'scan_incomplete'   => $partial || 'success' !== $completion,
				'server_type'       => $server_type,
				'errors'            => $errors,
			)
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
	 * @param string $state open|not_observed|disabled|enabled|unknown.
	 * @return string
	 */
	public static function browsing_label( $state ) {
		switch ( (string) $state ) {
			case self::BROWSING_OPEN:
				return __( 'Listing open', 'choctaw-wp-security' );
			case self::BROWSING_NOT_OBSERVED:
				return __( 'Directory listing not observed', 'choctaw-wp-security' );
			case self::BROWSING_DISABLED:
				return __( 'Disabled in .htaccess', 'choctaw-wp-security' );
			case self::BROWSING_ENABLED:
				return __( 'Enabled in .htaccess', 'choctaw-wp-security' );
			default:
				return __( 'Unknown', 'choctaw-wp-security' );
		}
	}

	/**
	 * Presentation mapping for the site-root .htaccess Directory Browsing column.
	 *
	 * Determinative Options -Indexes / +Indexes map to disabled/enabled.
	 * Nginx (ignores .htaccess) and missing/inconclusive Options map to unknown.
	 *
	 * @param string|null $indexes_state off|on|null.
	 * @param string      $server_type   Server family.
	 * @return array{browsing: string, browsing_label: string}
	 */
	public static function htaccess_browsing_presentation( $indexes_state, $server_type = self::SERVER_APACHE ) {
		if ( self::SERVER_NGINX === (string) $server_type ) {
			return array(
				'browsing'       => self::BROWSING_UNKNOWN,
				'browsing_label' => self::browsing_label( self::BROWSING_UNKNOWN ),
			);
		}

		if ( 'off' === $indexes_state ) {
			return array(
				'browsing'       => self::BROWSING_DISABLED,
				'browsing_label' => self::browsing_label( self::BROWSING_DISABLED ),
			);
		}

		if ( 'on' === $indexes_state ) {
			return array(
				'browsing'       => self::BROWSING_ENABLED,
				'browsing_label' => self::browsing_label( self::BROWSING_ENABLED ),
			);
		}

		return array(
			'browsing'       => self::BROWSING_UNKNOWN,
			'browsing_label' => self::browsing_label( self::BROWSING_UNKNOWN ),
		);
	}

	/**
	 * Context-aware folder guidance from structured .htaccess + HTTP evidence.
	 *
	 * @param string|null $indexes_state off|on|null (null = missing/nondeterminative/unusable for this server).
	 * @param string      $http_browsing open|not_observed|unknown.
	 * @param string      $server_type   Server family.
	 * @return array<int, array<string, mixed>>
	 */
	public static function folder_guidance_contributions( $indexes_state, $http_browsing, $server_type = self::SERVER_APACHE ) {
		$http_browsing = (string) $http_browsing;
		$server_type   = (string) $server_type;

		if ( self::SERVER_NGINX === $server_type ) {
			$indexes_state = null;
		}

		if ( self::BROWSING_UNKNOWN === $http_browsing ) {
			return array(
				array(
					'id'               => 'dirbrowse.folder.unknown.evidence',
					'kind'             => 'evidence_fact',
					'display_priority' => 10,
					'text'             => __( 'This scan could not determine whether directory listing is exposed for this folder. The HTTP request failed, timed out, returned an unclassifiable response, or the target could not be evaluated.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.exposure',
				),
				array(
					'id'               => 'dirbrowse.folder.unknown.action',
					'kind'             => 'recommended_action',
					'display_priority' => 20,
					'text'             => __( 'Verify the folder URL manually in a browser and confirm the site allows loopback HTTP requests. The scanner could not determine the current exposure, so avoid definitive enabled/disabled conclusions from this row alone.', 'choctaw-wp-security' ),
					'tags'             => array( 'investigate' ),
					'concern'          => 'dirbrowse.proceed',
				),
			);
		}

		if ( 'off' === $indexes_state && self::BROWSING_NOT_OBSERVED === $http_browsing ) {
			return array(
				array(
					'id'               => 'dirbrowse.folder.off_not_observed.evidence.htaccess',
					'kind'             => 'evidence_fact',
					'display_priority' => 10,
					'text'             => __( 'The site-root .htaccess contains Options -Indexes (applicable configuration for Apache/LiteSpeed).', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.config',
				),
				array(
					'id'               => 'dirbrowse.folder.off_not_observed.evidence.http',
					'kind'             => 'evidence_fact',
					'display_priority' => 11,
					'text'             => __( 'The tested URL did not expose a recognizable directory listing during this scan.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.exposure',
				),
				array(
					'id'               => 'dirbrowse.folder.off_not_observed.action',
					'kind'             => 'recommended_action',
					'display_priority' => 20,
					'text'             => __( 'No action is needed. The site-root .htaccess contains Options -Indexes, and no directory listing was observed at this URL during the scan.', 'choctaw-wp-security' ),
					'tags'             => array( 'nondestructive' ),
					'concern'          => 'dirbrowse.proceed',
				),
				array(
					'id'               => 'dirbrowse.folder.off_not_observed.caveat',
					'kind'             => 'warning_caveat',
					'display_priority' => 10,
					'text'             => __( 'Options -Indexes records the applicable .htaccess configuration, and the HTTP probe records what was observed externally. Neither observation alone proves every possible server configuration or override.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.certainty',
				),
			);
		}

		if ( 'off' === $indexes_state && self::BROWSING_OPEN === $http_browsing ) {
			return array(
				array(
					'id'               => 'dirbrowse.folder.off_open.evidence.listing',
					'kind'             => 'evidence_fact',
					'display_priority' => 10,
					'text'             => __( 'Requesting this folder URL returned a recognizable directory listing.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.exposure',
				),
				array(
					'id'               => 'dirbrowse.folder.off_open.evidence.htaccess',
					'kind'             => 'evidence_fact',
					'display_priority' => 11,
					'text'             => __( 'The site-root .htaccess contains Options -Indexes, which normally disables directory listings for directories covered by that configuration.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.config',
				),
				array(
					'id'               => 'dirbrowse.folder.off_open.caveat.override',
					'kind'             => 'warning_caveat',
					'display_priority' => 10,
					'text'             => __( 'An open listing while Options -Indexes is present suggests the directive may not be taking effect for this URL or may be overridden (for example by server config, AllowOverride, or a more specific directory configuration). An open listing is exposure / misconfiguration evidence, not proof of compromise.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.certainty',
				),
				array(
					'id'               => 'dirbrowse.folder.off_open.action',
					'kind'             => 'recommended_action',
					'display_priority' => 20,
					'text'             => __( 'Investigate why Options -Indexes is not preventing listing at this URL (host AllowOverride, vhost/directory config, or a more specific override). See “How to Turn Directory Browsing Off” for server-specific checks.', 'choctaw-wp-security' ),
					'tags'             => array( 'investigate' ),
					'concern'          => 'dirbrowse.proceed',
				),
			);
		}

		if ( 'on' === $indexes_state && self::BROWSING_OPEN === $http_browsing ) {
			return array(
				array(
					'id'               => 'dirbrowse.folder.on_open.evidence.listing',
					'kind'             => 'evidence_fact',
					'display_priority' => 10,
					'text'             => __( 'Requesting this folder URL returned a recognizable directory listing.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.exposure',
				),
				array(
					'id'               => 'dirbrowse.folder.on_open.evidence.htaccess',
					'kind'             => 'evidence_fact',
					'display_priority' => 11,
					'text'             => __( 'The site-root .htaccess explicitly enables directory indexes (Options +Indexes or Indexes).', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.config',
				),
				array(
					'id'               => 'dirbrowse.folder.on_open.caveat.exposure',
					'kind'             => 'warning_caveat',
					'display_priority' => 10,
					'text'             => __( 'An open directory listing is a security misconfiguration and reconnaissance exposure. It does not itself indicate that the site is compromised.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.certainty',
				),
				array(
					'id'               => 'dirbrowse.folder.on_open.action',
					'kind'             => 'recommended_action',
					'display_priority' => 20,
					'text'             => __( 'Remove or override the enabling Options +Indexes / Indexes directive (prefer Options -Indexes when your host allows it). See “How to Turn Directory Browsing Off”.', 'choctaw-wp-security' ),
					'tags'             => array( 'investigate' ),
					'concern'          => 'dirbrowse.proceed',
				),
			);
		}

		if ( 'on' === $indexes_state && self::BROWSING_NOT_OBSERVED === $http_browsing ) {
			return array(
				array(
					'id'               => 'dirbrowse.folder.on_not_observed.evidence.http',
					'kind'             => 'evidence_fact',
					'display_priority' => 10,
					'text'             => __( 'The tested URL did not expose a recognizable directory listing during this scan.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.exposure',
				),
				array(
					'id'               => 'dirbrowse.folder.on_not_observed.evidence.htaccess',
					'kind'             => 'evidence_fact',
					'display_priority' => 11,
					'text'             => __( 'The site-root .htaccess explicitly enables directory indexes (Options +Indexes or Indexes).', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.config',
				),
				array(
					'id'               => 'dirbrowse.folder.on_not_observed.caveat',
					'kind'             => 'warning_caveat',
					'display_priority' => 10,
					'text'             => __( 'No exposure was observed at this URL, but an explicit enabling directive remains in applicable .htaccess configuration. An index file, redirect, authentication response, CDN/WAF response, or custom error page might mask browsing posture.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.certainty',
				),
				array(
					'id'               => 'dirbrowse.folder.on_not_observed.action',
					'kind'             => 'recommended_action',
					'display_priority' => 20,
					'text'             => __( 'No directory listing was observed at this URL, but the explicit enabling Options +Indexes / Indexes directive should be reviewed and normally removed or replaced with Options -Indexes when your host allows it.', 'choctaw-wp-security' ),
					'tags'             => array( 'investigate' ),
					'concern'          => 'dirbrowse.proceed',
				),
			);
		}

		if ( self::BROWSING_OPEN === $http_browsing ) {
			return array(
				array(
					'id'               => 'dirbrowse.folder.null_open.evidence.listing',
					'kind'             => 'evidence_fact',
					'display_priority' => 10,
					'text'             => __( 'Requesting this folder URL returned a recognizable directory listing. The site-root .htaccess was missing, empty, or nondeterminative for Options ±Indexes (or is not applicable on this server).', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.exposure',
				),
				array(
					'id'               => 'dirbrowse.folder.null_open.caveat.exposure',
					'kind'             => 'warning_caveat',
					'display_priority' => 10,
					'text'             => __( 'An open directory listing is a security misconfiguration and reconnaissance exposure. It does not itself indicate that the site is compromised.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.certainty',
				),
				array(
					'id'               => 'dirbrowse.folder.null_open.action',
					'kind'             => 'recommended_action',
					'display_priority' => 20,
					'text'             => self::SERVER_NGINX === $server_type
						? __( 'Disable autoindex in the Nginx server or location block (autoindex off;), reload Nginx, or add a blank index.php in this folder as a temporary fallback. See “How to Turn Directory Browsing Off”.', 'choctaw-wp-security' )
						: __( 'Prefer disabling indexes site-wide with Options -Indexes in .htaccess when allowed, or add a blank index file in this folder as a fallback. See “How to Turn Directory Browsing Off”.', 'choctaw-wp-security' ),
					'tags'             => array( 'investigate' ),
					'concern'          => 'dirbrowse.proceed',
				),
			);
		}

		// Missing/nondeterminative .htaccess + listing not observed.
		return array(
			array(
				'id'               => 'dirbrowse.folder.null_not_observed.evidence.http',
				'kind'             => 'evidence_fact',
				'display_priority' => 10,
				'text'             => __( 'The tested URL did not expose a recognizable directory listing during this scan.', 'choctaw-wp-security' ),
				'concern'          => 'dirbrowse.exposure',
			),
			array(
				'id'               => 'dirbrowse.folder.null_not_observed.caveat',
				'kind'             => 'warning_caveat',
				'display_priority' => 10,
				'text'             => __( 'This is an observed HTTP result, not proof that the underlying server configuration disables directory browsing. An index file, redirect, authentication response, CDN/WAF response, or custom error page might mask browsing posture. The site-root .htaccess was missing, empty, or nondeterminative for Options ±Indexes.', 'choctaw-wp-security' ),
				'concern'          => 'dirbrowse.certainty',
			),
			array(
				'id'               => 'dirbrowse.folder.null_not_observed.action',
				'kind'             => 'recommended_action',
				'display_priority' => 20,
				'text'             => __( 'No directory listing was observed at this URL. Hardening with Options -Indexes (or the equivalent server setting) is optional and recommended for defense in depth; remediation is not required solely because of this HTTP result.', 'choctaw-wp-security' ),
				'tags'             => array( 'nondestructive' ),
				'concern'          => 'dirbrowse.proceed',
			),
		);
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
			'include_observation' => false,
			'unreadable'          => false,
			'exists'              => false,
			'readable'            => false,
			'indexes_state'       => null,
			'contents'            => '',
			'contents_truncated'   => false,
			'absolute_path'       => $path,
			'display_path'        => '.htaccess',
			'unknown_reason'      => 'not_found',
		);

		$exists = file_exists( $path );

		if ( self::SERVER_NGINX === $server_type ) {
			if ( ! $exists ) {
				return $result;
			}

			$result['include_observation'] = true;
			$result['exists']              = true;
			$result['unknown_reason']      = 'nginx_ignores';

			if ( is_readable( $path ) ) {
				$result['readable'] = true;
				$preview            = Choctaw_Wp_Security_Utils::read_file_contents_preview_result( $path );
				$result['contents'] = isset( $preview['contents'] ) ? (string) $preview['contents'] : '';
				$result['contents_truncated'] = ! empty( $preview['truncated'] );
			} else {
				$result['unreadable']         = true;
				$result['include_observation'] = false;
				$result['unknown_reason']     = 'unreadable';
			}

			return $result;
		}

		if ( ! $exists ) {
			$result['include_observation'] = true;
			$result['unknown_reason']      = 'not_found';
			return $result;
		}

		$result['exists'] = true;

		if ( ! is_readable( $path ) ) {
			$result['unreadable']         = true;
			$result['include_observation'] = false;
			$result['unknown_reason']     = 'unreadable';
			return $result;
		}

		$result['readable']            = true;
		$result['include_observation'] = true;
		$preview                       = Choctaw_Wp_Security_Utils::read_file_contents_preview_result( $path );
		$result['contents']            = isset( $preview['contents'] ) ? (string) $preview['contents'] : '';
		$result['contents_truncated']  = ! empty( $preview['truncated'] );

		if ( '' === trim( $result['contents'] ) && empty( $result['contents_truncated'] ) ) {
			$result['unknown_reason'] = 'not_found';
			$result['indexes_state']  = null;
			return $result;
		}

		$indexes_state           = $this->parse_htaccess_indexes_state( $result['contents'] );
		$result['indexes_state'] = $indexes_state;

		if ( 'off' === $indexes_state ) {
			$result['unknown_reason'] = '';
		} elseif ( 'on' === $indexes_state ) {
			$result['unknown_reason'] = '';
		} else {
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
	 * @param string                $folder_key  Folder key.
	 * @param array<string, string> $target      Target metadata.
	 * @param string                $server_type Server type.
	 * @return array<string, mixed>
	 */
	private function probe_folder( $folder_key, array $target, $server_type ) {
		$absolute = isset( $target['absolute_path'] ) ? (string) $target['absolute_path'] : '';
		$display  = isset( $target['display_path'] ) ? (string) $target['display_path'] : '';
		$label    = isset( $target['label'] ) ? (string) $target['label'] : $folder_key;

		$base = array(
			'folder_key'        => $folder_key,
			'label'             => $label,
			'absolute_path'     => $absolute,
			'display_path'      => $display,
			'test_url'          => '',
			'has_index'         => false,
			'index_name'        => '',
			'index_path'        => '',
			'http_status'       => 0,
			'http_class'        => 'failed',
			'browsing'          => self::BROWSING_UNKNOWN,
			'unevaluable'       => false,
			'contents'          => '',
			'contents_truncated' => false,
			'server_type'       => $server_type,
		);

		if ( '' === $absolute || ! is_dir( $absolute ) ) {
			$base['unevaluable'] = true;
			$base['http_class']  = 'unevaluable';
			return $base;
		}

		$index = $this->find_index_file( $absolute );
		$url   = trailingslashit( site_url( ltrim( $display, '/' ) ) );

		if ( '' === $display || '' === $url || 'http' !== substr( strtolower( $url ), 0, 4 ) ) {
			$base['unevaluable'] = true;
			$base['http_class']  = 'unevaluable';
			$base['has_index']   = '' !== $index['path'];
			$base['index_name']  = $index['name'];
			$base['index_path']  = $index['path'];
			return $base;
		}

		$http = $this->request_directory( $url );
		$browsing = self::BROWSING_UNKNOWN;

		if ( 'listing' === $http['classification'] ) {
			$browsing = self::BROWSING_OPEN;
		} elseif ( 'non_listing' === $http['classification'] ) {
			$browsing = self::BROWSING_NOT_OBSERVED;
		}

		$contents          = '';
		$contents_truncated = false;

		if ( self::BROWSING_OPEN === $browsing ) {
			$contents = '';
		} elseif ( self::BROWSING_NOT_OBSERVED === $browsing && $http['status_code'] > 0 ) {
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
			'label'             => $label,
			'absolute_path'     => $absolute,
			'display_path'      => $display,
			'test_url'          => $url,
			'has_index'         => '' !== $index['path'],
			'index_name'        => $index['name'],
			'index_path'        => $index['path'],
			'http_status'       => (int) $http['status_code'],
			'http_class'        => (string) $http['classification'],
			'browsing'          => $browsing,
			'unevaluable'       => false,
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
	 * Resolve htaccess rule_id from analysis + folder aggregate bands.
	 *
	 * @param array<string, mixed>  $htaccess     Htaccess analysis.
	 * @param array<string, string> $folder_bands Folder postures.
	 * @param string                $server_type  Server type.
	 * @return string|null Null when no observation should be emitted.
	 */
	private function resolve_htaccess_rule_id( array $htaccess, array $folder_bands, $server_type ) {
		if ( empty( $htaccess['include_observation'] ) ) {
			return null;
		}

		if ( self::SERVER_NGINX === $server_type ) {
			return 'htaccess-nginx-ignored';
		}

		$indexes = isset( $htaccess['indexes_state'] ) ? $htaccess['indexes_state'] : null;

		if ( 'off' === $indexes ) {
			return 'htaccess-indexes-disabled';
		}

		if ( 'on' === $indexes ) {
			return 'htaccess-indexes-enabled';
		}

		// Indexes not disabled (missing / empty / inconclusive).
		$has_open    = false;
		$all_not_obs = ! empty( $folder_bands );
		$has_unknown = false;

		foreach ( $folder_bands as $band ) {
			if ( self::BROWSING_OPEN === $band ) {
				$has_open = true;
			}
			if ( self::BROWSING_NOT_OBSERVED !== $band ) {
				$all_not_obs = false;
			}
			if ( self::BROWSING_UNKNOWN === $band ) {
				$has_unknown = true;
			}
		}

		if ( $has_open ) {
			return 'htaccess-unprotected-folders-open';
		}

		if ( $all_not_obs && ! $has_unknown && ! empty( $folder_bands ) ) {
			return 'htaccess-unprotected-folders-not-observed';
		}

		return 'htaccess-indexes-inconclusive';
	}

	/**
	 * Build htaccess Findings observation (or null).
	 *
	 * @param array<string, mixed>  $htaccess     Analysis.
	 * @param array<string, string> $folder_bands Folder bands.
	 * @param string                $server_type  Server type.
	 * @return array<string, mixed>|null
	 */
	private function build_htaccess_observation( array $htaccess, array $folder_bands, $server_type ) {
		$rule_id = $this->resolve_htaccess_rule_id( $htaccess, $folder_bands, $server_type );

		if ( null === $rule_id ) {
			return null;
		}

		$exists         = ! empty( $htaccess['exists'] );
		$indexes_state  = isset( $htaccess['indexes_state'] ) ? $htaccess['indexes_state'] : null;
		$unknown_reason = isset( $htaccess['unknown_reason'] ) ? (string) $htaccess['unknown_reason'] : '';
		$labels         = self::get_category_labels();
		$risk_level     = Sassh_Findings_Service::directory_browsing_risk_level( $rule_id );
		$is_compound    = in_array(
			$rule_id,
			array( 'htaccess-unprotected-folders-open', 'htaccess-unprotected-folders-not-observed' ),
			true
		);

		if ( $is_compound ) {
			$object_fp   = Sassh_Directory_Exposure_Key_Normalizer::htaccess_compound_fingerprint(
				$rule_id,
				$server_type,
				$exists,
				$indexes_state,
				$unknown_reason,
				$folder_bands
			);
			$category_fp = $object_fp;
		} else {
			$object_fp   = Sassh_Directory_Exposure_Key_Normalizer::htaccess_object_fingerprint(
				$server_type,
				$exists,
				$indexes_state,
				$unknown_reason
			);
			$category_fp = Sassh_Directory_Exposure_Key_Normalizer::htaccess_category_fingerprint(
				$rule_id,
				$server_type,
				$exists,
				$indexes_state,
				$unknown_reason
			);
		}

		$guidance     = $this->guidance_contributions_for_rule( $rule_id, $server_type, $unknown_reason );
		$presentation = self::htaccess_browsing_presentation( $indexes_state, $server_type );

		return array(
			'scanner_id'         => self::SCANNER_ID,
			'object_type'        => Sassh_Object_Type_Registry::TYPE_DIRECTORY_EXPOSURE,
			'object_key'         => Sassh_Directory_Exposure_Key_Normalizer::htaccess_object_key(),
			'blog_id'            => null,
			'object_fingerprint' => $object_fp,
			'title'              => '.htaccess',
			'description'        => __( 'Site root .htaccess directory-indexes posture.', 'choctaw-wp-security' ),
			'metadata'           => array(
				'path'              => (string) $htaccess['display_path'],
				'absolute_path'     => (string) $htaccess['absolute_path'],
				'test_url'          => '',
				'testing_method'    => $labels[ self::METHOD_HTACCESS ],
				'category'          => self::METHOD_HTACCESS,
				'category_label'    => $labels[ self::METHOD_HTACCESS ],
				'server_type'       => $server_type,
				'server_type_label' => self::server_type_label( $server_type ),
				'browsing'          => $presentation['browsing'],
				'browsing_label'    => $presentation['browsing_label'],
				'indexes_state'     => $indexes_state,
				'unknown_reason'    => $unknown_reason,
				'contents'          => (string) $htaccess['contents'],
				'contents_truncated' => ! empty( $htaccess['contents_truncated'] ),
				'folder_aggregate'  => Sassh_Directory_Exposure_Key_Normalizer::aggregate_folder_posture_payload( $folder_bands ),
			),
			'categories'         => array(
				array(
					'rule_id'                => $rule_id,
					'risk_level'             => $risk_level,
					'sassh_classification'   => Sassh_Findings_Service::default_classification( $risk_level ),
					'category_fingerprint'   => $category_fp,
					'title'                  => $rule_id,
					'metadata'               => array(
						'category_label'    => $labels[ self::METHOD_HTACCESS ],
						'testing_method'    => $labels[ self::METHOD_HTACCESS ],
						'rule_id'           => $rule_id,
						'server_type'       => $server_type,
						'indexes_state'     => $indexes_state,
						'unknown_reason'    => $unknown_reason,
					),
					'guidance_contributions' => $guidance,
				),
			),
		);
	}

	/**
	 * Build folder Findings observation.
	 *
	 * @param array<string, mixed> $folder      Folder probe.
	 * @param string               $server_type Server type.
	 * @param array<string, mixed> $htaccess    Site-root .htaccess analysis (structured evidence).
	 * @return array<string, mixed>|null
	 */
	private function build_folder_observation( array $folder, $server_type, array $htaccess = array() ) {
		$folder_key = isset( $folder['folder_key'] ) ? (string) $folder['folder_key'] : '';
		$object_key = Sassh_Directory_Exposure_Key_Normalizer::folder_object_key( $folder_key );

		if ( is_wp_error( $object_key ) ) {
			return null;
		}

		$browsing = isset( $folder['browsing'] ) ? (string) $folder['browsing'] : self::BROWSING_UNKNOWN;

		if ( self::BROWSING_OPEN === $browsing ) {
			$rule_id = 'directory-listing-open';
		} elseif ( self::BROWSING_NOT_OBSERVED === $browsing ) {
			$rule_id = 'directory-listing-not-observed';
		} else {
			$rule_id = 'directory-listing-unknown';
		}

		$http_class    = isset( $folder['http_class'] ) ? (string) $folder['http_class'] : 'failed';
		$has_index     = ! empty( $folder['has_index'] );
		$display       = isset( $folder['display_path'] ) ? (string) $folder['display_path'] : '';
		$blog_id       = Sassh_Directory_Exposure_Key_Normalizer::blog_id_for_folder( $folder_key, $display );
		$risk_level    = Sassh_Findings_Service::directory_browsing_risk_level( $rule_id );
		$labels        = self::get_category_labels();
		$object_fp     = Sassh_Directory_Exposure_Key_Normalizer::folder_object_fingerprint( $folder_key, $browsing, $http_class, $has_index );
		$category_fp   = Sassh_Directory_Exposure_Key_Normalizer::folder_category_fingerprint( $rule_id, $folder_key, $browsing, $http_class, $has_index );
		$indexes_state = array_key_exists( 'indexes_state', $htaccess ) ? $htaccess['indexes_state'] : null;
		$guidance      = self::folder_guidance_contributions( $indexes_state, $browsing, $server_type );

		$title = isset( $folder['label'] ) ? (string) $folder['label'] : $folder_key;

		return array(
			'scanner_id'         => self::SCANNER_ID,
			'object_type'        => Sassh_Object_Type_Registry::TYPE_DIRECTORY_EXPOSURE,
			'object_key'         => $object_key,
			'blog_id'            => $blog_id,
			'object_fingerprint' => $object_fp,
			'title'              => $title,
			'description'        => __( 'Public folder directory-listing HTTP probe.', 'choctaw-wp-security' ),
			'metadata'           => array(
				'path'              => $display,
				'absolute_path'     => isset( $folder['absolute_path'] ) ? (string) $folder['absolute_path'] : '',
				'test_url'          => isset( $folder['test_url'] ) ? (string) $folder['test_url'] : '',
				'testing_method'    => $labels[ self::METHOD_DIRECTORY_TEST ],
				'category'          => self::METHOD_DIRECTORY_TEST,
				'category_label'    => $labels[ self::METHOD_DIRECTORY_TEST ],
				'server_type'       => $server_type,
				'server_type_label' => self::server_type_label( $server_type ),
				'browsing'          => $browsing,
				'browsing_label'    => self::browsing_label( $browsing ),
				'http_status'       => isset( $folder['http_status'] ) ? (int) $folder['http_status'] : 0,
				'http_class'        => $http_class,
				'has_index'         => $has_index,
				'contents'          => isset( $folder['contents'] ) ? (string) $folder['contents'] : '',
				'contents_truncated' => ! empty( $folder['contents_truncated'] ),
				'folder_key'        => $folder_key,
				'indexes_state'     => $indexes_state,
			),
			'categories'         => array(
				array(
					'rule_id'                => $rule_id,
					'risk_level'             => $risk_level,
					'sassh_classification'   => Sassh_Findings_Service::default_classification( $risk_level ),
					'category_fingerprint'   => $category_fp,
					'title'                  => $rule_id,
					'metadata'               => array(
						'category_label' => $labels[ self::METHOD_DIRECTORY_TEST ],
						'testing_method' => $labels[ self::METHOD_DIRECTORY_TEST ],
						'rule_id'        => $rule_id,
						'browsing'       => $browsing,
						'http_class'     => $http_class,
						'indexes_state'  => $indexes_state,
					),
					'guidance_contributions' => $guidance,
				),
			),
		);
	}

	/**
	 * Built-in guidance contribution packs per rule.
	 *
	 * @param string $rule_id        Rule id.
	 * @param string $server_type    Server type.
	 * @param string $unknown_reason Htaccess unknown reason.
	 * @return array<int, array<string, mixed>>
	 */
	private function guidance_contributions_for_rule( $rule_id, $server_type, $unknown_reason ) {
		$packs = array(
			'directory-listing-open' => array(
				array(
					'id'               => 'dirbrowse.open.evidence.listing',
					'kind'             => 'evidence_fact',
					'display_priority' => 10,
					'text'             => __( 'Requesting this folder URL returned a recognizable directory listing.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.exposure',
				),
				array(
					'id'               => 'dirbrowse.open.interpretation.exposure_not_compromise',
					'kind'             => 'warning_caveat',
					'display_priority' => 10,
					'text'             => __( 'An open directory listing is a security misconfiguration and reconnaissance exposure. It does not itself indicate that the site is compromised or that malware is present. Warning reflects the seriousness of confirmed public exposure.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.certainty',
				),
				array(
					'id'               => 'dirbrowse.open.action.disable',
					'kind'             => 'recommended_action',
					'display_priority' => 20,
					'text'             => self::SERVER_NGINX === $server_type
						? __( 'Disable autoindex in the Nginx server or location block (autoindex off;), reload Nginx, or add a blank index.php in this folder as a temporary fallback. See “How to Turn Directory Browsing Off”.', 'choctaw-wp-security' )
						: __( 'Prefer disabling indexes site-wide with Options -Indexes in .htaccess when allowed, or add a blank index file in this folder as a fallback. See “How to Turn Directory Browsing Off”.', 'choctaw-wp-security' ),
					'tags'             => array( 'investigate' ),
					'concern'          => 'dirbrowse.proceed',
				),
			),
			'directory-listing-not-observed' => array(
				array(
					'id'               => 'dirbrowse.not_observed.evidence.http',
					'kind'             => 'evidence_fact',
					'display_priority' => 10,
					'text'             => __( 'The tested URL did not expose a recognizable directory listing during this scan.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.exposure',
				),
				array(
					'id'               => 'dirbrowse.not_observed.caveat.not_config_proof',
					'kind'             => 'warning_caveat',
					'display_priority' => 10,
					'text'             => __( 'This is an observed HTTP result, not proof that the underlying server configuration disables directory browsing. An index file, redirect, authentication response, CDN/WAF response, or custom error page might mask browsing posture.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.certainty',
				),
			),
			'directory-listing-unknown' => array(
				array(
					'id'               => 'dirbrowse.unknown.evidence',
					'kind'             => 'evidence_fact',
					'display_priority' => 10,
					'text'             => __( 'This scan could not determine whether directory listing is exposed for this folder. The HTTP request failed, timed out, returned an unclassifiable response, or the target could not be evaluated.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.exposure',
				),
				array(
					'id'               => 'dirbrowse.unknown.action.verify',
					'kind'             => 'recommended_action',
					'display_priority' => 20,
					'text'             => __( 'Verify the folder URL manually in a browser, confirm the site allows loopback HTTP requests, and review server directory-listing settings using “How to Turn Directory Browsing Off”.', 'choctaw-wp-security' ),
					'tags'             => array( 'investigate' ),
					'concern'          => 'dirbrowse.proceed',
				),
			),
			'htaccess-indexes-disabled' => array(
				array(
					'id'               => 'dirbrowse.htaccess.off.evidence',
					'kind'             => 'evidence_fact',
					'display_priority' => 10,
					'text'             => __( 'The site root .htaccess file contains Options -Indexes, which instructs Apache or LiteSpeed to disable directory listings for directories covered by this configuration.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.config',
				),
				array(
					'id'               => 'dirbrowse.htaccess.off.interpretation',
					'kind'             => 'interpretation',
					'display_priority' => 10,
					'text'             => __( 'Indexes appear disabled from evaluated .htaccess configuration. No action is required for the .htaccess file based on this check.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.config',
				),
				array(
					'id'               => 'dirbrowse.htaccess.off.action',
					'kind'             => 'recommended_action',
					'display_priority' => 20,
					'text'             => __( 'No action is required for the .htaccess file based on this check.', 'choctaw-wp-security' ),
					'tags'             => array( 'nondestructive' ),
					'concern'          => 'dirbrowse.proceed',
				),
			),
			'htaccess-indexes-enabled' => array(
				array(
					'id'               => 'dirbrowse.htaccess.on.evidence',
					'kind'             => 'evidence_fact',
					'display_priority' => 10,
					'text'             => __( 'The site root .htaccess file explicitly enables directory indexes (Options +Indexes or Indexes).', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.config',
				),
				array(
					'id'               => 'dirbrowse.htaccess.on.exposure_not_compromise',
					'kind'             => 'warning_caveat',
					'display_priority' => 10,
					'text'             => __( 'Enabled directory indexing is a security misconfiguration / reconnaissance exposure. It does not itself indicate compromise. Warning reflects exposure seriousness.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.certainty',
				),
				array(
					'id'               => 'dirbrowse.htaccess.on.action',
					'kind'             => 'recommended_action',
					'display_priority' => 20,
					'text'             => __( 'Replace Indexes / +Indexes with Options -Indexes when your host allows it. See “How to Turn Directory Browsing Off”.', 'choctaw-wp-security' ),
					'tags'             => array( 'investigate' ),
					'concern'          => 'dirbrowse.proceed',
				),
			),
			'htaccess-nginx-ignored' => array(
				array(
					'id'               => 'dirbrowse.htaccess.nginx.evidence',
					'kind'             => 'evidence_fact',
					'display_priority' => 10,
					'text'             => __( 'An .htaccess file was found in the WordPress root, but Nginx does not read .htaccess files.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.config',
				),
				array(
					'id'               => 'dirbrowse.htaccess.nginx.interpretation',
					'kind'             => 'interpretation',
					'display_priority' => 10,
					'text'             => __( 'Files like this are often left behind after a migration from Apache or LiteSpeed. No action is needed for this .htaccess file regarding directory browsing on Nginx.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.config',
				),
			),
			'htaccess-indexes-inconclusive' => array(
				array(
					'id'               => 'dirbrowse.htaccess.inconclusive.evidence',
					'kind'             => 'evidence_fact',
					'display_priority' => 10,
					'text'             => $this->htaccess_inconclusive_why( $unknown_reason ),
					'concern'          => 'dirbrowse.config',
				),
				array(
					'id'               => 'dirbrowse.htaccess.inconclusive.action',
					'kind'             => 'recommended_action',
					'display_priority' => 20,
					'text'             => __( 'Review the Directory Test rows for each public folder. Prefer adding Options -Indexes to the site root .htaccess when your host allows it. See “How to Turn Directory Browsing Off”.', 'choctaw-wp-security' ),
					'tags'             => array( 'investigate' ),
					'concern'          => 'dirbrowse.proceed',
				),
			),
			'htaccess-unprotected-folders-open' => array(
				array(
					'id'               => 'dirbrowse.htaccess.unprotected_open.evidence',
					'kind'             => 'evidence_fact',
					'display_priority' => 10,
					'text'             => __( 'The site root .htaccess file does not disable directory indexes, and at least one tested public folder returned a recognizable directory listing.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.exposure',
				),
				array(
					'id'               => 'dirbrowse.htaccess.unprotected_open.exposure_not_compromise',
					'kind'             => 'warning_caveat',
					'display_priority' => 10,
					'text'             => __( 'This combination is a security misconfiguration / reconnaissance exposure. It does not itself indicate compromise. Warning reflects exposure seriousness.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.certainty',
				),
				array(
					'id'               => 'dirbrowse.htaccess.unprotected_open.action',
					'kind'             => 'recommended_action',
					'display_priority' => 20,
					'text'             => __( 'Disable directory browsing site-wide by adding Options -Indexes to the site root .htaccess (when allowed), or fix each unprotected folder. See “How to Turn Directory Browsing Off”.', 'choctaw-wp-security' ),
					'tags'             => array( 'investigate' ),
					'concern'          => 'dirbrowse.proceed',
				),
			),
			'htaccess-unprotected-folders-not-observed' => array(
				array(
					'id'               => 'dirbrowse.htaccess.unprotected_ok.evidence',
					'kind'             => 'evidence_fact',
					'display_priority' => 10,
					'text'             => __( 'The site root .htaccess file does not disable directory indexes, but every intended public folder probe completed without exposing a recognizable directory listing.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.config',
				),
				array(
					'id'               => 'dirbrowse.htaccess.unprotected_ok.caveat',
					'kind'             => 'warning_caveat',
					'display_priority' => 10,
					'text'             => __( 'Prefer adding Options -Indexes for site-wide protection so browsing does not depend on individual folders or HTTP responses that may mask posture. See “How to Turn Directory Browsing Off”.', 'choctaw-wp-security' ),
					'concern'          => 'dirbrowse.certainty',
				),
			),
		);

		return isset( $packs[ $rule_id ] ) ? $packs[ $rule_id ] : array();
	}

	/**
	 * Why text for inconclusive htaccess.
	 *
	 * @param string $reason Unknown reason.
	 * @return string
	 */
	private function htaccess_inconclusive_why( $reason ) {
		if ( 'not_found' === $reason ) {
			return __( 'The site root .htaccess file could not be found or was empty, so this scan could not confirm whether Options -Indexes is configured.', 'choctaw-wp-security' );
		}

		if ( 'unreadable' === $reason ) {
			return __( 'The site root .htaccess file exists but could not be read by WordPress, so this scan could not confirm whether Options -Indexes is configured.', 'choctaw-wp-security' );
		}

		return __( 'The site root .htaccess file did not contain a clear Options directive related to directory indexes, so this method could not confirm browsing protection from configuration alone.', 'choctaw-wp-security' );
	}

	/**
	 * Partition guidance contributions into Why / How display strings.
	 *
	 * @param array<int, array<string, mixed>> $contributions Contributions.
	 * @return array{why: string, how: string}
	 */
	private static function guidance_texts_from_contributions( array $contributions ) {
		$why = array();
		$how = array();

		foreach ( $contributions as $c ) {
			$kind = isset( $c['kind'] ) ? (string) $c['kind'] : '';
			$text = isset( $c['text'] ) ? (string) $c['text'] : '';
			if ( '' === $text ) {
				continue;
			}
			if ( 'evidence_fact' === $kind || 'interpretation' === $kind || 'warning_caveat' === $kind ) {
				$why[] = $text;
			} elseif ( 'recommended_action' === $kind || 'prerequisite' === $kind ) {
				$how[] = $text;
			}
		}

		return array(
			'why' => implode( "\n\n", $why ),
			'how' => implode( "\n\n", $how ),
		);
	}

	/**
	 * Build UI report payload from persisted findings.
	 *
	 * @param Sassh_Findings_Service $service      Service.
	 * @param int                    $execution_id Execution id.
	 * @param array<string, mixed>   $run_meta     Run summary fields.
	 * @return array<string, mixed>
	 */
	private function build_report_from_findings( Sassh_Findings_Service $service, $execution_id, array $run_meta ) {
		$completion  = isset( $run_meta['completion_status'] ) ? (string) $run_meta['completion_status'] : 'failed';
		$coverage_ok = ( 'success' === $completion );
		$server_type = isset( $run_meta['server_type'] ) ? (string) $run_meta['server_type'] : $this->get_server_type();
		$rows        = $service->list_findings(
			array(
				'scanner_id'      => self::SCANNER_ID,
				'detection_state' => 'active',
			)
		);

		$htaccess_indexes_state = null;
		$htaccess_key           = Sassh_Directory_Exposure_Key_Normalizer::htaccess_object_key();
		foreach ( $rows as $probe_row ) {
			$probe_key = isset( $probe_row['object_key'] ) ? (string) $probe_row['object_key'] : '';
			$probe_cat = isset( $probe_row['category'] ) ? (string) $probe_row['category'] : '';
			if ( $htaccess_key === $probe_key || self::METHOD_HTACCESS === $probe_cat ) {
				if ( array_key_exists( 'indexes_state', $probe_row ) ) {
					$htaccess_indexes_state = $probe_row['indexes_state'];
				}
				break;
			}
		}

		$findings   = array();
		$critical   = 0;
		$warning    = 0;
		$suspicious = 0;
		$info       = 0;
		$safe       = 0;
		$confirmed  = 0;

		foreach ( $rows as $row ) {
			$confirmed_this_run = isset( $row['last_scanner_execution_id'] )
				&& (int) $row['last_scanner_execution_id'] === (int) $execution_id;

			if ( $confirmed_this_run ) {
				++$confirmed;
			}

			$risk = isset( $row['risk_level'] ) ? (string) $row['risk_level'] : 'info';

			if ( 'critical' === $risk ) {
				++$critical;
			} elseif ( 'warning' === $risk ) {
				++$warning;
			} elseif ( 'suspicious' === $risk ) {
				++$suspicious;
			} elseif ( 'info' === $risk ) {
				++$info;
			} elseif ( 'safe' === $risk ) {
				++$safe;
			}

			$why = isset( $row['why_seeing_this'] ) ? $row['why_seeing_this'] : '';
			$how = isset( $row['how_to_proceed'] ) ? $row['how_to_proceed'] : '';

			if ( is_array( $why ) ) {
				$why = implode( "\n\n", array_map( 'strval', $why ) );
			}
			if ( is_array( $how ) ) {
				$how = implode( "\n\n", array_map( 'strval', $how ) );
			}

			$browsing       = isset( $row['browsing'] ) ? (string) $row['browsing'] : '';
			$browsing_label = isset( $row['browsing_label'] ) ? (string) $row['browsing_label'] : '';
			$row_server     = isset( $row['server_type'] ) ? (string) $row['server_type'] : $server_type;
			$object_key     = isset( $row['object_key'] ) ? (string) $row['object_key'] : '';
			$category       = isset( $row['category'] ) ? (string) $row['category'] : '';

			// Prefer structured indexes_state for .htaccess column presentation.
			if (
				self::METHOD_HTACCESS === $category
				|| $htaccess_key === $object_key
			) {
				$indexes_state = array_key_exists( 'indexes_state', $row ) ? $row['indexes_state'] : null;
				$presentation  = self::htaccess_browsing_presentation( $indexes_state, $row_server );
				$browsing      = $presentation['browsing'];
				$browsing_label = $presentation['browsing_label'];
			} elseif ( '' === $browsing_label && '' !== $browsing ) {
				$browsing_label = self::browsing_label( $browsing );
			}

			// Rebuild folder Why/How from structured htaccess + HTTP evidence.
			if ( self::METHOD_DIRECTORY_TEST === $category && '' !== $browsing ) {
				$folder_indexes = array_key_exists( 'indexes_state', $row )
					? $row['indexes_state']
					: $htaccess_indexes_state;
				$texts = self::guidance_texts_from_contributions(
					self::folder_guidance_contributions( $folder_indexes, $browsing, $row_server )
				);
				if ( '' !== $texts['why'] ) {
					$why = $texts['why'];
				}
				if ( '' !== $texts['how'] ) {
					$how = $texts['how'];
				}
			}

			$findings[] = array(
				'id'                     => $row['finding_id'],
				'finding_id'             => $row['finding_id'],
				'fingerprint'            => $row['content_fingerprint'],
				'content_fingerprint'    => $row['content_fingerprint'],
				'object_fingerprint'     => $row['object_fingerprint'],
				'path'                   => isset( $row['path'] ) ? $row['path'] : $row['object_key'],
				'absolute_path'          => isset( $row['absolute_path'] ) ? $row['absolute_path'] : '',
				'test_url'               => isset( $row['test_url'] ) ? $row['test_url'] : '',
				'risk'                   => $risk,
				'risk_level'             => $risk,
				'risk_label'             => isset( $row['risk_label'] ) ? $row['risk_label'] : $risk,
				'status'                 => $row['effective_status'],
				'status_label'           => $row['status_label'],
				'effective_status'       => $row['effective_status'],
				'can_dismiss'            => ! empty( $row['can_dismiss'] ),
				'dismissal_control_state' => isset( $row['dismissal_control_state'] ) ? $row['dismissal_control_state'] : Sassh_Findings_Service::dismissal_control_state( $row ),
				'category'               => $category,
				'category_label'         => isset( $row['category_label'] ) ? $row['category_label'] : '',
				'category_label_display' => isset( $row['category_label_display'] ) ? $row['category_label_display'] : '',
				'testing_method'         => isset( $row['testing_method'] ) ? $row['testing_method'] : '',
				'server_type'            => $row_server,
				'server_type_label'      => isset( $row['server_type_label'] ) ? $row['server_type_label'] : self::server_type_label( $row_server ),
				'browsing'               => $browsing,
				'browsing_label'         => $browsing_label,
				'contents'               => isset( $row['contents'] ) ? $row['contents'] : '',
				'contents_truncated'       => ! empty( $row['contents_truncated'] ),
				'why_seeing_this'        => $why,
				'how_to_proceed'         => $how,
				'first_seen_at'          => $row['first_seen_at'],
				'last_seen_at'           => $row['last_seen_at'],
				'detection_state'        => $row['detection_state'],
				'confirmed_this_run'     => $confirmed_this_run,
				'categories'             => ( isset( $row['categories'] ) && is_array( $row['categories'] ) ) ? $row['categories'] : array(),
				'extra_rule_count'       => isset( $row['extra_rule_count'] ) ? (int) $row['extra_rule_count'] : 0,
				'guidance'               => ( isset( $row['guidance'] ) && is_array( $row['guidance'] ) ) ? $row['guidance'] : array(),
				'findings_backend'       => 'sassh',
			);
		}

		$count   = count( $findings );
		$flagged = $critical + $warning + $suspicious;

		return array(
			'success'             => $coverage_ok && 0 === $flagged,
			'coverage_complete'   => $coverage_ok,
			'absence_reconciled'  => $coverage_ok,
			'completion_status'   => $completion,
			'scan_incomplete'     => ! empty( $run_meta['scan_incomplete'] ) || ! $coverage_ok,
			'errors'              => isset( $run_meta['errors'] ) && is_array( $run_meta['errors'] ) ? $run_meta['errors'] : array(),
			'findings'            => $findings,
			'confirmed_this_run'  => $confirmed,
			'prior_findings_only' => ! $coverage_ok && $count > 0 && 0 === $confirmed,
			'server_type'         => $server_type,
			'server_type_label'   => self::server_type_label( $server_type ),
			'scanned_at'          => time(),
			'findings_backend'    => 'sassh',
			'summary'             => array(
				'critical'   => $critical,
				'warning'    => $warning,
				'suspicious' => $suspicious,
				'info'       => $info,
				'safe'       => $safe,
				'total'      => $count,
				'flagged'    => $flagged,
			),
		);
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
