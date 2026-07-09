<?php
/**
 * Central registry for admin help copy.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Help text keyed by stable identifiers.
 */
class Choctaw_Wp_Security_Admin_Help_Content {

	/**
	 * Field-level help content for settings and disclosures.
	 *
	 * @param string $id Field identifier.
	 * @return array<string, mixed>
	 */
	public static function get_field( $id ) {
		$fields = self::get_fields();

		return isset( $fields[ $id ] ) ? $fields[ $id ] : array();
	}

	/**
	 * Tab intro content: visible first paragraph plus About panel HTML.
	 *
	 * @param string $id Tab identifier.
	 * @return array<string, string>
	 */
	public static function get_tab_intro( $id ) {
		$intros = self::get_tab_intros();

		return isset( $intros[ $id ] ) ? $intros[ $id ] : array();
	}

	/**
	 * Guidance box content for actionable instructions.
	 *
	 * @param string $id Guidance identifier.
	 * @return array<string, mixed>
	 */
	public static function get_guidance( $id ) {
		$entries = self::get_guidance_entries();

		return isset( $entries[ $id ] ) ? $entries[ $id ] : array();
	}

	/**
	 * Supplementary detail for scan report subsections.
	 *
	 * @param string $section_key Section identifier.
	 * @return string
	 */
	public static function get_scan_section_detail( $section_key ) {
		$details = self::get_scan_section_details();

		return isset( $details[ $section_key ] ) ? (string) $details[ $section_key ] : '';
	}

	/**
	 * Supplementary detail for a Recent File Changes table row.
	 *
	 * @param string $relative_path WordPress-relative file path.
	 * @return string
	 */
	public static function get_core_file_change_detail( $relative_path ) {
		$details = self::get_core_file_change_details();

		$relative_path = wp_normalize_path( (string) $relative_path );

		return isset( $details[ $relative_path ] ) ? (string) $details[ $relative_path ] : '';
	}

	/**
	 * Stable help identifier for a Recent File Changes table row.
	 *
	 * @param string $relative_path WordPress-relative file path.
	 * @return string
	 */
	public static function get_core_file_change_help_id( $relative_path ) {
		return 'core-file-' . sanitize_key( str_replace( array( '/', '.' ), '-', wp_normalize_path( (string) $relative_path ) ) );
	}

	/**
	 * All field help entries.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private static function get_fields() {
		return array(
			'xmlrpc_blocking'           => array(
				'summary'             => __( 'XML-RPC is an old feature meant to facilitate WordPress functionality in third-party applications, but remains a popular attack vector for automated-hacks.', 'choctaw-wp-security' ),
				'detail'              => self::xmlrpc_blocking_detail_html(),
				'show_recommendation' => true,
			),
			'login_rate_limit'          => array(
				'summary'             => __( 'Forces login-delays after several failed login attempts. Both IP-only and IP-plus-username scopes are tracked.', 'choctaw-wp-security' ),
				'detail'              => self::login_rate_limit_detail_html(),
				'show_recommendation' => true,
			),
			'uploads_php_lockdown'      => array(
				'summary_html'        => self::uploads_lockdown_summary_html(),
				'detail'              => self::uploads_php_lockdown_apache_detail_html(),
				'show_recommendation' => true,
			),
			'block_user_rest_api'       => array(
				'summary'             => __( 'Block anonymous access to the "user" endpoint via REST API.', 'choctaw-wp-security' ),
				'detail'              => self::block_user_rest_api_detail_html(),
				'show_recommendation' => true,
			),
			'block_author_query'        => array(
				'summary_html'        => sprintf(
					/* translators: %s: author query URL pattern */
					__( 'Blocks anonymous users from seeing usernames when a user ID is requested from %s URL parameter.', 'choctaw-wp-security' ),
					'<code>/?author=x</code>'
				),
				'detail'              => self::block_author_query_detail_html(),
				'show_recommendation' => true,
			),
			'block_author_archives'     => array(
				'summary'             => __( 'Prevents anonymous users from obtaining usernames from Author Archive pages.', 'choctaw-wp-security' ),
				'detail'              => self::block_author_archives_detail_html(),
				'show_recommendation' => true,
			),
			'normalize_login_errors'    => array(
				'summary'             => __( 'Change the login error message to "Failed login, please try again."', 'choctaw-wp-security' ),
				'detail'              => self::normalize_login_errors_detail_html(),
				'show_recommendation' => true,
			),
			'allowed_failed_attempts'   => array(
				'summary' => __( 'Enter the maximum number of failed login attempts before delay kicks in.', 'choctaw-wp-security' ),
			),
			'failure_window_minutes'    => array(
				'summary' => __( 'This is the number of minutes in a window of failed attempts (5 failed attempts within a 15 minute window).', 'choctaw-wp-security' ),
			),
			'lockout_duration_minutes'  => array(
				'summary' => __( 'Enter how many minutes someone must wait to attempt more logins.', 'choctaw-wp-security' ),
			),
			'file_changes_recent'       => array(
				'summary' => __( 'These high-value WordPress files are frequently targeted by attackers. Unexpected modification dates or failed checksum verification may indicate unauthorized changes and should be investigated.', 'choctaw-wp-security' ),
				'detail'  => self::file_changes_recent_detail_html(),
			),
			'file_changes_php_uploads'  => array(
				'summary_html' => self::php_uploads_summary_html(),
				'detail'       => self::file_changes_php_uploads_detail_html(),
			),
			'file_changes_uploads_plugins' => array(
				'summary_html' => self::uploads_plugins_summary_html(),
				'detail'       => self::file_changes_uploads_plugins_detail_html(),
			),
			'recent_lockouts'           => array(
				'summary' => __( 'Shared IP addresses (NAT/office networks) may cause IP-only lockouts to affect other users temporarily.', 'choctaw-wp-security' ),
			),
		);
	}

	/**
	 * Tab intro entries.
	 *
	 * @return array<string, array<string, string>>
	 */
	private static function get_tab_intros() {
		return array(
			'database_scan'    => array(
				'visible'    => __( 'wp_options inspects a WordPress options table for records that may indicate compromise. It looks for hijacked site URLs, tampered plugin lists, suspicious cron jobs, oversized autoloaded options, PHP or execution patterns, and other high-risk indicators.', 'choctaw-wp-security' ),
				'about_html' => self::database_scan_about_html(),
			),
			'posts_scan'       => array(
				'visible'    => __( 'wp_posts inspects a WordPress posts table for content that may indicate compromise. It looks for PHP or execution patterns, script and iframe injections, SEO spam titles, unusually large post content, and changes since your last scan.', 'choctaw-wp-security' ),
				'about_html' => self::posts_scan_about_html(),
			),
			'users_table'      => array(
				'visible'     => __( 'This scan displays every user account stored in the selected WordPress users table, helping you identify unexpected accounts and review existing user assignments.', 'choctaw-wp-security' ),
				'detail_html' => self::users_table_detail_html(),
			),
			'component_scan'   => array(
				'visible'     => __( 'Checks your installed WordPress core version, active theme, and active plugins for publicly known security vulnerabilities using the WPVulnerability database. Components that cannot be matched to the database are listed separately.', 'choctaw-wp-security' ),
				'detail_html' => self::component_scan_detail_html(),
			),
			'core_checksum'    => array(
				'visible_html' => self::core_checksum_visible_html(),
				'detail_html'  => self::core_checksum_detail_html(),
			),
			'exposed_folders'  => array(
				'visible'     => __( 'Scan your web server to determine whether directory browsing is enabled.', 'choctaw-wp-security' ),
				'detail_html' => self::exposed_folders_detail_html(),
			),
		);
	}

	/**
	 * Optional supplementary detail for scan subsections (empty until post-implementation review).
	 *
	 * @return array<string, string>
	 */
	private static function get_scan_section_details() {
		return array();
	}

	/**
	 * Reduce Username Exposure section summary line.
	 *
	 * @return string
	 */
	public static function username_discovery_section_summary() {
		return __( 'These settings block the most common ways hackers and bots discover WordPress usernames. They do not block every possible discovery method.', 'choctaw-wp-security' );
	}

	/**
	 * Reduce Username Exposure section "Why this matters" detail HTML.
	 *
	 * @return string
	 */
	public static function username_discovery_section_detail_html() {
		return self::paragraphs_to_html(
			array(
				__( 'Before an attacker can guess a password, they must first know the username. For that reason, automated bots routinely probe WordPress websites looking for valid usernames using a variety of techniques. These include querying the WordPress REST API, requesting author archive pages, manipulating the ?author= URL parameter, and analyzing login error messages. Once a valid username has been identified, attackers can focus their password-guessing attacks against a known account instead of blindly trying random usernames.', 'choctaw-wp-security' ),
				__( 'These protections reduce the amount of information available to anonymous visitors by blocking the most common username enumeration techniques used by automated scanners. While no solution can completely prevent username discovery, enabling these protections makes automated reconnaissance more difficult and forces attackers to expend additional time and resources. These settings work particularly well when combined with Login Rate Limiting and strong passwords.', 'choctaw-wp-security' ),
			)
		);
	}

	/**
	 * Block User REST API "Why this matters" detail HTML.
	 *
	 * @return string
	 */
	private static function block_user_rest_api_detail_html() {
		return self::paragraphs_to_html(
			array(
				__( 'WordPress exposes a REST API that allows applications and plugins to communicate with the website. Unless restricted, one of its endpoints can return information about site users, including usernames and display names. Automated vulnerability scanners frequently query this endpoint as one of their first reconnaissance steps.', 'choctaw-wp-security' ),
				__( 'Enabling this option prevents anonymous visitors from accessing the user endpoint while allowing authenticated users and authorized applications to continue functioning normally. If other websites or applications rely on your site\'s "user" REST API, you may need to leave this option disabled.', 'choctaw-wp-security' ),
			)
		);
	}

	/**
	 * Block author query "Why this matters" detail HTML.
	 *
	 * @return string
	 */
	private static function block_author_query_detail_html() {
		return self::paragraphs_to_html(
			array(
				__( 'WordPress has long supported author pages using URLs such as /?author=1. When accessed, WordPress redirects visitors to the author\'s archive page, revealing the associated username in the URL. Automated bots often cycle through author IDs until they discover one or more valid usernames.', 'choctaw-wp-security' ),
				__( 'This setting blocks anonymous requests that attempt to enumerate users through the ?author= parameter. While this does not prevent every possible method of username discovery, it eliminates one of the oldest and most commonly used enumeration techniques.', 'choctaw-wp-security' ),
			)
		);
	}

	/**
	 * Block author archives "Why this matters" detail HTML.
	 *
	 * @return string
	 */
	private static function block_author_archives_detail_html() {
		return self::paragraphs_to_html(
			array(
				__( 'Author archive pages list all posts written by a particular user. Even when usernames are not directly displayed on the page, the URL structure and page metadata often reveal the author\'s login name. These pages are frequently indexed by search engines and are routinely checked by automated scanners.', 'choctaw-wp-security' ),
				__( 'If your website has only one or two authors, or if individual author pages are not important to your visitors, disabling public access helps reduce unnecessary exposure of user information. If your website depends on author archive pages for content discovery or SEO, you may wish to leave this feature disabled.', 'choctaw-wp-security' ),
			)
		);
	}

	/**
	 * Normalize login errors "Why this matters" detail HTML.
	 *
	 * @return string
	 */
	private static function normalize_login_errors_detail_html() {
		return self::paragraphs_to_html(
			array(
				__( 'By default, WordPress returns different login error messages depending on whether the username or password is incorrect. For example, it may indicate that a username does not exist while returning a different message for an incorrect password. Attackers can use this behavior to quickly identify valid usernames without needing to exploit another enumeration method.', 'choctaw-wp-security' ),
				__( 'This option replaces WordPress\'s default login errors with the generic message, "Failed login, please try again." Because the same response is shown regardless of whether the username or password is incorrect, attackers gain no additional information from failed login attempts. Legitimate users are still informed that the login failed, but the underlying reason is no longer disclosed.', 'choctaw-wp-security' ),
			)
		);
	}

	/**
	 * XML-RPC blocking "Why this matters" detail HTML.
	 *
	 * @return string
	 */
	private static function xmlrpc_blocking_detail_html() {
		return self::paragraphs_to_html(
			array(
				__( 'XML-RPC was introduced to allow external applications and services to communicate with WordPress over the Internet. While it was once important for remote publishing, many modern WordPress features now use the WordPress REST API instead, leaving XML-RPC unnecessary for most websites. Because it is enabled by default, attackers frequently target it for password-guessing attacks, pingback abuse, and other automated attempts to gain access or consume server resources. Disabling XML-RPC removes one of the most commonly scanned entry points without affecting the normal operation of most WordPress sites.', 'choctaw-wp-security' ),
				__( 'Some third-party services still rely on XML-RPC. You may need to leave it enabled if your site uses Jetpack (certain features), the WordPress mobile app, desktop publishing applications such as Open Live Writer, or legacy remote publishing tools. If you disable XML-RPC and later discover that one of these services no longer functions correctly, simply re-enable this setting. For the vast majority of WordPress websites, however, XML-RPC is no longer required and can be safely disabled.', 'choctaw-wp-security' ),
			)
		);
	}

	/**
	 * Login rate limiting "Why this matters" detail HTML.
	 *
	 * @return string
	 */
	private static function login_rate_limit_detail_html() {
		return self::paragraphs_to_html(
			array(
				__( 'Every WordPress website includes the wp-login.php page, making it one of the first places automated bots attempt to attack. Rather than exploiting a software vulnerability, these attacks simply try thousands of common usernames and passwords until one succeeds. Even if the attacker never gains access, a continuous stream of login attempts can consume server resources, fill security logs, and slow down your website. Most WordPress sites receive these attacks on a regular basis, regardless of their size or popularity.', 'choctaw-wp-security' ),
				__( 'Login rate limiting helps defend against these attacks by temporarily delaying additional login attempts after a configurable number of failed logins within a specified time window. This plugin tracks both repeated attempts from the same IP address and repeated attempts against the same username from different IP addresses, making distributed password-guessing attacks significantly less effective. While this feature cannot stop attacks against custom login pages or other authentication methods, it provides an effective layer of protection for the standard wp-login.php login page and is recommended for nearly all WordPress websites.', 'choctaw-wp-security' ),
			)
		);
	}

	/**
	 * Uploads lockdown summary with file path markup.
	 *
	 * @return string
	 */
	private static function uploads_lockdown_summary_html() {
		return sprintf(
			/* translators: %s: wp-content/uploads/ path */
			__( 'Prevents PHP scripts from being executed from your %s folder, which is a common attack vector.', 'choctaw-wp-security' ),
			'<code class="cws-file-path">wp-content/uploads/</code>'
		);
	}

	/**
	 * Uploads lockdown unavailable summary for Nginx servers.
	 *
	 * @return string
	 */
	public static function uploads_lockdown_nginx_unavailable_summary_html() {
		return sprintf(
			/* translators: %s: wp-content/uploads/ path */
			__( 'This checkbox is unavailable because this site is running on an Nginx server. Instead, add the server configuration snippet below to your site block to prevent PHP execution from within the %s folder.', 'choctaw-wp-security' ),
			'<code class="cws-file-path">wp-content/uploads/</code>'
		);
	}

	/**
	 * Uploads lockdown "Why this matters" detail for Apache and LiteSpeed.
	 *
	 * @return string
	 */
	private static function uploads_php_lockdown_apache_detail_html() {
		return self::paragraphs_to_html(
			array(
				self::uploads_php_lockdown_attack_vector_paragraph(),
				__( 'On Apache and LiteSpeed servers, this plugin can enforce the protection automatically by installing a managed .htaccess block in wp-content/uploads that denies access to PHP and related executable file types.', 'choctaw-wp-security' ),
			)
		);
	}

	/**
	 * Uploads lockdown "Why this matters" detail for Nginx servers.
	 *
	 * @return string
	 */
	public static function uploads_php_lockdown_nginx_detail_html() {
		return self::paragraphs_to_html(
			array(
				self::uploads_php_lockdown_attack_vector_paragraph(),
				__( 'Nginx does not use .htaccess files, so this plugin cannot apply the rule from WordPress. The checkbox is unavailable here because uploads PHP blocking must be configured directly in your Nginx site block using the snippet above.', 'choctaw-wp-security' ),
			)
		);
	}

	/**
	 * Shared attack-vector paragraph for uploads PHP lockdown help detail.
	 *
	 * @return string
	 */
	private static function uploads_php_lockdown_attack_vector_paragraph() {
		return __( 'Attackers often upload or place PHP files in writable directories such as wp-content/uploads, including by exploiting vulnerable file upload or attachment forms. If those files can be executed through the web server, they may be used as web shells to run commands, modify site files, or maintain persistent access to your site.', 'choctaw-wp-security' );
	}

	/**
	 * PHP uploads scan summary with file path markup.
	 *
	 * @return string
	 */
	private static function php_uploads_summary_html() {
		return sprintf(
			/* translators: %s: uploads directory path */
			__( 'PHP files in %s are suspicious. Must-use plugins may be legitimate, but are worth reviewing because they load automatically.', 'choctaw-wp-security' ),
			'<code class="cws-file-path">uploads</code>'
		);
	}

	/**
	 * Uploads plugins folder scan summary.
	 *
	 * @return string
	 */
	private static function uploads_plugins_summary_html() {
		return sprintf(
			/* translators: %s: wp-content/uploads/ path */
			__( 'The following folders were found in %s. Investigate these folders to determine if they are from active plugins, or if they are remnants of uninstalled plugins. Remnants of uninstalled plugins could still pose as attack vectors, especially if they contain executable files.', 'choctaw-wp-security' ),
			'<code class="cws-file-path">wp-content/uploads/</code>'
		);
	}

	/**
	 * Recent file changes "Why this matters" detail HTML.
	 *
	 * @return string
	 */
	private static function file_changes_recent_detail_html() {
		return self::paragraphs_to_html(
			array(
				__( 'WordPress is built from thousands of files, but attackers rarely modify them at random. Instead, they typically target a small number of high-value files that are loaded on every request, control user authentication, or initialize WordPress itself. Because malicious code placed in these files is executed frequently, they are popular locations for backdoors, malicious redirects, spam injection, and other persistent malware. This scan focuses on those critical files to help you identify unexpected changes that deserve closer inspection.', 'choctaw-wp-security' ),
				__( 'The Last Modified column helps identify files that have changed recently, while the Checksum Verified column confirms whether a WordPress core file exactly matches the official release published by WordPress.org. A failed checksum does not necessarily mean the file is malicious—it may have been modified intentionally or changed during development—but any unexpected modification should be investigated. Configuration files such as wp-config.php and .htaccess cannot be checksum verified because they are unique to each website, but they are included because they are among the most security-sensitive files in a WordPress installation.', 'choctaw-wp-security' ),
			)
		);
	}

	/**
	 * PHP files in uploads "Why this matters" detail HTML.
	 *
	 * @return string
	 */
	private static function file_changes_php_uploads_detail_html() {
		return self::paragraphs_to_html(
			array(
				__( 'The wp-content/uploads directory is intended for media files such as images, videos, PDFs, and other documents. Under normal circumstances, PHP files should rarely exist in this location. Because the uploads directory is writable by WordPress, attackers who successfully exploit a vulnerable plugin or theme often attempt to place malicious PHP files there to gain persistent access to the website. These files are commonly referred to as web shells or backdoors and can allow attackers to execute arbitrary code on the server.', 'choctaw-wp-security' ),
				__( 'This scan searches the uploads directory for PHP files and also lists any files found in the mu-plugins (Must-Use Plugins) directory. While PHP files in mu-plugins are often legitimate, they deserve attention because they are loaded automatically by WordPress and cannot be disabled through the Plugins screen. Review any files reported by this scan to confirm they belong to software you recognize. If you discover unexpected PHP files, investigate them before deleting anything, as some plugins legitimately install files outside the standard plugins directory.', 'choctaw-wp-security' ),
			)
		);
	}

	/**
	 * Uploads plugin folders "Why this matters" detail HTML.
	 *
	 * @return string
	 */
	private static function file_changes_uploads_plugins_detail_html() {
		return self::paragraphs_to_html(
			array(
				__( 'Some WordPress plugins create folders inside the uploads directory to store cache files, generated images, exports, backups, or other working data. These folders are usually harmless and expected. However, remnants of plugins that have been uninstalled are also commonly left behind, and those abandoned files may contain executable code or outdated software that is no longer maintained.', 'choctaw-wp-security' ),
				__( 'This scan identifies folders within the uploads directory whose names resemble WordPress plugins. Review each folder to determine whether it belongs to an active plugin or is simply leftover data from software that has already been removed. If a folder belongs to an uninstalled plugin and is no longer needed, removing it reduces unnecessary clutter and may eliminate files that could become security risks in the future. Always confirm that a plugin has been completely uninstalled before deleting any folders.', 'choctaw-wp-security' ),
			)
		);
	}

	/**
	 * Per-file detail HTML for the Recent File Changes table.
	 *
	 * @return array<string, string>
	 */
	private static function get_core_file_change_details() {
		$details = array(
			'wp-config.php'                   => __( 'Contains your website\'s database connection information, authentication keys, and other critical configuration settings. Attackers frequently target this file because modifying it can provide persistent access, redirect visitors, or compromise the entire website.', 'choctaw-wp-security' ),
			'.htaccess'                       => __( 'Controls how the Apache web server processes requests for your website. Attackers often modify this file to create malicious redirects, allow execution of unauthorized files, or bypass security restrictions.', 'choctaw-wp-security' ),
			'index.php'                       => __( 'Serves as the primary entry point for nearly every visitor request to a WordPress website. Because it is executed so frequently, attackers sometimes inject malicious code here to ensure it runs on every page load.', 'choctaw-wp-security' ),
			'wp-login.php'                    => __( 'Processes all standard WordPress login requests and user authentication. Attackers commonly target this file to steal credentials, intercept logins, or modify the authentication process.', 'choctaw-wp-security' ),
			'xmlrpc.php'                      => __( 'Provides remote communication between WordPress and external applications. Although legitimate for some uses, it is a well-known target for brute-force attacks, denial-of-service attacks, and other automated exploits.', 'choctaw-wp-security' ),
			'wp-cron.php'                     => __( 'Executes WordPress scheduled tasks such as publishing posts and running maintenance jobs. Attackers may abuse this file to schedule malicious code that continues running even after the initial compromise.', 'choctaw-wp-security' ),
			'wp-load.php'                     => __( 'Loads the WordPress environment and is required by many scripts before WordPress can run. Because it is involved in nearly every request, malware sometimes modifies it to execute hidden code site-wide.', 'choctaw-wp-security' ),
			'wp-settings.php'                 => __( 'Initializes WordPress by loading plugins, themes, and core components during every request. A compromise of this file allows malicious code to execute automatically whenever WordPress starts.', 'choctaw-wp-security' ),
			'wp-blog-header.php'              => __( 'Loads the WordPress environment and begins processing requests for the public-facing website. Attackers occasionally modify this file to inject malicious code that affects every visitor.', 'choctaw-wp-security' ),
			'wp-admin/admin.php'              => __( 'Acts as the primary bootstrap file for the WordPress administration area. Because every administrator request passes through it, attackers may target it to execute malicious code within the dashboard.', 'choctaw-wp-security' ),
			'wp-admin/includes/file.php'      => __( 'Contains functions responsible for file uploads and filesystem operations within WordPress. Modifying this file could allow attackers to bypass security checks or manipulate files on the server.', 'choctaw-wp-security' ),
			'wp-admin/includes/plugin.php'    => __( 'Provides the functions used to manage plugins, including activation and deactivation. Attackers may alter this file to hide malicious plugins or interfere with plugin management.', 'choctaw-wp-security' ),
			'wp-admin/includes/update.php'    => __( 'Manages WordPress core, plugin, and theme update operations. Attackers could modify this file to interfere with updates or prevent security patches from being installed.', 'choctaw-wp-security' ),
			'wp-includes/load.php'            => __( 'Performs early initialization of the WordPress environment before most other core components are loaded. Because it executes during every request, it is an attractive location for persistent malware.', 'choctaw-wp-security' ),
			'wp-includes/plugin.php'          => __( 'Implements WordPress\'s hook and filter system, allowing plugins and themes to modify behavior. Attackers sometimes inject malicious hooks into this file so their code executes throughout the application.', 'choctaw-wp-security' ),
			'wp-includes/pluggable.php'       => __( 'Contains many of WordPress\'s authentication, user, email, and cookie management functions. Modifying this file can allow attackers to bypass authentication or interfere with user sessions.', 'choctaw-wp-security' ),
			'wp-includes/functions.php'       => __( 'Provides hundreds of core utility functions used throughout WordPress. Since it is loaded on nearly every request, it is a common location for hidden malicious code.', 'choctaw-wp-security' ),
			'wp-includes/default-filters.php' => __( 'Registers WordPress\'s default actions and filters during startup. Attackers may modify this file to automatically attach malicious functions to the WordPress execution flow.', 'choctaw-wp-security' ),
			'wp-includes/class-wp-hook.php'   => __( 'Implements the core hook dispatcher responsible for executing WordPress actions and filters. A compromise here can cause malicious code to run transparently across much of the application.', 'choctaw-wp-security' ),
			'wp-includes/version.php'         => __( 'Stores the installed WordPress version and related metadata. While it is less commonly modified directly by attackers, unexpected changes may indicate that core files have been altered or the installation has been tampered with.', 'choctaw-wp-security' ),
		);

		$html = array();

		foreach ( $details as $relative_path => $detail ) {
			$html[ $relative_path ] = '<p>' . esc_html( $detail ) . '</p>';
		}

		return $html;
	}

	/**
	 * wp_options scan About panel HTML.
	 *
	 * @return string
	 */
	private static function database_scan_about_html() {
		$paragraphs = array(
			__( 'Some sites retain multiple options tables after staging copies or hosting migrations. Select the table you want to scan below. The WordPress configured table is selected by default.', 'choctaw-wp-security' ),
			__( 'This scan covers only the selected options table. It does not scan posts, users, comments, or other database tables. Findings are reported for investigation — nothing is automatically deleted or modified.', 'choctaw-wp-security' ),
			__( 'The first scan of a selected table establishes a baseline for change tracking. Subsequent scans of that same table report options that are new or changed since the previous scan.', 'choctaw-wp-security' ),
		);

		return self::paragraphs_to_html( $paragraphs );
	}

	/**
	 * wp_posts scan About panel HTML.
	 *
	 * @return string
	 */
	private static function posts_scan_about_html() {
		$paragraphs = array(
			__( 'Some sites retain multiple posts tables after staging copies or hosting migrations. Select the table you want to scan below. The WordPress configured table is selected by default.', 'choctaw-wp-security' ),
			__( 'This scan covers only the selected posts table. It does not scan options, users, comments, or post meta. Findings are reported for investigation — nothing is automatically deleted or modified.', 'choctaw-wp-security' ),
			__( 'The first scan of a selected table establishes a baseline for change tracking. Subsequent scans of that same table report posts that are new or changed since the previous scan.', 'choctaw-wp-security' ),
		);

		return self::paragraphs_to_html( $paragraphs );
	}

	/**
	 * wp_users tab "Why this matters" detail HTML.
	 *
	 * @return string
	 */
	private static function users_table_detail_html() {
		$paragraphs = array(
			__( 'Every user account represents a potential point of access to your website. Review this list periodically to identify administrator accounts you do not recognize, accounts that are no longer needed, users with excessive privileges, or accounts created during a security compromise. If you find a suspicious account, use View Activity to investigate its database activity, user metadata, and file references before deciding whether to remove it.', 'choctaw-wp-security' ),
		);

		return self::paragraphs_to_html( $paragraphs );
	}

	/**
	 * Core checksum tab visible intro HTML.
	 *
	 * @return string
	 */
	private static function core_checksum_visible_html() {
		return __( 'Compares your installed WordPress core files against the official files published by WordPress.org to detect missing, modified, or unexpected core files.', 'choctaw-wp-security' );
	}

	/**
	 * Component vulnerability tab "About this scan" copy.
	 *
	 * @return string
	 */
	public static function component_scan_about_text() {
		return __( 'This scan is detection-only. It reports known vulnerabilities for investigation; it does not update, deactivate, or modify any component.', 'choctaw-wp-security' );
	}

	/**
	 * Component vulnerability tab "Why this matters" detail HTML.
	 *
	 * @return string
	 */
	private static function component_scan_detail_html() {
		return self::paragraphs_to_html(
			array(
				__( 'Security vulnerabilities are software flaws that attackers can exploit to gain unauthorized access, execute malicious code, steal information, or disrupt the normal operation of your website. While WordPress core is generally well maintained, vulnerabilities are occasionally discovered in WordPress itself, themes, and—most commonly—plugins. Because newly disclosed vulnerabilities are quickly incorporated into automated attack tools, websites running outdated software are frequently targeted within days of a vulnerability becoming public.', 'choctaw-wp-security' ),
				__( 'This scan compares your installed WordPress core version, active theme, and active plugins against the public WPVulnerability database to identify components with known security vulnerabilities. Components that cannot be matched to the database are listed separately because they cannot be evaluated automatically. This does not mean they are unsafe; they may simply be custom-developed, privately distributed, premium, or otherwise absent from the public database. Any reported vulnerabilities should be reviewed promptly, and affected software should be updated, replaced, or removed whenever possible.', 'choctaw-wp-security' ),
			)
		);
	}

	/**
	 * Core checksum tab "Why this matters" detail HTML.
	 *
	 * @return string
	 */
	private static function core_checksum_detail_html() {
		return self::paragraphs_to_html(
			array(
				__( 'Every official WordPress release includes a unique digital fingerprint (called a checksum) for each core file. This scan compares the WordPress core files installed on your website against those official fingerprints published by WordPress.org. If a file has been modified, deleted, or an unexpected file has been added to a core directory, the scan reports it for review. This helps identify unauthorized changes that may indicate file corruption, incomplete updates, development changes, or malware.', 'choctaw-wp-security' ),
				__( 'Plugins, themes, uploads, mu-plugins, and site-specific configuration files are not included in this scan.', 'choctaw-wp-security' ),
			)
		);
	}

	/**
	 * Exposed folders tab "Why this matters" detail HTML.
	 *
	 * @return string
	 */
	private static function exposed_folders_detail_html() {
		return self::paragraphs_to_html(
			array(
				__( 'If directory browsing is enabled on your web server, visitors can sometimes view a list of files simply by navigating to a folder instead of a specific file. While this does not usually allow attackers to modify your website, it can reveal information about installed plugins, themes, file names, backup files, scripts, and other resources that may assist attackers during reconnaissance. The less information a website exposes unnecessarily, the more difficult it becomes for automated scanners and malicious users to identify potential weaknesses.', 'choctaw-wp-security' ),
				__( 'This scan checks your web server configuration and, when possible, performs a directory listing test to determine whether visitors can view folder contents. The preferred solution is to disable directory browsing at the web server level using your Apache, LiteSpeed, or Nginx configuration. While directory browsing alone is not a vulnerability, reducing unnecessary information disclosure is considered a WordPress security best practice.', 'choctaw-wp-security' ),
			)
		);
	}

	/**
	 * More info detail HTML for a server-level directory browsing result row.
	 *
	 * @param array<string, mixed> $row Scan row payload.
	 * @return string
	 */
	public static function get_directory_browsing_row_detail_html( array $row ) {
		$method         = isset( $row['method'] ) ? (string) $row['method'] : '';
		$status         = isset( $row['status'] ) ? (string) $row['status'] : '';
		$unknown_reason = isset( $row['unknown_reason'] ) ? (string) $row['unknown_reason'] : '';
		$test_urls      = isset( $row['test_urls'] ) && is_array( $row['test_urls'] ) ? $row['test_urls'] : array();
		$conflict       = ! empty( $row['conflict'] );
		$paragraphs     = array();

		if ( Choctaw_Wp_Security_Directory_Browsing_Scanner::METHOD_HTACCESS === $method ) {
			$paragraphs = self::get_htaccess_directory_browsing_detail_paragraphs( $status, $unknown_reason );
		} elseif ( Choctaw_Wp_Security_Directory_Browsing_Scanner::METHOD_DIRECTORY_TEST === $method ) {
			$paragraphs = self::get_directory_test_detail_paragraphs( $status, $unknown_reason, $test_urls );
		}

		if ( $conflict ) {
			$paragraphs[] = __( 'The .htaccess analysis and the directory listing test returned different results. This usually means directory browsing is controlled at the server or virtual host level rather than in .htaccess, or that .htaccess rules are not being applied. Trust the Directory Test result for actual visitor-visible behavior.', 'choctaw-wp-security' );
		}

		return self::paragraphs_to_html( $paragraphs );
	}

	/**
	 * Detail paragraphs for .htaccess directory browsing analysis.
	 *
	 * @param string $status         Result status.
	 * @param string $unknown_reason Unknown reason code when status is unknown.
	 * @return array<int, string>
	 */
	private static function get_htaccess_directory_browsing_detail_paragraphs( $status, $unknown_reason ) {
		if ( Choctaw_Wp_Security_Directory_Browsing_Scanner::STATUS_OFF === $status ) {
			return array(
				__( 'This result was determined by reading the site root .htaccess file. The file contains Options -Indexes, which instructs Apache or LiteSpeed to disable directory listings for directories covered by this configuration.', 'choctaw-wp-security' ),
				__( 'This indicates directory browsing is intended to be off at the .htaccess level. It does not guarantee enforcement if the server ignores .htaccess files (for example, when AllowOverride is disabled in the virtual host configuration). Use the Directory Test row, if available, to confirm actual behavior.', 'choctaw-wp-security' ),
			);
		}

		if ( Choctaw_Wp_Security_Directory_Browsing_Scanner::STATUS_ON === $status ) {
			return array(
				__( 'This result was determined by reading the site root .htaccess file. The file contains Options +Indexes or does not include Options -Indexes in a context where directory indexes may be enabled.', 'choctaw-wp-security' ),
				__( 'This suggests directory browsing may be allowed for directories governed by this .htaccess file. Server-level configuration elsewhere may still override this setting. Use the Directory Test row, if available, to confirm whether listings are actually returned to visitors.', 'choctaw-wp-security' ),
			);
		}

		if ( Choctaw_Wp_Security_Directory_Browsing_Scanner::UNKNOWN_HTACCESS_NOT_FOUND === $unknown_reason ) {
			return array(
				__( 'This result was determined by attempting to read the site root .htaccess file. The file could not be found or was empty.', 'choctaw-wp-security' ),
				__( 'A missing .htaccess entry does not mean directory browsing is enabled. Many hosts disable directory listings in the server or virtual host configuration instead. Refer to the Directory Test row for a behavioral check, if one was performed.', 'choctaw-wp-security' ),
			);
		}

		if ( Choctaw_Wp_Security_Directory_Browsing_Scanner::UNKNOWN_HTACCESS_UNREADABLE === $unknown_reason ) {
			return array(
				__( 'This result was determined by attempting to read the site root .htaccess file. The file exists but could not be read by WordPress.', 'choctaw-wp-security' ),
				__( 'Without access to .htaccess, this method cannot determine whether Options -Indexes is configured. Refer to the Directory Test row for a behavioral check, if one was performed.', 'choctaw-wp-security' ),
			);
		}

		return array(
			__( 'This result was determined by attempting to read the site root .htaccess file. The file did not contain a clear Options directive related to directory indexes.', 'choctaw-wp-security' ),
			__( 'An inconclusive .htaccess result does not confirm that directory browsing is on or off. Refer to the Directory Test row for a behavioral check, if one was performed.', 'choctaw-wp-security' ),
		);
	}

	/**
	 * Detail paragraphs for directory listing HTTP tests.
	 *
	 * @param string               $status         Result status.
	 * @param string               $unknown_reason Unknown reason code when status is unknown.
	 * @param array<int, string>   $test_urls      URLs that were requested.
	 * @return array<int, string>
	 */
	private static function get_directory_test_detail_paragraphs( $status, $unknown_reason, array $test_urls ) {
		if ( Choctaw_Wp_Security_Directory_Browsing_Scanner::STATUS_OFF === $status ) {
			$paragraphs = array(
				__( 'This result was determined by requesting one or more publicly accessible plugin or theme folder URLs that do not contain an index file. The server response did not include a directory listing (for example, an "Index of …" page or equivalent auto-generated file list).', 'choctaw-wp-security' ),
				__( 'The server returned a non-listing response such as a blank page, 403 Forbidden, or 404 Not Found. This indicates that directory browsing is effectively disabled for the tested folder(s), regardless of whether that protection comes from server configuration, an index-file fallback, or another rule.', 'choctaw-wp-security' ),
			);

			return array_merge( $paragraphs, self::format_directory_test_url_paragraphs( $test_urls ) );
		}

		if ( Choctaw_Wp_Security_Directory_Browsing_Scanner::STATUS_ON === $status ) {
			$paragraphs = array(
				__( 'This result was determined by requesting one or more publicly accessible plugin or theme folder URLs that do not contain an index file. The server returned a directory listing — an HTML page listing the files or subfolders in that directory.', 'choctaw-wp-security' ),
				__( 'Directory browsing appears to be enabled for at least one tested location. Visitors may be able to view file and folder names without knowing exact file paths, which can aid reconnaissance even though it does not by itself allow file modification.', 'choctaw-wp-security' ),
			);

			return array_merge( $paragraphs, self::format_directory_test_url_paragraphs( $test_urls ) );
		}

		if ( Choctaw_Wp_Security_Directory_Browsing_Scanner::UNKNOWN_DIRECTORY_NO_TARGETS === $unknown_reason ) {
			return array(
				__( 'No top-level plugin or theme folders missing an index file were found during this scan, so there was no suitable public folder URL to test.', 'choctaw-wp-security' ),
				__( 'This scan cannot determine directory browsing status without a folder that lacks an index file. If directory browsing is disabled globally at the server level, this is expected and not necessarily a concern.', 'choctaw-wp-security' ),
			);
		}

		if ( Choctaw_Wp_Security_Directory_Browsing_Scanner::UNKNOWN_DIRECTORY_HTTP_FAILED === $unknown_reason ) {
			$paragraphs = array(
				__( 'This result was determined by attempting an HTTP request to plugin or theme folder URLs that do not contain an index file. Every request failed or timed out before a response could be classified.', 'choctaw-wp-security' ),
				__( 'Common reasons include loopback requests being blocked on this host, SSL verification errors on internal requests, or temporary network issues. An inconclusive test does not confirm that directory browsing is on or off.', 'choctaw-wp-security' ),
			);

			return array_merge( $paragraphs, self::format_directory_test_url_paragraphs( $test_urls ) );
		}

		$paragraphs = array(
			__( 'This result was determined by attempting an HTTP request to plugin or theme folder URLs that do not contain an index file. The test could not produce a conclusive result for every URL.', 'choctaw-wp-security' ),
			__( 'Some responses could not be classified as a listing or a non-listing. An inconclusive test does not confirm that directory browsing is on or off. Review the .htaccess row if shown, or verify manually using the instructions below.', 'choctaw-wp-security' ),
		);

		return array_merge( $paragraphs, self::format_directory_test_url_paragraphs( $test_urls ) );
	}

	/**
	 * Build optional paragraphs listing tested directory URLs.
	 *
	 * @param array<int, string> $test_urls Tested URLs.
	 * @return array<int, string>
	 */
	private static function format_directory_test_url_paragraphs( array $test_urls ) {
		if ( empty( $test_urls ) ) {
			return array();
		}

		$url_lines = array();

		foreach ( $test_urls as $test_url ) {
			$url_lines[] = (string) $test_url;
		}

		return array(
			sprintf(
				/* translators: %s: newline-separated list of tested URLs */
				__( 'Tested URL(s): %s', 'choctaw-wp-security' ),
				implode( ', ', $url_lines )
			),
		);
	}

	/**
	 * Guidance box entries.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private static function get_guidance_entries() {
		return array(
			'checksum_modified' => array(
				'title' => __( 'How to proceed', 'choctaw-wp-security' ),
				'intro' => __( 'These official core files do not match the WordPress.org checksums. They have a high probability of being compromised.', 'choctaw-wp-security' ),
				'steps' => array(
					__( 'Download the suspected file to your local computer.', 'choctaw-wp-security' ),
					__( 'Open the file in a text editor and review its contents.', 'choctaw-wp-security' ),
					__( 'If you determine a file was maliciously altered, log into your web server via SSH.', 'choctaw-wp-security' ),
					__( 'Change directory to your WordPress installation.', 'choctaw-wp-security' ),
					sprintf(
						/* translators: %s: WP-CLI command */
						__( 'Run %s to reinstall a fresh set of core files from WordPress.', 'choctaw-wp-security' ),
						'<code>wp core download --force</code>'
					),
				),
			),
			'checksum_missing'  => array(
				'title' => __( 'How to proceed', 'choctaw-wp-security' ),
				'intro' => __( 'Official WordPress core files are expected at these paths but were not found on disk. This may indicate deletion, renaming, incomplete installation, or post-compromise cleanup.', 'choctaw-wp-security' ),
				'steps' => array(
					__( 'Confirm the files are genuinely missing (not a permissions or path issue).', 'choctaw-wp-security' ),
					__( 'Log into your web server via SSH.', 'choctaw-wp-security' ),
					__( 'Change directory to your WordPress installation.', 'choctaw-wp-security' ),
					sprintf(
						/* translators: %s: WP-CLI command */
						__( 'Run %s to restore missing core files from WordPress.', 'choctaw-wp-security' ),
						'<code>wp core download --force</code>'
					),
				),
			),
			'checksum_unknown'  => array(
				'title' => __( 'How to proceed', 'choctaw-wp-security' ),
				'intro' => __( 'WordPress does not recognize these files as official core files. That does not mean they are malicious—they may have been added by your web host or another tool.', 'choctaw-wp-security' ),
				'steps' => array(
					__( 'Download the file to your local computer.', 'choctaw-wp-security' ),
					__( 'Open the file in a text editor and review its contents.', 'choctaw-wp-security' ),
					__( 'Delete the file from the server if it is not needed or appears to be malicious.', 'choctaw-wp-security' ),
				),
			),
			'directory_browsing_fix' => array(
				'title'    => __( 'How to Turn Directory Browsing Off', 'choctaw-wp-security' ),
				'sections' => array(
					array(
						'heading'   => __( 'Apache & LiteSpeed', 'choctaw-wp-security' ),
						'text_html' => sprintf(
							/* translators: 1: .htaccess path, 2: .htaccess path */
							__( 'At the server or virtual host level, disable directory indexes for the site. On hosts that allow Options in %1$s, this can also be placed in the site root %2$s file:', 'choctaw-wp-security' ),
							self::file_path_html( '.htaccess' ),
							self::file_path_html( '.htaccess' )
						),
						'code'      => 'Options -Indexes',
						'code_rows' => 2,
					),
					array(
						'heading'   => __( 'Nginx', 'choctaw-wp-security' ),
						'text_html' => sprintf(
							/* translators: %s: .htaccess path */
							__( 'Nginx does not use %s files. Disable autoindex in the site server block or a more specific location block, then reload Nginx:', 'choctaw-wp-security' ),
							self::file_path_html( '.htaccess' )
						),
						'code'      => 'autoindex off;',
						'code_rows' => 2,
					),
					array(
						'heading'   => __( 'Folder-Level Fallback', 'choctaw-wp-security' ),
						'text_html' => sprintf(
							/* translators: %s: index.php path */
							__( 'Adding a small %s file to an individual folder usually prevents that folder from displaying a file listing, even when server-level directory browsing is enabled. Plugin and theme updates may remove manually added files, so server-level configuration is preferred when available.', 'choctaw-wp-security' ),
							self::file_path_html( 'index.php' )
						),
						'code'      => "<?php\n// Silence is golden.\n",
						'code_rows' => 3,
					),
				),
			),
			'remove_user_account' => array(
				'title'     => __( 'How to Safely Remove a User Account', 'choctaw-wp-security' ),
				'body_html' => self::remove_user_account_guidance_html(),
			),
		);
	}

	/**
	 * Guidance Box body HTML for safely removing a user account.
	 *
	 * @return string
	 */
	private static function remove_user_account_guidance_html() {
		$html  = '<h4>' . esc_html__( 'Before You Delete the User', 'choctaw-wp-security' ) . '</h4>';
		$html .= '<p>' . esc_html__( 'If you discover an administrator account that you do not recognize, do not immediately delete it. First determine whether the account was created by malicious code. Use the Database Activity, Usermeta Table, and File Activity tabs to investigate the account. If the File Activity scan identifies code that creates, modifies, or references the account unexpectedly, remove the malicious code before deleting the user. Otherwise, the account may simply be recreated the next time the malicious code executes.', 'choctaw-wp-security' ) . '</p>';

		$html .= '<h4>' . esc_html__( 'Using the WordPress Dashboard (Recommended)', 'choctaw-wp-security' ) . '</h4>';
		$html .= '<p>' . esc_html__( 'If the account appears under Users → All Users, delete it through the WordPress Dashboard. WordPress will prompt you to either delete the user\'s content or reassign ownership to another user. In most cases, reassigning content is recommended to preserve posts, pages, media, and other content created by that user.', 'choctaw-wp-security' ) . '</p>';

		$html .= '<h4>' . esc_html__( 'Using WP-CLI (Hidden or Inaccessible Accounts)', 'choctaw-wp-security' ) . '</h4>';
		$html .= '<p>' . esc_html__( 'Some malicious administrator accounts are hidden from the WordPress Dashboard but still exist in the database. If the account cannot be removed through the administrative interface, use WP-CLI from an SSH session.', 'choctaw-wp-security' ) . '</p>';
		$html .= '<p>' . esc_html__( 'Replace username with the account to delete and user-id with the ID of an existing user who should receive ownership of the deleted user\'s content.', 'choctaw-wp-security' ) . '</p>';
		$html .= '<textarea readonly rows="2" class="large-text code">wp user delete username --reassign=user-id</textarea>';
		$html .= '<p>' . esc_html__( 'Example:', 'choctaw-wp-security' ) . '</p>';
		$html .= '<textarea readonly rows="2" class="large-text code">wp user delete adminbackup --reassign=1</textarea>';
		$html .= '<p>' . esc_html__( 'This command removes the user account while safely reassigning ownership of posts, pages, media, and other content to another user.', 'choctaw-wp-security' ) . '</p>';

		$html .= '<h4>' . esc_html__( 'Avoid Deleting Users Directly from the Database', 'choctaw-wp-security' ) . '</h4>';
		$html .= '<p>' . esc_html__( 'Do not delete user records directly from the wp_users table using phpMyAdmin or another database utility. WordPress stores related information in multiple database tables, including wp_usermeta, while posts, comments, media, and other content may still reference the user\'s ID. Removing only the database record can leave orphaned data and inconsistent ownership references. Whenever possible, remove users through the WordPress Dashboard or WP-CLI so WordPress can properly update related records.', 'choctaw-wp-security' ) . '</p>';

		return $html;
	}

	/**
	 * Render a file path as inline code markup for help copy.
	 *
	 * @param string $path File path.
	 * @return string
	 */
	private static function file_path_html( $path ) {
		return '<code class="cws-file-path">' . esc_html( (string) $path ) . '</code>';
	}

	/**
	 * Convert translated paragraphs to HTML.
	 *
	 * @param array<int, string> $paragraphs Paragraph strings.
	 * @return string
	 */
	private static function paragraphs_to_html( array $paragraphs ) {
		$html = '';

		foreach ( $paragraphs as $paragraph ) {
			$html .= '<p>' . esc_html( $paragraph ) . '</p>';
		}

		return $html;
	}
}
