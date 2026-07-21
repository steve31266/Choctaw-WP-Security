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
	 * Info box content for informational panels.
	 *
	 * @param string $id Info identifier.
	 * @return array<string, mixed>
	 */
	public static function get_info( $id ) {
		$entries = self::get_info_entries();

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
				'summary'             => self::xmlrpc_section_summary(),
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
				'visible'     => __( 'wp_options inspects the WordPress options table for records that may indicate compromise. It looks for hijacked site URLs, tampered plugin lists, oversized autoloaded options, PHP or execution patterns, and other high-risk indicators.', 'choctaw-wp-security' ),
				'detail_html' => self::database_scan_about_html(),
			),
			'scheduled_tasks'  => array(
				'visible'     => __( 'WordPress stores background jobs in its WP-Cron system. Problem rules become Sassh Findings (Needs Review) for unknown hooks, missing handlers, unusual schedules, suspicious arguments, stale events, or excessive duplication. Recognized core and plugin/theme maintenance events appear in a separate non-dismissible inventory and are not Findings.', 'choctaw-wp-security' ),
				'detail_html' => self::scheduled_tasks_why_html(),
			),
			'posts_scan'       => array(
				'visible'     => __( 'wp_posts inspects the WordPress posts table for content that may indicate compromise. It looks for PHP or execution patterns, script and iframe injections, SEO spam titles, unusually large post content, and changes since your last scan.', 'choctaw-wp-security' ),
				'detail_html' => self::posts_scan_about_html(),
			),
			'users_table'      => array(
				'visible'     => __( 'This scan displays every user account stored in the WordPress users table (configured under Sassh → Settings → WordPress Tables), allowing you to see unexpected accounts and review existing user assignments and activities.', 'choctaw-wp-security' ),
				'detail_html' => self::users_table_detail_html(),
			),
			'component_scan'   => array(
				'visible'     => __( 'Checks your installed WordPress core version, themes (active and inactive), and plugins (active and inactive) for publicly known security vulnerabilities using the WPVulnerability database. Components that cannot be matched to the database are listed separately.', 'choctaw-wp-security' ),
				'detail_html' => self::component_scan_detail_html(),
			),
			'core_checksum'    => array(
				'visible_html' => self::core_checksum_visible_html(),
				'detail_html'  => self::core_checksum_detail_html(),
			),
			'exposed_folders'  => array(
				'visible'     => __( 'Checks whether directory browsing is blocked via the site root .htaccess file (when applicable) and HTTP tests of the plugins, themes, and uploads folder roots.', 'choctaw-wp-security' ),
				'detail_html' => self::exposed_folders_detail_html(),
			),
			'exposed_files'    => array(
				'visible'     => __( 'Scans the WordPress document root for sensitive leftover files that attackers commonly probe for, such as configuration backups, database dumps, logs, development metadata, and source repositories.', 'choctaw-wp-security' ),
				'detail_html' => self::exposed_files_detail_html(),
			),
			'uploads_folder'   => array(
				'visible_html' => self::uploads_folder_visible_html(),
				'detail_html'  => self::uploads_folder_detail_html(),
			),
			'mu_plugins'       => array(
				'visible'     => __( 'Lists PHP files in the must-use plugins directory. These plugins load automatically and are hidden from the Plugins screen, so unexpected files deserve careful review.', 'choctaw-wp-security' ),
				'detail_html' => self::mu_plugins_detail_html(),
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
	 * WordPress Tables section summary line.
	 *
	 * @return string
	 */
	public static function table_prefix_section_summary() {
		return __( 'Database scans use the live WordPress table prefix automatically. Override it here only when leftover staging or migration tables exist in the same database.', 'choctaw-wp-security' );
	}

	/**
	 * WordPress Tables section "Why this matters" detail HTML.
	 *
	 * @return string
	 */
	public static function table_prefix_section_detail_html() {
		return self::paragraphs_to_html(
			array(
				__( 'WordPress identifies its tables with a prefix defined in wp-config.php (for example wp_ or wp_kk5p3b_). After staging copies or hosting migrations, a database may contain more than one full set of WordPress tables. Scans for WP-Cron, wp_options, wp_posts, and wp_users should inspect the live install, not leftover tables.', 'choctaw-wp-security' ),
				__( 'By default this plugin uses the WordPress-configured prefix, the same source of truth WordPress itself uses. If that automatic choice is wrong, or if you intentionally need to inspect another leftover install set, choose a different prefix here. When only one prefix is present, the picker is shown but disabled because there is nothing to change.', 'choctaw-wp-security' ),
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
	 * XML-RPC section summary shown under the Disable XML-RPC heading.
	 *
	 * @return string
	 */
	public static function xmlrpc_section_summary() {
		return __( 'XML-RPC is an old feature meant to facilitate WordPress functionality in third-party applications, but remains a popular attack vector for automated-hacks.', 'choctaw-wp-security' );
	}

	/**
	 * XML-RPC blocking "Why this matters" detail HTML.
	 *
	 * @return string
	 */
	public static function xmlrpc_blocking_detail_html() {
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
	public static function uploads_lockdown_summary_html() {
		return sprintf(
			/* translators: %s: wp-content/uploads/ path */
			__( 'Prevents PHP files and scripts from being executed in the %s directory.', 'choctaw-wp-security' ),
			'<code class="cws-file-path">wp-content/uploads/</code>'
		);
	}

	/**
	 * Apache/LiteSpeed checkbox label for uploads lockdown.
	 *
	 * @return string
	 */
	public static function uploads_lockdown_enable_label() {
		return __( 'Enable protection (Recommended)', 'choctaw-wp-security' );
	}

	/**
	 * Apache/LiteSpeed checkbox subtext about automatic .htaccess rules.
	 *
	 * @return string
	 */
	public static function uploads_lockdown_htaccess_subtext_html() {
		return sprintf(
			/* translators: %s: .htaccess path */
			__( 'This plugin will automatically add the required rules using your %s file.', 'choctaw-wp-security' ),
			self::file_path_html( '.htaccess' )
		);
	}

	/**
	 * Active status label when uploads lockdown is enabled on Apache/LiteSpeed.
	 *
	 * @return string
	 */
	public static function uploads_lockdown_active_status_label() {
		return __( 'Active (Automatic)', 'choctaw-wp-security' );
	}

	/**
	 * Disabled/at-risk status label when uploads lockdown is off on Apache/LiteSpeed.
	 *
	 * @return string
	 */
	public static function uploads_lockdown_disabled_status_label() {
		return __( 'Disabled (at Risk)', 'choctaw-wp-security' );
	}

	/**
	 * Manual configuration required banner title for Nginx.
	 *
	 * @return string
	 */
	public static function uploads_lockdown_manual_config_title() {
		return __( 'Manual configuration required', 'choctaw-wp-security' );
	}

	/**
	 * Nginx explanation shown below the manual-configuration banner.
	 *
	 * @return string
	 */
	public static function uploads_lockdown_nginx_explanation() {
		return __( 'This site appears to be running on Nginx. WordPress plugins cannot modify Nginx server configuration automatically.', 'choctaw-wp-security' );
	}

	/**
	 * Unknown-server banner title.
	 *
	 * @return string
	 */
	public static function uploads_lockdown_unknown_banner_title() {
		return __( 'Server type could not be confirmed', 'choctaw-wp-security' );
	}

	/**
	 * Unknown-server banner subtitle.
	 *
	 * @return string
	 */
	public static function uploads_lockdown_unknown_banner_subtitle() {
		return __( "We couldn't determine your web server type.", 'choctaw-wp-security' );
	}

	/**
	 * Dual-path guidance for unknown servers.
	 *
	 * @return string
	 */
	public static function uploads_lockdown_unknown_guidance_html() {
		return sprintf(
			/* translators: %s: .htaccess path */
			__( 'On Apache/LiteSpeed servers, enable protection below to install a managed %s block. On Nginx servers, use the configuration snippet below to prevent PHP execution in uploads.', 'choctaw-wp-security' ),
			self::file_path_html( '.htaccess' )
		);
	}

	/**
	 * Toggle label for the Nginx snippet disclosure.
	 *
	 * @return string
	 */
	public static function uploads_lockdown_nginx_snippet_toggle_label() {
		return __( 'Display Nginx code snippet', 'choctaw-wp-security' );
	}

	/**
	 * Heading for the Nginx action steps section.
	 *
	 * @return string
	 */
	public static function uploads_lockdown_nginx_action_heading() {
		return __( 'What You Need to Do', 'choctaw-wp-security' );
	}

	/**
	 * Instruction shown above the Nginx snippet disclosure.
	 *
	 * @return string
	 */
	public static function uploads_lockdown_nginx_action_instruction() {
		return __( 'Add the following location block code snippet to your Nginx server configuration, then reload Nginx.', 'choctaw-wp-security' );
	}

	/**
	 * Uploads lockdown "Why this matters" detail for Apache and LiteSpeed.
	 *
	 * @return string
	 */
	public static function uploads_php_lockdown_apache_detail_html() {
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
				__( 'Nginx does not use .htaccess files, so this plugin cannot apply the rule from WordPress. Uploads PHP blocking must be configured directly in your Nginx site block using the configuration snippet provided above.', 'choctaw-wp-security' ),
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
	 * Exposed Files "Why this matters" detail HTML.
	 *
	 * @return string
	 */
	private static function exposed_files_detail_html() {
		return self::paragraphs_to_html(
			array(
				__( 'Site administrators and development tools sometimes leave sensitive files in the public WordPress document root during testing, migration, or maintenance. Attackers routinely request these well-known filenames because they often contain database credentials, backups, logs, dependency lists, or full source repositories.', 'choctaw-wp-security' ),
				__( 'This scan checks only the WordPress installation root (non-recursively) for common exposure patterns such as wp-config backups, .env files, SQL dumps, archive backups, diagnostic PHP scripts, logs, Composer/npm metadata, and .git/.svn directories. Findings should be removed or moved outside the web root whenever they are no longer required.', 'choctaw-wp-security' ),
			)
		);
	}

	/**
	 * Uploads Folder tab visible summary with file path markup.
	 *
	 * @return string
	 */
	private static function uploads_folder_visible_html() {
		return sprintf(
			/* translators: %s: uploads directory path */
			__( 'Scans %s for PHP executable files. PHP scripts normally do not belong in this writable media directory and are treated as critical findings.', 'choctaw-wp-security' ),
			'<code class="cws-file-path">uploads</code>'
		);
	}

	/**
	 * Uploads Folder "Why this matters" detail HTML.
	 *
	 * @return string
	 */
	private static function uploads_folder_detail_html() {
		return self::paragraphs_to_html(
			array(
				__( 'The wp-content/uploads directory is intended for media files such as images, videos, PDFs, and other documents. Under normal circumstances, PHP files should rarely exist in this location. Because the uploads directory is writable by WordPress, attackers who successfully exploit a vulnerable plugin or theme often attempt to place malicious PHP files there to gain persistent access to the website. These files are commonly referred to as web shells or backdoors and can allow attackers to execute arbitrary code on the server.', 'choctaw-wp-security' ),
				__( 'Review any files reported by this scan to confirm they belong to software you recognize. If you discover unexpected PHP files, investigate them before deleting anything, and enable Disable PHP Execution in Uploads when your server supports it.', 'choctaw-wp-security' ),
			)
		);
	}

	/**
	 * MU-Plugins "Why this matters" detail HTML.
	 *
	 * @return string
	 */
	private static function mu_plugins_detail_html() {
		return self::paragraphs_to_html(
			array(
				__( 'The wp-content/mu-plugins directory contains Must-Use plugins that WordPress loads automatically. They cannot be disabled through the Plugins screen, which makes the directory attractive to attackers and also a place where hosts and security tools legitimately install software.', 'choctaw-wp-security' ),
				__( 'Verify that each reported file belongs to software you intentionally installed or to your hosting provider. Unknown or unexpected files should be investigated before removal, as deleting legitimate Must-Use plugins can disable important site functionality or hosting features.', 'choctaw-wp-security' ),
			)
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
	 * wp_options tab "Why this matters" detail HTML.
	 *
	 * @return string
	 */
	private static function database_scan_about_html() {
		$paragraphs = array(
			__( 'This scan uses the options table for the WordPress Tables prefix chosen under Settings. By default that is the live WordPress-configured prefix from wp-config.php.', 'choctaw-wp-security' ),
			__( 'This scan covers only that options table. It does not scan posts, users, comments, or other database tables. Findings are reported for investigation — nothing is automatically deleted or modified.', 'choctaw-wp-security' ),
			__( 'Findings persist across scans. Sassh tracks first seen, last seen, and whether a condition is still detected. Only options tables that belong to a registered WordPress site can be scanned.', 'choctaw-wp-security' ),
		);

		return self::paragraphs_to_html( $paragraphs );
	}

	/**
	 * wp_posts tab "Why this matters" detail HTML.
	 *
	 * @return string
	 */
	private static function posts_scan_about_html() {
		$paragraphs = array(
			__( 'This scan uses the posts table for the WordPress Tables prefix chosen under Settings. By default that is the live WordPress-configured prefix from wp-config.php.', 'choctaw-wp-security' ),
			__( 'This scan covers only that posts table. It does not scan options, users, comments, or post meta. Findings are reported for investigation — nothing is automatically deleted or modified.', 'choctaw-wp-security' ),
			__( 'The first scan of a posts table establishes a baseline for change tracking. Subsequent scans of that same table report posts that are new or changed since the previous scan.', 'choctaw-wp-security' ),
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
				__( 'This scan compares your installed WordPress core version, themes (active and inactive), and plugins (active and inactive) against the public WPVulnerability database to identify components with known security vulnerabilities. Inactive themes and plugins are included because leftover software can still be exploited even when it is not currently in use. Components that cannot be matched to the database are listed separately because they cannot be evaluated automatically. This does not mean they are unsafe; they may simply be custom-developed, privately distributed, premium, or otherwise absent from the public database. Any reported vulnerabilities should be reviewed promptly, and affected software should be updated, replaced, or removed whenever possible.', 'choctaw-wp-security' ),
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
				__( 'This scan reviews the site root .htaccess file on Apache and LiteSpeed (and reports leftover .htaccess files on Nginx as informational). It also requests the public plugins, themes, and uploads folder URLs to see whether a directory listing is returned. The preferred solution is to disable directory browsing at the web server level. While directory browsing alone is not a vulnerability, reducing unnecessary information disclosure is considered a WordPress security best practice.', 'choctaw-wp-security' ),
			)
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
			'scheduled_tasks_remove' => array(
				'title'     => __( 'How to Remove a WP-Cron Event', 'choctaw-wp-security' ),
				'body_html' => self::scheduled_tasks_remove_guidance_html(),
			),
			'uploads_php_nginx' => array(
				'title'    => __( 'How to fix this', 'choctaw-wp-security' ),
				'sections' => array(
					array(
						'code'      => ( new Choctaw_Wp_Security_Uploads_Php_Lockdown() )->get_nginx_snippet(),
						'code_rows' => 5,
					),
					array(
						'text' => __( 'After adding this rule, reload Nginx and test that PHP files in uploads return HTTP 403. If your hosting provider manages Nginx for you, send them this snippet.', 'choctaw-wp-security' ),
					),
				),
			),
		);
	}

	/**
	 * Info box entries.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private static function get_info_entries() {
		return array(
			'scheduled_tasks_categories' => array(
				'title'   => __( 'Key to Categories', 'choctaw-wp-security' ),
				'entries' => array(
					array(
						'label' => __( 'Recognized Core', 'choctaw-wp-security' ),
						'text'  => __( 'This WP-Cron event is part of WordPress core and is generally expected on a healthy website. Core events perform routine maintenance such as update checks, cleanup, and scheduled housekeeping.', 'choctaw-wp-security' ),
					),
					array(
						'label' => __( 'Recognized Plugin / Theme', 'choctaw-wp-security' ),
						'text'  => __( 'This event belongs to an active plugin or the active theme and is usually legitimate. Review it only if you do not recognize the software or if it has also been flagged for another reason.', 'choctaw-wp-security' ),
					),
					array(
						'label' => __( 'Unknown Hook', 'choctaw-wp-security' ),
						'text'  => __( 'This WP-Cron event could not be associated with WordPress core, an active plugin, or the active theme. Unknown hooks deserve review because they may originate from custom code, removed software, or malicious activity.', 'choctaw-wp-security' ),
					),
					array(
						'label' => __( 'Unregistered Handler', 'choctaw-wp-security' ),
						'text'  => __( 'The WP-Cron event exists, but no matching handler was found during this scan. This may indicate an inactive or removed plugin, a stale cron entry, or an event that is no longer functional.', 'choctaw-wp-security' ),
					),
					array(
						'label' => __( 'Missing Source', 'choctaw-wp-security' ),
						'text'  => __( 'This event appears to belong to a plugin or theme that is no longer installed or active. Leftover WP-Cron events should be investigated and may be safe to remove if the associated software has been permanently removed.', 'choctaw-wp-security' ),
					),
					array(
						'label' => __( 'Unusual Frequency', 'choctaw-wp-security' ),
						'text'  => __( 'This event runs much more frequently than is typical for most WordPress maintenance jobs. While some plugins legitimately require frequent execution, malware often uses short intervals to maintain persistence or perform repeated actions.', 'choctaw-wp-security' ),
					),
					array(
						'label' => __( 'Stale Task', 'choctaw-wp-security' ),
						'text'  => __( 'The scheduled execution time is significantly overdue. This may indicate a broken WP-Cron system, an abandoned event, or software that no longer functions correctly.', 'choctaw-wp-security' ),
					),
					array(
						'label' => __( 'Duplicate Task', 'choctaw-wp-security' ),
						'text'  => __( 'Multiple instances of the same WP-Cron event were found. Excessive duplicates may indicate a software bug, repeated scheduling, or an attempt to maintain persistence.', 'choctaw-wp-security' ),
					),
					array(
						'label' => __( 'Suspicious Hook Name', 'choctaw-wp-security' ),
						'text'  => __( 'The hook name contains unusual, random, or potentially suspicious text. Although not conclusive evidence of malware, unfamiliar hook names should be investigated.', 'choctaw-wp-security' ),
					),
					array(
						'label' => __( 'Suspicious Arguments', 'choctaw-wp-security' ),
						'text'  => __( 'The WP-Cron event contains arguments that appear unusual or potentially unsafe, such as external URLs, encoded data, or executable code fragments. These events deserve immediate review because malware often hides its behavior within event arguments.', 'choctaw-wp-security' ),
					),
				),
			),
			'exposed_files_categories'   => array(
				'title'   => __( 'Key to Categories', 'choctaw-wp-security' ),
				'entries' => array(
					array(
						'label' => __( 'Configuration Files', 'choctaw-wp-security' ),
						'text'  => __( 'Configuration files contain the settings that allow WordPress and other applications to operate, including database connection information, authentication keys, API tokens, SMTP credentials, and other sensitive secrets. If exposed, these files can provide an attacker with everything needed to connect to your database, impersonate your website, or access third-party services. Because they often contain confidential credentials, exposed configuration files are considered one of the most serious security risks.', 'choctaw-wp-security' ),
					),
					array(
						'label' => __( 'Database & Backup Files', 'choctaw-wp-security' ),
						'text'  => __( 'Database exports and website backup archives often contain complete copies of your website, including WordPress content, user accounts, uploaded media, plugins, themes, and configuration files. An attacker who downloads one of these files may be able to examine your website offline, discover sensitive information, or restore an exact copy of your site in their own environment. Backup files should never remain inside the publicly accessible web root once they are no longer needed.', 'choctaw-wp-security' ),
					),
					array(
						'label' => __( 'Server & Diagnostic Files', 'choctaw-wp-security' ),
						'text'  => __( 'Diagnostic files are typically created temporarily by developers or administrators while troubleshooting a website. They may reveal information about your server configuration, installed software, PHP version, filesystem layout, enabled modules, or debugging utilities. Although these files rarely contain passwords, they provide attackers with valuable information that can be used to identify known vulnerabilities or plan more targeted attacks. Diagnostic files should normally be removed once troubleshooting is complete.', 'choctaw-wp-security' ),
					),
					array(
						'label' => __( 'Log Files', 'choctaw-wp-security' ),
						'text'  => __( 'Log files record application activity, errors, warnings, and debugging information generated by WordPress, PHP, plugins, or the web server. Depending on their contents, these files may expose internal file paths, SQL queries, plugin names, usernames, email addresses, or other information that can assist an attacker. While log files are often useful for troubleshooting, they should not be publicly accessible and should be reviewed periodically for sensitive information.', 'choctaw-wp-security' ),
					),
					array(
						'label' => __( 'Development Metadata', 'choctaw-wp-security' ),
						'text'  => __( 'Development metadata files are created by software development tools such as Composer and Node.js package managers. They describe the libraries, dependencies, and versions used to build or maintain a website. Although these files generally do not contain passwords or confidential data, they can reveal exactly which software components are installed, allowing attackers to identify publicly known vulnerabilities affecting those versions. Production websites rarely require these files to remain publicly accessible.', 'choctaw-wp-security' ),
					),
					array(
						'label' => __( 'Source Repository Files', 'choctaw-wp-security' ),
						'text'  => __( 'Source repository files belong to version control systems such as Git and Subversion and are intended for software development, not production websites. If these repositories become publicly accessible, attackers may be able to recover source code, configuration files, historical revisions, commit messages, and other sensitive development information. In some cases, an exposed repository can allow an attacker to reconstruct the entire website, making this one of the highest-risk forms of information disclosure.', 'choctaw-wp-security' ),
					),
				),
			),
		);
	}

	/**
	 * Why this matters HTML for the WP-Cron tab.
	 *
	 * @return string
	 */
	private static function scheduled_tasks_why_html() {
		return '<p>' . esc_html__(
			'WP-Cron lets WordPress and plugins run background maintenance automatically. Attackers sometimes abuse WP-Cron to maintain persistence, periodically download malware, send spam, or recreate deleted files. This report highlights WP-Cron events that deserve closer inspection while hiding normal maintenance activity by default.',
			'choctaw-wp-security'
		) . '</p>';
	}

	/**
	 * Guidance Box body HTML for removing a WP-Cron event.
	 *
	 * @return string
	 */
	private static function scheduled_tasks_remove_guidance_html() {
		$html  = '<p>' . esc_html__( 'Most WP-Cron events are legitimate and should not be removed. Before deleting an event, determine whether it belongs to WordPress core, an active plugin, or your active theme. Removing legitimate events may disable important features such as backups, updates, email notifications, or other background processing.', 'choctaw-wp-security' ) . '</p>';
		$html .= '<p><strong>' . esc_html__( 'Recommended workflow', 'choctaw-wp-security' ) . ':</strong> ' . esc_html__( 'If you believe a WP-Cron event is malicious, first identify and remove the underlying malware, vulnerable plugin, or compromised theme that created it. Once the source has been eliminated, remove the event and verify that it does not reappear. If the event returns after deletion, the website is likely still compromised.', 'choctaw-wp-security' ) . '</p>';
		$html .= '<p>' . esc_html__( 'The safest way to remove a WP-Cron event is with WP-CLI over SSH. First, identify the hook name shown in this report, then list the currently scheduled events:', 'choctaw-wp-security' ) . '</p>';
		$html .= '<textarea readonly rows="2" class="large-text code">wp cron event list</textarea>';
		$html .= '<p>' . esc_html__( 'To remove an event, use:', 'choctaw-wp-security' ) . '</p>';
		$html .= '<textarea readonly rows="2" class="large-text code">wp cron event delete &lt;hook-name&gt;</textarea>';
		$html .= '<p>' . esc_html__( 'For example:', 'choctaw-wp-security' ) . '</p>';
		$html .= '<textarea readonly rows="2" class="large-text code">wp cron event delete old_backup_cleanup</textarea>';
		$html .= '<p>' . esc_html__( 'WP-CLI updates the WordPress scheduling system safely and avoids corrupting the serialized cron option.', 'choctaw-wp-security' ) . '</p>';
		$html .= '<p>' . esc_html__( 'If SSH access is unavailable, several trusted plugins can safely manage WP-Cron events through the WordPress Dashboard. Plugins such as WP Crontrol allow administrators to view, edit, and delete events without directly modifying the database.', 'choctaw-wp-security' ) . '</p>';
		$html .= '<p>' . esc_html__( 'Avoid deleting WP-Cron events by editing the cron record in phpMyAdmin or another database utility. Because all events are stored in a single serialized database record, manual changes can easily corrupt the data or remove unrelated events, potentially causing WordPress or plugins to malfunction.', 'choctaw-wp-security' ) . '</p>';

		return $html;
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
