<?php
/**
 * Patterns and guidance for the Exposed Files scan.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Match rules, categories, risk resolution, and Why/How copy for exposed files.
 */
class Choctaw_Wp_Security_Exposed_Files_Patterns {

	const CATEGORY_CONFIGURATION = 'configuration';
	const CATEGORY_DATABASE_BACKUP = 'database_backup';
	const CATEGORY_SERVER_DIAGNOSTIC = 'server_diagnostic';
	const CATEGORY_LOG = 'log';
	const CATEGORY_DEV_METADATA = 'dev_metadata';
	const CATEGORY_SOURCE_REPO = 'source_repo';

	/**
	 * Category keys mapped to UI labels.
	 *
	 * @return array<string, string>
	 */
	public static function get_category_labels() {
		return array(
			self::CATEGORY_CONFIGURATION     => __( 'Configuration Files', 'choctaw-wp-security' ),
			self::CATEGORY_DATABASE_BACKUP   => __( 'Database & Backup Files', 'choctaw-wp-security' ),
			self::CATEGORY_SERVER_DIAGNOSTIC => __( 'Server & Diagnostic Files', 'choctaw-wp-security' ),
			self::CATEGORY_LOG               => __( 'Log Files', 'choctaw-wp-security' ),
			self::CATEGORY_DEV_METADATA      => __( 'Development Metadata', 'choctaw-wp-security' ),
			self::CATEGORY_SOURCE_REPO       => __( 'Source Repository Files', 'choctaw-wp-security' ),
		);
	}

	/**
	 * Human labels for risk keys.
	 *
	 * @return array<string, string>
	 */
	public static function get_risk_labels() {
		return array(
			'critical' => __( 'Critical', 'choctaw-wp-security' ),
			'alert'    => __( 'Alert', 'choctaw-wp-security' ),
			'warning'  => __( 'Warning', 'choctaw-wp-security' ),
			'info'     => __( 'Info', 'choctaw-wp-security' ),
		);
	}

	/**
	 * Exact basenames that map to a fixed pattern (files only).
	 *
	 * @return array<string, string>
	 */
	public static function get_exact_file_patterns() {
		return array(
			'composer.json'      => 'composer_json',
			'composer.lock'      => 'composer_lock',
			'package.json'       => 'package_json',
			'package-lock.json'  => 'package_lock',
			'error_log'          => 'error_log',
			'debug.log'          => 'debug_log',
			'test.php'           => 'diag_script',
			'info.php'           => 'diag_script',
			'install.php'        => 'diag_script',
			'phpinfo.php'        => 'diag_script',
		);
	}

	/**
	 * Exact directory basenames that map to a fixed pattern.
	 *
	 * @return array<string, string>
	 */
	public static function get_exact_directory_patterns() {
		return array(
			'.git' => 'git_dir',
			'.svn' => 'svn_dir',
		);
	}

	/**
	 * Archive / dump extensions checked longest-first.
	 *
	 * @return array<int, string>
	 */
	public static function get_archive_extensions() {
		return array( '.tar.gz', '.tgz', '.sql', '.zip', '.tar', '.gz', '.7z', '.rar' );
	}

	/**
	 * Basename keywords that indicate a likely site/database backup archive.
	 *
	 * @return array<int, string>
	 */
	public static function get_backup_archive_keywords() {
		return array(
			'backup',
			'bak',
			'dump',
			'sql',
			'wp-',
			'wordpress',
			'full',
			'site',
			'www',
			'html',
			'db',
		);
	}

	/**
	 * Active wp-config filenames that must not be reported.
	 *
	 * @return array<int, string>
	 */
	public static function get_wp_config_exclusions() {
		return array( 'wp-config.php', 'wp-config-sample.php' );
	}

	/**
	 * Pattern metadata: category, default risk, and guidance.
	 *
	 * @return array<string, array{category: string, risk: string, why: string, how: string}>
	 */
	public static function get_pattern_definitions() {
		return array(
			'wp_config_backup' => array(
				'category' => self::CATEGORY_CONFIGURATION,
				'risk'     => 'critical',
				'why'      => __( 'A file beginning with wp-config was found in the web root that is not the active WordPress configuration file. These files are commonly created as backups during maintenance. Attackers routinely probe for these filenames because they often contain database credentials, authentication salts, and other secrets.', 'choctaw-wp-security' ),
				'how'      => __( 'If this is an accidental backup of wp-config.php, delete it immediately. If it must be retained, move it outside the web-accessible document root. Confirm that only wp-config.php and wp-config-sample.php remain.', 'choctaw-wp-security' ),
			),
			'env_file'         => array(
				'category' => self::CATEGORY_CONFIGURATION,
				'risk'     => 'critical',
				'why'      => __( 'Environment files frequently contain database passwords, SMTP credentials, API tokens, and application secrets. Automated scanners routinely request common .env filenames.', 'choctaw-wp-security' ),
				'how'      => __( 'If the file is publicly accessible, remove it from the document root or relocate it outside the web root. Verify that no credentials have been exposed and rotate secrets if exposure is suspected.', 'choctaw-wp-security' ),
			),
			'sql_dump'         => array(
				'category' => self::CATEGORY_DATABASE_BACKUP,
				'risk'     => 'critical',
				'why'      => __( 'SQL dump files frequently contain the entire WordPress database, including users, hashed passwords, content, configuration, and plugin data.', 'choctaw-wp-security' ),
				'how'      => __( 'Database exports should never remain inside the web root. Move or delete the file after confirming it is no longer required.', 'choctaw-wp-security' ),
			),
			'backup_archive'   => array(
				'category' => self::CATEGORY_DATABASE_BACKUP,
				'risk'     => 'warning',
				'why'      => __( 'Website backup archives often contain the complete WordPress installation, configuration files, uploads, plugins, themes, and database exports.', 'choctaw-wp-security' ),
				'how'      => __( 'Determine whether the archive contains a website backup. If so, remove it from the document root or store it outside the web root.', 'choctaw-wp-security' ),
			),
			'phpinfo_script'   => array(
				'category' => self::CATEGORY_SERVER_DIAGNOSTIC,
				'risk'     => 'alert',
				'why'      => __( 'A PHP script appears to expose PHP configuration information. Attackers use this information to fingerprint server versions, extensions, filesystem paths, and enabled features.', 'choctaw-wp-security' ),
				'how'      => __( 'If this file is only used for troubleshooting, delete it after use. Diagnostic scripts should not remain on production websites.', 'choctaw-wp-security' ),
			),
			'diag_script'      => array(
				'category' => self::CATEGORY_SERVER_DIAGNOSTIC,
				'risk'     => 'warning',
				'why'      => __( 'Generic test or installer scripts are commonly forgotten after development. While they may be harmless, they sometimes expose debugging functionality or outdated code.', 'choctaw-wp-security' ),
				'how'      => __( 'Review the file contents and determine its purpose. Remove any file that is no longer required.', 'choctaw-wp-security' ),
			),
			'error_log'        => array(
				'category' => self::CATEGORY_LOG,
				'risk'     => 'alert',
				'why'      => __( 'Application logs may expose filesystem paths, SQL errors, stack traces, plugin names, and other information useful to attackers.', 'choctaw-wp-security' ),
				'how'      => __( 'Review the log for unexpected activity. Remove or relocate it if it is publicly accessible. Empty logs may simply be monitored.', 'choctaw-wp-security' ),
			),
			'debug_log'        => array(
				'category' => self::CATEGORY_LOG,
				'risk'     => 'alert',
				'why'      => __( 'WordPress debug logs frequently contain PHP notices, warnings, plugin paths, and configuration details.', 'choctaw-wp-security' ),
				'how'      => __( 'Disable debugging on production sites when no longer needed. Remove or relocate exposed logs.', 'choctaw-wp-security' ),
			),
			'composer_json'    => array(
				'category' => self::CATEGORY_DEV_METADATA,
				'risk'     => 'alert',
				'why'      => __( 'This file reveals project dependencies and package information that may help attackers identify vulnerable software.', 'choctaw-wp-security' ),
				'how'      => __( 'If Composer is not used on the production server, remove the file. Otherwise, determine whether it needs to remain publicly accessible.', 'choctaw-wp-security' ),
			),
			'composer_lock'    => array(
				'category' => self::CATEGORY_DEV_METADATA,
				'risk'     => 'alert',
				'why'      => __( 'This file contains exact dependency versions, making vulnerability fingerprinting much easier.', 'choctaw-wp-security' ),
				'how'      => __( 'Review whether the file is required in production. Remove it if unnecessary.', 'choctaw-wp-security' ),
			),
			'package_json'     => array(
				'category' => self::CATEGORY_DEV_METADATA,
				'risk'     => 'alert',
				'why'      => __( 'These files disclose JavaScript dependencies and development tooling.', 'choctaw-wp-security' ),
				'how'      => __( 'Review whether frontend build metadata is needed on the production server.', 'choctaw-wp-security' ),
			),
			'package_lock'     => array(
				'category' => self::CATEGORY_DEV_METADATA,
				'risk'     => 'alert',
				'why'      => __( 'These files disclose JavaScript dependencies and development tooling.', 'choctaw-wp-security' ),
				'how'      => __( 'Review whether frontend build metadata is needed on the production server.', 'choctaw-wp-security' ),
			),
			'git_dir'          => array(
				'category' => self::CATEGORY_SOURCE_REPO,
				'risk'     => 'info',
				'why'      => __( 'Git repositories located in the WordPress root are often the result of website hosts copying an entire site over to a staging environment. Usually, they deny public access to a ".git" folder with a 403 error. Otherwise, it\'s possible an automated hacker will test for this URL to see if they can browse the directory, or download the Git repo.', 'choctaw-wp-security' ),
				'how'      => __( 'You should test the 403 error by trying the URL in your browser (xxxxx.com/.git) or (xxxxx.com/.git/index) to see what comes up. If you get a 403 error, then it\'s nothing to worry about. But if you get a directory listing, or strange code appearing on your screen, it won\'t hurt your website to delete the entire folder, but whoever put it there won\'t be able to use it anymore.', 'choctaw-wp-security' ),
			),
			'svn_dir'          => array(
				'category' => self::CATEGORY_SOURCE_REPO,
				'risk'     => 'critical',
				'why'      => __( 'An exposed Subversion repository may reveal application source code and historical revisions.', 'choctaw-wp-security' ),
				'how'      => __( 'Remove repository metadata from production servers or block public access immediately.', 'choctaw-wp-security' ),
			),
		);
	}

	/**
	 * Resolve pattern, category, and risk for a root entry.
	 *
	 * @param string $basename Entry basename.
	 * @param bool   $is_dir   Whether the entry is a directory.
	 * @param int    $size     File size in bytes (0 for directories).
	 * @param string $snippet  Optional text snippet already read from the file.
	 * @return array{pattern: string, category: string, risk: string}|null
	 */
	public static function match_entry( $basename, $is_dir, $size = 0, $snippet = '' ) {
		$basename = (string) $basename;
		$defs     = self::get_pattern_definitions();

		if ( $is_dir ) {
			$dirs = self::get_exact_directory_patterns();
			if ( isset( $dirs[ $basename ] ) ) {
				$pattern = $dirs[ $basename ];
				return self::build_match( $pattern, $defs[ $pattern ]['risk'] );
			}
			return null;
		}

		$exact = self::get_exact_file_patterns();
		if ( isset( $exact[ $basename ] ) ) {
			$pattern = $exact[ $basename ];
			$risk    = $defs[ $pattern ]['risk'];

			if ( ( 'error_log' === $pattern || 'debug_log' === $pattern ) && 0 === (int) $size ) {
				$risk = 'info';
			}

			if ( 'diag_script' === $pattern && self::snippet_has_phpinfo( $snippet ) ) {
				return self::build_match( 'phpinfo_script', $defs['phpinfo_script']['risk'] );
			}

			return self::build_match( $pattern, $risk );
		}

		$lower = strtolower( $basename );

		if ( 0 === strpos( $lower, 'wp-config' ) ) {
			if ( in_array( $basename, self::get_wp_config_exclusions(), true ) ) {
				return null;
			}
			return self::build_match( 'wp_config_backup', $defs['wp_config_backup']['risk'] );
		}

		if ( 0 === strpos( $basename, '.env' ) ) {
			return self::build_match( 'env_file', $defs['env_file']['risk'] );
		}

		foreach ( self::get_archive_extensions() as $extension ) {
			$ext_len = strlen( $extension );
			if ( strlen( $lower ) > $ext_len && substr( $lower, -$ext_len ) === $extension ) {
				if ( '.sql' === $extension ) {
					return self::build_match( 'sql_dump', $defs['sql_dump']['risk'] );
				}

				$risk = self::is_likely_backup_archive( $basename ) ? 'critical' : 'warning';
				return self::build_match( 'backup_archive', $risk );
			}
		}

		if ( preg_match( '/\.php$/i', $basename ) && self::snippet_has_phpinfo( $snippet ) ) {
			return self::build_match( 'phpinfo_script', $defs['phpinfo_script']['risk'] );
		}

		return null;
	}

	/**
	 * Whether a filename looks like a site or database backup archive.
	 *
	 * @param string $basename Filename.
	 * @return bool
	 */
	public static function is_likely_backup_archive( $basename ) {
		$haystack = strtolower( (string) $basename );

		foreach ( self::get_backup_archive_keywords() as $keyword ) {
			if ( false !== strpos( $haystack, $keyword ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether a text snippet appears to call phpinfo().
	 *
	 * @param string $snippet File snippet.
	 * @return bool
	 */
	public static function snippet_has_phpinfo( $snippet ) {
		return (bool) preg_match( '/phpinfo\s*\(/i', (string) $snippet );
	}

	/**
	 * Guidance strings for a pattern ID.
	 *
	 * @param string $pattern Pattern ID.
	 * @return array{why: string, how: string}
	 */
	public static function get_guidance( $pattern ) {
		$defs = self::get_pattern_definitions();

		if ( ! isset( $defs[ $pattern ] ) ) {
			return array(
				'why' => '',
				'how' => '',
			);
		}

		return array(
			'why' => $defs[ $pattern ]['why'],
			'how' => $defs[ $pattern ]['how'],
		);
	}

	/**
	 * Build a normalized match array.
	 *
	 * @param string $pattern Pattern ID.
	 * @param string $risk    Risk key.
	 * @return array{pattern: string, category: string, risk: string}
	 */
	private static function build_match( $pattern, $risk ) {
		$defs = self::get_pattern_definitions();

		return array(
			'pattern'  => $pattern,
			'category' => $defs[ $pattern ]['category'],
			'risk'     => $risk,
		);
	}
}
