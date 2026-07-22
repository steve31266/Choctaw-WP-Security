<?php
/**
 * Bundled Sassh recognized-components registry (Phase 3.5).
 *
 * Recognition means only that Sassh knows the path/stylesheet as a known
 * third-party component identity. It does not mean the installed code was
 * audited, integrity-checked, or guaranteed safe.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Loads and indexes coreguard/data/recognized-components.json once per request.
 */
class Sassh_Recognized_Components_Registry {

	/**
	 * Supported schema_version values.
	 *
	 * @var array<int, int>
	 */
	const SUPPORTED_SCHEMA_VERSIONS = array( 1 );

	/**
	 * Relative path under the plugin root.
	 *
	 * @var string
	 */
	const RELATIVE_PATH = 'data/recognized-components.json';

	/**
	 * Human-readable recognition source label (display).
	 *
	 * @var string
	 */
	const RECOGNITION_SOURCE_LABEL = 'Sassh recognized-components registry';

	/**
	 * Machine recognition_source metadata value.
	 *
	 * @var string
	 */
	const RECOGNITION_SOURCE_KEY = 'sassh_recognized_components_registry';

	/**
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Absolute path override for tests.
	 *
	 * @var string|null
	 */
	private static $path_override = null;

	/**
	 * @var bool
	 */
	private $loaded = false;

	/**
	 * @var array<string, array{name: string, vendor: string}>
	 */
	private $plugins = array();

	/**
	 * @var array<string, array{name: string, vendor: string}>
	 */
	private $themes = array();

	/**
	 * Load / validation diagnostics (not user-facing “safe” claims).
	 *
	 * @var array<int, string>
	 */
	private $diagnostics = array();

	/**
	 * @return self
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Reset singleton and path override (unit tests).
	 *
	 * @return void
	 */
	public static function reset_for_tests() {
		self::$instance      = null;
		self::$path_override = null;
	}

	/**
	 * Override the JSON path for tests.
	 *
	 * @param string|null $path Absolute path, or null to clear.
	 * @return void
	 */
	public static function set_path_override_for_tests( $path ) {
		self::$path_override = ( null === $path || '' === (string) $path ) ? null : (string) $path;
		self::$instance      = null;
	}

	/**
	 * Default absolute path to the bundled registry file.
	 *
	 * @return string
	 */
	public static function default_path() {
		if ( null !== self::$path_override ) {
			return self::$path_override;
		}

		$base = defined( 'CHOCTAW_WP_SECURITY_PATH' ) ? CHOCTAW_WP_SECURITY_PATH : dirname( __DIR__ ) . '/';

		return rtrim( str_replace( '\\', '/', (string) $base ), '/' ) . '/' . self::RELATIVE_PATH;
	}

	/**
	 * Normalize a registry plugin main_file for exact identity matching.
	 *
	 * Conservatively rejects traversal and empty identities. Does not fold case
	 * (WordPress plugin basenames retain filesystem casing).
	 *
	 * @param string $raw Raw main_file from JSON or installed plugin basename.
	 * @return string Normalized identity, or empty when unsafe/invalid.
	 */
	public static function normalize_plugin_main_file( $raw ) {
		$file = Sassh_Component_Key_Normalizer::normalize_plugin_file( $raw );

		if ( '' === $file ) {
			return '';
		}

		if ( false !== strpos( $file, "\0" ) ) {
			return '';
		}

		// Reject traversal / dot segments after slash normalization.
		if ( preg_match( '#(^|/)\.\.?(?:/|$)#', $file ) ) {
			return '';
		}

		return $file;
	}

	/**
	 * Normalize a registry theme stylesheet for exact identity matching.
	 *
	 * @param string $raw Raw stylesheet from JSON or installed theme.
	 * @return string Normalized identity, or empty when unsafe/invalid.
	 */
	public static function normalize_theme_stylesheet( $raw ) {
		$stylesheet = Sassh_Component_Key_Normalizer::normalize_theme_stylesheet( $raw );

		if ( '' === $stylesheet ) {
			return '';
		}

		if ( false !== strpos( $stylesheet, "\0" ) ) {
			return '';
		}

		// Stylesheets are directory slugs — no path separators or traversal.
		if ( false !== strpos( $stylesheet, '/' ) || false !== strpos( $stylesheet, '\\' ) ) {
			return '';
		}

		if ( preg_match( '#^\.\.?$#', $stylesheet ) ) {
			return '';
		}

		return $stylesheet;
	}

	/**
	 * Decide recognition outcome after a WPVulnerability lookup (and optional registry hit).
	 *
	 * Registry is consulted only when the provider positively determined unrecognized.
	 * Incomplete / failed lookups stay unchecked even if a registry identity matches.
	 * Provider-recognized vulnerable results always win over registry recognition.
	 *
	 * @param array<string, mixed>     $lookup               Provider lookup (`checked`, `recognized`).
	 * @param array<string, mixed>|null $registry_entry      Registry hit or null.
	 * @param bool                     $has_applicable_vulns Applicable advisories when provider-recognized.
	 * @return string unchecked|unrecognized|recognized_clean|recognized_vulnerable
	 */
	public static function decide_after_provider_lookup( array $lookup, $registry_entry, $has_applicable_vulns ) {
		if ( empty( $lookup['checked'] ) ) {
			return 'unchecked';
		}

		if ( ! empty( $lookup['recognized'] ) ) {
			return $has_applicable_vulns ? 'recognized_vulnerable' : 'recognized_clean';
		}

		if ( is_array( $registry_entry ) && ! empty( $registry_entry['name'] ) ) {
			return 'recognized_clean';
		}

		return 'unrecognized';
	}

	/**
	 * Ensure the registry is loaded and indexed.
	 *
	 * @return void
	 */
	public function ensure_loaded() {
		if ( $this->loaded ) {
			return;
		}

		$this->loaded      = true;
		$this->plugins     = array();
		$this->themes      = array();
		$this->diagnostics = array();

		$path = self::default_path();

		if ( ! is_readable( $path ) ) {
			$this->diagnostics[] = sprintf(
				/* translators: %s: registry file path */
				__( 'Sassh recognized-components registry is missing or unreadable (%s). Provider results are unchanged.', 'choctaw-wp-security' ),
				$path
			);
			return;
		}

		$raw = file_get_contents( $path );

		if ( false === $raw ) {
			$this->diagnostics[] = __( 'Sassh recognized-components registry could not be read. Provider results are unchanged.', 'choctaw-wp-security' );
			return;
		}

		$data = json_decode( $raw, true );

		if ( ! is_array( $data ) ) {
			$this->diagnostics[] = __( 'Sassh recognized-components registry is not valid JSON. Provider results are unchanged.', 'choctaw-wp-security' );
			return;
		}

		$schema = isset( $data['schema_version'] ) ? (int) $data['schema_version'] : 0;

		if ( ! in_array( $schema, self::SUPPORTED_SCHEMA_VERSIONS, true ) ) {
			$this->diagnostics[] = sprintf(
				/* translators: %d: schema version number */
				__( 'Sassh recognized-components registry schema_version %d is unsupported. Provider results are unchanged.', 'choctaw-wp-security' ),
				$schema
			);
			return;
		}

		$plugins = isset( $data['plugins'] ) && is_array( $data['plugins'] ) ? $data['plugins'] : null;
		$themes  = isset( $data['themes'] ) && is_array( $data['themes'] ) ? $data['themes'] : null;

		if ( null === $plugins || null === $themes ) {
			$this->diagnostics[] = __( 'Sassh recognized-components registry is missing plugins or themes collections. Provider results are unchanged.', 'choctaw-wp-security' );
			return;
		}

		$this->index_plugins( $plugins );
		$this->index_themes( $themes );
	}

	/**
	 * @return array<int, string>
	 */
	public function get_diagnostics() {
		$this->ensure_loaded();

		return $this->diagnostics;
	}

	/**
	 * Look up a plugin by normalized main file. Version and display names never match.
	 *
	 * @param string $main_file Plugin basename (e.g. coreguard/sassh.php).
	 * @return array{name: string, vendor: string, main_file: string}|null
	 */
	public function lookup_plugin( $main_file ) {
		$this->ensure_loaded();

		$key = self::normalize_plugin_main_file( $main_file );

		if ( '' === $key || ! isset( $this->plugins[ $key ] ) ) {
			return null;
		}

		$entry               = $this->plugins[ $key ];
		$entry['main_file']  = $key;

		return $entry;
	}

	/**
	 * Look up a theme by normalized stylesheet.
	 *
	 * @param string $stylesheet Theme stylesheet.
	 * @return array{name: string, vendor: string, stylesheet: string}|null
	 */
	public function lookup_theme( $stylesheet ) {
		$this->ensure_loaded();

		$key = self::normalize_theme_stylesheet( $stylesheet );

		if ( '' === $key || ! isset( $this->themes[ $key ] ) ) {
			return null;
		}

		$entry               = $this->themes[ $key ];
		$entry['stylesheet'] = $key;

		return $entry;
	}

	/**
	 * Whether any identity was indexed (valid registry with ≥1 usable entry).
	 *
	 * @return bool
	 */
	public function has_entries() {
		$this->ensure_loaded();

		return ! empty( $this->plugins ) || ! empty( $this->themes );
	}

	/**
	 * @param array<int, mixed> $plugins Plugin entries from JSON.
	 * @return void
	 */
	private function index_plugins( array $plugins ) {
		foreach ( $plugins as $index => $entry ) {
			if ( ! is_array( $entry ) ) {
				$this->diagnostics[] = sprintf(
					/* translators: %d: entry index */
					__( 'Recognized-components registry: ignored malformed plugin entry at index %d.', 'choctaw-wp-security' ),
					(int) $index
				);
				continue;
			}

			$main_file = isset( $entry['main_file'] ) ? self::normalize_plugin_main_file( (string) $entry['main_file'] ) : '';
			$name      = isset( $entry['name'] ) ? trim( (string) $entry['name'] ) : '';

			if ( '' === $main_file || '' === $name ) {
				$this->diagnostics[] = sprintf(
					/* translators: %d: entry index */
					__( 'Recognized-components registry: ignored plugin entry at index %d (missing main_file or name).', 'choctaw-wp-security' ),
					(int) $index
				);
				continue;
			}

			if ( isset( $this->plugins[ $main_file ] ) ) {
				$this->diagnostics[] = sprintf(
					/* translators: %s: plugin main file */
					__( 'Recognized-components registry: duplicate plugin identity "%s" ignored.', 'choctaw-wp-security' ),
					$main_file
				);
				continue;
			}

			$vendor = isset( $entry['vendor'] ) ? trim( (string) $entry['vendor'] ) : '';

			$this->plugins[ $main_file ] = array(
				'name'   => $name,
				'vendor' => $vendor,
			);
		}
	}

	/**
	 * @param array<int, mixed> $themes Theme entries from JSON.
	 * @return void
	 */
	private function index_themes( array $themes ) {
		foreach ( $themes as $index => $entry ) {
			if ( ! is_array( $entry ) ) {
				$this->diagnostics[] = sprintf(
					/* translators: %d: entry index */
					__( 'Recognized-components registry: ignored malformed theme entry at index %d.', 'choctaw-wp-security' ),
					(int) $index
				);
				continue;
			}

			$stylesheet = isset( $entry['stylesheet'] ) ? self::normalize_theme_stylesheet( (string) $entry['stylesheet'] ) : '';
			$name       = isset( $entry['name'] ) ? trim( (string) $entry['name'] ) : '';

			if ( '' === $stylesheet || '' === $name ) {
				$this->diagnostics[] = sprintf(
					/* translators: %d: entry index */
					__( 'Recognized-components registry: ignored theme entry at index %d (missing stylesheet or name).', 'choctaw-wp-security' ),
					(int) $index
				);
				continue;
			}

			if ( isset( $this->themes[ $stylesheet ] ) ) {
				$this->diagnostics[] = sprintf(
					/* translators: %s: theme stylesheet */
					__( 'Recognized-components registry: duplicate theme identity "%s" ignored.', 'choctaw-wp-security' ),
					$stylesheet
				);
				continue;
			}

			$vendor = isset( $entry['vendor'] ) ? trim( (string) $entry['vendor'] ) : '';

			$this->themes[ $stylesheet ] = array(
				'name'   => $name,
				'vendor' => $vendor,
			);
		}
	}
}
