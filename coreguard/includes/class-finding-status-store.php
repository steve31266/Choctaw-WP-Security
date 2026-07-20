<?php
/**
 * Site-wide finding status registry (Needs Review / Review Not Needed / Dismissed).
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Persists dismissed finding fingerprints and merges status onto scan results.
 */
class Choctaw_Wp_Security_Finding_Status_Store {

	const STATUS_NEEDS_REVIEW     = 'needs_review';
	const STATUS_NO_ACTION_NEEDED = 'no_action_needed';
	const STATUS_DISMISSED        = 'dismissed';

	/**
	 * Scan types that participate in the Status system (v1).
	 *
	 * @var array<int, string>
	 */
	public static $supported_scan_types = array(
		'database-scan',
		'wp-posts',
		'scheduled-tasks',
		'exposed-files',
		'directory-browsing',
		'unrecognized-components',
	);

	/**
	 * Load the full registry from wp_options.
	 *
	 * @return array<string, array<string, array<string, mixed>>>
	 */
	public static function get_registry() {
		$stored = get_option( Choctaw_Wp_Security_Utils::FINDING_STATUSES_KEY, array() );

		if ( ! is_array( $stored ) ) {
			return array();
		}

		return $stored;
	}

	/**
	 * Persist the registry.
	 *
	 * @param array<string, array<string, array<string, mixed>>> $registry Registry payload.
	 * @return void
	 */
	public static function save_registry( array $registry ) {
		update_option( Choctaw_Wp_Security_Utils::FINDING_STATUSES_KEY, $registry, false );
	}

	/**
	 * Whether a scan type is supported.
	 *
	 * @param string $scan_type Scan type key.
	 * @return bool
	 */
	public static function is_supported_scan_type( $scan_type ) {
		return in_array( (string) $scan_type, self::$supported_scan_types, true );
	}

	/**
	 * Human label for a status key.
	 *
	 * @param string $status Status key.
	 * @return string
	 */
	public static function status_label( $status ) {
		switch ( (string) $status ) {
			case self::STATUS_DISMISSED:
				return __( 'Dismissed', 'choctaw-wp-security' );
			case self::STATUS_NO_ACTION_NEEDED:
				return __( 'Review Not Needed', 'choctaw-wp-security' );
			default:
				return __( 'Needs Review', 'choctaw-wp-security' );
		}
	}

	/**
	 * Default open status for a finding from its risk (when not dismissed).
	 *
	 * Safe findings are Review Not Needed; all other risks remain Needs Review
	 * (including Info soft-gap items).
	 *
	 * @param array<string, mixed> $finding Finding row.
	 * @return string
	 */
	public static function open_status_for_finding( array $finding ) {
		$risk = isset( $finding['risk'] ) ? (string) $finding['risk'] : '';

		if ( 'safe' === $risk ) {
			return self::STATUS_NO_ACTION_NEEDED;
		}

		return self::STATUS_NEEDS_REVIEW;
	}

	/**
	 * Whether a fingerprint is dismissed for a scan type.
	 *
	 * @param string $scan_type   Scan type key.
	 * @param string $fingerprint Finding fingerprint.
	 * @return bool
	 */
	public static function is_dismissed( $scan_type, $fingerprint ) {
		$scan_type   = (string) $scan_type;
		$fingerprint = (string) $fingerprint;

		if ( '' === $scan_type || '' === $fingerprint ) {
			return false;
		}

		$registry = self::get_registry();

		if ( empty( $registry[ $scan_type ][ $fingerprint ] ) || ! is_array( $registry[ $scan_type ][ $fingerprint ] ) ) {
			return false;
		}

		$status = isset( $registry[ $scan_type ][ $fingerprint ]['status'] )
			? (string) $registry[ $scan_type ][ $fingerprint ]['status']
			: '';

		return self::STATUS_DISMISSED === $status;
	}

	/**
	 * Merge status fields onto findings.
	 *
	 * @param string                         $scan_type Scan type key.
	 * @param array<int, array<string, mixed>> $findings Findings list.
	 * @return array<int, array<string, mixed>>
	 */
	public static function apply( $scan_type, array $findings ) {
		$scan_type = (string) $scan_type;
		$registry  = self::get_registry();
		$bucket    = ( isset( $registry[ $scan_type ] ) && is_array( $registry[ $scan_type ] ) )
			? $registry[ $scan_type ]
			: array();

		foreach ( $findings as &$finding ) {
			if ( ! is_array( $finding ) ) {
				continue;
			}

			$fingerprint = isset( $finding['fingerprint'] ) ? (string) $finding['fingerprint'] : '';

			if ( '' === $fingerprint && isset( $finding['id'] ) ) {
				$fingerprint = (string) $finding['id'];
				$finding['fingerprint'] = $fingerprint;
			}

			$is_dismissed = ( '' !== $fingerprint && isset( $bucket[ $fingerprint ] ) && is_array( $bucket[ $fingerprint ] )
				&& self::STATUS_DISMISSED === ( isset( $bucket[ $fingerprint ]['status'] ) ? (string) $bucket[ $fingerprint ]['status'] : '' ) );

			$status = $is_dismissed
				? self::STATUS_DISMISSED
				: self::open_status_for_finding( $finding );

			$finding['status']       = $status;
			$finding['status_label'] = self::status_label( $status );
		}
		unset( $finding );

		return $findings;
	}

	/**
	 * Apply status to a full scan result payload (mutates findings; syncs sections when present).
	 *
	 * @param string               $scan_type Scan type key.
	 * @param array<string, mixed> $result    Scan result.
	 * @return array<string, mixed>
	 */
	public static function apply_to_result( $scan_type, array $result ) {
		if ( empty( $result['findings'] ) || ! is_array( $result['findings'] ) ) {
			return $result;
		}

		$result['findings'] = self::apply( $scan_type, $result['findings'] );

		if ( ! empty( $result['sections'] ) && is_array( $result['sections'] ) ) {
			$by_fingerprint = array();

			foreach ( $result['findings'] as $finding ) {
				if ( ! is_array( $finding ) ) {
					continue;
				}

				$fp = isset( $finding['fingerprint'] ) ? (string) $finding['fingerprint'] : '';

				if ( '' !== $fp ) {
					$by_fingerprint[ $fp ] = $finding;
				}
			}

			foreach ( $result['sections'] as &$section ) {
				if ( empty( $section['findings'] ) || ! is_array( $section['findings'] ) ) {
					continue;
				}

				foreach ( $section['findings'] as &$finding ) {
					if ( ! is_array( $finding ) ) {
						continue;
					}

					$fp = isset( $finding['fingerprint'] ) ? (string) $finding['fingerprint'] : '';

					if ( '' === $fp && isset( $finding['id'] ) ) {
						$fp = (string) $finding['id'];
					}

					if ( '' !== $fp && isset( $by_fingerprint[ $fp ] ) ) {
						$finding['fingerprint']  = $by_fingerprint[ $fp ]['fingerprint'];
						$finding['status']       = $by_fingerprint[ $fp ]['status'];
						$finding['status_label'] = $by_fingerprint[ $fp ]['status_label'];
					} else {
						$enriched                = self::apply( $scan_type, array( $finding ) );
						$finding['fingerprint']  = $enriched[0]['fingerprint'];
						$finding['status']       = $enriched[0]['status'];
						$finding['status_label'] = $enriched[0]['status_label'];
					}
				}
				unset( $finding );
			}
			unset( $section );
		}

		return $result;
	}

	/**
	 * Mark a finding as dismissed.
	 *
	 * @param string $scan_type   Scan type key.
	 * @param string $fingerprint Finding fingerprint.
	 * @return true|WP_Error
	 */
	public static function dismiss( $scan_type, $fingerprint ) {
		$scan_type   = (string) $scan_type;
		$fingerprint = (string) $fingerprint;

		if ( ! self::is_supported_scan_type( $scan_type ) ) {
			return new WP_Error( 'invalid_scan_type', __( 'Unsupported scan type.', 'choctaw-wp-security' ) );
		}

		if ( '' === $fingerprint ) {
			return new WP_Error( 'invalid_fingerprint', __( 'Missing finding fingerprint.', 'choctaw-wp-security' ) );
		}

		$registry = self::get_registry();

		if ( ! isset( $registry[ $scan_type ] ) || ! is_array( $registry[ $scan_type ] ) ) {
			$registry[ $scan_type ] = array();
		}

		$registry[ $scan_type ][ $fingerprint ] = array(
			'status'       => self::STATUS_DISMISSED,
			'dismissed_at' => gmdate( 'Y-m-d H:i:s' ),
			'dismissed_by' => get_current_user_id(),
		);

		self::save_registry( $registry );

		return true;
	}

	/**
	 * Remove a dismissal (restore Needs Review).
	 *
	 * @param string $scan_type   Scan type key.
	 * @param string $fingerprint Finding fingerprint.
	 * @return true|WP_Error
	 */
	public static function undismiss( $scan_type, $fingerprint ) {
		$scan_type   = (string) $scan_type;
		$fingerprint = (string) $fingerprint;

		if ( ! self::is_supported_scan_type( $scan_type ) ) {
			return new WP_Error( 'invalid_scan_type', __( 'Unsupported scan type.', 'choctaw-wp-security' ) );
		}

		if ( '' === $fingerprint ) {
			return new WP_Error( 'invalid_fingerprint', __( 'Missing finding fingerprint.', 'choctaw-wp-security' ) );
		}

		$registry = self::get_registry();

		if ( isset( $registry[ $scan_type ] ) && is_array( $registry[ $scan_type ] ) ) {
			unset( $registry[ $scan_type ][ $fingerprint ] );

			if ( empty( $registry[ $scan_type ] ) ) {
				unset( $registry[ $scan_type ] );
			}

			self::save_registry( $registry );
		}

		return true;
	}

	/**
	 * Clear all dismissals for a scan type.
	 *
	 * @param string $scan_type Scan type key.
	 * @return true|WP_Error
	 */
	public static function clear_scan( $scan_type ) {
		$scan_type = (string) $scan_type;

		if ( ! self::is_supported_scan_type( $scan_type ) ) {
			return new WP_Error( 'invalid_scan_type', __( 'Unsupported scan type.', 'choctaw-wp-security' ) );
		}

		$registry = self::get_registry();
		unset( $registry[ $scan_type ] );
		self::save_registry( $registry );

		return true;
	}

	/**
	 * Build a stable fingerprint for an options-table finding.
	 *
	 * @param string               $section_key Section key.
	 * @param array<string, mixed> $finding     Finding row.
	 * @return string
	 */
	public static function fingerprint_options_finding( $section_key, array $finding ) {
		$section_key = (string) $section_key;
		$option_name = isset( $finding['option_name'] ) ? (string) $finding['option_name'] : '';
		$type_id     = isset( $finding['id'] ) ? (string) $finding['id'] : '';
		$excerpt     = isset( $finding['excerpt'] ) ? (string) $finding['excerpt'] : '';
		$detail      = isset( $finding['detail'] ) ? (string) $finding['detail'] : '';
		$option_id   = isset( $finding['option_id'] ) ? (int) $finding['option_id'] : 0;

		// Avoid nesting when re-fingerprinting an already-enriched row.
		if ( 0 === strpos( $type_id, 'options:' ) ) {
			$type_id = '';
		}

		if ( 'baseline_diff' === $section_key ) {
			$change_type = isset( $finding['change_type'] ) ? (string) $finding['change_type'] : 'changed';
			return 'options:baseline:' . $option_name . ':' . $change_type;
		}

		/*
		 * Disambiguate multiple findings that share an option_name (e.g. several
		 * active_plugins path/missing rows) using type id + excerpt/detail.
		 */
		$disambiguator = '' !== $excerpt ? $excerpt : $detail;

		return 'options:' . $section_key . ':' . $option_name . ':' . $type_id . ':' . $option_id . ':' . md5( $disambiguator );
	}

	/**
	 * Build a stable fingerprint for a posts-table finding.
	 *
	 * @param string               $section_key Section key.
	 * @param array<string, mixed> $finding     Finding row.
	 * @return string
	 */
	public static function fingerprint_posts_finding( $section_key, array $finding ) {
		$section_key = (string) $section_key;
		$post_id     = isset( $finding['post_id'] ) ? (int) $finding['post_id'] : 0;

		if ( 'baseline_diff' === $section_key ) {
			$change_type = isset( $finding['change_type'] ) ? (string) $finding['change_type'] : 'changed';
			return 'posts:baseline:' . $post_id . ':' . $change_type;
		}

		return 'posts:' . $section_key . ':' . $post_id;
	}

	/**
	 * Build a stable fingerprint for a scheduled-task finding.
	 *
	 * @param string               $hook Hook name.
	 * @param array<string, mixed> $args Event args.
	 * @return string
	 */
	public static function fingerprint_cron_finding( $hook, $args ) {
		$hook = (string) $hook;
		$serialized = is_array( $args ) ? wp_json_encode( $args ) : (string) $args;

		if ( false === $serialized ) {
			$serialized = serialize( $args ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize
		}

		return 'cron:' . $hook . ':' . md5( $serialized );
	}

	/**
	 * Build a stable fingerprint for an exposed-files finding.
	 *
	 * @param string $absolute_path Absolute path.
	 * @return string
	 */
	public static function fingerprint_exposed_file( $absolute_path ) {
		return 'exposed:' . (string) $absolute_path;
	}

	/**
	 * Build a stable fingerprint for an uploads-folder finding.
	 *
	 * @param string $absolute_path Absolute path.
	 * @return string
	 */
	public static function fingerprint_uploads_file( $absolute_path ) {
		return 'uploads:' . (string) $absolute_path;
	}

	/**
	 * Build a stable fingerprint for an MU-plugin finding.
	 *
	 * @param string $absolute_path Absolute path.
	 * @return string
	 */
	public static function fingerprint_mu_plugin( $absolute_path ) {
		return 'mu:' . (string) $absolute_path;
	}

	/**
	 * Build a stable fingerprint for a core checksum finding.
	 *
	 * @param string $relative_path Relative core path.
	 * @param string $issue_type    modified|missing|unknown.
	 * @return string
	 */
	public static function fingerprint_checksum( $relative_path, $issue_type ) {
		return 'core:' . (string) $relative_path . ':' . (string) $issue_type;
	}

	/**
	 * Build a stable fingerprint for a directory-browsing finding.
	 *
	 * @param string $kind htaccess|folder.
	 * @param string $path Display path or logical key.
	 * @return string
	 */
	public static function fingerprint_directory_browsing( $kind, $path ) {
		return 'dirbrowse:' . (string) $kind . ':' . (string) $path;
	}

	/**
	 * Build a stable fingerprint for an unrecognized component finding.
	 *
	 * @param string $category plugin|theme.
	 * @param string $slug     Component slug (theme stylesheet or plugin slug).
	 * @param string $file     Optional plugin file path for disambiguation.
	 * @return string
	 */
	public static function fingerprint_unrecognized_component( $category, $slug, $file = '' ) {
		$category = sanitize_key( (string) $category );
		$slug     = sanitize_title( (string) $slug );
		$file     = ltrim( wp_normalize_path( (string) $file ), '/' );

		if ( 'plugin' === $category && '' !== $file ) {
			return 'unrecognized:plugin:' . $file;
		}

		return 'unrecognized:' . $category . ':' . $slug;
	}
}
