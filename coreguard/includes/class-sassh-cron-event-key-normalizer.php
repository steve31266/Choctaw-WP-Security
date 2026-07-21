<?php
/**
 * Sassh Findings cron_event key normalization, canonicalization, and sanitization.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Shared rules for object_type=cron_event keys and argument digests.
 */
class Sassh_Cron_Event_Key_Normalizer {

	/**
	 * Max characters for sanitized argument previews in metadata / UI.
	 *
	 * @var int
	 */
	const ARGS_PREVIEW_MAX = 240;

	/**
	 * Max occurrence detail rows retained in Findings metadata.
	 *
	 * @var int
	 */
	const OCCURRENCE_META_CAP = 20;

	/**
	 * Normalize a cron hook name for object_key.
	 *
	 * @param string $hook Hook name.
	 * @return string
	 */
	public static function normalize_hook( $hook ) {
		return trim( (string) $hook );
	}

	/**
	 * Stable hex digest of canonicalized args.
	 *
	 * @param mixed $args Event args.
	 * @return string Hex digest, or empty string when unhashable.
	 */
	public static function args_digest( $args ) {
		$canonical = self::canonicalize( $args );

		if ( null === $canonical ) {
			return '';
		}

		$encoded = self::encode_canonical( $canonical );

		if ( '' === $encoded ) {
			return '';
		}

		return hash( 'sha256', $encoded );
	}

	/**
	 * Object key: hook#args_digest.
	 *
	 * @param string $hook Hook name.
	 * @param mixed  $args Event args.
	 * @return string|WP_Error Object key or error when args are unhashable.
	 */
	public static function object_key( $hook, $args ) {
		$hook = self::normalize_hook( $hook );

		if ( '' === $hook ) {
			return new WP_Error(
				'sassh_cron_hook_empty',
				__( 'Cron hook name is empty.', 'choctaw-wp-security' )
			);
		}

		$digest = self::args_digest( $args );

		if ( '' === $digest ) {
			return new WP_Error(
				'sassh_cron_args_unhashable',
				__( 'Cron event arguments could not be fingerprinted.', 'choctaw-wp-security' )
			);
		}

		return $hook . '#' . $digest;
	}

	/**
	 * Deterministic serialization of the sorted unique schedule/interval pair set.
	 *
	 * @param array<int, array{schedule?: string, interval?: int}> $pairs Schedule/interval pairs.
	 * @return string
	 */
	public static function encode_schedule_interval_set( array $pairs ) {
		$unique = array();

		foreach ( $pairs as $pair ) {
			if ( ! is_array( $pair ) ) {
				continue;
			}

			$schedule = isset( $pair['schedule'] ) ? (string) $pair['schedule'] : '';
			$interval = isset( $pair['interval'] ) ? (int) $pair['interval'] : 0;
			$key      = $schedule . "\0" . (string) $interval;
			$unique[ $key ] = array(
				'schedule' => $schedule,
				'interval' => $interval,
			);
		}

		ksort( $unique, SORT_STRING );

		$lines = array();

		foreach ( $unique as $row ) {
			$lines[] = self::length_prefix( $row['schedule'] ) . ':' . (string) (int) $row['interval'];
		}

		return implode( "\n", $lines );
	}

	/**
	 * Object fingerprint payload (hook + canonical args + sorted schedule/interval set).
	 *
	 * @param string                                               $hook Hook.
	 * @param mixed                                                $args Args.
	 * @param array<int, array{schedule?: string, interval?: int}> $pairs Schedule/interval pairs.
	 * @return string|WP_Error sha256:hex or error.
	 */
	public static function object_fingerprint( $hook, $args, array $pairs ) {
		$hook = self::normalize_hook( $hook );
		$canonical = self::canonicalize( $args );

		if ( null === $canonical ) {
			return new WP_Error(
				'sassh_cron_args_unhashable',
				__( 'Cron event arguments could not be fingerprinted.', 'choctaw-wp-security' )
			);
		}

		$payload = self::length_prefix( $hook )
			. "\n"
			. self::encode_canonical( $canonical )
			. "\n"
			. self::encode_schedule_interval_set( $pairs );

		return Sassh_Findings_Service::content_fingerprint_from_string( $payload );
	}

	/**
	 * Canonicalize a value for hashing.
	 *
	 * Preserves PHP type distinctions. Recursively sorts associative-map keys only.
	 * Does not reorder indexed arrays. Returns null for unsupported/unhashable values.
	 *
	 * @param mixed $value Value.
	 * @return array<string, mixed>|null Typed canonical node or null if unhashable.
	 */
	public static function canonicalize( $value ) {
		if ( null === $value ) {
			return array(
				't' => 'null',
				'v' => null,
			);
		}

		if ( is_bool( $value ) ) {
			return array(
				't' => 'bool',
				'v' => $value ? 1 : 0,
			);
		}

		if ( is_int( $value ) ) {
			return array(
				't' => 'int',
				'v' => $value,
			);
		}

		if ( is_float( $value ) ) {
			if ( is_nan( $value ) || is_infinite( $value ) ) {
				return null;
			}

			return array(
				't' => 'float',
				'v' => (string) $value,
			);
		}

		if ( is_string( $value ) ) {
			return array(
				't' => 'string',
				'v' => $value,
			);
		}

		if ( is_array( $value ) ) {
			if ( self::is_list_array( $value ) ) {
				$items = array();

				foreach ( $value as $child ) {
					$canonical_child = self::canonicalize( $child );

					if ( null === $canonical_child ) {
						return null;
					}

					$items[] = $canonical_child;
				}

				return array(
					't' => 'list',
					'v' => $items,
				);
			}

			$keys = array_keys( $value );
			$keys = array_map( 'strval', $keys );
			sort( $keys, SORT_STRING );

			$map = array();

			foreach ( $keys as $key ) {
				$canonical_child = self::canonicalize( $value[ $key ] );

				if ( null === $canonical_child ) {
					return null;
				}

				$map[] = array(
					'k' => (string) $key,
					'v' => $canonical_child,
				);
			}

			return array(
				't' => 'map',
				'v' => $map,
			);
		}

		// Objects, resources, callables, etc. are unhashable for Findings identity.
		return null;
	}

	/**
	 * Encode a canonical node to a stable string.
	 *
	 * @param array<string, mixed> $canonical Canonical node.
	 * @return string
	 */
	public static function encode_canonical( array $canonical ) {
		$type = isset( $canonical['t'] ) ? (string) $canonical['t'] : '';

		switch ( $type ) {
			case 'null':
				return 'n:';

			case 'bool':
				return 'b:' . ( ! empty( $canonical['v'] ) ? '1' : '0' );

			case 'int':
				return 'i:' . (string) (int) $canonical['v'];

			case 'float':
				return 'f:' . self::length_prefix( (string) $canonical['v'] );

			case 'string':
				return 's:' . self::length_prefix( (string) $canonical['v'] );

			case 'list':
				$parts = array();
				$items = isset( $canonical['v'] ) && is_array( $canonical['v'] ) ? $canonical['v'] : array();

				foreach ( $items as $item ) {
					if ( ! is_array( $item ) ) {
						return '';
					}
					$parts[] = self::encode_canonical( $item );
				}

				return 'l:' . count( $parts ) . ':[' . implode( ',', $parts ) . ']';

			case 'map':
				$parts = array();
				$items = isset( $canonical['v'] ) && is_array( $canonical['v'] ) ? $canonical['v'] : array();

				foreach ( $items as $item ) {
					if ( ! is_array( $item ) || ! isset( $item['k'], $item['v'] ) || ! is_array( $item['v'] ) ) {
						return '';
					}
					$parts[] = self::length_prefix( (string) $item['k'] ) . '=' . self::encode_canonical( $item['v'] );
				}

				return 'm:' . count( $parts ) . ':{' . implode( ',', $parts ) . '}';

			default:
				return '';
		}
	}

	/**
	 * Sanitize and cap an argument preview for metadata / UI.
	 *
	 * @param mixed $args Args.
	 * @param int   $max  Max length.
	 * @return array{preview: string, truncated: bool}
	 */
	public static function sanitize_args_preview( $args, $max = self::ARGS_PREVIEW_MAX ) {
		$max = (int) $max;

		if ( $max < 16 ) {
			$max = 16;
		}

		if ( is_array( $args ) || is_object( $args ) ) {
			$encoded = wp_json_encode( $args );
			$raw     = ( false !== $encoded ) ? $encoded : '';
		} else {
			$raw = (string) $args;
		}

		$raw = self::redact_sensitive_preview( $raw );

		if ( strlen( $raw ) <= $max ) {
			return array(
				'preview'   => $raw,
				'truncated' => false,
			);
		}

		return array(
			'preview'   => substr( $raw, 0, $max - 3 ) . '...',
			'truncated' => true,
		);
	}

	/**
	 * Cap an occurrence-details list for metadata.
	 *
	 * @param array<int, array<string, mixed>> $occurrences Occurrences.
	 * @param int                              $cap         Max rows.
	 * @return array<int, array<string, mixed>>
	 */
	public static function cap_occurrences( array $occurrences, $cap = self::OCCURRENCE_META_CAP ) {
		$cap = (int) $cap;

		if ( $cap < 1 ) {
			$cap = self::OCCURRENCE_META_CAP;
		}

		if ( count( $occurrences ) <= $cap ) {
			return array_values( $occurrences );
		}

		return array_slice( array_values( $occurrences ), 0, $cap );
	}

	/**
	 * Whether an array is a list (0..n-1 keys) vs associative map.
	 *
	 * @param array<mixed, mixed> $value Array.
	 * @return bool
	 */
	public static function is_list_array( array $value ) {
		if ( array() === $value ) {
			return true;
		}

		$expected = 0;

		foreach ( $value as $key => $_unused ) {
			if ( $key !== $expected ) {
				return false;
			}
			++$expected;
		}

		return true;
	}

	/**
	 * Length-prefixed string fragment for deterministic encoding.
	 *
	 * @param string $value Value.
	 * @return string
	 */
	private static function length_prefix( $value ) {
		$value = (string) $value;

		return strlen( $value ) . ':' . $value;
	}

	/**
	 * Best-effort redaction of credentials in preview strings.
	 *
	 * @param string $value Preview.
	 * @return string
	 */
	private static function redact_sensitive_preview( $value ) {
		$value = (string) $value;

		// user:pass@host → user:***@host
		$value = preg_replace( '#([a-z][a-z0-9+.-]*://)([^:/\\s@]+):([^@/\\s]+)@#i', '$1$2:***@', $value );

		if ( ! is_string( $value ) ) {
			return '';
		}

		// Common token-ish query params.
		$value = preg_replace(
			'#([?&](?:token|api[_-]?key|access[_-]?token|password|secret|auth)=)([^&\\s"\']+)#i',
			'$1***',
			$value
		);

		return is_string( $value ) ? $value : '';
	}
}
