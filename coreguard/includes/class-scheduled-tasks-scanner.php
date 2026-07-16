<?php
/**
 * Fact-only WP-Cron scheduled tasks scanner.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Detects and scores WP-Cron events stored in the cron option.
 *
 * Returns structured findings (rules, signals, score, confidence, risk).
 * Does not generate UI copy — use Choctaw_Wp_Security_Scheduled_Tasks_Presenter.
 */
class Choctaw_Wp_Security_Scheduled_Tasks_Scanner {

	/**
	 * Selected options table name.
	 *
	 * @var string
	 */
	private $options_table = '';

	/**
	 * Table discovery helper.
	 *
	 * @var Choctaw_Wp_Security_Options_Table_Discovery
	 */
	private $discovery;

	/**
	 * Cached option_id for the cron row.
	 *
	 * @var int|null
	 */
	private $cron_option_id = null;

	/**
	 * Hook occurrence counts for duplicate detection.
	 *
	 * @var array<string, int>
	 */
	private $hook_counts = array();

	/**
	 * Hook+args hash occurrence counts.
	 *
	 * @var array<string, int>
	 */
	private $hook_args_counts = array();

	/**
	 * @param string $options_table Requested options table name.
	 */
	public function __construct( $options_table = '' ) {
		$this->discovery     = new Choctaw_Wp_Security_Options_Table_Discovery();
		$this->options_table = $this->discovery->resolve_scan_table( $options_table );
	}

	/**
	 * Run the scheduled tasks scan.
	 *
	 * @return array<string, mixed>
	 */
	public function scan() {
		$cron_raw = $this->get_table_option( 'cron', array() );
		$cron     = is_array( $cron_raw ) ? $cron_raw : array();

		$this->cron_option_id = $this->get_option_id_for_name( 'cron' );
		$this->build_duplicate_counts( $cron );

		$findings = array();

		if ( ! is_array( $cron ) || empty( $cron ) ) {
			return $this->build_result( $findings );
		}

		foreach ( $cron as $timestamp => $hooks ) {
			if ( ! is_array( $hooks ) ) {
				continue;
			}

			foreach ( $hooks as $hook => $events ) {
				$hook = (string) $hook;

				if ( '' === $hook || ! is_array( $events ) ) {
					continue;
				}

				foreach ( $events as $event_key => $event ) {
					if ( ! is_array( $event ) ) {
						continue;
					}

					$findings[] = $this->analyze_event( $hook, (int) $timestamp, (string) $event_key, $event );
				}
			}
		}

		return $this->build_result( $findings );
	}

	/**
	 * Build the scan result payload.
	 *
	 * @param array<int, array<string, mixed>> $findings Raw findings.
	 * @return array<string, mixed>
	 */
	private function build_result( array $findings ) {
		$presenter = new Choctaw_Wp_Security_Scheduled_Tasks_Presenter();
		$enriched  = array();

		foreach ( $findings as $finding ) {
			$enriched[] = $presenter->enrich( $finding );
		}

		$summary = array(
			'critical'   => 0,
			'suspicious' => 0,
			'review'     => 0,
			'info'       => 0,
			'total'      => count( $enriched ),
			'flagged'    => 0,
		);

		foreach ( $enriched as $finding ) {
			$risk = isset( $finding['risk'] ) ? (string) $finding['risk'] : 'info';

			if ( isset( $summary[ $risk ] ) ) {
				++$summary[ $risk ];
			}

			if ( empty( $finding['is_recognized'] ) ) {
				++$summary['flagged'];
			}
		}

		return array(
			'success'                    => 0 === ( $summary['critical'] + $summary['suspicious'] ),
			'findings'                   => $enriched,
			'summary'                    => $summary,
			'options_table'              => $this->options_table,
			'wordpress_configured_table' => Choctaw_Wp_Security_Options_Table_Discovery::get_wordpress_configured_table(),
		);
	}

	/**
	 * Pre-count hooks for duplicate detection.
	 *
	 * @param array<mixed, mixed> $cron Cron array.
	 * @return void
	 */
	private function build_duplicate_counts( array $cron ) {
		$this->hook_counts      = array();
		$this->hook_args_counts = array();

		foreach ( $cron as $hooks ) {
			if ( ! is_array( $hooks ) ) {
				continue;
			}

			foreach ( $hooks as $hook => $events ) {
				$hook = (string) $hook;

				if ( '' === $hook || ! is_array( $events ) ) {
					continue;
				}

				foreach ( $events as $event ) {
					if ( ! is_array( $event ) ) {
						continue;
					}

					if ( ! isset( $this->hook_counts[ $hook ] ) ) {
						$this->hook_counts[ $hook ] = 0;
					}
					++$this->hook_counts[ $hook ];

					$args_hash = $this->args_hash( isset( $event['args'] ) ? $event['args'] : array() );
					$key       = $hook . '|' . $args_hash;

					if ( ! isset( $this->hook_args_counts[ $key ] ) ) {
						$this->hook_args_counts[ $key ] = 0;
					}
					++$this->hook_args_counts[ $key ];
				}
			}
		}
	}

	/**
	 * Analyze one stored cron event.
	 *
	 * @param string               $hook      Hook name.
	 * @param int                  $timestamp Next run timestamp.
	 * @param string               $event_key Event array key.
	 * @param array<string, mixed> $event     Event payload.
	 * @return array<string, mixed>
	 */
	private function analyze_event( $hook, $timestamp, $event_key, array $event ) {
		$args            = isset( $event['args'] ) && is_array( $event['args'] ) ? $event['args'] : array();
		$schedule        = isset( $event['schedule'] ) ? (string) $event['schedule'] : '';
		$interval        = isset( $event['interval'] ) ? (int) $event['interval'] : 0;
		$args_serialized = maybe_serialize( $args );
		$event_serialized = maybe_serialize( $event );
		$now             = time();
		$is_overdue      = $timestamp > 0 && $timestamp < ( $now - (int) Choctaw_Wp_Security_Scheduled_Tasks_Patterns::STALE_TASK_SECONDS );
		$overdue_seconds = $is_overdue ? ( $now - $timestamp ) : 0;

		$handler_registered = (bool) has_action( $hook );
		$source             = $this->resolve_source( $hook, $handler_registered );
		$is_core            = ( 'core' === $source['key'] );

		$rules    = array();
		$signals  = array();
		$evidence = array(
			'matched_arg_pattern' => '',
			'arg_key'             => '',
			'arg_preview'         => '',
			'interval'            => $interval,
			'duplicate_count'     => 0,
			'name_heuristic'      => '',
			'missing_source_hint' => '',
			'event_key'           => $event_key,
		);

		if ( $is_core ) {
			$rules[] = 'recognized_core';
		} elseif ( 'plugin' === $source['key'] || 'theme' === $source['key'] ) {
			$rules[] = 'recognized_plugin_theme';
		}

		// Core hooks often register handlers only when wp-cron runs, not during
		// an admin scan request. Do not flag them as unregistered/missing.
		if ( ! $is_core && ! $handler_registered ) {
			$rules[] = 'unregistered_handler';
		}

		// Known core hooks must never be classified as Unknown Hook.
		if ( ! $is_core && 'unknown' === $source['key'] ) {
			$rules[] = 'unknown_hook';
		}

		$missing_hint = '';
		if ( ! $is_core && ! $handler_registered ) {
			$missing_hint = $this->detect_missing_source_hint( $hook );
			if ( '' !== $missing_hint ) {
				$rules[]                         = 'missing_source';
				$evidence['missing_source_hint'] = $missing_hint;
			}
		}

		if ( $this->is_unusual_frequency( $schedule, $interval ) ) {
			$rules[] = 'unusual_frequency';
		}

		if ( $is_overdue ) {
			$rules[] = 'stale_task';
		}

		$dup_count = $this->get_duplicate_count( $hook, $args, $is_core );
		if ( $dup_count > 0 ) {
			$rules[]                     = 'duplicate_task';
			$evidence['duplicate_count'] = $dup_count;
		}

		$name_heuristic = $this->detect_suspicious_hook_name( $hook );
		if ( '' !== $name_heuristic ) {
			$rules[]                     = 'suspicious_hook_name';
			$evidence['name_heuristic']  = $name_heuristic;
		}

		$arg_scan = $this->scan_arguments( $args, $args_serialized . $event_serialized );
		if ( ! empty( $arg_scan['signals'] ) ) {
			$rules[]                          = 'suspicious_arguments';
			$signals                          = $arg_scan['signals'];
			$evidence['matched_arg_pattern']  = $arg_scan['matched_pattern'];
			$evidence['arg_key']              = $arg_scan['arg_key'];
			$evidence['arg_preview']          = $arg_scan['arg_preview'];
		}

		$rules   = array_values( array_unique( $rules ) );
		$signals = array_values( array_unique( $signals ) );

		$is_recognized = $this->is_recognized_only( $rules );
		$score         = $this->calculate_score( $rules, $signals );
		$confidence    = $this->calculate_confidence( $rules, $signals, $score );
		$risk          = Choctaw_Wp_Security_Scheduled_Tasks_Patterns::risk_from_score( $score, $is_recognized );

		$fingerprint = Choctaw_Wp_Security_Finding_Status_Store::fingerprint_cron_finding( $hook, $args );

		return array(
			'id'                 => $fingerprint,
			'fingerprint'        => $fingerprint,
			'hook'               => $hook,
			'schedule'           => $schedule,
			'interval'           => $interval,
			'next_run'           => $timestamp,
			'is_overdue'         => $is_overdue,
			'overdue_seconds'    => $overdue_seconds,
			'source_key'         => $source['key'],
			'source_name'        => $source['name'],
			'handler_registered' => (bool) $handler_registered,
			'size'               => strlen( $event_serialized ),
			'option_id'          => (int) $this->cron_option_id,
			'args'               => $args,
			'args_serialized'    => is_string( $args_serialized ) ? $args_serialized : '',
			'rules'              => $rules,
			'signals'            => $signals,
			'evidence'           => $evidence,
			'score'              => $score,
			'confidence'         => $confidence,
			'risk'               => $risk,
			'is_recognized'      => $is_recognized,
		);
	}

	/**
	 * Whether findings only contain recognized rules.
	 *
	 * @param array<int, string> $rules Rule IDs.
	 * @return bool
	 */
	private function is_recognized_only( array $rules ) {
		if ( empty( $rules ) ) {
			return false;
		}

		foreach ( $rules as $rule ) {
			if ( ! in_array( $rule, array( 'recognized_core', 'recognized_plugin_theme' ), true ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Calculate weighted score.
	 *
	 * @param array<int, string> $rules   Rule IDs.
	 * @param array<int, string> $signals Signal IDs.
	 * @return int
	 */
	private function calculate_score( array $rules, array $signals ) {
		$weights = Choctaw_Wp_Security_Scheduled_Tasks_Patterns::get_weights();
		$score   = 0;

		foreach ( $rules as $rule ) {
			if ( in_array( $rule, array( 'recognized_core', 'recognized_plugin_theme', 'suspicious_arguments' ), true ) ) {
				continue;
			}

			if ( isset( $weights[ $rule ] ) ) {
				$score += (int) $weights[ $rule ];
			}
		}

		foreach ( $signals as $signal ) {
			if ( isset( $weights[ $signal ] ) ) {
				$score += (int) $weights[ $signal ];
			}
		}

		return $score;
	}

	/**
	 * Calculate confidence from evidence composition.
	 *
	 * @param array<int, string> $rules   Rule IDs.
	 * @param array<int, string> $signals Signal IDs.
	 * @param int                $score   Weighted score.
	 * @return string
	 */
	private function calculate_confidence( array $rules, array $signals, $score ) {
		// Recognized-only inventory: confidence is certainty of the benign classification.
		if ( $this->is_recognized_only( $rules ) ) {
			if ( in_array( 'recognized_core', $rules, true ) ) {
				return 'very_high';
			}

			return 'high';
		}

		$strong         = Choctaw_Wp_Security_Scheduled_Tasks_Patterns::get_strong_signals();
		$review_ids     = Choctaw_Wp_Security_Scheduled_Tasks_Patterns::get_review_rule_ids();
		$strong_count   = count( array_intersect( $signals, $strong ) );
		$review_rules   = array_values( array_intersect( $rules, $review_ids ) );
		$review_count   = count( $review_rules );
		$score          = (int) $score;

		if ( $strong_count >= 2 || ( $score >= 100 && $strong_count >= 1 ) ) {
			return 'very_high';
		}

		if ( $score >= 80 || $review_count >= 3 || ( $strong_count >= 1 && $review_count >= 2 ) ) {
			return 'high';
		}

		if ( $score >= 40 || $review_count >= 2 ) {
			return 'medium';
		}

		return 'low';
	}

	/**
	 * Whether a hook is on the static WordPress core cron allowlist.
	 *
	 * @param string $hook Hook name.
	 * @return bool
	 */
	private function is_allowlisted_core_hook( $hook ) {
		return in_array( $hook, Choctaw_Wp_Security_Scheduled_Tasks_Patterns::get_core_hooks(), true );
	}

	/**
	 * Resolve source attribution (practical, not exhaustive).
	 *
	 * Core wins when the hook is allowlisted or a registered callback resolves
	 * under wp-includes / wp-admin/includes.
	 *
	 * @param string $hook               Hook name.
	 * @param bool   $handler_registered Whether a handler exists.
	 * @return array{key: string, name: string}
	 */
	private function resolve_source( $hook, $handler_registered ) {
		if ( $this->is_allowlisted_core_hook( $hook ) ) {
			return array(
				'key'  => 'core',
				'name' => '',
			);
		}

		if ( ! $handler_registered ) {
			return array(
				'key'  => 'unknown',
				'name' => '',
			);
		}

		$attributed = $this->attribute_handler( $hook );

		if ( is_array( $attributed ) ) {
			return $attributed;
		}

		return array(
			'key'  => 'unknown',
			'name' => '',
		);
	}

	/**
	 * Lightweight callback attribution via Reflection when practical.
	 *
	 * @param string $hook Hook name.
	 * @return array{key: string, name: string}|null
	 */
	private function attribute_handler( $hook ) {
		global $wp_filter;

		if ( empty( $wp_filter[ $hook ] ) || ! is_object( $wp_filter[ $hook ] ) ) {
			return null;
		}

		$callbacks = $wp_filter[ $hook ]->callbacks;

		if ( ! is_array( $callbacks ) || empty( $callbacks ) ) {
			return null;
		}

		ksort( $callbacks );
		$priority_group = reset( $callbacks );

		if ( ! is_array( $priority_group ) || empty( $priority_group ) ) {
			return null;
		}

		$entry = reset( $priority_group );

		if ( ! is_array( $entry ) || empty( $entry['function'] ) ) {
			return null;
		}

		$file = $this->callback_file( $entry['function'] );

		if ( '' === $file ) {
			return null;
		}

		$file = wp_normalize_path( $file );

		if ( $this->is_wordpress_core_file( $file ) ) {
			return array(
				'key'  => 'core',
				'name' => '',
			);
		}

		$plugin_dir = wp_normalize_path( WP_PLUGIN_DIR );
		if ( 0 === strpos( $file, $plugin_dir . '/' ) ) {
			$relative = substr( $file, strlen( $plugin_dir ) + 1 );
			$slug     = strtok( $relative, '/' );
			$name     = $this->plugin_name_from_slug( $slug );

			return array(
				'key'  => 'plugin',
				'name' => '' !== $name ? $name : $slug,
			);
		}

		$theme = wp_get_theme();
		if ( $theme->exists() ) {
			$stylesheet_dir = wp_normalize_path( $theme->get_stylesheet_directory() );
			$template_dir   = wp_normalize_path( $theme->get_template_directory() );

			if ( ( '' !== $stylesheet_dir && 0 === strpos( $file, $stylesheet_dir . '/' ) )
				|| ( '' !== $template_dir && 0 === strpos( $file, $template_dir . '/' ) )
			) {
				return array(
					'key'  => 'theme',
					'name' => (string) $theme->get( 'Name' ),
				);
			}
		}

		return null;
	}

	/**
	 * Whether a callback file path belongs to WordPress core.
	 *
	 * @param string $file Normalized absolute file path.
	 * @return bool
	 */
	private function is_wordpress_core_file( $file ) {
		$includes = wp_normalize_path( ABSPATH . WPINC );
		$admin    = wp_normalize_path( ABSPATH . 'wp-admin/includes' );

		if ( 0 === strpos( $file, $includes . '/' ) || $file === $includes ) {
			return true;
		}

		if ( 0 === strpos( $file, $admin . '/' ) || $file === $admin ) {
			return true;
		}

		return false;
	}

	/**
	 * Resolve a callable to a file path when practical.
	 *
	 * @param mixed $callable Callback.
	 * @return string
	 */
	private function callback_file( $callable ) {
		try {
			if ( is_string( $callable ) && function_exists( $callable ) ) {
				$ref = new ReflectionFunction( $callable );
				$file = $ref->getFileName();
				return is_string( $file ) ? $file : '';
			}

			if ( is_array( $callable ) && isset( $callable[0], $callable[1] ) ) {
				if ( is_object( $callable[0] ) ) {
					$ref = new ReflectionMethod( $callable[0], (string) $callable[1] );
				} elseif ( is_string( $callable[0] ) ) {
					$ref = new ReflectionMethod( $callable[0], (string) $callable[1] );
				} else {
					return '';
				}

				$file = $ref->getFileName();
				return is_string( $file ) ? $file : '';
			}
		} catch ( Exception $e ) {
			return '';
		} catch ( Error $e ) {
			return '';
		}

		return '';
	}

	/**
	 * Get a plugin display name from its directory slug.
	 *
	 * @param string $slug Plugin directory slug.
	 * @return string
	 */
	private function plugin_name_from_slug( $slug ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$plugins = get_plugins();

		foreach ( $plugins as $file => $data ) {
			if ( 0 === strpos( $file, $slug . '/' ) || $file === $slug . '.php' ) {
				return isset( $data['Name'] ) ? (string) $data['Name'] : '';
			}
		}

		return '';
	}

	/**
	 * Detect a missing-source hint from hook prefix vs inactive plugins.
	 *
	 * @param string $hook Hook name.
	 * @return string
	 */
	private function detect_missing_source_hint( $hook ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$active  = (array) get_option( 'active_plugins', array() );
		$plugins = get_plugins();
		$parts   = preg_split( '/[_-]/', strtolower( $hook ) );

		if ( ! is_array( $parts ) || empty( $parts ) ) {
			return '';
		}

		$prefix = $parts[0];

		if ( strlen( $prefix ) < 3 ) {
			return '';
		}

		foreach ( $plugins as $file => $data ) {
			$slug = dirname( $file );
			if ( '.' === $slug ) {
				$slug = basename( $file, '.php' );
			}

			$slug_l = strtolower( (string) $slug );
			$name   = isset( $data['Name'] ) ? (string) $data['Name'] : $slug;

			if ( false === strpos( $slug_l, $prefix ) ) {
				continue;
			}

			if ( in_array( $file, $active, true ) ) {
				continue;
			}

			return $name;
		}

		return '';
	}

	/**
	 * @param string $schedule Schedule name.
	 * @param int    $interval Interval seconds.
	 * @return bool
	 */
	private function is_unusual_frequency( $schedule, $interval ) {
		$threshold = (int) Choctaw_Wp_Security_Scheduled_Tasks_Patterns::UNUSUAL_FREQUENCY_SECONDS;

		if ( $interval > 0 && $interval <= $threshold ) {
			return true;
		}

		$schedule_l = strtolower( $schedule );

		if ( '' === $schedule_l ) {
			return false;
		}

		if ( preg_match( '/every[_-]?\d*[_-]?min|minute|every[_-]?minute/', $schedule_l ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Count duplicates when thresholds are met.
	 *
	 * For Recognized Core hooks, only identical hook + args hashes count as
	 * duplicates. Same-hook / different-args core events (e.g. upgrader cleanup
	 * per attachment ID) are expected and must not be flagged.
	 *
	 * @param string $hook    Hook name.
	 * @param array  $args    Args.
	 * @param bool   $is_core Whether the hook is Recognized Core.
	 * @return int Duplicate count when threshold met, else 0.
	 */
	private function get_duplicate_count( $hook, array $args, $is_core = false ) {
		$args_key   = $hook . '|' . $this->args_hash( $args );
		$args_count = isset( $this->hook_args_counts[ $args_key ] ) ? (int) $this->hook_args_counts[ $args_key ] : 0;

		if ( $args_count >= (int) Choctaw_Wp_Security_Scheduled_Tasks_Patterns::DUPLICATE_HOOK_ARGS_THRESHOLD ) {
			return $args_count;
		}

		if ( $is_core ) {
			return 0;
		}

		$hook_count = isset( $this->hook_counts[ $hook ] ) ? (int) $this->hook_counts[ $hook ] : 0;

		if ( $hook_count >= (int) Choctaw_Wp_Security_Scheduled_Tasks_Patterns::DUPLICATE_HOOK_THRESHOLD ) {
			return $hook_count;
		}

		return 0;
	}

	/**
	 * @param mixed $args Args value.
	 * @return string
	 */
	private function args_hash( $args ) {
		return md5( maybe_serialize( $args ) );
	}

	/**
	 * Detect suspicious hook name heuristics.
	 *
	 * @param string $hook Hook name.
	 * @return string Matched heuristic key, or empty.
	 */
	private function detect_suspicious_hook_name( $hook ) {
		$hook_l = strtolower( $hook );

		foreach ( Choctaw_Wp_Security_Scheduled_Tasks_Patterns::get_suspicious_hook_terms() as $term ) {
			if ( false !== strpos( $hook_l, $term ) ) {
				return $term;
			}
		}

		if ( strlen( $hook ) >= 24 ) {
			$alnum = preg_replace( '/[^a-z0-9]/i', '', $hook );
			if ( is_string( $alnum ) && strlen( $alnum ) >= 20 ) {
				$vowels = preg_match_all( '/[aeiou]/i', $alnum );
				if ( $vowels < 2 ) {
					return 'low_vowel_obfuscated';
				}
			}
		}

		if ( preg_match( '/^[a-z0-9]{16,}$/i', $hook ) && false === strpos( $hook, '_' ) ) {
			return 'random_charset';
		}

		return '';
	}

	/**
	 * Scan event arguments for suspicious signals.
	 *
	 * @param array  $args       Args array.
	 * @param string $serialized Serialized blob to scan.
	 * @return array{signals: array<int, string>, matched_pattern: string, arg_key: string, arg_preview: string}
	 */
	private function scan_arguments( array $args, $serialized ) {
		$result = array(
			'signals'          => array(),
			'matched_pattern'  => '',
			'arg_key'          => '',
			'arg_preview'      => '',
		);

		$flat = $this->flatten_args( $args );

		foreach ( $flat as $key => $value ) {
			$value_s = (string) $value;
			$hit     = $this->match_arg_signals( $value_s );

			if ( empty( $hit ) ) {
				continue;
			}

			$result['signals']         = array_merge( $result['signals'], $hit );
			$result['matched_pattern'] = $hit[0];
			$result['arg_key']         = (string) $key;
			$result['arg_preview']     = $this->truncate( $value_s, 120 );
			break;
		}

		if ( empty( $result['signals'] ) ) {
			$hit = $this->match_arg_signals( (string) $serialized );
			if ( ! empty( $hit ) ) {
				$result['signals']         = $hit;
				$result['matched_pattern'] = $hit[0];
				$result['arg_preview']     = $this->truncate( (string) $serialized, 120 );
			}
		}

		$result['signals'] = array_values( array_unique( $result['signals'] ) );

		return $result;
	}

	/**
	 * @param string $value Value to inspect.
	 * @return array<int, string>
	 */
	private function match_arg_signals( $value ) {
		$signals = array();
		$lower   = strtolower( $value );

		foreach ( array( 'eval(', 'base64_decode(', 'gzinflate(', 'phar://' ) as $needle ) {
			if ( false !== strpos( $lower, $needle ) ) {
				$signals[] = 'eval_family';
				break;
			}
		}

		if ( preg_match( '#https?://[^\s\'"<>]+#i', $value ) ) {
			$signals[] = 'external_url';
		}

		if ( preg_match( '/\b(?:\d{1,3}\.){3}\d{1,3}\b/', $value ) ) {
			$signals[] = 'ip_address';
		}

		if ( preg_match( '/[A-Za-z0-9+\/]{40,}={0,2}/', $value ) ) {
			$signals[] = 'base64_payload';
		}

		foreach ( array( '<?php', '$_get', '$_post', '$_request' ) as $needle ) {
			if ( false !== strpos( $lower, $needle ) ) {
				$signals[] = 'php_fragment';
				break;
			}
		}

		foreach ( array( '<script', 'document.', 'function(' ) as $needle ) {
			if ( false !== strpos( $lower, $needle ) ) {
				$signals[] = 'js_fragment';
				break;
			}
		}

		foreach ( array( 'curl ', 'wget ', '/bin/', 'cmd.exe' ) as $needle ) {
			if ( false !== strpos( $lower, $needle ) ) {
				$signals[] = 'shell_fragment';
				break;
			}
		}

		return array_values( array_unique( $signals ) );
	}

	/**
	 * Flatten nested args into key => scalar string map.
	 *
	 * @param mixed  $value Args value.
	 * @param string $prefix Key prefix.
	 * @return array<string, string>
	 */
	private function flatten_args( $value, $prefix = '' ) {
		$out = array();

		if ( is_array( $value ) ) {
			foreach ( $value as $key => $child ) {
				$child_key = '' === $prefix ? (string) $key : $prefix . '.' . $key;
				$out       = array_merge( $out, $this->flatten_args( $child, $child_key ) );
			}
			return $out;
		}

		if ( is_object( $value ) ) {
			return $out;
		}

		$key       = '' === $prefix ? '0' : $prefix;
		$out[ $key ] = (string) $value;

		return $out;
	}

	/**
	 * @param string $value Value.
	 * @param int    $max   Max length.
	 * @return string
	 */
	private function truncate( $value, $max ) {
		$value = (string) $value;

		if ( strlen( $value ) <= $max ) {
			return $value;
		}

		return substr( $value, 0, $max - 3 ) . '...';
	}

	/**
	 * Quoted options table SQL fragment.
	 *
	 * @return string
	 */
	private function get_options_table_sql() {
		return $this->discovery->quote_table_name( $this->options_table );
	}

	/**
	 * Read an option from the selected options table.
	 *
	 * @param string $option_name Option name.
	 * @param mixed  $default     Default.
	 * @return mixed
	 */
	private function get_table_option( $option_name, $default = false ) {
		global $wpdb;

		$value = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT option_value FROM ' . $this->get_options_table_sql() . ' WHERE option_name = %s LIMIT 1',
				$option_name
			)
		);

		if ( null === $value ) {
			return $default;
		}

		return maybe_unserialize( $value );
	}

	/**
	 * @param string $option_name Option name.
	 * @return int
	 */
	private function get_option_id_for_name( $option_name ) {
		global $wpdb;

		$id = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT option_id FROM ' . $this->get_options_table_sql() . ' WHERE option_name = %s LIMIT 1',
				$option_name
			)
		);

		return $id ? (int) $id : 0;
	}
}
