<?php
/**
 * Presentation layer for WP-Cron findings.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Maps scanner facts (rule IDs, evidence) into UI display strings.
 */
class Choctaw_Wp_Security_Scheduled_Tasks_Presenter {

	/**
	 * Enrich a scanner finding with display fields.
	 *
	 * @param array<string, mixed> $finding Scanner finding.
	 * @return array<string, mixed>
	 */
	public function enrich( array $finding ) {
		$rules    = isset( $finding['rules'] ) && is_array( $finding['rules'] ) ? $finding['rules'] : array();
		$evidence = isset( $finding['evidence'] ) && is_array( $finding['evidence'] ) ? $finding['evidence'] : array();
		$labels   = Choctaw_Wp_Security_Scheduled_Tasks_Patterns::get_category_labels();

		$category_labels = array();
		foreach ( $rules as $rule ) {
			if ( isset( $labels[ $rule ] ) ) {
				$category_labels[] = $labels[ $rule ];
			}
		}

		$finding['category_labels']   = $category_labels;
		$finding['risk_label']        = $this->risk_label( isset( $finding['risk'] ) ? (string) $finding['risk'] : 'info' );
		$finding['confidence_label']  = $this->confidence_label( isset( $finding['confidence'] ) ? (string) $finding['confidence'] : 'low' );
		$finding['source']            = $this->format_source(
			isset( $finding['source_key'] ) ? (string) $finding['source_key'] : 'unknown',
			isset( $finding['source_name'] ) ? (string) $finding['source_name'] : ''
		);
		$finding['schedule_label']    = $this->format_schedule(
			isset( $finding['schedule'] ) ? (string) $finding['schedule'] : '',
			isset( $finding['interval'] ) ? (int) $finding['interval'] : 0
		);
		$finding['next_run_label']    = $this->format_next_run_label( isset( $finding['next_run'] ) ? (int) $finding['next_run'] : 0 );
		$finding['next_run_relative'] = $this->format_next_run_relative(
			isset( $finding['next_run'] ) ? (int) $finding['next_run'] : 0,
			! empty( $finding['is_overdue'] ),
			isset( $finding['overdue_seconds'] ) ? (int) $finding['overdue_seconds'] : 0
		);
		$finding['size_label']        = size_format( isset( $finding['size'] ) ? (int) $finding['size'] : 0 );
		$finding['summary']           = $this->build_summary( $finding, $rules, $evidence );
		$finding['recommendations']   = $this->build_recommendations( $finding, $rules, $evidence );
		$finding['detail']            = implode( "\n", $this->build_detail_lines( $finding, $rules, $evidence ) );
		$finding['excerpt']           = $this->truncate(
			isset( $finding['args_serialized'] ) ? (string) $finding['args_serialized'] : '',
			120
		);
		$args_preview                 = $this->format_args_pretty( isset( $finding['args'] ) ? $finding['args'] : array() );
		$finding['args_pretty']       = $args_preview['contents'];
		$finding['contents_truncated'] = ! empty( $args_preview['truncated'] );

		return $finding;
	}

	/**
	 * @param string $risk Risk key.
	 * @return string
	 */
	private function risk_label( $risk ) {
		$map = array(
			'info'       => __( 'Info', 'choctaw-wp-security' ),
			'review'     => __( 'Review', 'choctaw-wp-security' ),
			'suspicious' => __( 'Suspicious', 'choctaw-wp-security' ),
			'critical'   => __( 'Critical', 'choctaw-wp-security' ),
		);

		return isset( $map[ $risk ] ) ? $map[ $risk ] : $map['info'];
	}

	/**
	 * @param string $confidence Confidence key.
	 * @return string
	 */
	private function confidence_label( $confidence ) {
		$map = array(
			'low'       => __( 'Low', 'choctaw-wp-security' ),
			'medium'    => __( 'Medium', 'choctaw-wp-security' ),
			'high'      => __( 'High', 'choctaw-wp-security' ),
			'very_high' => __( 'Very High', 'choctaw-wp-security' ),
		);

		return isset( $map[ $confidence ] ) ? $map[ $confidence ] : $map['low'];
	}

	/**
	 * @param string $key  Source key.
	 * @param string $name Source name.
	 * @return string
	 */
	private function format_source( $key, $name ) {
		if ( 'core' === $key ) {
			return __( 'WordPress Core', 'choctaw-wp-security' );
		}

		if ( 'plugin' === $key ) {
			return '' !== $name
				? sprintf(
					/* translators: %s: plugin name */
					__( 'Plugin: %s', 'choctaw-wp-security' ),
					$name
				)
				: __( 'Plugin', 'choctaw-wp-security' );
		}

		if ( 'theme' === $key ) {
			return '' !== $name
				? sprintf(
					/* translators: %s: theme name */
					__( 'Theme: %s', 'choctaw-wp-security' ),
					$name
				)
				: __( 'Theme', 'choctaw-wp-security' );
		}

		return __( 'Unknown', 'choctaw-wp-security' );
	}

	/**
	 * @param string $schedule Schedule slug.
	 * @param int    $interval Interval seconds.
	 * @return string
	 */
	private function format_schedule( $schedule, $interval ) {
		if ( '' !== $schedule ) {
			return $schedule;
		}

		if ( $interval > 0 ) {
			return sprintf(
				/* translators: %d: interval seconds */
				__( 'every %d seconds', 'choctaw-wp-security' ),
				$interval
			);
		}

		return __( 'one-time', 'choctaw-wp-security' );
	}

	/**
	 * @param int $timestamp Unix timestamp.
	 * @return string
	 */
	private function format_next_run_label( $timestamp ) {
		if ( $timestamp <= 0 ) {
			return __( 'Unknown', 'choctaw-wp-security' );
		}

		return gmdate( 'Y-m-d H:i:s', $timestamp ) . ' UTC';
	}

	/**
	 * @param int  $timestamp       Unix timestamp.
	 * @param bool $is_overdue      Whether stale/overdue.
	 * @param int  $overdue_seconds Overdue duration.
	 * @return string
	 */
	private function format_next_run_relative( $timestamp, $is_overdue, $overdue_seconds ) {
		if ( $timestamp <= 0 ) {
			return '';
		}

		if ( $is_overdue || $timestamp < time() ) {
			$seconds = $is_overdue ? $overdue_seconds : ( time() - $timestamp );
			return sprintf(
				/* translators: %s: human time difference */
				__( '%s overdue', 'choctaw-wp-security' ),
				human_time_diff( time() - max( 1, $seconds ), time() )
			);
		}

		return sprintf(
			/* translators: %s: human time difference */
			__( 'in %s', 'choctaw-wp-security' ),
			human_time_diff( time(), $timestamp )
		);
	}

	/**
	 * Short list-row detail lines.
	 *
	 * @param array<string, mixed> $finding  Finding.
	 * @param array<int, string>   $rules    Rules.
	 * @param array<string, mixed> $evidence Evidence.
	 * @return array<int, string>
	 */
	private function build_detail_lines( array $finding, array $rules, array $evidence ) {
		$lines = array();

		if ( in_array( 'suspicious_arguments', $rules, true ) ) {
			$pattern = isset( $evidence['matched_arg_pattern'] ) ? (string) $evidence['matched_arg_pattern'] : '';
			if ( 'external_url' === $pattern ) {
				$lines[] = __( 'Contains external URL', 'choctaw-wp-security' );
			} elseif ( '' !== $pattern ) {
				$lines[] = sprintf(
					/* translators: %s: matched pattern key */
					__( 'Suspicious arguments: %s', 'choctaw-wp-security' ),
					$pattern
				);
			} else {
				$lines[] = __( 'Suspicious arguments detected', 'choctaw-wp-security' );
			}
		}

		if ( in_array( 'unusual_frequency', $rules, true ) ) {
			$interval = isset( $evidence['interval'] ) ? (int) $evidence['interval'] : (int) $finding['interval'];
			if ( $interval > 0 ) {
				$lines[] = sprintf(
					/* translators: %d: seconds */
					__( 'Runs every %d seconds', 'choctaw-wp-security' ),
					$interval
				);
			} else {
				$lines[] = __( 'Unusually frequent schedule', 'choctaw-wp-security' );
			}
		}

		if ( in_array( 'unregistered_handler', $rules, true ) ) {
			$lines[] = __( 'No active handler found', 'choctaw-wp-security' );
		}

		if ( in_array( 'missing_source', $rules, true ) ) {
			$lines[] = __( 'Plugin not installed or inactive', 'choctaw-wp-security' );
		}

		if ( in_array( 'stale_task', $rules, true ) ) {
			$lines[] = __( 'Next run is overdue', 'choctaw-wp-security' );
		}

		if ( in_array( 'duplicate_task', $rules, true ) ) {
			$count   = isset( $evidence['duplicate_count'] ) ? (int) $evidence['duplicate_count'] : 0;
			$lines[] = sprintf(
				/* translators: %d: duplicate count */
				__( '%d duplicate events', 'choctaw-wp-security' ),
				max( 1, $count )
			);
		}

		if ( in_array( 'unknown_hook', $rules, true ) && empty( $lines ) ) {
			$lines[] = __( 'Unknown hook', 'choctaw-wp-security' );
		}

		if ( in_array( 'suspicious_hook_name', $rules, true ) ) {
			$lines[] = __( 'Suspicious hook name', 'choctaw-wp-security' );
		}

		if ( empty( $lines ) && ! empty( $finding['is_recognized'] ) ) {
			$lines[] = __( 'Recognized maintenance event', 'choctaw-wp-security' );
		}

		return $lines;
	}

	/**
	 * Summary bullets for the expandable panel.
	 *
	 * @param array<string, mixed> $finding  Finding.
	 * @param array<int, string>   $rules    Rules.
	 * @param array<string, mixed> $evidence Evidence.
	 * @return array<int, string>
	 */
	private function build_summary( array $finding, array $rules, array $evidence ) {
		$hook     = isset( $finding['hook'] ) ? (string) $finding['hook'] : '';
		$summary  = array();
		$ctx      = $this->placeholder_context( $finding, $evidence );

		foreach ( $rules as $rule ) {
			$line = $this->summary_for_rule( $rule, $ctx );
			if ( '' !== $line ) {
				$summary[] = $line;
			}
		}

		if ( empty( $summary ) ) {
			$summary[] = sprintf(
				/* translators: %s: hook name */
				__( 'Scheduled task for hook %s.', 'choctaw-wp-security' ),
				$hook
			);
		}

		return array_values( array_unique( $summary ) );
	}

	/**
	 * Recommendations for the expandable panel.
	 *
	 * Emits one focused primary recommendation, plus at most one secondary tip
	 * for higher-risk findings. Avoids stacking generic per-rule advice.
	 *
	 * @param array<string, mixed> $finding  Finding.
	 * @param array<int, string>   $rules    Rules.
	 * @param array<string, mixed> $evidence Evidence.
	 * @return array<int, string>
	 */
	private function build_recommendations( array $finding, array $rules, array $evidence ) {
		$ctx         = $this->placeholder_context( $finding, $evidence );
		$source_key  = isset( $finding['source_key'] ) ? (string) $finding['source_key'] : 'unknown';
		$risk        = isset( $finding['risk'] ) ? (string) $finding['risk'] : 'info';
		$strongest   = $this->strongest_review_rule( $rules );
		$trusted     = in_array( $source_key, array( 'core', 'plugin', 'theme' ), true );
		$primary     = $this->primary_recommendation( $strongest, $trusted, $source_key, $ctx, $finding );
		$secondary   = $this->secondary_recommendation( $strongest, $trusted, $risk, $ctx );

		$out = array();
		if ( '' !== $primary ) {
			$out[] = $primary;
		}
		if ( '' !== $secondary && $secondary !== $primary ) {
			$out[] = $secondary;
		}

		return $out;
	}

	/**
	 * Review-rule priority (strongest first).
	 *
	 * @return array<int, string>
	 */
	private function review_rule_priority() {
		return array(
			'suspicious_arguments',
			'suspicious_hook_name',
			'unknown_hook',
			'unregistered_handler',
			'missing_source',
			'duplicate_task',
			'stale_task',
			'unusual_frequency',
		);
	}

	/**
	 * Pick the strongest matched review rule.
	 *
	 * @param array<int, string> $rules Rules.
	 * @return string
	 */
	private function strongest_review_rule( array $rules ) {
		foreach ( $this->review_rule_priority() as $rule ) {
			if ( in_array( $rule, $rules, true ) ) {
				return $rule;
			}
		}

		if ( in_array( 'recognized_plugin_theme', $rules, true ) ) {
			return 'recognized_plugin_theme';
		}

		if ( in_array( 'recognized_core', $rules, true ) ) {
			return 'recognized_core';
		}

		return '';
	}

	/**
	 * Whether this hook is a commonly legitimate high-frequency runner.
	 *
	 * @param string $hook Hook name.
	 * @return bool
	 */
	private function is_known_benign_high_frequency_hook( $hook ) {
		$known = array(
			'action_scheduler_run_queue',
		);

		return in_array( (string) $hook, $known, true );
	}

	/**
	 * Build the primary recommendation for this finding.
	 *
	 * @param string               $strongest Strongest review rule.
	 * @param bool                 $trusted   Whether source is core/plugin/theme.
	 * @param string               $source_key Source key.
	 * @param array<string, string> $ctx       Placeholders.
	 * @param array<string, mixed> $finding   Finding.
	 * @return string
	 */
	private function primary_recommendation( $strongest, $trusted, $source_key, array $ctx, array $finding ) {
		$hook = isset( $finding['hook'] ) ? (string) $finding['hook'] : '';

		if ( 'suspicious_arguments' === $strongest ) {
			return strtr(
				__(
					'Inspect the Raw Arguments for {hook}. Unusual URLs, tokens, or encoded data deserve immediate investigation of the owning code before you remove only the cron row.',
					'choctaw-wp-security'
				),
				$ctx
			);
		}

		if ( 'suspicious_hook_name' === $strongest ) {
			return strtr(
				__(
					'Search the site files and database for {hook}. If no trusted plugin or theme owns this name, treat it as high priority for manual review.',
					'choctaw-wp-security'
				),
				$ctx
			);
		}

		if ( 'unknown_hook' === $strongest ) {
			return strtr(
				__(
					'Identify what created {hook} before changing it. Search installed plugins, the active theme, and custom code; if nothing legitimate owns it, treat the event as orphaned or potentially malicious.',
					'choctaw-wp-security'
				),
				$ctx
			);
		}

		if ( 'unregistered_handler' === $strongest || 'missing_source' === $strongest ) {
			return strtr(
				__(
					'{hook} has no active handler during this scan{missing_clause}. Confirm whether the related plugin or theme was deactivated or removed; leftover cron rows are common after incomplete uninstalls.',
					'choctaw-wp-security'
				),
				array_merge(
					$ctx,
					array(
						'{missing_clause}' => ( 'missing_source' === $strongest && '' !== $ctx['{plugin_or_theme}'] && __( 'Unknown', 'choctaw-wp-security' ) !== $ctx['{plugin_or_theme}'] )
							? sprintf(
								/* translators: %s: plugin or theme name hint */
								__( ' and appears related to %s', 'choctaw-wp-security' ),
								$ctx['{plugin_or_theme}']
							)
							: '',
					)
				)
			);
		}

		if ( 'unusual_frequency' === $strongest && $trusted ) {
			if ( $this->is_known_benign_high_frequency_hook( $hook ) ) {
				return strtr(
					__(
						'{source} registered {hook} on an aggressive schedule ({schedule}). Queue runners like this are often intentional. Leave the task in place unless you have a separate performance concern with that plugin.',
						'choctaw-wp-security'
					),
					$ctx
				);
			}

			return strtr(
				__(
					'{source} registered {hook} on an aggressive schedule ({schedule}). For a known active plugin or theme, frequent schedules are often intentional. Leave it alone unless that software is unwanted or causing performance problems.',
					'choctaw-wp-security'
				),
				$ctx
			);
		}

		if ( 'unusual_frequency' === $strongest ) {
			return strtr(
				__(
					'{hook} runs unusually often ({schedule}), and its source could not be confirmed. Identify the owning code before leaving a high-frequency task in place.',
					'choctaw-wp-security'
				),
				$ctx
			);
		}

		if ( 'stale_task' === $strongest && $trusted ) {
			return strtr(
				__(
					'{hook} from {source} is overdue. Check whether WP-Cron is disabled or failing site-wide before changing this individual task.',
					'choctaw-wp-security'
				),
				$ctx
			);
		}

		if ( 'stale_task' === $strongest ) {
			return strtr(
				__(
					'{hook} is significantly overdue and its source is unclear. Verify WP-Cron is running, then identify whether this leftover event still belongs to installed software.',
					'choctaw-wp-security'
				),
				$ctx
			);
		}

		if ( 'duplicate_task' === $strongest && $trusted ) {
			return strtr(
				__(
					'Multiple stored events exist for {hook} from {source}. Check that plugin or theme for repeated scheduling bugs before removing extras.',
					'choctaw-wp-security'
				),
				$ctx
			);
		}

		if ( 'duplicate_task' === $strongest ) {
			return strtr(
				__(
					'Multiple stored events exist for {hook}. Identify the owner first, then keep only the intended schedule if duplicates are confirmed.',
					'choctaw-wp-security'
				),
				$ctx
			);
		}

		if ( 'core' === $source_key || 'recognized_core' === $strongest ) {
			return __(
				'Do not delete this WordPress core WP-Cron event; removing it can break updates, cleanup, or other core maintenance.',
				'choctaw-wp-security'
			);
		}

		if ( $trusted || 'recognized_plugin_theme' === $strongest ) {
			return strtr(
				__(
					'{hook} belongs to {source}. No security action is needed unless another stronger warning also applies.',
					'choctaw-wp-security'
				),
				$ctx
			);
		}

		return strtr(
			__(
				'Review {hook} carefully and identify its owner before deleting the cron event.',
				'choctaw-wp-security'
			),
			$ctx
		);
	}

	/**
	 * Optional secondary tip (only for higher-risk / untrusted findings).
	 *
	 * @param string               $strongest Strongest review rule.
	 * @param bool                 $trusted   Whether source is trusted.
	 * @param string               $risk      Risk level.
	 * @param array<string, string> $ctx       Placeholders.
	 * @return string
	 */
	private function secondary_recommendation( $strongest, $trusted, $risk, array $ctx ) {
		$high_risk_rules = array(
			'suspicious_arguments',
			'suspicious_hook_name',
			'unknown_hook',
		);

		if ( in_array( $strongest, $high_risk_rules, true ) || in_array( $risk, array( 'suspicious', 'critical' ), true ) ) {
			return __(
				'Do not delete the cron row alone until you understand what created it; the registering code may recreate the event.',
				'choctaw-wp-security'
			);
		}

		if ( ! $trusted && 'unusual_frequency' === $strongest ) {
			return __(
				'If you cannot identify a trusted owner, treat frequent execution as higher risk and investigate before leaving it enabled.',
				'choctaw-wp-security'
			);
		}

		return '';
	}

	/**
	 * @param array<string, mixed> $finding  Finding.
	 * @param array<string, mixed> $evidence Evidence.
	 * @return array<string, string>
	 */
	private function placeholder_context( array $finding, array $evidence ) {
		$overdue = '';
		if ( ! empty( $finding['is_overdue'] ) && ! empty( $finding['overdue_seconds'] ) ) {
			$overdue = human_time_diff( time() - (int) $finding['overdue_seconds'], time() );
		}

		return array(
			'{hook}'             => isset( $finding['hook'] ) ? (string) $finding['hook'] : '',
			'{schedule}'         => isset( $finding['schedule'] ) && '' !== (string) $finding['schedule']
				? (string) $finding['schedule']
				: __( 'one-time', 'choctaw-wp-security' ),
			'{interval}'         => (string) ( isset( $evidence['interval'] ) ? (int) $evidence['interval'] : (int) ( $finding['interval'] ?? 0 ) ),
			'{next_run}'         => $this->format_next_run_label( isset( $finding['next_run'] ) ? (int) $finding['next_run'] : 0 ),
			'{overdue_for}'      => $overdue,
			'{source}'           => isset( $finding['source'] ) ? (string) $finding['source'] : $this->format_source(
				isset( $finding['source_key'] ) ? (string) $finding['source_key'] : 'unknown',
				isset( $finding['source_name'] ) ? (string) $finding['source_name'] : ''
			),
			'{duplicate_count}'  => (string) ( isset( $evidence['duplicate_count'] ) ? (int) $evidence['duplicate_count'] : 0 ),
			'{matched_pattern}'  => isset( $evidence['matched_arg_pattern'] ) && '' !== (string) $evidence['matched_arg_pattern']
				? (string) $evidence['matched_arg_pattern']
				: ( isset( $evidence['name_heuristic'] ) ? (string) $evidence['name_heuristic'] : '' ),
			'{arg_key}'          => isset( $evidence['arg_key'] ) ? (string) $evidence['arg_key'] : '',
			'{arg_preview}'      => isset( $evidence['arg_preview'] ) ? (string) $evidence['arg_preview'] : '',
			'{plugin_or_theme}'  => isset( $evidence['missing_source_hint'] ) && '' !== (string) $evidence['missing_source_hint']
				? (string) $evidence['missing_source_hint']
				: __( 'Unknown', 'choctaw-wp-security' ),
		);
	}

	/**
	 * @param string               $rule Rule ID.
	 * @param array<string, string> $ctx  Placeholders.
	 * @return string
	 */
	private function summary_for_rule( $rule, array $ctx ) {
		$templates = array(
			'unknown_hook' => __(
				'Hook {hook} is not a recognized WordPress core task and could not be attributed to an active plugin or the active theme.',
				'choctaw-wp-security'
			),
			'unregistered_handler' => __(
				'A scheduled event exists for {hook}, but no handler was registered during this scan. Next run: {next_run}.',
				'choctaw-wp-security'
			),
			'missing_source' => __(
				'This task appears to belong to software that is no longer installed or active ({plugin_or_theme}).',
				'choctaw-wp-security'
			),
			'unusual_frequency' => __(
				'This task is scheduled unusually often ({schedule}, every {interval} seconds).',
				'choctaw-wp-security'
			),
			'stale_task' => __(
				'Next run {next_run} is significantly overdue ({overdue_for}).',
				'choctaw-wp-security'
			),
			'duplicate_task' => __(
				'Found {duplicate_count} stored events for {hook} meeting the duplication threshold.',
				'choctaw-wp-security'
			),
			'suspicious_hook_name' => __(
				'Hook name {hook} matched suspicious naming heuristic {matched_pattern}.',
				'choctaw-wp-security'
			),
			'suspicious_arguments' => __(
				'Arguments matched {matched_pattern} in {arg_key} (preview: {arg_preview}).',
				'choctaw-wp-security'
			),
			'recognized_core' => __(
				'{hook} is a recognized WordPress core WP-Cron event.',
				'choctaw-wp-security'
			),
			'recognized_plugin_theme' => __(
				'{hook} is registered by active software ({source}).',
				'choctaw-wp-security'
			),
		);

		if ( ! isset( $templates[ $rule ] ) ) {
			return '';
		}

		return strtr( $templates[ $rule ], $ctx );
	}

	/**
	 * @param mixed $args Args.
	 * @return string
	 */
	private function format_args_pretty( $args ) {
		if ( empty( $args ) ) {
			return array(
				'contents'  => __( '(no arguments)', 'choctaw-wp-security' ),
				'truncated' => false,
			);
		}

		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_print_r -- intentional for admin display.
		$pretty = print_r( $args, true );

		if ( ! is_string( $pretty ) ) {
			return array(
				'contents'  => '',
				'truncated' => false,
			);
		}

		return Choctaw_Wp_Security_Utils::truncate_report_contents_result( $pretty );
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
}
