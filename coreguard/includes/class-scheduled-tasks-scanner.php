<?php
/**
 * WP-Cron scheduled tasks scanner (Sassh Findings producer).
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Detects WP-Cron events and records problem-rule Findings.
 *
 * Recognized-only events are exposed as non-dismissible report inventory.
 */
class Choctaw_Wp_Security_Scheduled_Tasks_Scanner {

	/**
	 * Problem rule ids (kebab) that become Findings.
	 *
	 * @var array<int, string>
	 */
	const PROBLEM_RULES = array(
		Sassh_Findings_Service::RULE_UNKNOWN_HOOK,
		Sassh_Findings_Service::RULE_UNREGISTERED_HANDLER,
		Sassh_Findings_Service::RULE_MISSING_SOURCE,
		Sassh_Findings_Service::RULE_UNUSUAL_FREQUENCY,
		Sassh_Findings_Service::RULE_STALE_TASK,
		Sassh_Findings_Service::RULE_DUPLICATE_TASK,
		Sassh_Findings_Service::RULE_SUSPICIOUS_HOOK_NAME,
		Sassh_Findings_Service::RULE_SUSPICIOUS_ARGUMENTS,
	);

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
	 * Fingerprint failures during the run.
	 *
	 * @var int
	 */
	private $hash_failures = 0;

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
		Sassh_Findings_Schema::maybe_upgrade();

		$this->hash_failures = 0;

		$blog_id = Sassh_Option_Key_Normalizer::map_options_table_to_registered_site_blog_id( $this->options_table );

		if ( is_wp_error( $blog_id ) ) {
			return $this->build_rejection_report( $blog_id );
		}

		$blog_id = (int) $blog_id;

		$cron_raw = $this->get_table_option( 'cron', array() );

		if ( ! is_array( $cron_raw ) ) {
			return $this->run_failed_corrupt_cron( $blog_id );
		}

		$cron = $cron_raw;

		$this->cron_option_id = $this->get_option_id_for_name( 'cron' );
		$this->build_duplicate_counts( $cron );

		$physical    = $this->collect_physical_events( $cron );
		$inventory   = array();
		$agg_buckets = array();

		foreach ( $physical as $event ) {
			if ( ! empty( $event['unhashable'] ) ) {
				++$this->hash_failures;
				continue;
			}

			$problem_rules = isset( $event['problem_rules'] ) && is_array( $event['problem_rules'] )
				? $event['problem_rules']
				: array();

			if ( empty( $problem_rules ) ) {
				$inventory[] = $this->build_inventory_item( $event, $blog_id );
				continue;
			}

			foreach ( $problem_rules as $rule_id ) {
				$this->aggregate_problem_event( $agg_buckets, $event, (string) $rule_id );
			}
		}

		$scope_key    = Sassh_Findings_Service::scheduled_tasks_scope_key( $this->options_table );
		$service      = new Sassh_Findings_Service();
		$execution_id = $service->begin_scanner_execution(
			Sassh_Findings_Service::SCANNER_SCHEDULED_TASKS,
			array(
				'scope_key'  => $scope_key,
				'run_type'   => 'individual',
				'run_source' => 'wordpress_admin',
				'meta'       => array(
					'options_table'              => $this->options_table,
					'wordpress_configured_table' => Choctaw_Wp_Security_Options_Table_Discovery::get_wordpress_configured_table(),
					'blog_id'                    => $blog_id,
					'inventory_count'            => count( $inventory ),
				),
			)
		);

		$observations = $this->build_observations_from_buckets( $agg_buckets, $blog_id );

		$service->record_observations( $execution_id, $observations );
		$service->update_execution_meta(
			$execution_id,
			array(
				'recognized_inventory' => $inventory,
				'inventory_count'      => count( $inventory ),
			)
		);

		$errors            = array();
		$completion_status = 'success';

		if ( $this->hash_failures > 0 ) {
			$completion_status = 'partial';
			$errors[]          = __( 'One or more cron events could not be fingerprinted. Previously detected findings were not cleared.', 'choctaw-wp-security' );
		}

		$ok = $service->finalize_scanner_execution( $execution_id, $completion_status );

		if ( 'success' === $completion_status && ! $ok ) {
			$completion_status = 'failed';
			$errors[]          = __( 'The scan could not be finalized.', 'choctaw-wp-security' );
		}

		return $this->build_report_from_findings(
			$service,
			$execution_id,
			array(
				'completion_status' => $completion_status,
				'scan_incomplete'   => 'success' !== $completion_status,
				'errors'            => $errors,
				'inventory'         => $inventory,
				'blog_id'           => $blog_id,
			)
		);
	}

	/**
	 * Get the selected options table name.
	 *
	 * @return string
	 */
	public function get_options_table() {
		return $this->options_table;
	}

	/**
	 * Failed run when cron option is corrupt (not an array).
	 *
	 * @param int $blog_id Blog id.
	 * @return array<string, mixed>
	 */
	private function run_failed_corrupt_cron( $blog_id ) {
		$scope_key    = Sassh_Findings_Service::scheduled_tasks_scope_key( $this->options_table );
		$service      = new Sassh_Findings_Service();
		$execution_id = $service->begin_scanner_execution(
			Sassh_Findings_Service::SCANNER_SCHEDULED_TASKS,
			array(
				'scope_key'  => $scope_key,
				'run_type'   => 'individual',
				'run_source' => 'wordpress_admin',
				'meta'       => array(
					'options_table'              => $this->options_table,
					'wordpress_configured_table' => Choctaw_Wp_Security_Options_Table_Discovery::get_wordpress_configured_table(),
					'blog_id'                    => (int) $blog_id,
				),
			)
		);

		$service->finalize_scanner_execution( $execution_id, 'failed' );

		return $this->build_report_from_findings(
			$service,
			$execution_id,
			array(
				'completion_status' => 'failed',
				'scan_incomplete'   => true,
				'errors'            => array(
					__( 'The cron option could not be read as an array. Previously detected findings were not cleared.', 'choctaw-wp-security' ),
				),
				'inventory'         => array(),
				'blog_id'           => (int) $blog_id,
			)
		);
	}

	/**
	 * Rejection payload — no Findings execution.
	 *
	 * @param WP_Error $error Mapping error.
	 * @return array<string, mixed>
	 */
	private function build_rejection_report( WP_Error $error ) {
		$message = $error->get_error_message();

		if ( '' === $message ) {
			$message = __( 'The selected options table is not associated with a registered WordPress site.', 'choctaw-wp-security' );
		}

		return array(
			'success'                    => false,
			'rejected'                   => true,
			'findings_backend'           => 'sassh',
			'errors'                     => array( $message ),
			'findings'                   => array(),
			'inventory'                  => array(),
			'summary'                    => array(
				'critical'   => 0,
				'warning'    => 0,
				'suspicious' => 0,
				'safe'       => 0,
				'info'       => 0,
				'total'      => 0,
				'flagged'    => 0,
			),
			'options_table'              => $this->options_table,
			'wordpress_configured_table' => Choctaw_Wp_Security_Options_Table_Discovery::get_wordpress_configured_table(),
			'scan_incomplete'            => false,
			'coverage_complete'          => false,
			'absence_reconciled'         => false,
			'completion_status'          => 'rejected',
			'confirmed_this_run'         => 0,
			'scanned_at'                 => time(),
		);
	}

	/**
	 * Walk the cron array into physical event records.
	 *
	 * @param array<mixed, mixed> $cron Cron option.
	 * @return array<int, array<string, mixed>>
	 */
	private function collect_physical_events( array $cron ) {
		$out = array();

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

					$out[] = $this->analyze_physical_event( $hook, (int) $timestamp, (string) $event_key, $event );
				}
			}
		}

		return $out;
	}

	/**
	 * Analyze one stored cron event into an intermediate record.
	 *
	 * @param string               $hook      Hook name.
	 * @param int                  $timestamp Next run timestamp.
	 * @param string               $event_key Event array key.
	 * @param array<string, mixed> $event     Event payload.
	 * @return array<string, mixed>
	 */
	private function analyze_physical_event( $hook, $timestamp, $event_key, array $event ) {
		$args     = isset( $event['args'] ) && is_array( $event['args'] ) ? $event['args'] : array();
		$schedule = isset( $event['schedule'] ) ? (string) $event['schedule'] : '';
		$interval = isset( $event['interval'] ) ? (int) $event['interval'] : 0;
		$now      = time();
		$is_overdue = $timestamp > 0 && $timestamp < ( $now - (int) Choctaw_Wp_Security_Scheduled_Tasks_Patterns::STALE_TASK_SECONDS );
		$overdue_seconds = $is_overdue ? ( $now - $timestamp ) : 0;

		$object_key = Sassh_Cron_Event_Key_Normalizer::object_key( $hook, $args );

		if ( is_wp_error( $object_key ) ) {
			return array(
				'unhashable' => true,
				'hook'       => $hook,
				'timestamp'  => $timestamp,
				'event_key'  => $event_key,
			);
		}

		$handler_registered = (bool) has_action( $hook );
		$source             = $this->resolve_source( $hook, $handler_registered );
		$is_core            = ( 'core' === $source['key'] );

		$legacy_rules = array();
		$signals      = array();
		$evidence     = array(
			'matched_arg_pattern' => '',
			'arg_key'             => '',
			'arg_preview'         => '',
			'interval'            => $interval,
			'duplicate_count'     => 0,
			'name_heuristic'      => '',
			'missing_source_hint' => '',
			'event_key'           => $event_key,
			'duplicate_family'    => '',
		);

		if ( $is_core ) {
			$legacy_rules[] = 'recognized_core';
		} elseif ( 'plugin' === $source['key'] || 'theme' === $source['key'] ) {
			$legacy_rules[] = 'recognized_plugin_theme';
		}

		if ( ! $is_core && ! $handler_registered ) {
			$legacy_rules[] = 'unregistered_handler';
		}

		if ( ! $is_core && 'unknown' === $source['key'] ) {
			$legacy_rules[] = 'unknown_hook';
		}

		$missing_hint = '';
		if ( ! $is_core && ! $handler_registered ) {
			$missing_hint = $this->detect_missing_source_hint( $hook );
			if ( '' !== $missing_hint ) {
				$legacy_rules[]                  = 'missing_source';
				$evidence['missing_source_hint'] = $missing_hint;
			}
		}

		if ( $this->is_unusual_frequency( $schedule, $interval ) ) {
			$legacy_rules[] = 'unusual_frequency';
		}

		if ( $is_overdue ) {
			$legacy_rules[] = 'stale_task';
		}

		$dup = $this->get_duplicate_info( $hook, $args, $is_core );
		if ( $dup['count'] > 0 ) {
			$legacy_rules[]              = 'duplicate_task';
			$evidence['duplicate_count'] = $dup['count'];
			$evidence['duplicate_family'] = $dup['family'];
		}

		$name_heuristic = $this->detect_suspicious_hook_name( $hook );
		if ( '' !== $name_heuristic ) {
			$legacy_rules[]                    = 'suspicious_hook_name';
			$evidence['name_heuristic']        = $name_heuristic;
		}

		$args_serialized  = maybe_serialize( $args );
		$event_serialized = maybe_serialize( $event );
		$arg_scan         = $this->scan_arguments( $args, ( is_string( $args_serialized ) ? $args_serialized : '' ) . ( is_string( $event_serialized ) ? $event_serialized : '' ) );

		if ( ! empty( $arg_scan['signals'] ) ) {
			$legacy_rules[]                 = 'suspicious_arguments';
			$signals                        = $arg_scan['signals'];
			$evidence['matched_arg_pattern'] = $arg_scan['matched_pattern'];
			$evidence['arg_key']             = $arg_scan['arg_key'];
			$preview                         = Sassh_Cron_Event_Key_Normalizer::sanitize_args_preview(
				'' !== $arg_scan['arg_preview'] ? $arg_scan['arg_preview'] : $args
			);
			$evidence['arg_preview'] = $preview['preview'];
		}

		$legacy_rules = array_values( array_unique( $legacy_rules ) );
		$signals      = array_values( array_unique( $signals ) );

		$problem_rules = array();
		foreach ( $legacy_rules as $legacy ) {
			if ( in_array( $legacy, array( 'recognized_core', 'recognized_plugin_theme' ), true ) ) {
				continue;
			}
			$problem_rules[] = str_replace( '_', '-', $legacy );
		}
		$problem_rules = array_values( array_unique( $problem_rules ) );

		$args_preview = Sassh_Cron_Event_Key_Normalizer::sanitize_args_preview( $args );

		return array(
			'unhashable'         => false,
			'hook'               => $hook,
			'object_key'         => (string) $object_key,
			'args'               => $args,
			'schedule'           => $schedule,
			'interval'           => $interval,
			'timestamp'          => $timestamp,
			'event_key'          => $event_key,
			'is_overdue'         => $is_overdue,
			'overdue_seconds'    => $overdue_seconds,
			'source_key'         => $source['key'],
			'source_name'        => $source['name'],
			'handler_registered' => $handler_registered,
			'is_core'            => $is_core,
			'legacy_rules'       => $legacy_rules,
			'problem_rules'      => $problem_rules,
			'signals'            => $signals,
			'evidence'           => $evidence,
			'args_preview'       => $args_preview['preview'],
			'args_truncated'     => ! empty( $args_preview['truncated'] ),
			'size'               => is_string( $event_serialized ) ? strlen( $event_serialized ) : 0,
			'option_id'          => (int) $this->cron_option_id,
		);
	}

	/**
	 * Aggregate a physical event into a (object_key, rule_id) bucket.
	 *
	 * @param array<string, array<string, mixed>> $buckets Bucket map (by ref).
	 * @param array<string, mixed>                $event   Physical event.
	 * @param string                              $rule_id Kebab rule id.
	 * @return void
	 */
	private function aggregate_problem_event( array &$buckets, array $event, $rule_id ) {
		$object_key = (string) $event['object_key'];
		$key        = $object_key . "\0" . $rule_id;

		if ( ! isset( $buckets[ $key ] ) ) {
			$buckets[ $key ] = array(
				'object_key'         => $object_key,
				'rule_id'            => $rule_id,
				'hook'               => (string) $event['hook'],
				'args'               => $event['args'],
				'source_key'         => (string) $event['source_key'],
				'source_name'        => (string) $event['source_name'],
				'handler_registered' => ! empty( $event['handler_registered'] ),
				'is_core'            => ! empty( $event['is_core'] ),
				'signals'            => array(),
				'name_heuristics'    => array(),
				'missing_hints'      => array(),
				'duplicate_family'   => '',
				'duplicate_count'    => 0,
				'overdue'            => false,
				'schedule_pairs'     => array(),
				'occurrences'        => array(),
				'occurrence_count'   => 0,
				'overdue_count'      => 0,
			);
		}

		$bucket = &$buckets[ $key ];

		++$bucket['occurrence_count'];

		if ( ! empty( $event['is_overdue'] ) ) {
			$bucket['overdue'] = true;
			++$bucket['overdue_count'];
		}

		$bucket['schedule_pairs'][] = array(
			'schedule' => (string) $event['schedule'],
			'interval' => (int) $event['interval'],
		);

		if ( ! empty( $event['signals'] ) && is_array( $event['signals'] ) ) {
			$bucket['signals'] = array_values( array_unique( array_merge( $bucket['signals'], $event['signals'] ) ) );
		}

		$evidence = isset( $event['evidence'] ) && is_array( $event['evidence'] ) ? $event['evidence'] : array();

		if ( ! empty( $evidence['name_heuristic'] ) ) {
			$bucket['name_heuristics'][] = (string) $evidence['name_heuristic'];
			$bucket['name_heuristics']   = array_values( array_unique( $bucket['name_heuristics'] ) );
		}

		if ( ! empty( $evidence['missing_source_hint'] ) ) {
			$bucket['missing_hints'][] = (string) $evidence['missing_source_hint'];
			$bucket['missing_hints']   = array_values( array_unique( $bucket['missing_hints'] ) );
		}

		if ( Sassh_Findings_Service::RULE_DUPLICATE_TASK === $rule_id ) {
			$family = isset( $evidence['duplicate_family'] ) ? (string) $evidence['duplicate_family'] : '';
			$count  = isset( $evidence['duplicate_count'] ) ? (int) $evidence['duplicate_count'] : 0;

			// Prefer hook_args family when present; otherwise keep hook_name.
			if ( 'hook_args' === $family || '' === $bucket['duplicate_family'] ) {
				$bucket['duplicate_family'] = $family;
			}
			if ( $count > (int) $bucket['duplicate_count'] ) {
				$bucket['duplicate_count'] = $count;
			}
		}

		$bucket['occurrences'][] = array(
			'timestamp'       => (int) $event['timestamp'],
			'schedule'        => (string) $event['schedule'],
			'interval'        => (int) $event['interval'],
			'is_overdue'      => ! empty( $event['is_overdue'] ),
			'event_key'       => (string) $event['event_key'],
			'overdue_seconds' => isset( $event['overdue_seconds'] ) ? (int) $event['overdue_seconds'] : 0,
		);

		unset( $bucket );
	}

	/**
	 * Build Findings observations from aggregation buckets.
	 *
	 * @param array<string, array<string, mixed>> $buckets Buckets.
	 * @param int                                 $blog_id Blog id.
	 * @return array<int, array<string, mixed>>
	 */
	private function build_observations_from_buckets( array $buckets, $blog_id ) {
		ksort( $buckets, SORT_STRING );

		$observations = array();
		$presenter    = new Choctaw_Wp_Security_Scheduled_Tasks_Presenter();

		foreach ( $buckets as $bucket ) {
			$obs = $this->bucket_to_observation( $bucket, $blog_id, $presenter );

			if ( null !== $obs ) {
				$observations[] = $obs;
			}
		}

		return $observations;
	}

	/**
	 * Convert one aggregation bucket to an observation.
	 *
	 * @param array<string, mixed>                         $bucket    Bucket.
	 * @param int                                          $blog_id   Blog id.
	 * @param Choctaw_Wp_Security_Scheduled_Tasks_Presenter $presenter Presenter.
	 * @return array<string, mixed>|null
	 */
	private function bucket_to_observation( array $bucket, $blog_id, $presenter ) {
		$rule_id    = (string) $bucket['rule_id'];
		$hook       = (string) $bucket['hook'];
		$object_key = (string) $bucket['object_key'];
		$args       = $bucket['args'];

		$object_fp = Sassh_Cron_Event_Key_Normalizer::object_fingerprint(
			$hook,
			$args,
			isset( $bucket['schedule_pairs'] ) && is_array( $bucket['schedule_pairs'] ) ? $bucket['schedule_pairs'] : array()
		);

		if ( is_wp_error( $object_fp ) ) {
			++$this->hash_failures;
			return null;
		}

		$signals = isset( $bucket['signals'] ) && is_array( $bucket['signals'] ) ? $bucket['signals'] : array();
		sort( $signals, SORT_STRING );

		$risk_level = Sassh_Findings_Service::scheduled_tasks_risk_level(
			$rule_id,
			array( 'signals' => $signals )
		);

		$content_fp = $this->finding_fingerprint_for_rule( $bucket, $rule_id, $signals );

		if ( '' === $content_fp ) {
			++$this->hash_failures;
			return null;
		}

		$legacy_rule = str_replace( '-', '_', $rule_id );
		$evidence    = array(
			'interval'            => $this->primary_interval( $bucket ),
			'duplicate_count'     => (int) $bucket['duplicate_count'],
			'duplicate_family'    => (string) $bucket['duplicate_family'],
			'name_heuristic'      => ! empty( $bucket['name_heuristics'][0] ) ? (string) $bucket['name_heuristics'][0] : '',
			'missing_source_hint' => ! empty( $bucket['missing_hints'][0] ) ? (string) $bucket['missing_hints'][0] : '',
			'matched_arg_pattern' => ! empty( $signals[0] ) ? (string) $signals[0] : '',
			'event_key'           => '',
		);

		$args_preview = Sassh_Cron_Event_Key_Normalizer::sanitize_args_preview( $args );
		$occurrences  = Sassh_Cron_Event_Key_Normalizer::cap_occurrences(
			isset( $bucket['occurrences'] ) && is_array( $bucket['occurrences'] ) ? $bucket['occurrences'] : array()
		);

		$next_run = 0;
		foreach ( $occurrences as $occ ) {
			$ts = isset( $occ['timestamp'] ) ? (int) $occ['timestamp'] : 0;
			if ( $ts > 0 && ( 0 === $next_run || $ts < $next_run ) ) {
				$next_run = $ts;
			}
		}

		$display = array(
			'hook'               => $hook,
			'schedule'           => $this->primary_schedule( $bucket ),
			'interval'           => $this->primary_interval( $bucket ),
			'next_run'           => $next_run,
			'is_overdue'         => ! empty( $bucket['overdue'] ),
			'overdue_seconds'    => 0,
			'source_key'         => (string) $bucket['source_key'],
			'source_name'        => (string) $bucket['source_name'],
			'handler_registered' => ! empty( $bucket['handler_registered'] ),
			'args'               => $args,
			'args_serialized'    => '',
			'rules'              => array( $legacy_rule ),
			'signals'            => $signals,
			'evidence'           => $evidence,
			'risk'               => $risk_level,
			'is_recognized'      => false,
			'size'               => 0,
		);

		if ( ! empty( $bucket['overdue'] ) && $next_run > 0 ) {
			$display['overdue_seconds'] = max( 0, time() - $next_run );
		}

		$enriched = $presenter->enrich( $display );

		$category_labels = Choctaw_Wp_Security_Scheduled_Tasks_Patterns::get_category_labels();
		$category_label  = isset( $category_labels[ $legacy_rule ] ) ? $category_labels[ $legacy_rule ] : $rule_id;

		$summary = isset( $enriched['summary'] ) && is_array( $enriched['summary'] ) ? $enriched['summary'] : array();
		$recs    = isset( $enriched['recommendations'] ) && is_array( $enriched['recommendations'] ) ? $enriched['recommendations'] : array();

		$metadata = array(
			'hook'                 => $hook,
			'schedule'             => $display['schedule'],
			'interval'             => $display['interval'],
			'next_run'             => $next_run,
			'is_overdue'           => ! empty( $bucket['overdue'] ),
			'source_key'           => (string) $bucket['source_key'],
			'source_name'          => (string) $bucket['source_name'],
			'handler_registered'   => ! empty( $bucket['handler_registered'] ),
			'category_label'       => $category_label,
			'category_labels'      => array( $category_label ),
			'signals'              => $signals,
			'occurrence_count'     => (int) $bucket['occurrence_count'],
			'overdue_count'        => (int) $bucket['overdue_count'],
			'occurrences'          => $occurrences,
			'args_preview'         => $args_preview['preview'],
			'contents_truncated'   => ! empty( $args_preview['truncated'] ),
			'why_seeing_this'      => $summary,
			'how_to_proceed'       => $recs,
			'recommendations'      => $recs,
			'summary'              => $summary,
			'schedule_label'       => isset( $enriched['schedule_label'] ) ? $enriched['schedule_label'] : '',
			'next_run_label'       => isset( $enriched['next_run_label'] ) ? $enriched['next_run_label'] : '',
			'next_run_relative'    => isset( $enriched['next_run_relative'] ) ? $enriched['next_run_relative'] : '',
			'source'               => isset( $enriched['source'] ) ? $enriched['source'] : '',
			'options_table'        => $this->options_table,
			'option_id'            => (int) $this->cron_option_id,
			'duplicate_family'     => (string) $bucket['duplicate_family'],
			'duplicate_count'      => (int) $bucket['duplicate_count'],
			'name_heuristic'       => $evidence['name_heuristic'],
			'missing_source_hint'  => $evidence['missing_source_hint'],
		);

		if ( Sassh_Findings_Service::RULE_DUPLICATE_TASK === $rule_id && 'hook_name' === $bucket['duplicate_family'] ) {
			$metadata['hook_wide_count']           = (int) $bucket['duplicate_count'];
			$metadata['duplicate_threshold_family'] = 'hook_name';
		} elseif ( Sassh_Findings_Service::RULE_DUPLICATE_TASK === $rule_id ) {
			$metadata['duplicate_threshold_family'] = 'hook_args';
		}

		$description = ! empty( $summary[0] ) ? (string) $summary[0] : sprintf(
			/* translators: %s: hook name */
			__( 'Scheduled task issue for hook %s.', 'choctaw-wp-security' ),
			$hook
		);

		return array(
			'scanner_id'           => Sassh_Findings_Service::SCANNER_SCHEDULED_TASKS,
			'rule_id'              => $rule_id,
			'object_type'          => Sassh_Object_Type_Registry::TYPE_CRON_EVENT,
			'object_key'           => $object_key,
			'blog_id'              => (int) $blog_id,
			'risk_level'           => $risk_level,
			'sassh_classification' => Sassh_Findings_Service::default_classification( $risk_level ),
			'content_fingerprint'  => $content_fp,
			'object_fingerprint'   => $object_fp,
			'title'                => $hook,
			'description'          => $description,
			'metadata'             => $metadata,
		);
	}

	/**
	 * Finding fingerprint for a rule bucket.
	 *
	 * @param array<string, mixed> $bucket  Bucket.
	 * @param string               $rule_id Rule id.
	 * @param array<int, string>   $signals Signals.
	 * @return string sha256:hex or empty on failure.
	 */
	private function finding_fingerprint_for_rule( array $bucket, $rule_id, array $signals ) {
		$hook       = (string) $bucket['hook'];
		$args_dig   = Sassh_Cron_Event_Key_Normalizer::args_digest( $bucket['args'] );
		$source_key = (string) $bucket['source_key'];
		$handler    = ! empty( $bucket['handler_registered'] ) ? '1' : '0';

		if ( '' === $args_dig ) {
			return '';
		}

		switch ( $rule_id ) {
			case Sassh_Findings_Service::RULE_UNKNOWN_HOOK:
			case Sassh_Findings_Service::RULE_UNREGISTERED_HANDLER:
			case Sassh_Findings_Service::RULE_MISSING_SOURCE:
				$hint = ! empty( $bucket['missing_hints'][0] ) ? (string) $bucket['missing_hints'][0] : '';
				$payload = $hook . "\n" . $source_key . "\n" . $handler . "\n" . $hint;
				break;

			case Sassh_Findings_Service::RULE_UNUSUAL_FREQUENCY:
				$payload = $hook . "\n" . Sassh_Cron_Event_Key_Normalizer::encode_schedule_interval_set(
					isset( $bucket['schedule_pairs'] ) && is_array( $bucket['schedule_pairs'] ) ? $bucket['schedule_pairs'] : array()
				);
				break;

			case Sassh_Findings_Service::RULE_STALE_TASK:
				$overdue = ! empty( $bucket['overdue'] ) ? '1' : '0';
				$payload = $hook . "\n" . $args_dig . "\n" . $overdue;
				break;

			case Sassh_Findings_Service::RULE_DUPLICATE_TASK:
				$family  = (string) $bucket['duplicate_family'];
				if ( '' === $family ) {
					$family = 'hook_args';
				}
				$payload = $hook . "\n" . $args_dig . "\n" . $family;
				break;

			case Sassh_Findings_Service::RULE_SUSPICIOUS_HOOK_NAME:
				$heuristics = isset( $bucket['name_heuristics'] ) && is_array( $bucket['name_heuristics'] )
					? $bucket['name_heuristics']
					: array();
				sort( $heuristics, SORT_STRING );
				$payload = $hook . "\n" . implode( ',', $heuristics );
				break;

			case Sassh_Findings_Service::RULE_SUSPICIOUS_ARGUMENTS:
				$canonical = Sassh_Cron_Event_Key_Normalizer::canonicalize( $bucket['args'] );
				if ( null === $canonical ) {
					return '';
				}
				$payload = Sassh_Cron_Event_Key_Normalizer::encode_canonical( $canonical ) . "\n" . implode( ',', $signals );
				break;

			default:
				$payload = $hook . "\n" . $args_dig . "\n" . $rule_id;
				break;
		}

		return Sassh_Findings_Service::content_fingerprint_from_string( $payload );
	}

	/**
	 * @param array<string, mixed> $bucket Bucket.
	 * @return string
	 */
	private function primary_schedule( array $bucket ) {
		$pairs = isset( $bucket['schedule_pairs'] ) && is_array( $bucket['schedule_pairs'] ) ? $bucket['schedule_pairs'] : array();
		$encoded = Sassh_Cron_Event_Key_Normalizer::encode_schedule_interval_set( $pairs );

		if ( '' === $encoded ) {
			return '';
		}

		$first = explode( "\n", $encoded );
		$line  = isset( $first[0] ) ? $first[0] : '';
		$pos   = strrpos( $line, ':' );

		if ( false === $pos ) {
			return '';
		}

		// length-prefixed schedule before final :interval
		$before_interval = substr( $line, 0, $pos );
		$colon           = strpos( $before_interval, ':' );

		if ( false === $colon ) {
			return '';
		}

		return substr( $before_interval, $colon + 1 );
	}

	/**
	 * @param array<string, mixed> $bucket Bucket.
	 * @return int
	 */
	private function primary_interval( array $bucket ) {
		$pairs = isset( $bucket['schedule_pairs'] ) && is_array( $bucket['schedule_pairs'] ) ? $bucket['schedule_pairs'] : array();

		if ( empty( $pairs[0]['interval'] ) ) {
			return 0;
		}

		return (int) $pairs[0]['interval'];
	}

	/**
	 * Build a non-Findings inventory row for a recognized-only event.
	 *
	 * @param array<string, mixed> $event   Physical event.
	 * @param int                  $blog_id Blog id.
	 * @return array<string, mixed>
	 */
	private function build_inventory_item( array $event, $blog_id ) {
		$presenter = new Choctaw_Wp_Security_Scheduled_Tasks_Presenter();
		$display   = array(
			'hook'               => (string) $event['hook'],
			'schedule'           => (string) $event['schedule'],
			'interval'           => (int) $event['interval'],
			'next_run'           => (int) $event['timestamp'],
			'is_overdue'         => false,
			'overdue_seconds'    => 0,
			'source_key'         => (string) $event['source_key'],
			'source_name'        => (string) $event['source_name'],
			'handler_registered' => ! empty( $event['handler_registered'] ),
			'args'               => $event['args'],
			'args_serialized'    => '',
			'rules'              => isset( $event['legacy_rules'] ) ? $event['legacy_rules'] : array(),
			'signals'            => array(),
			'evidence'           => array(),
			'risk'               => 'info',
			'is_recognized'      => true,
			'size'               => isset( $event['size'] ) ? (int) $event['size'] : 0,
		);

		$enriched = $presenter->enrich( $display );

		return array(
			'hook'               => (string) $event['hook'],
			'source_key'         => (string) $event['source_key'],
			'source_name'        => (string) $event['source_name'],
			'source'             => isset( $enriched['source'] ) ? $enriched['source'] : '',
			'schedule'           => (string) $event['schedule'],
			'schedule_label'     => isset( $enriched['schedule_label'] ) ? $enriched['schedule_label'] : '',
			'interval'           => (int) $event['interval'],
			'next_run'           => (int) $event['timestamp'],
			'next_run_label'     => isset( $enriched['next_run_label'] ) ? $enriched['next_run_label'] : '',
			'next_run_relative'  => isset( $enriched['next_run_relative'] ) ? $enriched['next_run_relative'] : '',
			'args_preview'       => isset( $event['args_preview'] ) ? (string) $event['args_preview'] : '',
			'contents_truncated' => ! empty( $event['args_truncated'] ),
			'options_table'      => $this->options_table,
			'blog_id'            => (int) $blog_id,
			'is_recognized'      => true,
			'inventory'          => true,
			'risk'               => 'info',
			'risk_level'         => 'info',
			'risk_label'         => __( 'Info', 'choctaw-wp-security' ),
		);
	}

	/**
	 * Build the AJAX/report DTO from Findings + inventory.
	 *
	 * @param Sassh_Findings_Service $service      Service.
	 * @param int                    $execution_id Execution id.
	 * @param array<string, mixed>   $run_meta     Run meta.
	 * @return array<string, mixed>
	 */
	private function build_report_from_findings( Sassh_Findings_Service $service, $execution_id, array $run_meta ) {
		$completion  = isset( $run_meta['completion_status'] ) ? (string) $run_meta['completion_status'] : 'failed';
		$coverage_ok = ( 'success' === $completion );
		$inventory   = isset( $run_meta['inventory'] ) && is_array( $run_meta['inventory'] ) ? $run_meta['inventory'] : array();

		$rows = $service->list_findings(
			array(
				'scanner_id'      => Sassh_Findings_Service::SCANNER_SCHEDULED_TASKS,
				'detection_state' => 'active',
			)
		);

		$findings   = array();
		$critical   = 0;
		$warning    = 0;
		$suspicious = 0;
		$info       = 0;
		$safe       = 0;
		$confirmed  = 0;

		foreach ( $rows as $row ) {
			if ( isset( $row['options_table'] ) && '' !== (string) $row['options_table'] && (string) $row['options_table'] !== $this->options_table ) {
				continue;
			}

			$confirmed_this_run = isset( $row['last_scanner_execution_id'] )
				&& (int) $row['last_scanner_execution_id'] === (int) $execution_id;

			if ( $confirmed_this_run ) {
				++$confirmed;
			}

			$risk = isset( $row['risk_level'] ) ? (string) $row['risk_level'] : 'info';

			switch ( $risk ) {
				case 'critical':
					++$critical;
					break;
				case 'warning':
					++$warning;
					break;
				case 'suspicious':
					++$suspicious;
					break;
				case 'safe':
					++$safe;
					break;
				default:
					++$info;
					break;
			}

			$hook = isset( $row['hook'] ) ? (string) $row['hook'] : (string) $row['object_key'];

			$findings[] = array(
				'id'                  => $row['finding_id'],
				'finding_id'          => $row['finding_id'],
				'fingerprint'         => $row['content_fingerprint'],
				'content_fingerprint' => $row['content_fingerprint'],
				'object_fingerprint'  => $row['object_fingerprint'],
				'rule_id'             => isset( $row['rule_id'] ) ? $row['rule_id'] : '',
				'rules'               => array( isset( $row['rule_id'] ) ? str_replace( '-', '_', (string) $row['rule_id'] ) : '' ),
				'title'               => isset( $row['title'] ) ? $row['title'] : $hook,
				'hook'                => $hook,
				'schedule'            => isset( $row['schedule'] ) ? $row['schedule'] : '',
				'schedule_label'      => isset( $row['schedule_label'] ) ? $row['schedule_label'] : '',
				'interval'            => isset( $row['interval'] ) ? (int) $row['interval'] : 0,
				'next_run'            => isset( $row['next_run'] ) ? (int) $row['next_run'] : 0,
				'next_run_label'      => isset( $row['next_run_label'] ) ? $row['next_run_label'] : '',
				'next_run_relative'   => isset( $row['next_run_relative'] ) ? $row['next_run_relative'] : '',
				'is_overdue'          => ! empty( $row['is_overdue'] ),
				'source_key'          => isset( $row['source_key'] ) ? $row['source_key'] : '',
				'source_name'         => isset( $row['source_name'] ) ? $row['source_name'] : '',
				'source'              => isset( $row['source'] ) ? $row['source'] : '',
				'handler_registered'  => ! empty( $row['handler_registered'] ),
				'category_labels'     => ( isset( $row['category_labels'] ) && is_array( $row['category_labels'] ) ) ? $row['category_labels'] : array(),
				'category_label'      => isset( $row['category_label'] ) ? $row['category_label'] : '',
				'detail'              => isset( $row['description'] ) ? (string) $row['description'] : '',
				'description'         => isset( $row['description'] ) ? (string) $row['description'] : '',
				'summary'             => ( isset( $row['summary'] ) && is_array( $row['summary'] ) ) ? $row['summary'] : array(),
				'recommendations'     => ( isset( $row['recommendations'] ) && is_array( $row['recommendations'] ) ) ? $row['recommendations'] : array(),
				'why_seeing_this'     => ( isset( $row['why_seeing_this'] ) && is_array( $row['why_seeing_this'] ) ) ? $row['why_seeing_this'] : array(),
				'how_to_proceed'      => ( isset( $row['how_to_proceed'] ) && is_array( $row['how_to_proceed'] ) ) ? $row['how_to_proceed'] : array(),
				'args_pretty'         => isset( $row['args_preview'] ) ? (string) $row['args_preview'] : '',
				'excerpt'             => isset( $row['args_preview'] ) ? (string) $row['args_preview'] : '',
				'contents_truncated'  => ! empty( $row['contents_truncated'] ),
				'signals'             => ( isset( $row['signals'] ) && is_array( $row['signals'] ) ) ? $row['signals'] : array(),
				'occurrence_count'    => isset( $row['occurrence_count'] ) ? (int) $row['occurrence_count'] : 1,
				'risk'                => $risk,
				'risk_level'          => $risk,
				'risk_label'          => isset( $row['risk_label'] ) ? $row['risk_label'] : $risk,
				'status'              => $row['effective_status'],
				'status_label'        => $row['status_label'],
				'effective_status'    => $row['effective_status'],
				'options_table'       => isset( $row['options_table'] ) ? $row['options_table'] : $this->options_table,
				'blog_id'             => isset( $row['blog_id'] ) ? (int) $row['blog_id'] : null,
				'first_seen_at'       => $row['first_seen_at'],
				'last_seen_at'        => $row['last_seen_at'],
				'detection_state'     => $row['detection_state'],
				'confirmed_this_run'  => $confirmed_this_run,
				'findings_backend'    => 'sassh',
				'is_recognized'       => false,
			);
		}

		$count   = count( $findings );
		$flagged = $critical + $warning + $suspicious;

		return array(
			'success'                    => $coverage_ok && 0 === $flagged,
			'rejected'                   => false,
			'coverage_complete'          => $coverage_ok,
			'absence_reconciled'         => $coverage_ok,
			'completion_status'          => $completion,
			'scan_incomplete'            => ! empty( $run_meta['scan_incomplete'] ) || ! $coverage_ok,
			'errors'                     => isset( $run_meta['errors'] ) && is_array( $run_meta['errors'] ) ? $run_meta['errors'] : array(),
			'findings'                   => $findings,
			'inventory'                  => $inventory,
			'confirmed_this_run'         => $confirmed,
			'prior_findings_only'        => ! $coverage_ok && $count > 0 && 0 === $confirmed,
			'summary'                    => array(
				'critical'   => $critical,
				'warning'    => $warning,
				'suspicious' => $suspicious,
				'safe'       => $safe,
				'info'       => $info,
				'total'      => $count,
				'flagged'    => $flagged,
				'inventory'  => count( $inventory ),
			),
			'scanned_at'                 => time(),
			'execution_id'               => $execution_id,
			'findings_backend'           => 'sassh',
			'options_table'              => $this->options_table,
			'wordpress_configured_table' => Choctaw_Wp_Security_Options_Table_Discovery::get_wordpress_configured_table(),
			'blog_id'                    => isset( $run_meta['blog_id'] ) ? (int) $run_meta['blog_id'] : null,
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
	 * Duplicate count + threshold family for an event.
	 *
	 * @param string $hook    Hook name.
	 * @param array  $args    Args.
	 * @param bool   $is_core Whether Recognized Core.
	 * @return array{count: int, family: string}
	 */
	private function get_duplicate_info( $hook, array $args, $is_core = false ) {
		$args_key   = $hook . '|' . $this->args_hash( $args );
		$args_count = isset( $this->hook_args_counts[ $args_key ] ) ? (int) $this->hook_args_counts[ $args_key ] : 0;

		if ( $args_count >= (int) Choctaw_Wp_Security_Scheduled_Tasks_Patterns::DUPLICATE_HOOK_ARGS_THRESHOLD ) {
			return array(
				'count'  => $args_count,
				'family' => 'hook_args',
			);
		}

		if ( $is_core ) {
			return array(
				'count'  => 0,
				'family' => '',
			);
		}

		$hook_count = isset( $this->hook_counts[ $hook ] ) ? (int) $this->hook_counts[ $hook ] : 0;

		if ( $hook_count >= (int) Choctaw_Wp_Security_Scheduled_Tasks_Patterns::DUPLICATE_HOOK_THRESHOLD ) {
			return array(
				'count'  => $hook_count,
				'family' => 'hook_name',
			);
		}

		return array(
			'count'  => 0,
			'family' => '',
		);
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
	 * Resolve source attribution.
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
	 * @param mixed $callable Callback.
	 * @return string
	 */
	private function callback_file( $callable ) {
		try {
			if ( is_string( $callable ) && function_exists( $callable ) ) {
				$ref  = new ReflectionFunction( $callable );
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
	 * @param mixed $args Args value.
	 * @return string
	 */
	private function args_hash( $args ) {
		return md5( maybe_serialize( $args ) );
	}

	/**
	 * @param string $hook Hook name.
	 * @return string
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
	 * @param array  $args       Args array.
	 * @param string $serialized Serialized blob to scan.
	 * @return array{signals: array<int, string>, matched_pattern: string, arg_key: string, arg_preview: string}
	 */
	private function scan_arguments( array $args, $serialized ) {
		$result = array(
			'signals'         => array(),
			'matched_pattern' => '',
			'arg_key'         => '',
			'arg_preview'     => '',
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
			$preview                   = Sassh_Cron_Event_Key_Normalizer::sanitize_args_preview( $value_s );
			$result['arg_preview']     = $preview['preview'];
			break;
		}

		if ( empty( $result['signals'] ) ) {
			$hit = $this->match_arg_signals( (string) $serialized );
			if ( ! empty( $hit ) ) {
				$result['signals']         = $hit;
				$result['matched_pattern'] = $hit[0];
				$preview                   = Sassh_Cron_Event_Key_Normalizer::sanitize_args_preview( (string) $serialized );
				$result['arg_preview']     = $preview['preview'];
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
	 * @param mixed  $value  Args value.
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

		$key         = '' === $prefix ? '0' : $prefix;
		$out[ $key ] = (string) $value;

		return $out;
	}

	/**
	 * @return string
	 */
	private function get_options_table_sql() {
		return $this->discovery->quote_table_name( $this->options_table );
	}

	/**
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
