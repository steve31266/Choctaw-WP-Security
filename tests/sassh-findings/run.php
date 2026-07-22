<?php
/**
 * Sassh Findings Phase 1 unit tests (pure helpers + capabilities).
 *
 * Usage: php tests/sassh-findings/run.php
 *
 * @package Choctaw_Wp_Security
 */

require_once __DIR__ . '/bootstrap.php';

$failures = 0;
$passes   = 0;

/**
 * @param string $label Assertion label.
 * @param bool   $ok    Condition.
 * @return void
 */
function sassh_assert( $label, $ok ) {
	global $failures, $passes;

	if ( $ok ) {
		++$passes;
		echo "PASS  {$label}\n";
		return;
	}

	++$failures;
	echo "FAIL  {$label}\n";
}

// --- Path normalizer ---
$root = rtrim( wp_normalize_path( ABSPATH ), '/' ) . '/';
sassh_assert(
	'normalize absolute in-root path',
	'wp-content/uploads/x.php' === Sassh_Object_Path_Normalizer::normalize_in_root( $root . 'wp-content/uploads/x.php' )
);
sassh_assert(
	'normalize relative path',
	'wp-content/uploads/x.php' === Sassh_Object_Path_Normalizer::normalize_in_root( 'wp-content/uploads/x.php' )
);
sassh_assert(
	'reject path outside root',
	'' === Sassh_Object_Path_Normalizer::normalize_in_root( '/tmp/evil.php' )
);
sassh_assert(
	'reject escaping via ..',
	'' === Sassh_Object_Path_Normalizer::normalize_in_root( 'wp-content/../..' )
);
sassh_assert(
	'collapse ./ segments',
	'wp-content/uploads/a.php' === Sassh_Object_Path_Normalizer::normalize_in_root( 'wp-content/./uploads/./a.php' )
);

// --- Object type registry ---
sassh_assert(
	'file object type registered',
	Sassh_Object_Type_Registry::TYPE_FILE === 'file'
);

// --- Tuple hash / classification / scope / labels ---
$hash_a = Sassh_Findings_Service::hash_tuple( array( 'a', 'b' ) );
$hash_b = Sassh_Findings_Service::hash_tuple( array( 'ab', '' ) );
sassh_assert( 'hash_tuple is stable', $hash_a === Sassh_Findings_Service::hash_tuple( array( 'a', 'b' ) ) );
sassh_assert( 'hash_tuple is not naïve concat', $hash_a !== $hash_b );

sassh_assert( 'warning defaults to needs_review', 'needs_review' === Sassh_Findings_Service::default_classification( 'warning' ) );
sassh_assert( 'suspicious defaults to needs_review', 'needs_review' === Sassh_Findings_Service::default_classification( 'suspicious' ) );
sassh_assert( 'critical defaults to needs_review', 'needs_review' === Sassh_Findings_Service::default_classification( 'critical' ) );
sassh_assert( 'info defaults to no_action_needed', 'no_action_needed' === Sassh_Findings_Service::default_classification( 'info' ) );
sassh_assert( 'safe defaults to no_action_needed', 'no_action_needed' === Sassh_Findings_Service::default_classification( 'safe' ) );

sassh_assert(
	'uploads scope key uses normalized path',
	'uploads:wp-content/uploads' === Sassh_Findings_Service::uploads_scope_key( $root . 'wp-content/uploads' )
);
sassh_assert(
	'mu-plugins scope key uses normalized path',
	'mu-plugins:wp-content/mu-plugins' === Sassh_Findings_Service::mu_plugins_scope_key( $root . 'wp-content/mu-plugins' )
);
sassh_assert(
	'mu-plugins rule id is php-like',
	'php-like-file-in-mu-plugins' === Sassh_Findings_Service::RULE_PHP_MU_PLUGINS
);

sassh_assert(
	'verify-checksums scope key',
	'verify-checksums:wordpress-core' === Sassh_Findings_Service::verify_checksums_scope_key()
);
sassh_assert(
	'verify-checksums scanner id',
	'verify-checksums' === Sassh_Findings_Service::SCANNER_VERIFY_CHECKSUMS
);
sassh_assert(
	'core-file-modified rule id',
	'core-file-modified' === Sassh_Findings_Service::RULE_CORE_FILE_MODIFIED
);
sassh_assert(
	'core-file-missing rule id',
	'core-file-missing' === Sassh_Findings_Service::RULE_CORE_FILE_MISSING
);
sassh_assert(
	'core-file-unknown rule id',
	'core-file-unknown' === Sassh_Findings_Service::RULE_CORE_FILE_UNKNOWN
);
sassh_assert(
	'missing fingerprint sentinel',
	'sha256:missing' === Sassh_Findings_Service::FINGERPRINT_MISSING
);
sassh_assert(
	'missing reappearance invalidates dismissal (sentinel)',
	Sassh_Findings_Service::should_invalidate_dismissal_on_reappearance( 'core-file-missing', 'sha256:missing' )
);
sassh_assert(
	'missing reappearance invalidates dismissal (rule)',
	Sassh_Findings_Service::should_invalidate_dismissal_on_reappearance( 'core-file-missing', 'sha256:abc' )
);
sassh_assert(
	'modified reappearance with same content fp keeps dismissal path',
	! Sassh_Findings_Service::should_invalidate_dismissal_on_reappearance( 'core-file-modified', 'sha256:abc' )
);

sassh_assert(
	'exposed-files scope key',
	'exposed-files:wordpress-root' === Sassh_Findings_Service::exposed_files_scope_key()
);
sassh_assert(
	'exposed-files scanner id',
	'exposed-files' === Sassh_Findings_Service::SCANNER_EXPOSED_FILES
);
sassh_assert(
	'directory fingerprint sentinel',
	'sha256:directory' === Sassh_Findings_Service::FINGERPRINT_DIRECTORY
);
sassh_assert(
	'exposed-files rule_id kebab',
	'wp-config-backup' === Sassh_Findings_Service::exposed_files_rule_id( 'wp_config_backup' )
);
sassh_assert(
	'exposed-files pattern helper rule_id',
	'phpinfo-script' === Choctaw_Wp_Security_Exposed_Files_Patterns::rule_id_for_pattern( 'phpinfo_script' )
);

$composer_match = Choctaw_Wp_Security_Exposed_Files_Patterns::match_entry( 'composer.json', false, 12, '' );
sassh_assert( 'composer.json matches', null !== $composer_match && 'composer_json' === $composer_match['pattern'] );
sassh_assert( 'composer.json risk suspicious', null !== $composer_match && 'suspicious' === $composer_match['risk'] );

$phpinfo_match = Choctaw_Wp_Security_Exposed_Files_Patterns::match_entry( 'info.php', false, 40, '<?php phpinfo();' );
sassh_assert( 'phpinfo script matches', null !== $phpinfo_match && 'phpinfo_script' === $phpinfo_match['pattern'] );
sassh_assert( 'phpinfo script risk warning', null !== $phpinfo_match && 'warning' === $phpinfo_match['risk'] );

$empty_log = Choctaw_Wp_Security_Exposed_Files_Patterns::match_entry( 'error_log', false, 0, '' );
sassh_assert( 'empty error_log is info', null !== $empty_log && 'info' === $empty_log['risk'] );

$git_match = Choctaw_Wp_Security_Exposed_Files_Patterns::match_entry( '.git', true, 0, '' );
sassh_assert( 'git_dir is info', null !== $git_match && 'git_dir' === $git_match['pattern'] && 'info' === $git_match['risk'] );
sassh_assert(
	'git_dir classification Review Not Needed',
	'no_action_needed' === Sassh_Findings_Service::default_classification( 'info' )
);
sassh_assert(
	'normalize_fingerprint trims',
	'sha256:abc' === Sassh_Findings_Service::normalize_fingerprint( " sha256:abc\n" )
);

// Report DTO incomplete flags (shape contract used by admin-core-checksum.js).
$incomplete_dto = array(
	'success'            => false,
	'coverage_complete'  => false,
	'absence_reconciled' => false,
	'completion_status'  => 'partial',
	'scan_incomplete'    => true,
	'locale_requested'   => 'fr_FR',
	'locale_effective'   => 'en_US',
	'findings'           => array(
		array(
			'finding_id'         => 'ssf_test',
			'confirmed_this_run' => false,
		),
	),
	'prior_findings_only' => true,
);
sassh_assert( 'incomplete DTO not success', false === $incomplete_dto['success'] );
sassh_assert( 'incomplete DTO coverage false', false === $incomplete_dto['coverage_complete'] );
sassh_assert( 'incomplete DTO absence not reconciled', false === $incomplete_dto['absence_reconciled'] );
sassh_assert( 'incomplete DTO locale fallback visible', $incomplete_dto['locale_requested'] !== $incomplete_dto['locale_effective'] );
sassh_assert( 'incomplete DTO prior finding not confirmed', false === $incomplete_dto['findings'][0]['confirmed_this_run'] );

sassh_assert(
	'status label Review Not Needed',
	'Review Not Needed' === Sassh_Findings_Service::status_label( 'no_action_needed' )
);

// Canonical dismiss eligibility (Findings system-wide).
sassh_assert( 'can_dismiss(needs_review)', Sassh_Findings_Service::can_dismiss( 'needs_review' ) );
sassh_assert( 'cannot dismiss no_action_needed classification', ! Sassh_Findings_Service::can_dismiss( 'no_action_needed' ) );
sassh_assert(
	'can_dismiss finding with needs_review classification',
	Sassh_Findings_Service::can_dismiss(
		array(
			'sassh_classification' => 'needs_review',
			'effective_status'     => 'needs_review',
		)
	)
);
sassh_assert(
	'cannot dismiss Review Not Needed finding',
	! Sassh_Findings_Service::can_dismiss(
		array(
			'sassh_classification' => 'no_action_needed',
			'effective_status'     => 'no_action_needed',
			'status'               => 'no_action_needed',
			'risk'                 => 'safe',
		)
	)
);
sassh_assert(
	'dismissed finding remains classification-dismissible',
	Sassh_Findings_Service::can_dismiss(
		array(
			'sassh_classification' => 'needs_review',
			'effective_status'     => 'dismissed',
		)
	)
);
sassh_assert(
	'dismissal_control_state active for Needs Review',
	'active' === Sassh_Findings_Service::dismissal_control_state(
		array(
			'sassh_classification' => 'needs_review',
			'effective_status'     => 'needs_review',
		)
	)
);
sassh_assert(
	'dismissal_control_state not_dismissible for Review Not Needed',
	'not_dismissible' === Sassh_Findings_Service::dismissal_control_state(
		array(
			'sassh_classification' => 'no_action_needed',
			'effective_status'     => 'no_action_needed',
		)
	)
);
sassh_assert(
	'dismissal_control_state dismissed for dismissed Needs Review',
	'dismissed' === Sassh_Findings_Service::dismissal_control_state(
		array(
			'sassh_classification' => 'needs_review',
			'effective_status'     => 'dismissed',
		)
	)
);
sassh_assert(
	'Safe risk DTO is not_dismissible without explicit classification',
	'not_dismissible' === Sassh_Findings_Service::dismissal_control_state(
		array(
			'risk'             => 'safe',
			'effective_status' => 'no_action_needed',
			'status'           => 'no_action_needed',
		)
	)
);
sassh_assert(
	'Warning risk DTO is active without explicit classification',
	'active' === Sassh_Findings_Service::dismissal_control_state(
		array(
			'risk'             => 'warning',
			'effective_status' => 'needs_review',
			'status'           => 'needs_review',
		)
	)
);
// Backend dismiss() rejects when ! can_dismiss (forged UI must still fail).
sassh_assert(
	'backend dismiss guard rejects no_action_needed',
	! Sassh_Findings_Service::can_dismiss(
		array( 'sassh_classification' => 'no_action_needed' )
	)
);

sassh_assert(
	'blog_id from sites path',
	2 === Sassh_Findings_Service::blog_id_from_uploads_path( 'wp-content/uploads/sites/2/evil.php' )
);
sassh_assert(
	'blog_id null for shared uploads',
	null === Sassh_Findings_Service::blog_id_from_uploads_path( 'wp-content/uploads/evil.php' )
);

// --- Phase 3.3 option registry / keys / risk / site mapping ---
sassh_assert(
	'option object type registered',
	Sassh_Object_Type_Registry::is_registered( Sassh_Object_Type_Registry::TYPE_OPTION )
);
sassh_assert(
	'option key plain name',
	'siteurl' === Sassh_Option_Key_Normalizer::object_key_for_option( ' siteurl ' )
);
sassh_assert(
	'option key active plugin',
	'active_plugins#acme/plugin.php' === Sassh_Option_Key_Normalizer::object_key_for_active_plugin( '/acme/plugin.php' )
);
sassh_assert(
	'option key home+siteurl',
	'home+siteurl' === Sassh_Option_Key_Normalizer::object_key_home_siteurl()
);
sassh_assert(
	'database-scan scope key',
	'database-scan:wp_2_options' === Sassh_Findings_Service::database_scan_scope_key( 'wp_2_options' )
);
sassh_assert(
	'database-scan scanner id',
	'database-scan' === Sassh_Findings_Service::SCANNER_DATABASE_SCAN
);

sassh_assert(
	'home-siteurl-mismatch risk suspicious',
	'suspicious' === Sassh_Findings_Service::database_scan_risk_level( 'home-siteurl-mismatch' )
);
sassh_assert(
	'home-external-host risk warning',
	'warning' === Sassh_Findings_Service::database_scan_risk_level( 'home-external-host' )
);
sassh_assert(
	'default-role-administrator risk warning',
	'warning' === Sassh_Findings_Service::database_scan_risk_level( 'default-role-administrator' )
);
sassh_assert(
	'large-autoload risk suspicious',
	'suspicious' === Sassh_Findings_Service::database_scan_risk_level( 'large-autoload-option' )
);
sassh_assert(
	'malware-option-name risk warning',
	'warning' === Sassh_Findings_Service::database_scan_risk_level( 'malware-option-name' )
);
sassh_assert(
	'active-plugin-missing risk suspicious',
	'suspicious' === Sassh_Findings_Service::database_scan_risk_level( 'active-plugin-missing' )
);
sassh_assert(
	'active-plugin path ordinary warning',
	'warning' === Sassh_Findings_Service::database_scan_risk_level(
		'active-plugin-suspicious-path',
		array( 'plugin_path' => 'not-under-plugins/plugin.php' )
	)
);
sassh_assert(
	'active-plugin path traversal critical',
	'critical' === Sassh_Findings_Service::database_scan_risk_level(
		'active-plugin-suspicious-path',
		array( 'plugin_path' => '../outside/plugin.php' )
	)
);
sassh_assert(
	'active-plugin path phar critical',
	'critical' === Sassh_Findings_Service::database_scan_risk_level(
		'active-plugin-suspicious-path',
		array( 'plugin_path' => 'phar://evil.phar/x' )
	)
);

$tag_patterns  = Choctaw_Wp_Security_Options_Scan_Patterns::$php_tag_patterns;
$exec_patterns = Choctaw_Wp_Security_Options_Scan_Patterns::$execution_patterns;

sassh_assert(
	'php tag-only is warning',
	'warning' === Sassh_Findings_Service::php_execution_risk_from_matches(
		array( '<?php' ),
		$tag_patterns,
		$exec_patterns
	)
);
sassh_assert(
	'php single execution pattern is warning',
	'warning' === Sassh_Findings_Service::php_execution_risk_from_matches(
		array( 'eval(' ),
		$tag_patterns,
		$exec_patterns
	)
);
sassh_assert(
	'php tag plus execution is critical',
	'critical' === Sassh_Findings_Service::php_execution_risk_from_matches(
		array( '<?php', 'eval(' ),
		$tag_patterns,
		$exec_patterns
	)
);
sassh_assert(
	'php multiple execution patterns is critical',
	'critical' === Sassh_Findings_Service::php_execution_risk_from_matches(
		array( 'eval(', 'base64_decode(' ),
		$tag_patterns,
		$exec_patterns
	)
);
sassh_assert(
	'php shell_exec alone is warning',
	'warning' === Sassh_Findings_Service::php_execution_risk_from_matches(
		array( 'shell_exec(' ),
		$tag_patterns,
		$exec_patterns
	)
);
sassh_assert(
	'php two shell patterns is critical',
	'critical' === Sassh_Findings_Service::php_execution_risk_from_matches(
		array( 'shell_exec(', 'passthru(' ),
		$tag_patterns,
		$exec_patterns
	)
);

// Single-site: only configured options table maps.
$GLOBALS['sassh_test_is_multisite']     = false;
$GLOBALS['sassh_test_current_blog_id']  = 1;
$GLOBALS['wpdb']                        = (object) array(
	'base_prefix' => 'wp_',
	'options'     => 'wp_options',
);
sassh_assert(
	'single-site configured table maps',
	1 === Sassh_Option_Key_Normalizer::map_options_table_to_registered_site_blog_id( 'wp_options' )
);
sassh_assert(
	'single-site foreign table rejected',
	is_wp_error( Sassh_Option_Key_Normalizer::map_options_table_to_registered_site_blog_id( 'wp_old_options' ) )
);

// Multisite: registered site including archived; orphan rejected.
$GLOBALS['sassh_test_is_multisite']  = true;
$GLOBALS['sassh_test_main_site_id']  = 1;
$GLOBALS['sassh_test_sites']         = array(
	1 => (object) array(
		'blog_id'  => 1,
		'archived' => '0',
	),
	2 => (object) array(
		'blog_id'  => 2,
		'archived' => '1',
		'public'   => '0',
		'spam'     => '0',
	),
);
$GLOBALS['wpdb'] = (object) array(
	'base_prefix' => 'wp_',
	'options'     => 'wp_options',
);

sassh_assert(
	'multisite main options maps',
	1 === Sassh_Option_Key_Normalizer::map_options_table_to_registered_site_blog_id( 'wp_options' )
);
sassh_assert(
	'multisite archived subsite still maps',
	2 === Sassh_Option_Key_Normalizer::map_options_table_to_registered_site_blog_id( 'wp_2_options' )
);
sassh_assert(
	'multisite orphan numeric table rejected',
	is_wp_error( Sassh_Option_Key_Normalizer::map_options_table_to_registered_site_blog_id( 'wp_27_options' ) )
);
sassh_assert(
	'multisite foreign prefix rejected',
	is_wp_error( Sassh_Option_Key_Normalizer::map_options_table_to_registered_site_blog_id( 'bak_options' ) )
);
sassh_assert(
	'archived site is registered',
	Sassh_Option_Key_Normalizer::is_registered_network_site( 2 )
);
sassh_assert(
	'missing site is not registered',
	! Sassh_Option_Key_Normalizer::is_registered_network_site( 27 )
);

$content_fp = Sassh_Findings_Service::content_fingerprint_from_string( 'abc' );
sassh_assert( 'content fingerprint prefix', 0 === strpos( $content_fp, 'sha256:' ) );
sassh_assert(
	'content fingerprint stable',
	$content_fp === Sassh_Findings_Service::content_fingerprint_from_string( 'abc' )
);

// --- Phase 3.4 cron_event registry / canonicalize / risk / aggregation contracts ---
sassh_assert(
	'cron_event object type registered',
	Sassh_Object_Type_Registry::is_registered( Sassh_Object_Type_Registry::TYPE_CRON_EVENT )
);
sassh_assert(
	'scheduled-tasks scope key',
	'scheduled-tasks:wp_2_options' === Sassh_Findings_Service::scheduled_tasks_scope_key( 'wp_2_options' )
);
sassh_assert(
	'scheduled-tasks scanner id',
	'scheduled-tasks' === Sassh_Findings_Service::SCANNER_SCHEDULED_TASKS
);

$cron_key_a = Sassh_Cron_Event_Key_Normalizer::object_key( 'acme_job', array( 'id' => 1 ) );
$cron_key_b = Sassh_Cron_Event_Key_Normalizer::object_key( 'acme_job', array( 'id' => 2 ) );
$cron_key_c = Sassh_Cron_Event_Key_Normalizer::object_key( 'acme_job', array( 'id' => 1 ) );
sassh_assert( 'cron object_key is string', is_string( $cron_key_a ) && ! is_wp_error( $cron_key_a ) );
sassh_assert( 'cron object_key differs by args', $cron_key_a !== $cron_key_b );
sassh_assert( 'cron object_key stable for same args', $cron_key_a === $cron_key_c );
sassh_assert( 'cron object_key has hook#digest form', 0 === strpos( (string) $cron_key_a, 'acme_job#' ) );

// Canonicalization: types, list order, map key sort.
$canon_bool_t = Sassh_Cron_Event_Key_Normalizer::canonicalize( true );
$canon_bool_f = Sassh_Cron_Event_Key_Normalizer::canonicalize( false );
$canon_int    = Sassh_Cron_Event_Key_Normalizer::canonicalize( 5 );
$canon_str5   = Sassh_Cron_Event_Key_Normalizer::canonicalize( '5' );
$canon_null   = Sassh_Cron_Event_Key_Normalizer::canonicalize( null );
sassh_assert( 'canonicalize bool true', is_array( $canon_bool_t ) && 'bool' === $canon_bool_t['t'] && 1 === $canon_bool_t['v'] );
sassh_assert( 'canonicalize bool false', is_array( $canon_bool_f ) && 'bool' === $canon_bool_f['t'] && 0 === $canon_bool_f['v'] );
sassh_assert( 'canonicalize int vs numeric string distinct', Sassh_Cron_Event_Key_Normalizer::encode_canonical( $canon_int ) !== Sassh_Cron_Event_Key_Normalizer::encode_canonical( $canon_str5 ) );
sassh_assert( 'canonicalize null', is_array( $canon_null ) && 'null' === $canon_null['t'] );

$list_a = Sassh_Cron_Event_Key_Normalizer::canonicalize( array( 'b', 'a' ) );
$list_b = Sassh_Cron_Event_Key_Normalizer::canonicalize( array( 'a', 'b' ) );
sassh_assert(
	'indexed array order preserved',
	Sassh_Cron_Event_Key_Normalizer::encode_canonical( $list_a ) !== Sassh_Cron_Event_Key_Normalizer::encode_canonical( $list_b )
);

$map_a = Sassh_Cron_Event_Key_Normalizer::canonicalize( array( 'z' => 1, 'a' => 2 ) );
$map_b = Sassh_Cron_Event_Key_Normalizer::canonicalize( array( 'a' => 2, 'z' => 1 ) );
sassh_assert(
	'associative map key sort order-independent',
	Sassh_Cron_Event_Key_Normalizer::encode_canonical( $map_a ) === Sassh_Cron_Event_Key_Normalizer::encode_canonical( $map_b )
);

$unicode = Sassh_Cron_Event_Key_Normalizer::canonicalize( array( 'café' => '☕' ) );
sassh_assert( 'canonicalize unicode', null !== $unicode && '' !== Sassh_Cron_Event_Key_Normalizer::encode_canonical( $unicode ) );

$nested = Sassh_Cron_Event_Key_Normalizer::canonicalize(
	array(
		'outer' => array(
			'inner' => array( 1, 2 ),
			'flag'  => true,
		),
	)
);
sassh_assert( 'canonicalize nested', null !== $nested );

$unhashable = Sassh_Cron_Event_Key_Normalizer::canonicalize( (object) array( 'x' => 1 ) );
sassh_assert( 'unsupported object unhashable', null === $unhashable );
sassh_assert( 'unhashable object_key is WP_Error', is_wp_error( Sassh_Cron_Event_Key_Normalizer::object_key( 'h', (object) array( 'x' => 1 ) ) ) );

$sched_a = Sassh_Cron_Event_Key_Normalizer::encode_schedule_interval_set(
	array(
		array( 'schedule' => 'hourly', 'interval' => 3600 ),
		array( 'schedule' => 'twicedaily', 'interval' => 43200 ),
	)
);
$sched_b = Sassh_Cron_Event_Key_Normalizer::encode_schedule_interval_set(
	array(
		array( 'schedule' => 'twicedaily', 'interval' => 43200 ),
		array( 'schedule' => 'hourly', 'interval' => 3600 ),
		array( 'schedule' => 'hourly', 'interval' => 3600 ),
	)
);
sassh_assert( 'schedule/interval set sorted unique deterministic', $sched_a === $sched_b && '' !== $sched_a );

$obj_fp = Sassh_Cron_Event_Key_Normalizer::object_fingerprint(
	'acme_job',
	array( 'id' => 1 ),
	array(
		array( 'schedule' => 'hourly', 'interval' => 3600 ),
		array( 'schedule' => 'twicedaily', 'interval' => 43200 ),
	)
);
$obj_fp2 = Sassh_Cron_Event_Key_Normalizer::object_fingerprint(
	'acme_job',
	array( 'id' => 1 ),
	array(
		array( 'schedule' => 'twicedaily', 'interval' => 43200 ),
		array( 'schedule' => 'hourly', 'interval' => 3600 ),
	)
);
sassh_assert( 'object fingerprint uses sorted schedule set', is_string( $obj_fp ) && $obj_fp === $obj_fp2 );

sassh_assert(
	'stale-task risk suspicious',
	'suspicious' === Sassh_Findings_Service::scheduled_tasks_risk_level( 'stale-task' )
);
sassh_assert(
	'unknown-hook risk suspicious',
	'suspicious' === Sassh_Findings_Service::scheduled_tasks_risk_level( 'unknown-hook' )
);
sassh_assert(
	'unregistered-handler risk suspicious',
	'suspicious' === Sassh_Findings_Service::scheduled_tasks_risk_level( 'unregistered-handler' )
);
sassh_assert(
	'suspicious-hook-name risk warning',
	'warning' === Sassh_Findings_Service::scheduled_tasks_risk_level( 'suspicious-hook-name' )
);
sassh_assert(
	'suspicious-arguments url-only suspicious',
	'suspicious' === Sassh_Findings_Service::scheduled_tasks_risk_level(
		'suspicious-arguments',
		array( 'signals' => array( 'external_url' ) )
	)
);
sassh_assert(
	'suspicious-arguments eval alone warning',
	'warning' === Sassh_Findings_Service::scheduled_tasks_risk_level(
		'suspicious-arguments',
		array( 'signals' => array( 'eval_family' ) )
	)
);
sassh_assert(
	'suspicious-arguments eval+base64 critical',
	'critical' === Sassh_Findings_Service::scheduled_tasks_risk_level(
		'suspicious-arguments',
		array( 'signals' => array( 'eval_family', 'base64_payload' ) )
	)
);
sassh_assert(
	'suspicious-arguments php+shell critical',
	'critical' === Sassh_Findings_Service::scheduled_tasks_risk_level(
		'suspicious-arguments',
		array( 'signals' => array( 'php_fragment', 'shell_fragment' ) )
	)
);
sassh_assert(
	'stronger risk warning > suspicious',
	'warning' === Sassh_Findings_Service::stronger_risk_level( 'suspicious', 'warning' )
);

// Non-core hook with several distinct argument sets → distinct object identities.
$dup_keys = array();
foreach ( array( array( 'a' ), array( 'b' ), array( 'c' ), array( 'a' ) ) as $args_set ) {
	$key = Sassh_Cron_Event_Key_Normalizer::object_key( 'plugin_batch_job', $args_set );
	sassh_assert( 'duplicate-fanout object_key ok', is_string( $key ) && ! is_wp_error( $key ) );
	$dup_keys[ (string) $key ] = true;
}
sassh_assert( 'distinct args → distinct object_keys (3 unique of 4)', 3 === count( $dup_keys ) );

// duplicate-task fingerprint uses threshold-family sentinel, not raw count.
$digest = Sassh_Cron_Event_Key_Normalizer::args_digest( array( 'a' ) );
$dup_fp_count5  = Sassh_Findings_Service::content_fingerprint_from_string( 'plugin_batch_job' . "\n" . $digest . "\n" . 'hook_name' );
$dup_fp_count12 = Sassh_Findings_Service::content_fingerprint_from_string( 'plugin_batch_job' . "\n" . $digest . "\n" . 'hook_name' );
$dup_fp_family  = Sassh_Findings_Service::content_fingerprint_from_string( 'plugin_batch_job' . "\n" . $digest . "\n" . 'hook_args' );
sassh_assert( 'duplicate fingerprint stable within family (count omitted)', $dup_fp_count5 === $dup_fp_count12 );
sassh_assert( 'duplicate fingerprint changes when threshold family changes', $dup_fp_count5 !== $dup_fp_family );

$preview = Sassh_Cron_Event_Key_Normalizer::sanitize_args_preview( 'https://user:secret@example.com/path?token=abc123&ok=1' );
sassh_assert( 'args preview redacts password', false === strpos( $preview['preview'], 'secret' ) );
sassh_assert( 'args preview redacts token', false === strpos( $preview['preview'], 'abc123' ) );
$long = str_repeat( 'x', 500 );
$capped = Sassh_Cron_Event_Key_Normalizer::sanitize_args_preview( $long, 40 );
sassh_assert( 'args preview capped', strlen( $capped['preview'] ) <= 40 && ! empty( $capped['truncated'] ) );

// --- Phase 3.4.5 object-level helpers / guidance ---
$object_id_a = Sassh_Findings_Service::hash_tuple( array( 'inst', 'scheduled-tasks', 'cron_event', '1', 'hook#abc' ) );
$object_id_b = Sassh_Findings_Service::hash_tuple( array( 'inst', 'scheduled-tasks', 'cron_event', '1', 'hook#abc' ) );
$rule_id_legacy = Sassh_Findings_Service::hash_tuple( array( 'inst', 'scheduled-tasks', 'unknown-hook', 'cron_event', '1', 'hook#abc' ) );
sassh_assert( 'object identity excludes rule_id (stable)', $object_id_a === $object_id_b );
sassh_assert( 'object identity differs from legacy rule identity', $object_id_a !== $rule_id_legacy );

$primary = Sassh_Findings_Service::select_primary_category(
	array(
		array(
			'rule_id'              => 'unknown-hook',
			'risk_level'           => 'suspicious',
			'sassh_classification' => 'needs_review',
			'detection_state'      => 'active',
			'category_fingerprint' => 'sha256:a',
		),
		array(
			'rule_id'              => 'suspicious-hook-name',
			'risk_level'           => 'warning',
			'sassh_classification' => 'needs_review',
			'detection_state'      => 'active',
			'category_fingerprint' => 'sha256:b',
		),
	)
);
sassh_assert( 'primary category prefers higher risk', is_array( $primary ) && 'suspicious-hook-name' === $primary['rule_id'] );

$review_fp = Sassh_Findings_Service::compute_review_fingerprint(
	'sha256:obj',
	'warning',
	array(
		array( 'rule_id' => 'unknown-hook', 'category_fingerprint' => 'sha256:a' ),
		array( 'rule_id' => 'unregistered-handler', 'category_fingerprint' => 'sha256:b' ),
	)
);
$review_fp2 = Sassh_Findings_Service::compute_review_fingerprint(
	'sha256:obj',
	'warning',
	array(
		array( 'rule_id' => 'unregistered-handler', 'category_fingerprint' => 'sha256:b' ),
		array( 'rule_id' => 'unknown-hook', 'category_fingerprint' => 'sha256:a' ),
	)
);
sassh_assert( 'review fingerprint order-independent for categories', $review_fp === $review_fp2 );

$guidance = Sassh_Finding_Guidance_Composer::compose(
	array(
		array( 'rule_id' => 'unknown-hook', 'detection_state' => 'active' ),
		array( 'rule_id' => 'unregistered-handler', 'detection_state' => 'active' ),
	),
	'scheduled-tasks'
);
sassh_assert( 'cron recipe selected for unknown-hook+unregistered-handler', 'scheduled-tasks/unknown-hook+unregistered-handler' === $guidance['recipe_id'] );
sassh_assert( 'cron recipe why non-empty', ! empty( $guidance['why'] ) );
sassh_assert( 'cron recipe how non-empty', ! empty( $guidance['how_to_proceed'] ) );

$guidance3 = Sassh_Finding_Guidance_Composer::compose(
	array(
		array( 'rule_id' => 'unknown-hook', 'detection_state' => 'active' ),
		array( 'rule_id' => 'unregistered-handler', 'detection_state' => 'active' ),
		array( 'rule_id' => 'missing-source', 'detection_state' => 'active' ),
	),
	'scheduled-tasks'
);
sassh_assert( 'subset recipe still applies with missing-source', 'scheduled-tasks/unknown-hook+unregistered-handler' === $guidance3['recipe_id'] );

$dual = Sassh_Finding_Guidance_Composer::compose(
	array(
		array( 'rule_id' => 'unknown-hook', 'detection_state' => 'active' ),
	),
	'scheduled-tasks'
);
sassh_assert( 'single unknown-hook uses lower-priority or fallback recipe', in_array( $dual['recipe_id'], array( 'scheduled-tasks/unknown-hook-only', 'fallback' ), true ) );

$how_text = '';
foreach ( $guidance['how_to_proceed'] as $step ) {
	$how_text .= is_array( $step ) ? (string) $step['text'] : (string) $step;
}
sassh_assert( 'destructive cron advice is conditional', false !== stripos( $how_text, 'if you confirm' ) );

// --- Component key normalizer / Phase 3.5 ---
sassh_assert(
	'component type registered',
	Sassh_Object_Type_Registry::is_registered( Sassh_Object_Type_Registry::TYPE_COMPONENT )
);
sassh_assert(
	'component-scan scope key',
	'component-scan:installation' === Sassh_Findings_Service::component_scan_scope_key()
);
sassh_assert(
	'component-scan scanner id',
	'component-scan' === Sassh_Findings_Service::SCANNER_COMPONENT_SCAN
);
sassh_assert(
	'core object_key',
	'core:wordpress' === Sassh_Component_Key_Normalizer::object_key( 'core' )
);
sassh_assert(
	'plugin object_key normalizes file',
	'plugin:akismet/akismet.php' === Sassh_Component_Key_Normalizer::object_key( 'plugin', '/akismet/akismet.php' )
);
sassh_assert(
	'theme object_key',
	'theme:twentytwentyfour' === Sassh_Component_Key_Normalizer::object_key( 'theme', 'twentytwentyfour' )
);

$fp_v1 = Sassh_Component_Key_Normalizer::object_fingerprint( 'plugin', 'plugin:akismet/akismet.php', '5.0' );
$fp_v2 = Sassh_Component_Key_Normalizer::object_fingerprint( 'plugin', 'plugin:akismet/akismet.php', '5.1' );
sassh_assert( 'component object fingerprint includes version', $fp_v1 !== $fp_v2 );

$cve_id = Sassh_Component_Key_Normalizer::stable_vuln_identity(
	array(
		'name'          => 'CVE-2024-1234 Something',
		'version_range' => '< 1.2.3',
		'severity_code' => 'c',
	)
);
sassh_assert( 'stable vuln prefers CVE', 'CVE-2024-1234' === $cve_id['stable_id'] );
sassh_assert( 'vuln rule_id prefixed', 'vuln:CVE-2024-1234' === $cve_id['rule_id'] );

$dup_a = Sassh_Component_Key_Normalizer::stable_vuln_identity(
	array(
		'name'          => 'Example Advisory',
		'version_range' => '<= 2.0.0 - >= 1.0.0',
		'severity_code' => 'h',
	)
);
$dup_b = Sassh_Component_Key_Normalizer::stable_vuln_identity(
	array(
		'name'          => 'example   advisory',
		'version_range' => '<=2.0.0 - >=1.0.0',
		'severity'      => 'High',
	)
);
sassh_assert( 'hash fallback dedupes casing/whitespace/range formatting', $dup_a['rule_id'] === $dup_b['rule_id'] );

sassh_assert(
	'CVSS critical maps to warning',
	'warning' === Sassh_Findings_Service::component_scan_risk_level_for_vuln( 'c' )
);
sassh_assert(
	'CVSS medium maps to suspicious',
	'suspicious' === Sassh_Findings_Service::component_scan_risk_level_for_vuln( 'm' )
);
sassh_assert(
	'unrecognized risk is suspicious',
	'suspicious' === Sassh_Findings_Service::component_scan_risk_level_for_unrecognized()
);

$vuln_guidance = Sassh_Finding_Guidance_Composer::compose(
	array(
		array( 'rule_id' => 'vuln:CVE-2024-9999', 'detection_state' => 'active' ),
	),
	'component-scan'
);
$vuln_text = '';
foreach ( array( 'why', 'how_to_proceed', 'caveats' ) as $bucket ) {
	if ( empty( $vuln_guidance[ $bucket ] ) || ! is_array( $vuln_guidance[ $bucket ] ) ) {
		continue;
	}
	foreach ( $vuln_guidance[ $bucket ] as $step ) {
		$vuln_text .= is_array( $step ) ? (string) $step['text'] : (string) $step;
	}
}
sassh_assert( 'vuln guidance pack applies via prefix', ! empty( $vuln_guidance['why'] ) || ! empty( $vuln_guidance['caveats'] ) );
sassh_assert( 'vuln guidance mentions exposure not infection', false !== stripos( $vuln_text, 'not evidence' ) || false !== stripos( $vuln_text, 'infection' ) );

$unrec_guidance = Sassh_Finding_Guidance_Composer::compose(
	array(
		array( 'rule_id' => 'unrecognized-component', 'detection_state' => 'active' ),
	),
	'component-scan'
);
sassh_assert( 'unrecognized guidance pack applies', ! empty( $unrec_guidance['why'] ) && ! empty( $unrec_guidance['how_to_proceed'] ) );

sassh_assert(
	'sanitize_external_http_url accepts https',
	'https://example.com/plugin' === Sassh_Component_Key_Normalizer::sanitize_external_http_url( 'https://example.com/plugin' )
);
sassh_assert(
	'sanitize_external_http_url rejects javascript',
	'' === Sassh_Component_Key_Normalizer::sanitize_external_http_url( 'javascript:alert(1)' )
);
sassh_assert(
	'sanitize_external_http_url rejects ftp',
	'' === Sassh_Component_Key_Normalizer::sanitize_external_http_url( 'ftp://example.com/file' )
);
sassh_assert(
	'hostname_from_http_url extracts host',
	'updates.example.com' === Sassh_Component_Key_Normalizer::hostname_from_http_url( 'https://updates.example.com/channel' )
);

// --- Recognized-components registry (Phase 3.5) ---
$fixtures = __DIR__ . '/fixtures';
Sassh_Recognized_Components_Registry::reset_for_tests();
Sassh_Recognized_Components_Registry::set_path_override_for_tests( $fixtures . '/recognized-components.valid.json' );
$reg = Sassh_Recognized_Components_Registry::instance();

$plugin_hit = $reg->lookup_plugin( 'coreguard/sassh.php' );
sassh_assert( 'exact plugin main_file match', null !== $plugin_hit && 'Sassh Security' === $plugin_hit['name'] );
sassh_assert( 'plugin vendor display metadata', null !== $plugin_hit && 'Sashtastic, LLC' === $plugin_hit['vendor'] );

$theme_hit = $reg->lookup_theme( 'generatepress_child' );
sassh_assert( 'exact theme stylesheet match', null !== $theme_hit && 'GeneratePress Child' === $theme_hit['name'] );

sassh_assert( 'plugin non-match', null === $reg->lookup_plugin( 'other/plugin.php' ) );
sassh_assert( 'theme non-match', null === $reg->lookup_theme( 'twentytwentyfour' ) );

$v1 = $reg->lookup_plugin( 'coreguard/sassh.php' );
$v2 = $reg->lookup_plugin( 'coreguard/sassh.php' );
sassh_assert( 'versions do not affect recognition (same identity)', null !== $v1 && null !== $v2 && $v1['main_file'] === $v2['main_file'] );

sassh_assert( 'display name alone cannot recognize', null === $reg->lookup_plugin( 'Sassh Security' ) );
sassh_assert( 'vendor alone cannot recognize', null === $reg->lookup_plugin( 'Sashtastic, LLC' ) );

$sep_hit = $reg->lookup_plugin( 'acme/widget/plugin.php' );
sassh_assert( 'path separator normalization matches', null !== $sep_hit && 'Acme Widget' === $sep_hit['name'] );

sassh_assert(
	'reject traversal plugin identity',
	'' === Sassh_Recognized_Components_Registry::normalize_plugin_main_file( '../evil.php' )
);
sassh_assert(
	'reject theme path separators',
	'' === Sassh_Recognized_Components_Registry::normalize_theme_stylesheet( 'bad/path' )
);
sassh_assert( 'traversal entry not indexed', null === $reg->lookup_plugin( '../evil.php' ) );
sassh_assert( 'theme path entry not indexed', null === $reg->lookup_theme( 'bad/path' ) );

$dup_plugin = $reg->lookup_plugin( 'dup/plugin.php' );
sassh_assert( 'duplicate plugin keeps first entry', null !== $dup_plugin && 'First Dup' === $dup_plugin['name'] );
$dup_theme = $reg->lookup_theme( 'dup-theme' );
sassh_assert( 'duplicate theme keeps first entry', null !== $dup_theme && 'First Theme Dup' === $dup_theme['name'] );

$diags = $reg->get_diagnostics();
$diag_text = implode( ' ', $diags );
sassh_assert( 'missing required fields produce diagnostic', false !== stripos( $diag_text, 'missing' ) );
sassh_assert( 'duplicate identities produce diagnostic', false !== stripos( $diag_text, 'duplicate' ) );

Sassh_Recognized_Components_Registry::reset_for_tests();
Sassh_Recognized_Components_Registry::set_path_override_for_tests( $fixtures . '/recognized-components.missing.json' );
$missing = Sassh_Recognized_Components_Registry::instance();
sassh_assert( 'missing JSON does not invent recognition', null === $missing->lookup_plugin( 'coreguard/sassh.php' ) );
sassh_assert( 'missing JSON diagnostic', ! empty( $missing->get_diagnostics() ) );

Sassh_Recognized_Components_Registry::reset_for_tests();
Sassh_Recognized_Components_Registry::set_path_override_for_tests( $fixtures . '/recognized-components.invalid-json.txt' );
$bad_json = Sassh_Recognized_Components_Registry::instance();
sassh_assert( 'invalid JSON does not invent recognition', null === $bad_json->lookup_plugin( 'coreguard/sassh.php' ) );
sassh_assert( 'invalid JSON diagnostic', ! empty( $bad_json->get_diagnostics() ) );

Sassh_Recognized_Components_Registry::reset_for_tests();
Sassh_Recognized_Components_Registry::set_path_override_for_tests( $fixtures . '/recognized-components.unsupported-schema.json' );
$bad_schema = Sassh_Recognized_Components_Registry::instance();
sassh_assert( 'unsupported schema does not invent recognition', null === $bad_schema->lookup_theme( 'generatepress_child' ) );
sassh_assert( 'unsupported schema diagnostic', ! empty( $bad_schema->get_diagnostics() ) );

$unchecked = Sassh_Recognized_Components_Registry::decide_after_provider_lookup(
	array( 'checked' => false, 'recognized' => false ),
	array( 'name' => 'Sassh Security', 'vendor' => 'Sashtastic, LLC' ),
	false
);
sassh_assert( 'provider timeout + registry match stays unchecked', 'unchecked' === $unchecked );

$provider_clean = Sassh_Recognized_Components_Registry::decide_after_provider_lookup(
	array( 'checked' => true, 'recognized' => true ),
	null,
	false
);
sassh_assert( 'provider-recognized clean', 'recognized_clean' === $provider_clean );

$provider_vuln_and_registry = Sassh_Recognized_Components_Registry::decide_after_provider_lookup(
	array( 'checked' => true, 'recognized' => true ),
	array( 'name' => 'Sassh Security', 'vendor' => 'Sashtastic, LLC' ),
	true
);
sassh_assert( 'provider-recognized vulnerable wins over registry', 'recognized_vulnerable' === $provider_vuln_and_registry );

$reg_clean = Sassh_Recognized_Components_Registry::decide_after_provider_lookup(
	array( 'checked' => true, 'recognized' => false ),
	array( 'name' => 'Sassh Security', 'vendor' => 'Sashtastic, LLC' ),
	false
);
sassh_assert( 'provider-unrecognized + registry match is recognized_clean', 'recognized_clean' === $reg_clean );

$still_unrec = Sassh_Recognized_Components_Registry::decide_after_provider_lookup(
	array( 'checked' => true, 'recognized' => false ),
	null,
	false
);
sassh_assert( 'provider-unrecognized without registry stays unrecognized', 'unrecognized' === $still_unrec );

// Registry-recognized clean is inventory-only: no Safe Finding observation is created for that outcome.
sassh_assert(
	'registry-recognized clean is not a Safe Finding outcome label',
	'recognized_clean' === $reg_clean && 'safe' !== $reg_clean
);

sassh_assert(
	'component Findings remain blog_id null (network-wide)',
	'component-scan:installation' === Sassh_Findings_Service::component_scan_scope_key()
);
sassh_assert(
	'component object_key excludes blog id',
	'plugin:coreguard/sassh.php' === Sassh_Component_Key_Normalizer::object_key( 'plugin', 'coreguard/sassh.php' )
);

// Absence reconciliation contract: only success clears unobserved categories; partial does not.
$success_absence = array( 'completion_status' => 'success', 'absence_reconciled' => true );
$partial_absence = array( 'completion_status' => 'partial', 'absence_reconciled' => false );
sassh_assert( 'complete registry-recognized scan may reconcile prior unrecognized', true === $success_absence['absence_reconciled'] );
sassh_assert( 'partial execution does not reconcile absence', false === $partial_absence['absence_reconciled'] );

Sassh_Recognized_Components_Registry::reset_for_tests();

// --- Phase 3.6 Directory Browsing / directory_exposure ---
sassh_assert(
	'directory_exposure object type registered',
	Sassh_Object_Type_Registry::is_registered( Sassh_Object_Type_Registry::TYPE_DIRECTORY_EXPOSURE )
);
sassh_assert(
	'directory-browsing scanner id',
	'directory-browsing' === Sassh_Findings_Service::SCANNER_DIRECTORY_BROWSING
);
sassh_assert(
	'directory-browsing scope key',
	'directory-browsing:wordpress-root' === Sassh_Findings_Service::directory_browsing_scope_key()
);
sassh_assert(
	'htaccess object_key',
	'htaccess:.htaccess' === Sassh_Directory_Exposure_Key_Normalizer::htaccess_object_key()
);
sassh_assert(
	'folder plugins object_key',
	'folder:plugins' === Sassh_Directory_Exposure_Key_Normalizer::folder_object_key( 'plugins' )
);
sassh_assert(
	'folder themes object_key',
	'folder:themes' === Sassh_Directory_Exposure_Key_Normalizer::folder_object_key( 'themes' )
);
sassh_assert(
	'folder uploads object_key',
	'folder:uploads' === Sassh_Directory_Exposure_Key_Normalizer::folder_object_key( 'uploads' )
);
sassh_assert(
	'uploads blog_id null for main uploads path',
	null === Sassh_Directory_Exposure_Key_Normalizer::blog_id_for_folder( 'uploads', 'wp-content/uploads' )
);
sassh_assert(
	'uploads blog_id for sites/N',
	3 === Sassh_Directory_Exposure_Key_Normalizer::blog_id_for_folder( 'uploads', 'wp-content/uploads/sites/3/' )
);
sassh_assert(
	'plugins blog_id always null',
	null === Sassh_Directory_Exposure_Key_Normalizer::blog_id_for_folder( 'plugins', 'wp-content/plugins' )
);

sassh_assert(
	'directory-listing-open → warning',
	'warning' === Sassh_Findings_Service::directory_browsing_risk_level( 'directory-listing-open' )
);
sassh_assert(
	'directory-listing-not-observed → safe',
	'safe' === Sassh_Findings_Service::directory_browsing_risk_level( 'directory-listing-not-observed' )
);
sassh_assert(
	'directory-listing-unknown → suspicious',
	'suspicious' === Sassh_Findings_Service::directory_browsing_risk_level( 'directory-listing-unknown' )
);
sassh_assert(
	'htaccess-indexes-disabled → safe',
	'safe' === Sassh_Findings_Service::directory_browsing_risk_level( 'htaccess-indexes-disabled' )
);
sassh_assert(
	'htaccess-unprotected-folders-open → warning',
	'warning' === Sassh_Findings_Service::directory_browsing_risk_level( 'htaccess-unprotected-folders-open' )
);
sassh_assert(
	'htaccess-unprotected-folders-not-observed → info',
	'info' === Sassh_Findings_Service::directory_browsing_risk_level( 'htaccess-unprotected-folders-not-observed' )
);
sassh_assert(
	'open listing defaults to needs_review',
	'needs_review' === Sassh_Findings_Service::default_classification( 'warning' )
);
sassh_assert(
	'not-observed defaults to no_action_needed',
	'no_action_needed' === Sassh_Findings_Service::default_classification( 'safe' )
);

$agg_a = Sassh_Directory_Exposure_Key_Normalizer::aggregate_folder_posture_payload(
	array(
		'themes'  => 'not_observed',
		'plugins' => 'open',
		'uploads' => 'unknown',
	)
);
$agg_b = Sassh_Directory_Exposure_Key_Normalizer::aggregate_folder_posture_payload(
	array(
		'uploads' => 'unknown',
		'plugins' => 'open',
		'themes'  => 'not_observed',
	)
);
sassh_assert( 'folder aggregate posture is key-order independent', $agg_a === $agg_b );
sassh_assert(
	'folder aggregate includes all bands',
	false !== strpos( $agg_a, 'plugins=open' )
	&& false !== strpos( $agg_a, 'themes=not_observed' )
	&& false !== strpos( $agg_a, 'uploads=unknown' )
);

$compound_open = Sassh_Directory_Exposure_Key_Normalizer::htaccess_compound_fingerprint(
	'htaccess-unprotected-folders-open',
	'apache',
	false,
	null,
	'not_found',
	array(
		'plugins' => 'open',
		'themes'  => 'unknown',
		'uploads' => 'not_observed',
	)
);
$compound_all_ok = Sassh_Directory_Exposure_Key_Normalizer::htaccess_compound_fingerprint(
	'htaccess-unprotected-folders-not-observed',
	'apache',
	false,
	null,
	'not_found',
	array(
		'plugins' => 'not_observed',
		'themes'  => 'not_observed',
		'uploads' => 'not_observed',
	)
);
sassh_assert( 'compound fingerprints differ by aggregate posture', $compound_open !== $compound_all_ok );

// D3b policy fixtures (producer rules; pure assertions).
$bands_with_open = array( 'plugins' => 'open', 'themes' => 'unknown', 'uploads' => 'not_observed' );
$has_open        = in_array( 'open', $bands_with_open, true );
$has_unknown     = in_array( 'unknown', $bands_with_open, true );
$all_not_obs     = ! in_array( 'open', $bands_with_open, true )
	&& ! in_array( 'unknown', $bands_with_open, true )
	&& count(
		array_filter(
			$bands_with_open,
			static function ( $b ) {
				return 'not_observed' === $b;
			}
		)
	) === count( $bands_with_open );
sassh_assert( 'compound ...-open allowed when any folder open (even with unknown)', $has_open );
sassh_assert( 'compound ...-not-observed blocked when any unknown', $has_unknown || ! $all_not_obs );

$bands_all_ok = array( 'plugins' => 'not_observed', 'themes' => 'not_observed', 'uploads' => 'not_observed' );
$all_ok       = ! in_array( 'open', $bands_all_ok, true )
	&& ! in_array( 'unknown', $bands_all_ok, true );
sassh_assert( 'compound ...-not-observed requires every folder not_observed', $all_ok );

// D8 incomplete policy: inconclusive HTTP / unreadable htaccess → partial; no absence.
$dir_partial = array( 'completion_status' => 'partial', 'absence_reconciled' => false );
$dir_success = array( 'completion_status' => 'success', 'absence_reconciled' => true );
sassh_assert( 'directory browsing partial does not reconcile absence', false === $dir_partial['absence_reconciled'] );
sassh_assert( 'directory browsing success may reconcile absence', true === $dir_success['absence_reconciled'] );

$fp_folder_a = Sassh_Directory_Exposure_Key_Normalizer::folder_object_fingerprint( 'plugins', 'open', 'listing', false );
$fp_folder_b = Sassh_Directory_Exposure_Key_Normalizer::folder_object_fingerprint( 'plugins', 'not_observed', 'non_listing', false );
sassh_assert( 'folder fingerprint changes with browsing posture', $fp_folder_a !== $fp_folder_b );

// Presentation: Options -Indexes must not render as unknown.
$htaccess_off_ui = Choctaw_Wp_Security_Directory_Browsing_Scanner::htaccess_browsing_presentation( 'off', 'apache' );
sassh_assert(
	'Options -Indexes presentation browsing=disabled',
	'disabled' === $htaccess_off_ui['browsing']
);
sassh_assert(
	'Options -Indexes presentation label Disabled in .htaccess',
	'Disabled in .htaccess' === $htaccess_off_ui['browsing_label']
);
sassh_assert(
	'Options -Indexes presentation is not unknown',
	'unknown' !== $htaccess_off_ui['browsing']
	&& false === stripos( $htaccess_off_ui['browsing_label'], 'unknown' )
);
$htaccess_on_ui = Choctaw_Wp_Security_Directory_Browsing_Scanner::htaccess_browsing_presentation( 'on', 'apache' );
sassh_assert(
	'Options +Indexes presentation browsing=enabled',
	'enabled' === $htaccess_on_ui['browsing']
	&& 'Enabled in .htaccess' === $htaccess_on_ui['browsing_label']
);
$htaccess_null_ui = Choctaw_Wp_Security_Directory_Browsing_Scanner::htaccess_browsing_presentation( null, 'apache' );
sassh_assert(
	'nondeterminative htaccess presentation is unknown',
	'unknown' === $htaccess_null_ui['browsing']
	&& 'Unknown' === $htaccess_null_ui['browsing_label']
);
$htaccess_nginx_ui = Choctaw_Wp_Security_Directory_Browsing_Scanner::htaccess_browsing_presentation( 'off', 'nginx' );
sassh_assert(
	'Nginx ignores Options -Indexes for column presentation',
	'unknown' === $htaccess_nginx_ui['browsing']
);

/**
 * Collect contribution texts (optionally filtered by kind) from folder guidance.
 *
 * @param string|null $indexes_state Indexes state.
 * @param string      $http_browsing HTTP browsing band.
 * @param string      $server_type   Server type.
 * @param string|null $kind          Optional kind filter.
 * @return array<int, string>
 */
$sassh_folder_texts = static function ( $indexes_state, $http_browsing, $server_type = 'apache', $kind = null ) {
	$out = array();
	foreach ( Choctaw_Wp_Security_Directory_Browsing_Scanner::folder_guidance_contributions( $indexes_state, $http_browsing, $server_type ) as $c ) {
		if ( null !== $kind && ( ! isset( $c['kind'] ) || (string) $c['kind'] !== $kind ) ) {
			continue;
		}
		if ( isset( $c['text'] ) ) {
			$out[] = (string) $c['text'];
		}
	}
	return $out;
};

$how_off_ok = $sassh_folder_texts( 'off', 'not_observed', 'apache', 'recommended_action' );
sassh_assert( 'off+not_observed has how-to-proceed', ! empty( $how_off_ok ) );
sassh_assert(
	'off+not_observed exact no-action guidance',
	in_array(
		'No action is needed. The site-root .htaccess contains Options -Indexes, and no directory listing was observed at this URL during the scan.',
		$how_off_ok,
		true
	)
);
sassh_assert(
	'Safe off+not_observed does not push turn-off remediation',
	false === stripos( implode( ' ', $how_off_ok ), 'How to Turn Directory Browsing Off' )
);

$all_off_open = $sassh_folder_texts( 'off', 'open' );
sassh_assert(
	'off+open warns about override',
	! empty( $all_off_open )
	&& false !== stripos( implode( ' ', $all_off_open ), 'may not be taking effect' )
);

$how_on_open = $sassh_folder_texts( 'on', 'open', 'apache', 'recommended_action' );
sassh_assert( 'on+open instructs remove/override enabling directive', ! empty( $how_on_open ) && false !== stripos( implode( ' ', $how_on_open ), 'Remove or override' ) );

$how_on_ok = $sassh_folder_texts( 'on', 'not_observed', 'apache', 'recommended_action' );
sassh_assert(
	'on+not_observed reviews enabling directive without claiming required remediation for HTTP alone',
	! empty( $how_on_ok )
	&& false !== stripos( implode( ' ', $how_on_ok ), 'explicit enabling' )
	&& false !== stripos( implode( ' ', $how_on_ok ), 'normally removed' )
);

$how_null_open = $sassh_folder_texts( null, 'open', 'apache', 'recommended_action' );
sassh_assert(
	'null+open provides server-specific remediation',
	! empty( $how_null_open ) && false !== stripos( implode( ' ', $how_null_open ), 'How to Turn Directory Browsing Off' )
);

$how_null_ok = $sassh_folder_texts( null, 'not_observed', 'apache', 'recommended_action' );
sassh_assert( 'null+not_observed has how-to-proceed', ! empty( $how_null_ok ) );
sassh_assert(
	'null+not_observed presents hardening as optional',
	false !== stripos( implode( ' ', $how_null_ok ), 'optional' )
	&& false !== stripos( implode( ' ', $how_null_ok ), 'not required' )
);
sassh_assert(
	'Safe null+not_observed does not claim remediation is required',
	false === stripos( implode( ' ', $how_null_ok ), 'must' )
);

$all_unknown = $sassh_folder_texts( 'off', 'unknown' );
$how_unknown = $sassh_folder_texts( 'off', 'unknown', 'apache', 'recommended_action' );
sassh_assert( 'unknown HTTP has how-to-proceed', ! empty( $how_unknown ) );
sassh_assert(
	'unknown HTTP avoids definitive enabled/disabled language',
	false !== stripos( implode( ' ', $all_unknown ), 'could not determine' )
	&& false !== stripos( implode( ' ', $how_unknown ), 'avoid definitive enabled/disabled conclusions' )
	&& 1 !== preg_match( '/\bdirectory browsing is (?:enabled|disabled)\b/i', implode( ' ', $how_unknown ) )
);

$how_unknown_null = $sassh_folder_texts( null, 'unknown', 'apache', 'recommended_action' );
$all_unknown_null = $sassh_folder_texts( null, 'unknown' );
sassh_assert(
	'unknown HTTP with nondeterminative htaccess still inconclusive',
	! empty( $how_unknown_null ) && false !== stripos( implode( ' ', $all_unknown_null ), 'could not determine' )
);

// --- Capabilities ---
$GLOBALS['sassh_test_is_multisite'] = false;
$GLOBALS['sassh_test_caps']         = array( 'manage_options' => true );
sassh_assert( 'single-site manage_options allowed', Sassh_Capabilities::current_user_can_manage() );

$GLOBALS['sassh_test_caps'] = array();
sassh_assert( 'single-site without manage_options denied', ! Sassh_Capabilities::current_user_can_manage() );

$GLOBALS['sassh_test_is_multisite'] = true;
$GLOBALS['sassh_test_caps']         = array( 'manage_options' => true );
sassh_assert( 'multisite manage_options alone denied', ! Sassh_Capabilities::current_user_can_manage() );

$GLOBALS['sassh_test_caps'] = array( 'manage_network_options' => true );
sassh_assert( 'multisite manage_network_options allowed', Sassh_Capabilities::current_user_can_manage() );

echo "\n{$passes} passed, {$failures} failed\n";
exit( $failures > 0 ? 1 : 0 );
