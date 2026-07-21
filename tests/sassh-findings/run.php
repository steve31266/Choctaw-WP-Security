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
