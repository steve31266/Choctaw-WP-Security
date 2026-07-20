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
