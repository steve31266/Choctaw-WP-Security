<?php
/**
 * Sassh Findings object-type registry.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Documents allowed coarse object types.
 */
class Sassh_Object_Type_Registry {

	const TYPE_FILE   = 'file';
	const TYPE_OPTION = 'option';

	/**
	 * Whether an object type is registered.
	 *
	 * @param string $object_type Type key.
	 * @return bool
	 */
	public static function is_registered( $object_type ) {
		return in_array( (string) $object_type, self::registered_types(), true );
	}

	/**
	 * Registered object types.
	 *
	 * Coarse shared types only. Option key normalization lives in
	 * Sassh_Option_Key_Normalizer (option name; active_plugins#path; home+siteurl).
	 *
	 * @return array<int, string>
	 */
	public static function registered_types() {
		return array(
			self::TYPE_FILE,
			self::TYPE_OPTION,
		);
	}
}
