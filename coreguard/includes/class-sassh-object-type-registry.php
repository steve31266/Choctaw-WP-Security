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

	const TYPE_FILE = 'file';

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
	 * @return array<int, string>
	 */
	public static function registered_types() {
		return array(
			self::TYPE_FILE,
		);
	}
}
