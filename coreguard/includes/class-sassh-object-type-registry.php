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

	const TYPE_FILE               = 'file';
	const TYPE_OPTION             = 'option';
	const TYPE_CRON_EVENT         = 'cron_event';
	const TYPE_COMPONENT          = 'component';
	const TYPE_DIRECTORY_EXPOSURE = 'directory_exposure';

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
	 * Cron event key normalization lives in Sassh_Cron_Event_Key_Normalizer
	 * (hook#args_digest; typed args canonicalization).
	 * Component key normalization lives in Sassh_Component_Key_Normalizer
	 * (core:wordpress; plugin:{file}; theme:{stylesheet}).
	 * Directory exposure key normalization lives in Sassh_Directory_Exposure_Key_Normalizer
	 * (htaccess:.htaccess; folder:plugins|themes|uploads).
	 *
	 * @return array<int, string>
	 */
	public static function registered_types() {
		return array(
			self::TYPE_FILE,
			self::TYPE_OPTION,
			self::TYPE_CRON_EVENT,
			self::TYPE_COMPONENT,
			self::TYPE_DIRECTORY_EXPOSURE,
		);
	}
}
