<?php
/**
 * Central plugin coordinator.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Loads plugin modules and registers their hooks.
 */
class Choctaw_Wp_Security_Plugin {

	/**
	 * Singleton instance.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Settings module.
	 *
	 * @var Choctaw_Wp_Security_Settings
	 */
	private $settings;

	/**
	 * XML-RPC protection module.
	 *
	 * @var Choctaw_Wp_Security_Xml_Rpc_Protection
	 */
	private $xml_rpc_protection;

	/**
	 * Login rate limiter module.
	 *
	 * @var Choctaw_Wp_Security_Login_Rate_Limiter
	 */
	private $login_rate_limiter;

	/**
	 * Uploads PHP lockdown module.
	 *
	 * @var Choctaw_Wp_Security_Uploads_Php_Lockdown
	 */
	private $uploads_php_lockdown;

	/**
	 * Retrieve the singleton instance.
	 *
	 * @return self
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Initialize plugin modules.
	 *
	 * @return void
	 */
	public function init() {
		$this->settings             = new Choctaw_Wp_Security_Settings();
		$this->xml_rpc_protection   = new Choctaw_Wp_Security_Xml_Rpc_Protection();
		$this->login_rate_limiter   = new Choctaw_Wp_Security_Login_Rate_Limiter();
		$this->uploads_php_lockdown = new Choctaw_Wp_Security_Uploads_Php_Lockdown();

		$this->settings->register_hooks();
		$this->xml_rpc_protection->register_hooks();
		$this->login_rate_limiter->register_hooks();
		$this->uploads_php_lockdown->register_hooks();
	}
}
