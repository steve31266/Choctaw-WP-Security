<?php
/**
 * Sassh Findings option-key normalization and options-table → site mapping.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Shared rules for object_type=option keys and registered-site blog_id mapping.
 */
class Sassh_Option_Key_Normalizer {

	/**
	 * Normalize a plain option name for object_key.
	 *
	 * @param string $option_name Option name as stored.
	 * @return string
	 */
	public static function normalize_option_name( $option_name ) {
		return trim( (string) $option_name );
	}

	/**
	 * Object key for a single option name.
	 *
	 * @param string $option_name Option name.
	 * @return string
	 */
	public static function object_key_for_option( $option_name ) {
		return self::normalize_option_name( $option_name );
	}

	/**
	 * Object key for an active_plugins list entry.
	 *
	 * @param string $plugin_relative_path Plugin path as stored in active_plugins.
	 * @return string
	 */
	public static function object_key_for_active_plugin( $plugin_relative_path ) {
		$path = str_replace( '\\', '/', trim( (string) $plugin_relative_path ) );
		$path = ltrim( $path, '/' );

		return 'active_plugins#' . $path;
	}

	/**
	 * Synthetic object key for home/siteurl mismatch (one composite condition).
	 *
	 * @return string
	 */
	public static function object_key_home_siteurl() {
		return 'home+siteurl';
	}

	/**
	 * Map an options table name to a registered/current network site blog_id.
	 *
	 * Confirms a site record exists. Does not reject archived, private, spam-marked,
	 * or otherwise non-public sites — only foreign/orphaned tables.
	 *
	 * @param string $options_table Options table name.
	 * @return int|WP_Error Blog id or error.
	 */
	public static function map_options_table_to_registered_site_blog_id( $options_table ) {
		global $wpdb;

		$options_table = (string) $options_table;

		if ( '' === $options_table || ! isset( $wpdb ) || ! is_object( $wpdb ) ) {
			return new WP_Error(
				'sassh_options_table_unmappable',
				__( 'The selected options table cannot be associated with a registered WordPress site.', 'choctaw-wp-security' )
			);
		}

		$base_prefix = isset( $wpdb->base_prefix ) ? (string) $wpdb->base_prefix : '';
		$configured  = isset( $wpdb->options ) ? (string) $wpdb->options : '';

		if ( ! is_multisite() ) {
			if ( '' === $configured || $options_table !== $configured ) {
				return new WP_Error(
					'sassh_options_table_foreign',
					__( 'The selected options table appears to be foreign or leftover and is not the WordPress-configured options table for this site. Sassh only scans options tables that belong to a registered site.', 'choctaw-wp-security' )
				);
			}

			$blog_id = function_exists( 'get_current_blog_id' ) ? (int) get_current_blog_id() : 1;

			if ( $blog_id <= 0 || ! self::is_registered_network_site( $blog_id ) ) {
				return new WP_Error(
					'sassh_options_table_unmappable',
					__( 'The selected options table cannot be associated with a registered WordPress site.', 'choctaw-wp-security' )
				);
			}

			return $blog_id;
		}

		if ( '' === $base_prefix ) {
			return new WP_Error(
				'sassh_options_table_unmappable',
				__( 'The selected options table cannot be associated with a registered WordPress site.', 'choctaw-wp-security' )
			);
		}

		$main_table = $base_prefix . 'options';

		if ( $options_table === $main_table || ( '' !== $configured && $options_table === $configured && $configured === $main_table ) ) {
			$main_id = function_exists( 'get_main_site_id' ) ? (int) get_main_site_id() : 1;

			if ( ! self::is_registered_network_site( $main_id ) ) {
				return new WP_Error(
					'sassh_options_table_orphaned',
					__( 'The selected options table looks like the network main-site table, but no matching registered site record was found.', 'choctaw-wp-security' )
				);
			}

			return $main_id;
		}

		$pattern = '/^' . preg_quote( $base_prefix, '/' ) . '(\d+)_options$/';

		if ( preg_match( $pattern, $options_table, $matches ) ) {
			$blog_id = isset( $matches[1] ) ? (int) $matches[1] : 0;

			if ( $blog_id <= 0 || ! self::is_registered_network_site( $blog_id ) ) {
				return new WP_Error(
					'sassh_options_table_orphaned',
					__( 'The selected options table looks Multisite-shaped, but it does not correspond to a registered site in this network. It may be leftover or orphaned.', 'choctaw-wp-security' )
				);
			}

			return $blog_id;
		}

		return new WP_Error(
			'sassh_options_table_foreign',
			__( 'The selected options table appears to be foreign or leftover and is not associated with a registered WordPress site. Sassh only scans options tables that belong to a registered site.', 'choctaw-wp-security' )
		);
	}

	/**
	 * Whether a blog_id has a corresponding site record in this installation.
	 *
	 * Does not treat archived / private / spam / non-public flags as disqualifying.
	 *
	 * @param int $blog_id Blog id.
	 * @return bool
	 */
	public static function is_registered_network_site( $blog_id ) {
		$blog_id = (int) $blog_id;

		if ( $blog_id <= 0 ) {
			return false;
		}

		if ( ! is_multisite() ) {
			$current = function_exists( 'get_current_blog_id' ) ? (int) get_current_blog_id() : 1;

			return $blog_id === $current;
		}

		if ( function_exists( 'get_site' ) ) {
			$site = get_site( $blog_id );

			if ( $site && is_object( $site ) ) {
				$site_id = isset( $site->blog_id ) ? (int) $site->blog_id : ( isset( $site->id ) ? (int) $site->id : 0 );

				return $site_id === $blog_id;
			}
		}

		if ( function_exists( 'get_blog_details' ) ) {
			$details = get_blog_details( $blog_id );

			if ( $details && is_object( $details ) ) {
				$site_id = isset( $details->blog_id ) ? (int) $details->blog_id : 0;

				return $site_id === $blog_id;
			}
		}

		return false;
	}
}
