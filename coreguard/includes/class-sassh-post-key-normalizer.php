<?php
/**
 * Sassh Findings post-key normalization and posts-table → site mapping.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Shared rules for object_type=post keys, registered-site blog_id mapping, and fingerprints.
 */
class Sassh_Post_Key_Normalizer {

	/**
	 * Normalize a post ID to an object_key string.
	 *
	 * @param int|string $post_id Post ID.
	 * @return string|WP_Error Decimal ID string or error.
	 */
	public static function object_key_for_post_id( $post_id ) {
		$id = (int) $post_id;

		if ( $id <= 0 ) {
			return new WP_Error(
				'sassh_post_id_invalid',
				__( 'Post object key requires a positive post ID.', 'choctaw-wp-security' )
			);
		}

		return (string) $id;
	}

	/**
	 * Map a posts table name to a registered/current network site blog_id.
	 *
	 * Confirms a site record exists. Does not reject archived, private, spam-marked,
	 * or otherwise non-public sites — only foreign/orphaned tables.
	 *
	 * @param string $posts_table Posts table name.
	 * @return int|WP_Error Blog id or error.
	 */
	public static function map_posts_table_to_registered_site_blog_id( $posts_table ) {
		global $wpdb;

		$posts_table = (string) $posts_table;

		if ( '' === $posts_table || ! isset( $wpdb ) || ! is_object( $wpdb ) ) {
			return new WP_Error(
				'sassh_posts_table_unmappable',
				__( 'The selected posts table cannot be associated with a registered WordPress site.', 'choctaw-wp-security' )
			);
		}

		$base_prefix = isset( $wpdb->base_prefix ) ? (string) $wpdb->base_prefix : '';
		$configured  = isset( $wpdb->posts ) ? (string) $wpdb->posts : '';

		if ( ! is_multisite() ) {
			if ( '' === $configured || $posts_table !== $configured ) {
				return new WP_Error(
					'sassh_posts_table_foreign',
					__( 'The selected posts table appears to be foreign or leftover and is not the WordPress-configured posts table for this site. Sassh only scans posts tables that belong to a registered site.', 'choctaw-wp-security' )
				);
			}

			$blog_id = function_exists( 'get_current_blog_id' ) ? (int) get_current_blog_id() : 1;

			if ( $blog_id <= 0 || ! self::is_registered_network_site( $blog_id ) ) {
				return new WP_Error(
					'sassh_posts_table_unmappable',
					__( 'The selected posts table cannot be associated with a registered WordPress site.', 'choctaw-wp-security' )
				);
			}

			return $blog_id;
		}

		if ( '' === $base_prefix ) {
			return new WP_Error(
				'sassh_posts_table_unmappable',
				__( 'The selected posts table cannot be associated with a registered WordPress site.', 'choctaw-wp-security' )
			);
		}

		$main_table = $base_prefix . 'posts';

		if ( $posts_table === $main_table || ( '' !== $configured && $posts_table === $configured && $configured === $main_table ) ) {
			$main_id = function_exists( 'get_main_site_id' ) ? (int) get_main_site_id() : 1;

			if ( ! self::is_registered_network_site( $main_id ) ) {
				return new WP_Error(
					'sassh_posts_table_orphaned',
					__( 'The selected posts table looks like the network main-site table, but no matching registered site record was found.', 'choctaw-wp-security' )
				);
			}

			return $main_id;
		}

		$pattern = '/^' . preg_quote( $base_prefix, '/' ) . '(\d+)_posts$/';

		if ( preg_match( $pattern, $posts_table, $matches ) ) {
			$blog_id = isset( $matches[1] ) ? (int) $matches[1] : 0;

			if ( $blog_id <= 0 || ! self::is_registered_network_site( $blog_id ) ) {
				return new WP_Error(
					'sassh_posts_table_orphaned',
					__( 'The selected posts table looks Multisite-shaped, but it does not correspond to a registered site in this network. It may be leftover or orphaned.', 'choctaw-wp-security' )
				);
			}

			return $blog_id;
		}

		return new WP_Error(
			'sassh_posts_table_foreign',
			__( 'The selected posts table appears to be foreign or leftover and is not associated with a registered WordPress site. Sassh only scans posts tables that belong to a registered site.', 'choctaw-wp-security' )
		);
	}

	/**
	 * Whether a blog_id has a corresponding site record in this installation.
	 *
	 * @param int $blog_id Blog id.
	 * @return bool
	 */
	public static function is_registered_network_site( $blog_id ) {
		return Sassh_Option_Key_Normalizer::is_registered_network_site( $blog_id );
	}

	/**
	 * Canonical object fingerprint for a post (complete reviewed post state).
	 *
	 * Length-prefixed: ID, title, content, excerpt, type, status.
	 *
	 * @param int    $post_id      Post ID.
	 * @param string $post_title   Raw title.
	 * @param string $post_content Raw content.
	 * @param string $post_excerpt Raw excerpt.
	 * @param string $post_type    Post type.
	 * @param string $post_status  Post status.
	 * @return string sha256:… fingerprint.
	 */
	public static function object_fingerprint( $post_id, $post_title, $post_content, $post_excerpt, $post_type, $post_status ) {
		$payload = self::length_prefixed(
			array(
				(string) (int) $post_id,
				(string) $post_title,
				(string) $post_content,
				(string) $post_excerpt,
				(string) $post_type,
				(string) $post_status,
			)
		);

		return Sassh_Findings_Service::content_fingerprint_from_string( $payload );
	}

	/**
	 * Category fingerprint for pattern matches on a post field.
	 *
	 * @param string             $field_value      Raw field bytes reviewed.
	 * @param array<int, string> $matched_patterns Sorted unique matched patterns.
	 * @return string
	 */
	public static function pattern_category_fingerprint( $field_value, array $matched_patterns ) {
		$patterns = array_values(
			array_unique(
				array_filter(
					array_map( 'strval', $matched_patterns )
				)
			)
		);
		sort( $patterns, SORT_STRING );

		$payload = self::length_prefixed(
			array_merge(
				array( (string) $field_value ),
				$patterns
			)
		);

		return Sassh_Findings_Service::content_fingerprint_from_string( $payload );
	}

	/**
	 * Category fingerprint for SEO spam title matches.
	 *
	 * @param string             $post_title Raw title.
	 * @param array<int, string> $keywords   Matched keywords.
	 * @return string
	 */
	public static function seo_category_fingerprint( $post_title, array $keywords ) {
		$keywords = array_values(
			array_unique(
				array_filter(
					array_map( 'strval', $keywords )
				)
			)
		);
		sort( $keywords, SORT_STRING );

		$payload = self::length_prefixed(
			array_merge(
				array( (string) $post_title ),
				$keywords
			)
		);

		return Sassh_Findings_Service::content_fingerprint_from_string( $payload );
	}

	/**
	 * Category fingerprint for large post content.
	 *
	 * @param int    $content_size Content byte length.
	 * @param string $post_content Raw content.
	 * @return string
	 */
	public static function large_content_category_fingerprint( $content_size, $post_content ) {
		$payload = self::length_prefixed(
			array(
				(string) (int) $content_size,
				hash( 'sha256', (string) $post_content ),
			)
		);

		return Sassh_Findings_Service::content_fingerprint_from_string( $payload );
	}

	/**
	 * Length-prefixed concatenation for stable hashing.
	 *
	 * @param array<int, string> $parts Parts.
	 * @return string
	 */
	private static function length_prefixed( array $parts ) {
		$out = '';

		foreach ( $parts as $part ) {
			$part = (string) $part;
			$out .= strlen( $part ) . ':' . $part . "\n";
		}

		return $out;
	}
}
