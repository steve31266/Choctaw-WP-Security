<?php
/**
 * Reusable admin help / disclosure UI.
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Renders field descriptions, inline disclosures, and section About panels.
 */
class Choctaw_Wp_Security_Admin_Help {

	/**
	 * Allowed HTML for help detail panels.
	 *
	 * @return array<string, array<string, bool>>
	 */
	public static function get_allowed_detail_markup() {
		return array(
			'p'        => array(),
			'strong'   => array(),
			'em'       => array(),
			'code'     => array(
				'class' => true,
			),
			'a'        => array(
				'href'   => true,
				'target' => true,
				'rel'    => true,
			),
			'ul'       => array(),
			'ol'       => array(
				'class' => true,
			),
			'li'       => array(),
			'h3'       => array(),
			'h4'       => array(),
			'div'      => array(
				'class' => true,
			),
			'textarea' => array(
				'readonly' => true,
				'rows'     => true,
				'class'    => true,
			),
		);
	}

	/**
	 * Toggle button label.
	 *
	 * @return string
	 */
	public static function get_toggle_label() {
		return __( 'Why this matters', 'choctaw-wp-security' );
	}

	/**
	 * Recommendation label.
	 *
	 * @return string
	 */
	public static function get_recommendation_label() {
		return __( 'Recommended: On', 'choctaw-wp-security' );
	}

	/**
	 * Default label for section-level About panels on settings sections.
	 *
	 * @return string
	 */
	public static function get_section_about_label() {
		return __( 'About these protections', 'choctaw-wp-security' );
	}

	/**
	 * Default label for scan tab About panels.
	 *
	 * @return string
	 */
	public static function get_scan_about_label() {
		return __( 'About this scan', 'choctaw-wp-security' );
	}

	/**
	 * Default title for Guidance Boxes.
	 *
	 * @return string
	 */
	public static function get_guidance_box_title() {
		return __( 'How to fix this', 'choctaw-wp-security' );
	}

	/**
	 * Enqueue help assets on the plugin settings page.
	 *
	 * @return void
	 */
	public static function enqueue_assets() {
		wp_enqueue_style(
			'choctaw-wp-security-admin-help',
			CHOCTAW_WP_SECURITY_URL . 'assets/css/admin-help.css',
			array( 'choctaw-wp-security-admin' ),
			CHOCTAW_WP_SECURITY_VERSION
		);

		wp_enqueue_script(
			'choctaw-wp-security-admin-help',
			CHOCTAW_WP_SECURITY_URL . 'assets/js/admin-help.js',
			array(),
			CHOCTAW_WP_SECURITY_VERSION,
			true
		);

		wp_localize_script(
			'choctaw-wp-security-admin-help',
			'choctawWpSecurityAdmin',
			array(
				'coreGuardMarkHtml' => Choctaw_Wp_Security_Utils::get_coreguard_mark_html(),
			)
		);
	}

	/**
	 * Render the summary line for a consolidated feature row (no recommendation label).
	 *
	 * @param string               $id   Help content identifier.
	 * @param array<string, mixed> $args Optional overrides.
	 * @return void
	 */
	public static function render_feature_summary( $id, array $args = array() ) {
		$content = self::resolve_field_content( $id, $args );

		if ( empty( $content['summary'] ) && empty( $content['summary_html'] ) ) {
			return;
		}

		$detail        = isset( $content['detail'] ) ? trim( (string) $content['detail'] ) : '';
		$summary_class = 'description cws-feature-setting-summary';

		if ( ! empty( $args['summary_class'] ) ) {
			$summary_class = 'description ' . sanitize_html_class( (string) $args['summary_class'] );
		}
		?>
		<p class="<?php echo esc_attr( $summary_class ); ?>">
			<?php
			if ( ! empty( $content['summary_html'] ) ) {
				echo wp_kses( $content['summary_html'], self::get_allowed_detail_markup() );
			} else {
				echo esc_html( (string) $content['summary'] );
			}

			if ( '' !== $detail ) {
				self::render_disclosure_toggle( $id );
			}
			?>
		</p>
		<?php

		if ( '' !== $detail ) {
			self::render_help_panel( $id, $detail );
		}
	}

	/**
	 * Whether a help entry should show the recommendation label in feature headers.
	 *
	 * @param string $id Help content identifier.
	 * @return bool
	 */
	public static function shows_recommendation( $id ) {
		$content = self::resolve_field_content( $id, array() );

		return ! empty( $content['show_recommendation'] );
	}

	/**
	 * Render a settings field description with optional inline disclosure.
	 *
	 * @param string               $id   Help content identifier.
	 * @param array<string, mixed> $args Optional overrides.
	 * @return void
	 */
	public static function render_field_description( $id, array $args = array() ) {
		$content = self::resolve_field_content( $id, $args );

		if ( empty( $content['summary'] ) && empty( $content['summary_html'] ) ) {
			return;
		}

		$detail = isset( $content['detail'] ) ? trim( (string) $content['detail'] ) : '';
		?>
		<p class="description">
			<?php
			if ( ! empty( $content['summary_html'] ) ) {
				echo wp_kses( $content['summary_html'], self::get_allowed_detail_markup() );
			} else {
				echo esc_html( (string) $content['summary'] );
			}

			if ( ! empty( $content['show_recommendation'] ) ) {
				echo ' <span class="cws-help-recommendation">' . esc_html( self::get_recommendation_label() ) . '</span>';
			}

			if ( '' !== $detail ) {
				self::render_disclosure_toggle( $id );
			}
			?>
		</p>
		<?php

		if ( '' !== $detail ) {
			self::render_help_panel( $id, $detail );
		}
	}

	/**
	 * Render a scan tab intro: first paragraph visible, remainder behind Why this matters.
	 *
	 * @param string $id Help content identifier for tab intro data.
	 * @return void
	 */
	public static function render_tab_intro( $id ) {
		$intro = Choctaw_Wp_Security_Admin_Help_Content::get_tab_intro( $id );

		if ( empty( $intro ) ) {
			return;
		}

		$detail   = isset( $intro['detail_html'] ) ? trim( (string) $intro['detail_html'] ) : '';
		$panel_id = 'tab-' . $id;

		if ( ! empty( $intro['visible_html'] ) || ! empty( $intro['visible'] ) ) {
			echo '<p>';
			if ( ! empty( $intro['visible_html'] ) ) {
				echo wp_kses( (string) $intro['visible_html'], self::get_allowed_detail_markup() );
			} else {
				echo esc_html( (string) $intro['visible'] );
			}

			if ( '' !== $detail ) {
				self::render_disclosure_toggle( $panel_id );
			}
			echo '</p>';
		}

		if ( '' !== $detail ) {
			self::render_help_panel( $panel_id, $detail );
		}
	}

	/**
	 * Render scan report subsection guidance.
	 *
	 * @param string $guidance     Visible guidance text.
	 * @param string $section_key  Section identifier for panel IDs.
	 * @param string $detail_html  Optional supplementary detail HTML.
	 * @return void
	 */
	public static function render_scan_guidance( $guidance, $section_key, $detail_html = '' ) {
		$guidance    = trim( (string) $guidance );
		$detail_html = trim( (string) $detail_html );

		if ( '' === $guidance && '' === $detail_html ) {
			return;
		}

		if ( '' === $guidance ) {
			$guidance = wp_strip_all_tags( $detail_html );
		}

		$panel_id = 'scan-' . sanitize_key( $section_key );
		?>
		<p class="description">
			<?php echo esc_html( $guidance ); ?>
			<?php if ( '' !== $detail_html ) : ?>
				<?php self::render_disclosure_toggle( $panel_id ); ?>
			<?php endif; ?>
		</p>
		<?php if ( '' !== $detail_html ) : ?>
			<?php self::render_help_panel( $panel_id, $detail_html ); ?>
		<?php endif; ?>
		<?php
	}

	/**
	 * Render an Info Box (gray informational panel).
	 *
	 * Collapsible by default as a closed accordion. Pass collapsible => false
	 * to render a static panel (e.g. when nested inside another disclosure).
	 *
	 * @param string               $id   Info content identifier.
	 * @param array<string, mixed> $args Optional overrides. Supported: collapsible (bool).
	 * @return void
	 */
	public static function render_info_box( $id, array $args = array() ) {
		$collapsible = self::consume_collapsible_arg( $args );
		$content     = self::resolve_info_content( $id, $args );

		if ( ! self::info_box_has_body( $content ) ) {
			return;
		}

		$panel_id = self::get_panel_id( 'info-' . $id );
		$title_id = $panel_id . '-title';
		$title    = ! empty( $content['title'] ) ? (string) $content['title'] : __( 'Information', 'choctaw-wp-security' );
		$classes  = $collapsible ? 'cws-info-box cws-help-accordion' : 'cws-info-box';

		if ( $collapsible ) {
			?>
			<details
				class="<?php echo esc_attr( $classes ); ?>"
				id="<?php echo esc_attr( $panel_id ); ?>"
				aria-labelledby="<?php echo esc_attr( $title_id ); ?>"
			>
				<summary class="cws-help-accordion-summary">
					<span class="cws-help-accordion-summary-main">
						<span class="dashicons dashicons-info" aria-hidden="true"></span>
						<span class="cws-info-box-title" id="<?php echo esc_attr( $title_id ); ?>">
							<?php echo esc_html( $title ); ?>
						</span>
					</span>
					<span class="dashicons dashicons-arrow-down-alt2 cws-help-accordion-chevron" aria-hidden="true"></span>
				</summary>
				<div class="cws-info-box-body">
					<?php self::render_info_box_body( $content ); ?>
				</div>
			</details>
			<?php
			return;
		}
		?>
		<aside
			class="<?php echo esc_attr( $classes ); ?>"
			id="<?php echo esc_attr( $panel_id ); ?>"
			aria-labelledby="<?php echo esc_attr( $title_id ); ?>"
		>
			<header class="cws-info-box-header">
				<span class="dashicons dashicons-info" aria-hidden="true"></span>
				<h3 class="cws-info-box-title" id="<?php echo esc_attr( $title_id ); ?>">
					<?php echo esc_html( $title ); ?>
				</h3>
			</header>
			<div class="cws-info-box-body">
				<?php self::render_info_box_body( $content ); ?>
			</div>
		</aside>
		<?php
	}

	/**
	 * Render Info Box body content.
	 *
	 * @param array<string, mixed> $content Info content.
	 * @return void
	 */
	private static function render_info_box_body( array $content ) {
		if ( ! empty( $content['intro'] ) ) {
			echo '<p>' . esc_html( (string) $content['intro'] ) . '</p>';
		}

		if ( ! empty( $content['entries'] ) && is_array( $content['entries'] ) ) {
			foreach ( $content['entries'] as $entry ) {
				if ( ! is_array( $entry ) ) {
					continue;
				}
				?>
				<div class="cws-info-box-entry">
					<?php if ( ! empty( $entry['label'] ) ) : ?>
						<h4 class="cws-info-box-entry-label"><?php echo esc_html( (string) $entry['label'] ); ?></h4>
					<?php endif; ?>
					<?php if ( ! empty( $entry['text'] ) ) : ?>
						<p><?php echo esc_html( (string) $entry['text'] ); ?></p>
					<?php endif; ?>
				</div>
				<?php
			}
		}

		if ( ! empty( $content['body_html'] ) ) {
			echo wp_kses( (string) $content['body_html'], self::get_allowed_detail_markup() );
		}
	}

	/**
	 * Resolve Info Box content from registry and overrides.
	 *
	 * @param string               $id   Info identifier.
	 * @param array<string, mixed> $args Optional overrides.
	 * @return array<string, mixed>
	 */
	private static function resolve_info_content( $id, array $args ) {
		$content = Choctaw_Wp_Security_Admin_Help_Content::get_info( $id );
		$content = is_array( $content ) ? $content : array();

		return array_merge(
			array(
				'title'     => '',
				'intro'     => '',
				'entries'   => array(),
				'body_html' => '',
			),
			$content,
			$args
		);
	}

	/**
	 * Whether an Info Box has renderable body content.
	 *
	 * @param array<string, mixed> $content Info content.
	 * @return bool
	 */
	private static function info_box_has_body( array $content ) {
		if ( ! empty( $content['intro'] ) || ! empty( $content['body_html'] ) ) {
			return true;
		}

		return ! empty( $content['entries'] ) && is_array( $content['entries'] );
	}

	/**
	 * Render a Guidance Box with actionable instructions.
	 *
	 * Collapsible by default as a closed accordion. Pass collapsible => false
	 * to render a static panel (e.g. when nested inside another disclosure).
	 *
	 * @param string               $id   Guidance content identifier.
	 * @param array<string, mixed> $args Optional overrides. Supported: collapsible (bool).
	 * @return void
	 */
	public static function render_guidance_box( $id, array $args = array() ) {
		$collapsible = self::consume_collapsible_arg( $args );
		$content     = self::resolve_guidance_content( $id, $args );

		if ( ! self::guidance_box_has_body( $content ) ) {
			return;
		}

		$panel_id = self::get_panel_id( 'guidance-' . $id );
		$title_id = $panel_id . '-title';
		$title    = ! empty( $content['title'] ) ? (string) $content['title'] : self::get_guidance_box_title();
		$classes  = $collapsible ? 'cws-guidance-box cws-help-accordion' : 'cws-guidance-box';

		if ( $collapsible ) {
			?>
			<details
				class="<?php echo esc_attr( $classes ); ?>"
				id="<?php echo esc_attr( $panel_id ); ?>"
				aria-labelledby="<?php echo esc_attr( $title_id ); ?>"
			>
				<summary class="cws-help-accordion-summary">
					<span class="cws-help-accordion-summary-main">
						<span class="dashicons dashicons-admin-tools" aria-hidden="true"></span>
						<span class="cws-guidance-box-title" id="<?php echo esc_attr( $title_id ); ?>">
							<?php echo esc_html( $title ); ?>
						</span>
					</span>
					<span class="dashicons dashicons-arrow-down-alt2 cws-help-accordion-chevron" aria-hidden="true"></span>
				</summary>
				<div class="cws-guidance-box-body">
					<?php self::render_guidance_box_body( $content ); ?>
				</div>
			</details>
			<?php
			return;
		}
		?>
		<aside
			class="<?php echo esc_attr( $classes ); ?>"
			id="<?php echo esc_attr( $panel_id ); ?>"
			aria-labelledby="<?php echo esc_attr( $title_id ); ?>"
		>
			<header class="cws-guidance-box-header">
				<span class="dashicons dashicons-admin-tools" aria-hidden="true"></span>
				<h3 class="cws-guidance-box-title" id="<?php echo esc_attr( $title_id ); ?>">
					<?php echo esc_html( $title ); ?>
				</h3>
			</header>
			<div class="cws-guidance-box-body">
				<?php self::render_guidance_box_body( $content ); ?>
			</div>
		</aside>
		<?php
	}

	/**
	 * Read and remove the collapsible flag from render args.
	 *
	 * @param array<string, mixed> $args Render args (modified by reference).
	 * @return bool Whether the box should render as an accordion.
	 */
	private static function consume_collapsible_arg( array &$args ) {
		$collapsible = ! array_key_exists( 'collapsible', $args ) || ! empty( $args['collapsible'] );
		unset( $args['collapsible'] );

		return (bool) $collapsible;
	}

	/**
	 * Render Guidance Box body content.
	 *
	 * @param array<string, mixed> $content Guidance content.
	 * @return void
	 */
	private static function render_guidance_box_body( array $content ) {
		self::render_guidance_box_intro( $content );
		self::render_guidance_box_items( $content );
		self::render_guidance_box_steps( $content );
		self::render_guidance_box_sections( $content );

		if ( ! empty( $content['body_html'] ) ) {
			echo wp_kses( (string) $content['body_html'], self::get_allowed_detail_markup() );
		}
	}

	/**
	 * Render optional intro copy for a Guidance Box.
	 *
	 * @param array<string, mixed> $content Guidance content.
	 * @return void
	 */
	private static function render_guidance_box_intro( array $content ) {
		if ( ! empty( $content['intro_html'] ) ) {
			echo wp_kses( (string) $content['intro_html'], self::get_allowed_detail_markup() );
			return;
		}

		if ( ! empty( $content['intro'] ) ) {
			echo '<p>' . esc_html( (string) $content['intro'] ) . '</p>';
		}
	}

	/**
	 * Render optional checkmark action items for a Guidance Box.
	 *
	 * @param array<string, mixed> $content Guidance content.
	 * @return void
	 */
	private static function render_guidance_box_items( array $content ) {
		if ( empty( $content['items'] ) || ! is_array( $content['items'] ) ) {
			return;
		}
		?>
		<ul class="cws-guidance-box-actions">
			<?php foreach ( $content['items'] as $item ) : ?>
				<?php if ( ! is_array( $item ) ) : ?>
					<?php continue; ?>
				<?php endif; ?>
				<li>
					<span class="dashicons dashicons-yes-alt" aria-hidden="true"></span>
					<div class="cws-guidance-box-action-text">
						<?php if ( ! empty( $item['label'] ) && ! empty( $item['text_html'] ) ) : ?>
							<p>
								<strong><?php echo esc_html( (string) $item['label'] ); ?>:</strong>
								<?php echo wp_kses( (string) $item['text_html'], self::get_allowed_detail_markup() ); ?>
							</p>
						<?php elseif ( ! empty( $item['text_html'] ) ) : ?>
							<p><?php echo wp_kses( (string) $item['text_html'], self::get_allowed_detail_markup() ); ?></p>
						<?php elseif ( ! empty( $item['text'] ) ) : ?>
							<p>
								<?php if ( ! empty( $item['label'] ) ) : ?>
									<strong><?php echo esc_html( (string) $item['label'] ); ?>:</strong>
								<?php endif; ?>
								<?php echo esc_html( (string) $item['text'] ); ?>
							</p>
						<?php endif; ?>
						<?php if ( ! empty( $item['detail_html'] ) ) : ?>
							<p class="cws-guidance-box-action-detail">
								<?php echo wp_kses( (string) $item['detail_html'], self::get_allowed_detail_markup() ); ?>
							</p>
						<?php elseif ( ! empty( $item['detail'] ) ) : ?>
							<p class="cws-guidance-box-action-detail"><?php echo esc_html( (string) $item['detail'] ); ?></p>
						<?php endif; ?>
					</div>
				</li>
			<?php endforeach; ?>
		</ul>
		<?php
	}

	/**
	 * Render optional ordered steps for a Guidance Box.
	 *
	 * @param array<string, mixed> $content Guidance content.
	 * @return void
	 */
	private static function render_guidance_box_steps( array $content ) {
		if ( empty( $content['steps'] ) || ! is_array( $content['steps'] ) ) {
			return;
		}
		?>
		<ol class="cws-guidance-box-steps">
			<?php foreach ( $content['steps'] as $step ) : ?>
				<li><?php echo wp_kses( (string) $step, self::get_allowed_detail_markup() ); ?></li>
			<?php endforeach; ?>
		</ol>
		<?php
	}

	/**
	 * Render optional server/config sections for a Guidance Box.
	 *
	 * @param array<string, mixed> $content Guidance content.
	 * @return void
	 */
	private static function render_guidance_box_sections( array $content ) {
		if ( empty( $content['sections'] ) || ! is_array( $content['sections'] ) ) {
			return;
		}
		?>
		<div class="cws-guidance-box-sections">
			<?php foreach ( $content['sections'] as $section ) : ?>
				<?php if ( ! is_array( $section ) ) : ?>
					<?php continue; ?>
				<?php endif; ?>
				<section class="cws-guidance-box-section">
					<?php if ( ! empty( $section['heading'] ) ) : ?>
						<h4><?php echo esc_html( (string) $section['heading'] ); ?></h4>
					<?php endif; ?>
					<?php if ( ! empty( $section['text_html'] ) ) : ?>
						<p><?php echo wp_kses( (string) $section['text_html'], self::get_allowed_detail_markup() ); ?></p>
					<?php elseif ( ! empty( $section['text'] ) ) : ?>
						<p><?php echo esc_html( (string) $section['text'] ); ?></p>
					<?php endif; ?>
					<?php if ( isset( $section['code'] ) && '' !== (string) $section['code'] ) : ?>
						<?php
						$code_rows = ! empty( $section['code_rows'] ) ? (int) $section['code_rows'] : 2;
						?>
						<textarea readonly rows="<?php echo (int) $code_rows; ?>" class="large-text code"><?php echo esc_textarea( (string) $section['code'] ); ?></textarea>
					<?php endif; ?>
				</section>
			<?php endforeach; ?>
		</div>
		<?php
	}

	/**
	 * Resolve Guidance Box content from registry and overrides.
	 *
	 * @param string               $id   Guidance identifier.
	 * @param array<string, mixed> $args Optional overrides.
	 * @return array<string, mixed>
	 */
	private static function resolve_guidance_content( $id, array $args ) {
		$content = Choctaw_Wp_Security_Admin_Help_Content::get_guidance( $id );
		$content = is_array( $content ) ? $content : array();

		return array_merge(
			array(
				'title'      => '',
				'intro'      => '',
				'intro_html' => '',
				'items'      => array(),
				'steps'      => array(),
				'sections'   => array(),
				'body_html'  => '',
			),
			$content,
			$args
		);
	}

	/**
	 * Whether a Guidance Box has renderable body content.
	 *
	 * @param array<string, mixed> $content Guidance content.
	 * @return bool
	 */
	private static function guidance_box_has_body( array $content ) {
		if ( ! empty( $content['intro'] ) || ! empty( $content['intro_html'] ) || ! empty( $content['body_html'] ) ) {
			return true;
		}

		foreach ( array( 'items', 'steps', 'sections' ) as $key ) {
			if ( ! empty( $content[ $key ] ) && is_array( $content[ $key ] ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Render a standalone disclosure block (e.g. long instructional content).
	 *
	 * @param string               $id           Unique identifier.
	 * @param string               $detail_html  Panel HTML.
	 * @param string               $summary      Optional visible summary before the toggle.
	 * @param string               $toggle_label Optional toggle button label.
	 * @param array<string, mixed> $args         Optional overrides. Supported:
	 *                                           summary_is_html (bool), summary_class (string).
	 * @return void
	 */
	public static function render_disclosure_block( $id, $detail_html, $summary = '', $toggle_label = '', array $args = array() ) {
		$detail_html  = trim( (string) $detail_html );
		$summary      = trim( (string) $summary );
		$toggle_label = trim( (string) $toggle_label );

		if ( '' === $detail_html && '' === $summary ) {
			return;
		}

		if ( '' === $toggle_label ) {
			$toggle_label = self::get_toggle_label();
		}

		$summary_is_html = ! empty( $args['summary_is_html'] );
		$summary_class   = ! empty( $args['summary_class'] ) ? sanitize_html_class( (string) $args['summary_class'] ) : '';
		$paragraph_class = 'description';

		if ( '' !== $summary_class ) {
			$paragraph_class .= ' ' . $summary_class;
		}

		$panel_id = self::get_panel_id( $id );
		?>
		<p class="<?php echo esc_attr( $paragraph_class ); ?>">
			<?php
			if ( '' !== $summary ) {
				if ( $summary_is_html ) {
					echo wp_kses( $summary, self::get_allowed_detail_markup() );
				} else {
					echo esc_html( $summary );
				}
			}

			if ( '' !== $detail_html ) {
				self::render_disclosure_toggle( $id, $toggle_label );
			}
			?>
		</p>
		<?php
		if ( '' !== $detail_html ) {
			self::render_help_panel( $id, $detail_html );
		}
	}

	/**
	 * Render a hidden help detail panel.
	 *
	 * @param string $id          Help content identifier.
	 * @param string $detail_html Panel HTML.
	 * @param string $extra_class Optional extra CSS class.
	 * @return void
	 */
	private static function render_help_panel( $id, $detail_html, $extra_class = '' ) {
		$detail_html = trim( (string) $detail_html );

		if ( '' === $detail_html ) {
			return;
		}

		$classes = 'cws-help-panel';

		if ( '' !== trim( (string) $extra_class ) ) {
			$classes .= ' ' . sanitize_html_class( (string) $extra_class );
		}

		$panel_id = self::get_panel_id( $id );
		?>
		<div id="<?php echo esc_attr( $panel_id ); ?>" class="<?php echo esc_attr( $classes ); ?>" hidden>
			<?php echo wp_kses( $detail_html, self::get_allowed_detail_markup() ); ?>
		</div>
		<?php
	}

	/**
	 * Render a disclosure that expands to a Guidance Box.
	 *
	 * @param string $id           Unique disclosure identifier.
	 * @param string $guidance_id  Guidance Box registry identifier.
	 * @param string $toggle_label Toggle button label.
	 * @return void
	 */
	public static function render_guidance_disclosure( $id, $guidance_id, $toggle_label ) {
		$panel_id = self::get_panel_id( $id );
		?>
		<p class="description">
			<?php self::render_disclosure_toggle( $id, $toggle_label ); ?>
		</p>
		<div id="<?php echo esc_attr( $panel_id ); ?>" class="cws-help-panel" hidden>
			<?php self::render_guidance_box( $guidance_id, array( 'collapsible' => false ) ); ?>
		</div>
		<?php
	}

	/**
	 * Render a disclosure toggle button for a table row detail panel.
	 *
	 * @param string $id    Help content identifier.
	 * @param string $label Optional visible button label.
	 * @return void
	 */
	public static function render_disclosure_toggle( $id, $label = '' ) {
		$panel_id    = self::get_panel_id( $id );
		$button_label = '' !== trim( (string) $label ) ? (string) $label : self::get_toggle_label();
		?>
		<button
			type="button"
			class="cws-help-toggle"
			aria-expanded="false"
			aria-controls="<?php echo esc_attr( $panel_id ); ?>"
		><?php echo esc_html( $button_label ); ?></button>
		<?php
	}

	/**
	 * Label for table-row detail disclosures.
	 *
	 * @return string
	 */
	public static function get_more_info_label() {
		return __( 'More info', 'choctaw-wp-security' );
	}

	/**
	 * Render a full-width table row containing a hidden disclosure panel.
	 *
	 * @param string $id          Help content identifier.
	 * @param string $detail_html Panel HTML.
	 * @param int    $colspan     Number of columns to span.
	 * @return void
	 */
	public static function render_table_disclosure_row( $id, $detail_html, $colspan = 3 ) {
		$detail_html = trim( (string) $detail_html );

		if ( '' === $detail_html ) {
			return;
		}
		?>
		<tr class="cws-help-table-detail-row">
			<td colspan="<?php echo (int) $colspan; ?>" class="cws-help-table-detail-cell">
				<?php self::render_help_panel( $id, $detail_html, 'cws-help-panel-table-row' ); ?>
			</td>
		</tr>
		<?php
	}

	/**
	 * Resolve field help content from registry and overrides.
	 *
	 * @param string               $id   Help content identifier.
	 * @param array<string, mixed> $args Optional overrides.
	 * @return array<string, mixed>
	 */
	private static function resolve_field_content( $id, array $args ) {
		$content = Choctaw_Wp_Security_Admin_Help_Content::get_field( $id );
		$content = is_array( $content ) ? $content : array();

		return array_merge(
			array(
				'summary'             => '',
				'summary_html'        => '',
				'detail'              => '',
				'show_recommendation' => false,
			),
			$content,
			$args
		);
	}

	/**
	 * Build a stable panel element ID.
	 *
	 * @param string $id Help identifier.
	 * @return string
	 */
	private static function get_panel_id( $id ) {
		return 'cws-help-' . sanitize_key( (string) $id );
	}
}
