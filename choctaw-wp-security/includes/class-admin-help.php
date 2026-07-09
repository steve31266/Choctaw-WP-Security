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

		$panel_id      = self::get_panel_id( $id );
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
				?>
				<button
					type="button"
					class="cws-help-toggle"
					aria-expanded="false"
					aria-controls="<?php echo esc_attr( $panel_id ); ?>"
				><?php echo esc_html( self::get_toggle_label() ); ?></button>
				<?php
			}
			?>
		</p>
		<?php

		if ( '' !== $detail ) {
			?>
			<div id="<?php echo esc_attr( $panel_id ); ?>" class="cws-help-panel" hidden>
				<?php echo wp_kses( $detail, self::get_allowed_detail_markup() ); ?>
			</div>
			<?php
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

		$panel_id = self::get_panel_id( $id );
		$detail   = isset( $content['detail'] ) ? trim( (string) $content['detail'] ) : '';
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
				?>
				<button
					type="button"
					class="cws-help-toggle"
					aria-expanded="false"
					aria-controls="<?php echo esc_attr( $panel_id ); ?>"
				><?php echo esc_html( self::get_toggle_label() ); ?></button>
				<?php
			}
			?>
		</p>
		<?php

		if ( '' !== $detail ) {
			?>
			<div id="<?php echo esc_attr( $panel_id ); ?>" class="cws-help-panel" hidden>
				<?php echo wp_kses( $detail, self::get_allowed_detail_markup() ); ?>
			</div>
			<?php
		}
	}

	/**
	 * Render a collapsible About panel for a settings section or scan tab.
	 *
	 * @param string $id            Help content identifier.
	 * @param string $summary_label Visible summary text for the details element.
	 * @param string $detail_html   HTML shown inside the panel.
	 * @return void
	 */
	public static function render_section_about( $id, $summary_label, $detail_html ) {
		$detail_html = trim( (string) $detail_html );

		if ( '' === $detail_html ) {
			return;
		}
		?>
		<details class="cws-help-section-about" id="<?php echo esc_attr( self::get_panel_id( 'about-' . $id ) ); ?>">
			<summary><?php echo esc_html( $summary_label ); ?></summary>
			<div class="cws-help-panel">
				<?php echo wp_kses( $detail_html, self::get_allowed_detail_markup() ); ?>
			</div>
		</details>
		<?php
	}

	/**
	 * Render a scan tab intro: first paragraph visible, remainder in About panel.
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
		$panel_id = self::get_panel_id( 'tab-' . $id );

		if ( ! empty( $intro['visible_html'] ) || ! empty( $intro['visible'] ) ) {
			echo '<p>';
			if ( ! empty( $intro['visible_html'] ) ) {
				echo wp_kses( (string) $intro['visible_html'], self::get_allowed_detail_markup() );
			} else {
				echo esc_html( (string) $intro['visible'] );
			}

			if ( '' !== $detail ) {
				?>
				<button
					type="button"
					class="cws-help-toggle"
					aria-expanded="false"
					aria-controls="<?php echo esc_attr( $panel_id ); ?>"
				><?php echo esc_html( self::get_toggle_label() ); ?></button>
				<?php
			}
			echo '</p>';
		}

		if ( '' !== $detail ) {
			?>
			<div id="<?php echo esc_attr( $panel_id ); ?>" class="cws-help-panel" hidden>
				<?php echo wp_kses( $detail, self::get_allowed_detail_markup() ); ?>
			</div>
			<?php
		}

		if ( ! empty( $intro['about_html'] ) ) {
			self::render_section_about( $id, self::get_scan_about_label(), (string) $intro['about_html'] );
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

		$panel_id = self::get_panel_id( 'scan-' . sanitize_key( $section_key ) );
		?>
		<p class="description">
			<?php echo esc_html( $guidance ); ?>
			<?php if ( '' !== $detail_html ) : ?>
				<button
					type="button"
					class="cws-help-toggle"
					aria-expanded="false"
					aria-controls="<?php echo esc_attr( $panel_id ); ?>"
				><?php echo esc_html( self::get_toggle_label() ); ?></button>
			<?php endif; ?>
		</p>
		<?php if ( '' !== $detail_html ) : ?>
			<div id="<?php echo esc_attr( $panel_id ); ?>" class="cws-help-panel" hidden>
				<?php echo wp_kses( $detail_html, self::get_allowed_detail_markup() ); ?>
			</div>
		<?php endif; ?>
		<?php
	}

	/**
	 * Render an always-visible Guidance Box with actionable instructions.
	 *
	 * @param string               $id   Guidance content identifier.
	 * @param array<string, mixed> $args Optional overrides.
	 * @return void
	 */
	public static function render_guidance_box( $id, array $args = array() ) {
		$content = self::resolve_guidance_content( $id, $args );

		if ( ! self::guidance_box_has_body( $content ) ) {
			return;
		}

		$title_id = self::get_guidance_box_title_id( $id );
		$title    = ! empty( $content['title'] ) ? (string) $content['title'] : self::get_guidance_box_title();
		?>
		<aside class="cws-guidance-box" aria-labelledby="<?php echo esc_attr( $title_id ); ?>">
			<header class="cws-guidance-box-header">
				<span class="dashicons dashicons-admin-tools" aria-hidden="true"></span>
				<h3 class="cws-guidance-box-title" id="<?php echo esc_attr( $title_id ); ?>">
					<?php echo esc_html( $title ); ?>
				</h3>
			</header>
			<div class="cws-guidance-box-body">
				<?php self::render_guidance_box_intro( $content ); ?>
				<?php self::render_guidance_box_items( $content ); ?>
				<?php self::render_guidance_box_steps( $content ); ?>
				<?php self::render_guidance_box_sections( $content ); ?>
				<?php
				if ( ! empty( $content['body_html'] ) ) {
					echo wp_kses( (string) $content['body_html'], self::get_allowed_detail_markup() );
				}
				?>
			</div>
		</aside>
		<?php
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
	 * Build a stable Guidance Box title element ID.
	 *
	 * @param string $id Guidance identifier.
	 * @return string
	 */
	private static function get_guidance_box_title_id( $id ) {
		return self::get_panel_id( 'guidance-' . $id ) . '-title';
	}

	/**
	 * Render a standalone disclosure block (e.g. long instructional content).
	 *
	 * @param string $id          Unique identifier.
	 * @param string $detail_html Panel HTML.
	 * @param string $summary     Optional visible summary before the toggle.
	 * @return void
	 */
	public static function render_disclosure_block( $id, $detail_html, $summary = '' ) {
		$detail_html = trim( (string) $detail_html );
		$summary     = trim( (string) $summary );

		if ( '' === $detail_html && '' === $summary ) {
			return;
		}

		$panel_id = self::get_panel_id( $id );
		?>
		<p class="description">
			<?php
			if ( '' !== $summary ) {
				echo esc_html( $summary );
			}

			if ( '' !== $detail_html ) {
				?>
				<button
					type="button"
					class="cws-help-toggle"
					aria-expanded="false"
					aria-controls="<?php echo esc_attr( $panel_id ); ?>"
				><?php echo esc_html( self::get_toggle_label() ); ?></button>
				<?php
			}
			?>
		</p>
		<?php
		if ( '' !== $detail_html ) {
			?>
			<div id="<?php echo esc_attr( $panel_id ); ?>" class="cws-help-panel" hidden>
				<?php echo wp_kses( $detail_html, self::get_allowed_detail_markup() ); ?>
			</div>
			<?php
		}
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

		$panel_id = self::get_panel_id( $id );
		?>
		<tr class="cws-help-table-detail-row">
			<td colspan="<?php echo (int) $colspan; ?>" class="cws-help-table-detail-cell">
				<div id="<?php echo esc_attr( $panel_id ); ?>" class="cws-help-panel cws-help-panel-table-row" hidden>
					<?php echo wp_kses( $detail_html, self::get_allowed_detail_markup() ); ?>
				</div>
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
