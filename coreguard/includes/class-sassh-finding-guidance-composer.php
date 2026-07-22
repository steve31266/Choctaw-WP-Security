<?php
/**
 * Object-level Findings guidance composer (Phase 3.4.5).
 *
 * @package Choctaw_Wp_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Composes Why / How to proceed from category guidance contributions + subset recipes.
 */
class Sassh_Finding_Guidance_Composer {

	/**
	 * @var array<string, array<string, mixed>>|null
	 */
	private static $contribution_registry = null;

	/**
	 * Compose guidance for active categories.
	 *
	 * @param array<int, array<string, mixed>> $active_categories Active enriched categories.
	 * @param string                           $scanner_id        Scanner id.
	 * @return array<string, mixed>
	 */
	public static function compose( array $active_categories, $scanner_id ) {
		$scanner_id = (string) $scanner_id;
		$rule_ids   = array();
		$by_rule    = array();

		foreach ( $active_categories as $cat ) {
			$rule_id = isset( $cat['rule_id'] ) ? (string) $cat['rule_id'] : '';
			if ( '' === $rule_id ) {
				continue;
			}
			$rule_ids[]        = $rule_id;
			$by_rule[ $rule_id ] = $cat;
		}

		$rule_ids = array_values( array_unique( $rule_ids ) );
		sort( $rule_ids, SORT_STRING );

		$contributions = self::collect_contributions( $by_rule );
		self::assert_registry_consistent( $contributions );

		$recipe = self::select_recipe( $scanner_id, $rule_ids );

		if ( $recipe ) {
			$covered = isset( $recipe['required_rule_ids'] ) ? (array) $recipe['required_rule_ids'] : array();
			$covered = array_merge( $covered, isset( $recipe['optional_rule_ids'] ) ? (array) $recipe['optional_rule_ids'] : array() );
			$covered = array_values( array_intersect( $rule_ids, $covered ) );

			$selected = self::apply_recipe( $recipe, $contributions, $covered );
			$residual_rules = array_values( array_diff( $rule_ids, $covered ) );
			if ( ! empty( $residual_rules ) ) {
				$residual = array();
				foreach ( $contributions as $c ) {
					if ( in_array( (string) $c['rule_id'], $residual_rules, true ) ) {
						$residual[] = $c;
					}
				}
				$selected = self::merge_without_conflict( $selected, self::fallback_compose( $residual ) );
			}
			$composed = $selected;
			$recipe_id = (string) $recipe['recipe_id'];
		} else {
			$composed  = self::fallback_compose( $contributions );
			$recipe_id = 'fallback';
		}

		return array(
			'why'            => isset( $composed['why'] ) ? $composed['why'] : array(),
			'how_to_proceed' => isset( $composed['how_to_proceed'] ) ? $composed['how_to_proceed'] : array(),
			'caveats'        => isset( $composed['caveats'] ) ? $composed['caveats'] : array(),
			'recipe_id'      => $recipe_id,
			'active_rule_ids'=> $rule_ids,
		);
	}

	/**
	 * Validate contribution registry consistency (same id ⇒ same text).
	 *
	 * @param array<int, array<string, mixed>> $contributions Contributions.
	 * @return void
	 * @throws RuntimeException On conflicting definitions.
	 */
	public static function assert_registry_consistent( array $contributions ) {
		$seen = array();
		foreach ( $contributions as $c ) {
			$id   = isset( $c['id'] ) ? (string) $c['id'] : '';
			$text = isset( $c['text'] ) ? (string) $c['text'] : '';
			if ( '' === $id ) {
				continue;
			}
			if ( isset( $seen[ $id ] ) && $seen[ $id ] !== $text ) {
				throw new RuntimeException( 'Conflicting guidance contribution id: ' . $id );
			}
			$seen[ $id ] = $text;
		}
	}

	/**
	 * @param array<string, array<string, mixed>> $by_rule Categories by rule.
	 * @return array<int, array<string, mixed>>
	 */
	private static function collect_contributions( array $by_rule ) {
		$out = array();
		foreach ( $by_rule as $rule_id => $cat ) {
			$pack = self::contributions_for_rule( $rule_id, $cat );
			foreach ( $pack as $c ) {
				$c['rule_id'] = $rule_id;
				$out[]        = $c;
			}
		}
		return $out;
	}

	/**
	 * @param string               $rule_id Rule id.
	 * @param array<string, mixed> $cat     Category.
	 * @return array<int, array<string, mixed>>
	 */
	private static function contributions_for_rule( $rule_id, array $cat ) {
		if ( ! empty( $cat['guidance_contributions'] ) && is_array( $cat['guidance_contributions'] ) ) {
			return $cat['guidance_contributions'];
		}
		if ( ! empty( $cat['metadata']['guidance_contributions'] ) && is_array( $cat['metadata']['guidance_contributions'] ) ) {
			return $cat['metadata']['guidance_contributions'];
		}

		// Built-in packs for cron reference recipe + component-scan.
		$builtin = self::builtin_packs();
		if ( isset( $builtin[ $rule_id ] ) ) {
			return $builtin[ $rule_id ];
		}

		// Shared pack for all known-vulnerability categories (vuln:{stable_id}).
		if ( 0 === strpos( (string) $rule_id, 'vuln:' ) && isset( $builtin['vuln'] ) ) {
			return $builtin['vuln'];
		}

		// Adapter from legacy why/how strings.
		$out  = array();
		$why  = isset( $cat['why_seeing_this'] ) ? $cat['why_seeing_this'] : ( isset( $cat['metadata']['why_seeing_this'] ) ? $cat['metadata']['why_seeing_this'] : null );
		$how  = isset( $cat['how_to_proceed'] ) ? $cat['how_to_proceed'] : ( isset( $cat['metadata']['how_to_proceed'] ) ? $cat['metadata']['how_to_proceed'] : null );
		$prio = 100;
		foreach ( self::texts_to_list( $why ) as $i => $text ) {
			$out[] = array(
				'id'               => $rule_id . '.legacy.why.' . $i,
				'kind'             => 'interpretation',
				'display_priority' => $prio + $i,
				'text'             => $text,
				'concern'          => $rule_id . '.why',
			);
		}
		foreach ( self::texts_to_list( $how ) as $i => $text ) {
			$kind = self::looks_destructive( $text ) ? 'recommended_action' : 'recommended_action';
			$tags = self::looks_destructive( $text ) ? array( 'destructive' ) : array( 'investigate' );
			$out[] = array(
				'id'               => $rule_id . '.legacy.how.' . $i,
				'kind'             => $kind,
				'display_priority' => 200 + $i,
				'text'             => self::looks_destructive( $text ) ? self::conditionalize_destructive( $text ) : $text,
				'tags'             => $tags,
				'concern'          => $rule_id . '.how',
			);
		}
		return $out;
	}

	/**
	 * Built-in contribution packs (cron reference).
	 *
	 * @return array<string, array<int, array<string, mixed>>>
	 */
	private static function builtin_packs() {
		return array(
			'unknown-hook' => array(
				array(
					'id'               => 'cron.unknown_hook.evidence.unfamiliar',
					'kind'             => 'evidence_fact',
					'display_priority' => 10,
					'text'             => 'This scheduled event uses a hook name that is not in the recognized WordPress core, plugin, or theme catalog for this site.',
					'concern'          => 'cron.identity',
				),
				array(
					'id'               => 'cron.unknown_hook.interpretation.not_proof',
					'kind'             => 'warning_caveat',
					'display_priority' => 10,
					'text'             => 'An unfamiliar hook name alone is not proof of malware; custom or renamed plugins often register uncommon hooks.',
					'concern'          => 'cron.certainty',
					'severity'        => 50,
				),
				array(
					'id'               => 'cron.unknown_hook.action.identify_owner',
					'kind'             => 'recommended_action',
					'display_priority' => 20,
					'text'             => 'Identify which plugin, theme, or custom code registers this hook before changing or deleting the event.',
					'tags'             => array( 'investigate', 'nondestructive' ),
					'concern'          => 'cron.proceed',
				),
			),
			'unregistered-handler' => array(
				array(
					'id'               => 'cron.unregistered_handler.evidence.no_action',
					'kind'             => 'evidence_fact',
					'display_priority' => 20,
					'text'             => 'No current action callback is registered for this hook (has_action is empty for non-core allowlisted hooks).',
					'concern'          => 'cron.handler',
				),
				array(
					'id'               => 'cron.unregistered_handler.interpretation.orphan',
					'kind'             => 'interpretation',
					'display_priority' => 20,
					'text'             => 'This often means an inactive or removed plugin left an orphaned cron event, or the handler registers lazily.',
					'concern'          => 'cron.handler',
				),
				array(
					'id'               => 'cron.unregistered_handler.caveat.not_proof',
					'kind'             => 'warning_caveat',
					'display_priority' => 10,
					'text'             => 'A missing handler is not by itself high-confidence malware evidence.',
					'concern'          => 'cron.certainty',
					'severity'        => 40,
				),
				array(
					'id'               => 'cron.unregistered_handler.prereq.confirm_unused',
					'kind'             => 'prerequisite',
					'display_priority' => 30,
					'text'             => 'Confirm that the event belongs to a plugin or feature that was intentionally removed and is no longer needed.',
					'concern'          => 'cron.prereq',
				),
				array(
					'id'               => 'cron.unregistered_handler.action.remove_conditional',
					'kind'             => 'recommended_action',
					'display_priority' => 80,
					'text'             => 'If you confirm that the event belongs to a plugin that was intentionally removed and is no longer needed, back up the site and remove the orphaned event.',
					'tags'             => array( 'destructive' ),
					'requires'         => array( 'cron.unregistered_handler.prereq.confirm_unused' ),
					'concern'          => 'cron.proceed',
				),
			),
			'missing-source' => array(
				array(
					'id'               => 'cron.missing_source.evidence.no_owner',
					'kind'             => 'evidence_fact',
					'display_priority' => 30,
					'text'             => 'Sassh could not attribute this event to an active plugin or theme source on disk.',
					'concern'          => 'cron.source',
				),
				array(
					'id'               => 'cron.missing_source.action.locate',
					'kind'             => 'recommended_action',
					'display_priority' => 40,
					'text'             => 'Search installed (including inactive) plugins and mu-plugins for the hook name before cleanup.',
					'tags'             => array( 'investigate', 'nondestructive' ),
					'concern'          => 'cron.proceed',
				),
			),
			// Shared pack for rule_id prefix vuln:{stable_id} (Phase 3.5).
			'vuln' => array(
				array(
					'id'               => 'component.vuln.evidence.known_advisory',
					'kind'             => 'evidence_fact',
					'display_priority' => 10,
					'text'             => 'A public advisory in the WPVulnerability database applies to the installed version of this component.',
					'concern'          => 'component.vuln.evidence',
				),
				array(
					'id'               => 'component.vuln.interpretation.exposure_not_infection',
					'kind'             => 'warning_caveat',
					'display_priority' => 10,
					'text'             => 'A known vulnerability means exposure / unpatched risk. It is not evidence that this site is infected or that malware is present. Review the CVSS severity shown for the advisory; Sassh Warning here means review urgency, not a malware verdict.',
					'concern'          => 'component.vuln.certainty',
					'severity'        => 80,
				),
				array(
					'id'               => 'component.vuln.action.update_or_mitigate',
					'kind'             => 'recommended_action',
					'display_priority' => 20,
					'text'             => 'Update the component to a fixed version when available, or apply vendor mitigation guidance. Prefer official updates over deleting software until you understand the impact.',
					'tags'             => array( 'investigate', 'nondestructive' ),
					'concern'          => 'component.vuln.proceed',
				),
			),
			'unrecognized-component' => array(
				array(
					'id'               => 'component.unrecognized.evidence.not_in_db',
					'kind'             => 'evidence_fact',
					'display_priority' => 10,
					'text'             => 'The WPVulnerability API returned a valid response indicating this plugin or theme is not listed in popular public directories (or its slug may be custom/altered).',
					'concern'          => 'component.unrecognized.evidence',
				),
				array(
					'id'               => 'component.unrecognized.interpretation.not_malware',
					'kind'             => 'interpretation',
					'display_priority' => 20,
					'text'             => 'Unrecognized does not mean unsafe. Premium, private, hosting-bundled, or custom components often appear here. It does mean Sassh cannot automatically evaluate known vulnerabilities for it.',
					'concern'          => 'component.unrecognized.certainty',
				),
				array(
					'id'               => 'component.unrecognized.action.review_source',
					'kind'             => 'recommended_action',
					'display_priority' => 30,
					'text'             => 'Confirm you intentionally installed this component from a trusted source. If it is unused, uninstall it to reduce attack surface. Dismiss only after you have reviewed the current version.',
					'tags'             => array( 'investigate', 'nondestructive' ),
					'concern'          => 'component.unrecognized.proceed',
				),
			),
		);
	}

	/**
	 * Recipe registry with subset matching.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private static function recipes() {
		return array(
			array(
				'recipe_id'          => 'scheduled-tasks/unknown-hook+unregistered-handler',
				'scanner_id'         => 'scheduled-tasks',
				'required_rule_ids'  => array( 'unknown-hook', 'unregistered-handler' ),
				'optional_rule_ids'  => array( 'missing-source' ),
				'excluded_rule_ids'  => array(),
				'priority'           => 100,
				'select_ids'         => array(
					'cron.unknown_hook.evidence.unfamiliar',
					'cron.unregistered_handler.evidence.no_action',
					'cron.unregistered_handler.interpretation.orphan',
					'cron.unknown_hook.interpretation.not_proof',
					'cron.unknown_hook.action.identify_owner',
					'cron.unregistered_handler.prereq.confirm_unused',
					'cron.unregistered_handler.action.remove_conditional',
					'cron.missing_source.evidence.no_owner',
					'cron.missing_source.action.locate',
				),
			),
			// Lower-priority overlapping recipe for dual-match fixture tests.
			array(
				'recipe_id'          => 'scheduled-tasks/unknown-hook-only',
				'scanner_id'         => 'scheduled-tasks',
				'required_rule_ids'  => array( 'unknown-hook' ),
				'optional_rule_ids'  => array(),
				'excluded_rule_ids'  => array(),
				'priority'           => 10,
				'select_ids'         => array(
					'cron.unknown_hook.evidence.unfamiliar',
					'cron.unknown_hook.interpretation.not_proof',
					'cron.unknown_hook.action.identify_owner',
				),
			),
		);
	}

	/**
	 * @param string             $scanner_id Scanner id.
	 * @param array<int, string> $rule_ids   Active rule ids (sorted).
	 * @return array<string, mixed>|null
	 */
	private static function select_recipe( $scanner_id, array $rule_ids ) {
		$matches = array();
		foreach ( self::recipes() as $recipe ) {
			if ( (string) $recipe['scanner_id'] !== $scanner_id ) {
				continue;
			}
			$required = isset( $recipe['required_rule_ids'] ) ? (array) $recipe['required_rule_ids'] : array();
			$excluded = isset( $recipe['excluded_rule_ids'] ) ? (array) $recipe['excluded_rule_ids'] : array();
			$ok       = true;
			foreach ( $required as $r ) {
				if ( ! in_array( (string) $r, $rule_ids, true ) ) {
					$ok = false;
					break;
				}
			}
			if ( ! $ok ) {
				continue;
			}
			foreach ( $excluded as $r ) {
				if ( in_array( (string) $r, $rule_ids, true ) ) {
					$ok = false;
					break;
				}
			}
			if ( ! $ok ) {
				continue;
			}
			$matches[] = $recipe;
		}

		if ( empty( $matches ) ) {
			return null;
		}

		usort(
			$matches,
			static function ( $a, $b ) {
				$ra = count( isset( $a['required_rule_ids'] ) ? $a['required_rule_ids'] : array() );
				$rb = count( isset( $b['required_rule_ids'] ) ? $b['required_rule_ids'] : array() );
				if ( $ra !== $rb ) {
					return $rb - $ra;
				}
				$pa = isset( $a['priority'] ) ? (int) $a['priority'] : 0;
				$pb = isset( $b['priority'] ) ? (int) $b['priority'] : 0;
				if ( $pa !== $pb ) {
					return $pb - $pa;
				}
				return strcmp( (string) $a['recipe_id'], (string) $b['recipe_id'] );
			}
		);

		return $matches[0];
	}

	/**
	 * @param array<string, mixed>             $recipe        Recipe.
	 * @param array<int, array<string, mixed>> $contributions All contributions.
	 * @param array<int, string>               $covered_rules Covered rule ids.
	 * @return array<string, array>
	 */
	private static function apply_recipe( array $recipe, array $contributions, array $covered_rules ) {
		$by_id = array();
		foreach ( $contributions as $c ) {
			if ( ! in_array( (string) $c['rule_id'], $covered_rules, true ) ) {
				continue;
			}
			$by_id[ (string) $c['id'] ] = $c;
		}
		$selected = array();
		foreach ( (array) $recipe['select_ids'] as $id ) {
			if ( isset( $by_id[ $id ] ) ) {
				$selected[] = $by_id[ $id ];
			}
		}
		return self::order_and_partition( $selected );
	}

	/**
	 * @param array<int, array<string, mixed>> $contributions Contributions.
	 * @return array<string, array>
	 */
	private static function fallback_compose( array $contributions ) {
		return self::order_and_partition( $contributions );
	}

	/**
	 * @param array<string, array> $base Base composed.
	 * @param array<string, array> $extra Extra composed.
	 * @return array<string, array>
	 */
	private static function merge_without_conflict( array $base, array $extra ) {
		$seen = array();
		foreach ( array( 'why', 'how_to_proceed', 'caveats' ) as $key ) {
			if ( ! isset( $base[ $key ] ) ) {
				$base[ $key ] = array();
			}
			foreach ( $base[ $key ] as $item ) {
				$id = is_array( $item ) && isset( $item['id'] ) ? (string) $item['id'] : '';
				if ( '' !== $id ) {
					$seen[ $id ] = true;
				}
			}
		}
		foreach ( array( 'why', 'how_to_proceed', 'caveats' ) as $key ) {
			if ( empty( $extra[ $key ] ) || ! is_array( $extra[ $key ] ) ) {
				continue;
			}
			foreach ( $extra[ $key ] as $item ) {
				$id = is_array( $item ) && isset( $item['id'] ) ? (string) $item['id'] : '';
				if ( '' !== $id && isset( $seen[ $id ] ) ) {
					continue;
				}
				if ( '' !== $id ) {
					$seen[ $id ] = true;
				}
				$base[ $key ][] = $item;
			}
		}
		return $base;
	}

	/**
	 * @param array<int, array<string, mixed>> $contributions Contributions.
	 * @return array<string, array>
	 */
	private static function order_and_partition( array $contributions ) {
		usort(
			$contributions,
			static function ( $a, $b ) {
				$pa = isset( $a['display_priority'] ) ? (int) $a['display_priority'] : 100;
				$pb = isset( $b['display_priority'] ) ? (int) $b['display_priority'] : 100;
				if ( $pa !== $pb ) {
					return $pa - $pb;
				}
				return strcmp( (string) $a['id'], (string) $b['id'] );
			}
		);

		$why     = array();
		$how     = array();
		$caveats = array();
		$seen    = array();

		foreach ( $contributions as $c ) {
			$id = (string) $c['id'];
			if ( isset( $seen[ $id ] ) ) {
				continue;
			}
			$seen[ $id ] = true;
			$kind = isset( $c['kind'] ) ? (string) $c['kind'] : '';
			$item = array(
				'id'   => $id,
				'text' => (string) $c['text'],
				'kind' => $kind,
			);
			if ( 'evidence_fact' === $kind || 'interpretation' === $kind ) {
				$why[] = $item;
			} elseif ( 'warning_caveat' === $kind ) {
				$caveats[] = array_merge(
					$item,
					array(
						'concern'   => isset( $c['concern'] ) ? (string) $c['concern'] : $id,
						'severity' => isset( $c['severity'] ) ? (int) $c['severity'] : 0,
					)
				);
			} elseif ( 'prerequisite' === $kind ) {
				$how[] = $item;
			} elseif ( 'recommended_action' === $kind ) {
				$tags = isset( $c['tags'] ) && is_array( $c['tags'] ) ? $c['tags'] : array();
				$text = (string) $c['text'];
				if ( in_array( 'destructive', $tags, true ) && ! self::is_already_conditional( $text ) ) {
					$text = self::conditionalize_destructive( $text );
				}
				$item['text'] = $text;
				$item['tags'] = $tags;
				$how[]        = $item;
			}
		}

		$caveats = self::merge_caveats( $caveats );

		return array(
			'why'            => $why,
			'how_to_proceed' => $how,
			'caveats'        => $caveats,
		);
	}

	/**
	 * Preserve non-overlapping caveats; strongest among same concern.
	 *
	 * @param array<int, array<string, mixed>> $caveats Caveats.
	 * @return array<int, array<string, mixed>>
	 */
	private static function merge_caveats( array $caveats ) {
		$by_concern = array();
		foreach ( $caveats as $c ) {
			$concern = isset( $c['concern'] ) ? (string) $c['concern'] : (string) $c['id'];
			$sev     = isset( $c['severity'] ) ? (int) $c['severity'] : 0;
			if ( ! isset( $by_concern[ $concern ] ) || $sev > (int) $by_concern[ $concern ]['severity'] ) {
				$by_concern[ $concern ] = $c;
			}
		}
		return array_values( $by_concern );
	}

	/**
	 * @param mixed $value String or list.
	 * @return array<int, string>
	 */
	private static function texts_to_list( $value ) {
		if ( is_array( $value ) ) {
			$out = array();
			foreach ( $value as $v ) {
				$v = trim( (string) $v );
				if ( '' !== $v ) {
					$out[] = $v;
				}
			}
			return $out;
		}
		$value = trim( (string) $value );
		return '' === $value ? array() : array( $value );
	}

	/**
	 * @param string $text Text.
	 * @return bool
	 */
	private static function looks_destructive( $text ) {
		return (bool) preg_match( '/\b(delete|remove|uninstall|drop)\b/i', $text );
	}

	/**
	 * @param string $text Text.
	 * @return bool
	 */
	private static function is_already_conditional( $text ) {
		return (bool) preg_match( '/^\s*if you confirm/i', $text );
	}

	/**
	 * @param string $text Text.
	 * @return string
	 */
	private static function conditionalize_destructive( $text ) {
		$text = trim( $text );
		if ( self::is_already_conditional( $text ) ) {
			return $text;
		}
		return 'If you confirm the related prerequisites and have an appropriate backup, then: ' . $text;
	}
}
