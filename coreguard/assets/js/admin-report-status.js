/**
 * Shared report Status helpers (Needs Review / Review Not Needed / Dismissed).
 *
 * Expects window.choctawWpSecurityFindingStatus from wp_localize_script.
 */
(function (window, document) {
	'use strict';

	var config = window.choctawWpSecurityFindingStatus || {};
	var strings = config.strings || {};

	function text(value) {
		if (value === null || typeof value === 'undefined') {
			return '';
		}
		return String(value);
	}

	function createElement(tag, className, content) {
		var el = document.createElement(tag);
		if (className) {
			el.className = className;
		}
		if (typeof content !== 'undefined' && content !== null && content !== '') {
			el.appendChild(document.createTextNode(text(content)));
		}
		return el;
	}

	function findingFingerprint(finding) {
		if (!finding || typeof finding !== 'object') {
			return '';
		}
		if (finding.content_fingerprint) {
			return text(finding.content_fingerprint);
		}
		if (finding.fingerprint) {
			return text(finding.fingerprint);
		}
		return text(finding.id);
	}

	function findingId(finding) {
		if (!finding || typeof finding !== 'object') {
			return '';
		}
		if (finding.finding_id) {
			return text(finding.finding_id);
		}
		return '';
	}

	function usesSasshFindings(finding, scanType) {
		if (findingId(finding)) {
			return true;
		}
		return scanType === 'uploads-folder'
			|| scanType === 'mu-plugins'
			|| scanType === 'verify-checksums'
			|| scanType === 'exposed-files'
			|| scanType === 'database-scan'
			|| scanType === 'scheduled-tasks'
			|| scanType === 'component-scan'
			|| scanType === 'directory-browsing'
			|| scanType === 'wp-posts'
			|| (finding && finding.findings_backend === 'sassh');
	}

	function openStatusForFinding(finding) {
		var risk = finding && finding.risk ? text(finding.risk) : '';
		if (risk === 'safe' || risk === 'info') {
			return 'no_action_needed';
		}
		return 'needs_review';
	}

	function statusLabelFor(status) {
		if (status === 'dismissed') {
			return strings.dismissed || 'Dismissed';
		}
		if (status === 'no_action_needed') {
			return strings.noActionNeeded || 'Review Not Needed';
		}
		return strings.needsReview || 'Needs Review';
	}

	function findingStatus(finding) {
		if (finding && finding.status === 'dismissed') {
			return 'dismissed';
		}
		if (finding && finding.effective_status) {
			return text(finding.effective_status);
		}
		if (finding && finding.status) {
			return text(finding.status);
		}
		return openStatusForFinding(finding);
	}

	/**
	 * Canonical dismiss-control state from Findings (or local fallback).
	 *
	 * @param {Object} finding
	 * @return {'active'|'dismissed'|'not_dismissible'}
	 */
	function dismissalControlState(finding) {
		var supplied = finding && finding.dismissal_control_state
			? text(finding.dismissal_control_state)
			: '';
		if (supplied === 'active' || supplied === 'dismissed' || supplied === 'not_dismissible') {
			return supplied;
		}

		var status = findingStatus(finding);
		if (status === 'dismissed') {
			return 'dismissed';
		}
		if (finding && typeof finding.can_dismiss !== 'undefined') {
			return finding.can_dismiss ? 'active' : 'not_dismissible';
		}
		if (status === 'needs_review') {
			return 'active';
		}
		return 'not_dismissible';
	}

	/**
	 * Status filter matching.
	 */
	function matchesStatusFilter(finding, statusFilter) {
		var status = findingStatus(finding);

		if (statusFilter === 'dismissed') {
			return status === 'dismissed';
		}

		if (statusFilter === 'no_action_needed') {
			return status === 'no_action_needed';
		}

		if (statusFilter === 'needs_review') {
			return status === 'needs_review';
		}

		// All statuses.
		return true;
	}

	function renderStatusCell(finding) {
		var status = findingStatus(finding);
		// Prefer label derived from effective status so a stale status_label cannot disagree.
		var label = statusLabelFor(status);

		return createElement('span', 'cws-status-text', label);
	}

	function appendStatusFilter(toolbar, uiState, onChange) {
		var select = document.createElement('select');
		var options = [
			{ value: 'needs_review', label: strings.needsReview || 'Needs Review' },
			{ value: 'no_action_needed', label: strings.noActionNeeded || 'Review Not Needed' },
			{ value: 'dismissed', label: strings.dismissed || 'Dismissed' },
			{ value: '', label: strings.allStatuses || 'All statuses' }
		];

		select.setAttribute('aria-label', strings.status || 'Status');
		options.forEach(function (option) {
			var el = createElement('option', '', option.label);
			el.value = option.value;
			if (uiState.status === option.value) {
				el.selected = true;
			}
			select.appendChild(el);
		});
		select.addEventListener('change', function () {
			uiState.status = select.value;
			if (typeof onChange === 'function') {
				onChange();
			}
		});
		toolbar.appendChild(select);
		return select;
	}

	function postStatusAction(action, scanType, fingerprint) {
		var body = new window.FormData();
		body.append('action', action);
		body.append('nonce', config.nonce || '');
		body.append('scan_type', scanType);
		if (fingerprint) {
			body.append('fingerprint', fingerprint);
		}

		return window.fetch(config.ajaxUrl || '', {
			method: 'POST',
			credentials: 'same-origin',
			body: body
		}).then(function (response) {
			return response.json();
		}).then(function (payload) {
			if (!payload || !payload.success) {
				var message = payload && payload.data && payload.data.message
					? text(payload.data.message)
					: (strings.statusError || 'The status could not be updated.');
				throw new Error(message);
			}
			return payload.data || {};
		});
	}

	function postSasshFindingAction(action, id, fingerprint) {
		var body = new window.FormData();
		body.append('action', action);
		body.append('nonce', config.sasshNonce || '');
		body.append('finding_id', id);
		if (fingerprint) {
			body.append('fingerprint', fingerprint);
		}

		return window.fetch(config.ajaxUrl || '', {
			method: 'POST',
			credentials: 'same-origin',
			body: body
		}).then(function (response) {
			return response.json();
		}).then(function (payload) {
			if (!payload || !payload.success) {
				var message = payload && payload.data && payload.data.message
					? text(payload.data.message)
					: (strings.statusError || 'The status could not be updated.');
				throw new Error(message);
			}
			return payload.data || {};
		});
	}

	/**
	 * Append dismiss controls under How to proceed / Recommendations.
	 * State comes from Findings can_dismiss / dismissal_control_state (not per-scanner rules).
	 *
	 * @param {HTMLElement} parent
	 * @param {Object} finding
	 * @param {string} scanType
	 * @param {Function} onUpdated function(updatedFinding)
	 */
	function appendDismissControls(parent, finding, scanType, onUpdated) {
		var controlState = dismissalControlState(finding);
		var block = createElement('div', 'cws-report-dismiss');
		var error = createElement('p', 'cws-report-dismiss-error');
		var label;
		var checkbox;
		var submit;

		error.hidden = true;

		if (controlState === 'not_dismissible') {
			block.className = 'cws-report-dismiss is-not-dismissible';
			block.appendChild(
				createElement(
					'p',
					'cws-report-dismiss-note description',
					strings.notDismissible || 'This finding does not require review and cannot be dismissed.'
				)
			);
			parent.appendChild(block);
			return block;
		}

		label = createElement('label', 'cws-report-dismiss-label');
		checkbox = document.createElement('input');
		submit = createElement('button', 'button button-secondary cws-report-dismiss-submit', strings.submit || 'Submit');

		checkbox.type = 'checkbox';
		checkbox.className = 'cws-report-dismiss-checkbox';
		checkbox.checked = controlState === 'dismissed';

		label.appendChild(checkbox);
		label.appendChild(document.createTextNode(' ' + (strings.dismissThisItem || 'Dismiss this item')));

		submit.type = 'button';

		submit.addEventListener('click', function () {
			var fingerprint = findingFingerprint(finding);
			var id = findingId(finding);
			var wantDismissed = checkbox.checked;
			var request;

			error.hidden = true;
			submit.disabled = true;

			if (usesSasshFindings(finding, scanType)) {
				if (!id) {
					error.textContent = strings.statusError || 'The status could not be updated.';
					error.hidden = false;
					submit.disabled = false;
					checkbox.checked = findingStatus(finding) === 'dismissed';
					return;
				}
				request = postSasshFindingAction(
					wantDismissed ? 'sassh_finding_dismiss' : 'sassh_finding_undismiss',
					id,
					fingerprint
				);
			} else {
				request = postStatusAction(
					wantDismissed
						? 'choctaw_wp_security_finding_dismiss'
						: 'choctaw_wp_security_finding_undismiss',
					scanType,
					fingerprint
				);
			}

			request
				.then(function (data) {
					var nextStatus = wantDismissed
						? 'dismissed'
						: (data && data.status ? text(data.status) : openStatusForFinding(finding));
					finding.status = nextStatus;
					finding.effective_status = nextStatus;
					finding.status_label = (data && data.status_label) ? text(data.status_label) : statusLabelFor(nextStatus);
					finding.fingerprint = fingerprint;
					finding.content_fingerprint = fingerprint;
					finding.can_dismiss = nextStatus === 'needs_review' || nextStatus === 'dismissed';
					finding.dismissal_control_state = nextStatus === 'dismissed' ? 'dismissed' : (finding.can_dismiss ? 'active' : 'not_dismissible');
					if (id) {
						finding.finding_id = id;
					}
					if (typeof onUpdated === 'function') {
						onUpdated(finding);
					}
				})
				.catch(function (err) {
					error.textContent = err && err.message ? err.message : (strings.statusError || 'The status could not be updated.');
					error.hidden = false;
					checkbox.checked = findingStatus(finding) === 'dismissed';
				})
				.then(function () {
					submit.disabled = false;
				});
		});

		block.appendChild(label);
		block.appendChild(submit);
		block.appendChild(error);
		parent.appendChild(block);
		return block;
	}

	function bindClearHistoryButtons(root) {
		var scope = root || document;
		var buttons = scope.querySelectorAll('[data-cws-clear-history]');

		Array.prototype.forEach.call(buttons, function (button) {
			if (button.getAttribute('data-cws-clear-bound') === '1') {
				return;
			}
			button.setAttribute('data-cws-clear-bound', '1');
			button.addEventListener('click', function () {
				var scanType = button.getAttribute('data-cws-clear-history') || '';
				button.disabled = true;
				postStatusAction('choctaw_wp_security_finding_clear_history', scanType, '')
					.then(function () {
						window.location.reload();
					})
					.catch(function () {
						button.disabled = false;
						window.alert(strings.clearHistoryError || 'History could not be cleared.');
					});
			});
		});
	}

	/**
	 * Bind dismiss controls rendered by PHP (checksum fallback tables).
	 */
	function bindPhpDismissControls(root) {
		var scope = root || document;
		var blocks = scope.querySelectorAll('[data-cws-dismiss-block]');

		Array.prototype.forEach.call(blocks, function (block) {
			if (block.getAttribute('data-cws-dismiss-bound') === '1') {
				return;
			}
			block.setAttribute('data-cws-dismiss-bound', '1');

			var checkbox = block.querySelector('.cws-report-dismiss-checkbox');
			var submit = block.querySelector('.cws-report-dismiss-submit');
			var error = block.querySelector('.cws-report-dismiss-error');
			var scanType = block.getAttribute('data-scan-type') || '';
			var fingerprint = block.getAttribute('data-fingerprint') || '';
			var findingId = block.getAttribute('data-finding-id') || '';
			var currentStatus = block.getAttribute('data-status') || 'needs_review';

			if (!checkbox || !submit) {
				return;
			}

			submit.addEventListener('click', function () {
				var wantDismissed = checkbox.checked;
				var request;

				if (error) {
					error.hidden = true;
				}
				submit.disabled = true;

				if (findingId) {
					request = postSasshFindingAction(
						wantDismissed ? 'sassh_finding_dismiss' : 'sassh_finding_undismiss',
						findingId,
						fingerprint
					);
				} else {
					request = postStatusAction(
						wantDismissed ? 'choctaw_wp_security_finding_dismiss' : 'choctaw_wp_security_finding_undismiss',
						scanType,
						fingerprint
					);
				}

				request
					.then(function () {
						window.location.reload();
					})
					.catch(function (err) {
						if (error) {
							error.textContent = err && err.message ? err.message : (strings.statusError || 'The status could not be updated.');
							error.hidden = false;
						}
						checkbox.checked = currentStatus === 'dismissed';
						submit.disabled = false;
					});
			});
		});
	}

	function ready(callback) {
		if (document.readyState === 'loading') {
			document.addEventListener('DOMContentLoaded', callback);
			return;
		}
		callback();
	}

	ready(function () {
		bindClearHistoryButtons(document);
		bindPhpDismissControls(document);
	});

	window.CwsReportStatus = {
		matchesStatusFilter: matchesStatusFilter,
		renderStatusCell: renderStatusCell,
		appendStatusFilter: appendStatusFilter,
		appendDismissControls: appendDismissControls,
		dismissalControlState: dismissalControlState,
		findingStatus: findingStatus,
		findingFingerprint: findingFingerprint,
		findingId: findingId,
		openStatusForFinding: openStatusForFinding,
		bindClearHistoryButtons: bindClearHistoryButtons,
		bindPhpDismissControls: bindPhpDismissControls,
		strings: strings
	};
}(window, document));
