(function () {
	'use strict';

	var config = window.choctawWpSecurityFileChanges || {};
	var strings = config.strings || {};
	var filterState = {
		risk: ''
	};

	function ready(callback) {
		if (document.readyState === 'loading') {
			document.addEventListener('DOMContentLoaded', callback);
			return;
		}

		callback();
	}

	function text(value) {
		if (value === null || typeof value === 'undefined') {
			return '';
		}

		return String(value);
	}

	function clearElement(element) {
		while (element.firstChild) {
			element.removeChild(element.firstChild);
		}
	}

	function appendText(parent, value) {
		parent.appendChild(document.createTextNode(text(value)));
	}

	function createDashicon(iconClass) {
		var icon = document.createElement('span');

		icon.className = 'dashicons ' + iconClass;
		icon.setAttribute('aria-hidden', 'true');

		return icon;
	}

	function createCoreGuardMark() {
		var html = (window.choctawWpSecurityAdmin && window.choctawWpSecurityAdmin.coreGuardMarkHtml) || '';
		var holder;
		var mark;

		if (!html) {
			return createDashicon('dashicons-shield');
		}

		holder = document.createElement('span');
		holder.innerHTML = html;
		mark = holder.firstElementChild;

		return mark || createDashicon('dashicons-shield');
	}

	function mapChecksumStatusToRisk(status) {
		switch (status) {
			case 'verified':
				return 'safe';
			case 'failed':
				return 'critical';
			case 'missing':
				return 'missing';
			case 'not_applicable':
				return 'na';
			default:
				return 'na';
		}
	}

	function riskLabel(risk) {
		switch (risk) {
			case 'safe':
				return strings.riskSafe || 'Safe';
			case 'critical':
				return strings.riskCritical || 'Critical';
			case 'missing':
				return strings.riskMissing || 'Missing';
			case 'na':
				return strings.riskNa || strings.notApplicableAbbr || 'N/A';
			default:
				return strings.unavailable || '—';
		}
	}

	function riskExplanation(risk) {
		switch (risk) {
			case 'safe':
				return strings.riskExplainSafe || '';
			case 'critical':
				return strings.riskExplainCritical || '';
			case 'missing':
				return strings.riskExplainMissing || '';
			case 'na':
				return strings.riskExplainNa || '';
			case 'pending':
				return strings.riskExplainPending || '';
			default:
				return strings.riskExplainUnavailable || '';
		}
	}

	function renderRiskBadge(risk) {
		var wrap = document.createElement('div');
		var label = document.createElement('span');
		var icon = createCoreGuardMark();

		wrap.className = 'cws-risk is-' + risk;
		label.className = 'cws-risk-label';
		label.appendChild(icon);
		appendText(label, riskLabel(risk));
		wrap.appendChild(label);

		return wrap;
	}

	function updateRowRisk(row, status) {
		var cell = row.querySelector('.cws-file-change-risk-cell');
		var risk = mapChecksumStatusToRisk(status);
		var detailRowId = row.getAttribute('data-row-id');
		var detailRow;
		var explanation;

		if (!cell) {
			return;
		}

		clearElement(cell);
		cell.appendChild(renderRiskBadge(risk));
		row.setAttribute('data-risk', risk);

		if (detailRowId) {
			detailRow = document.getElementById(detailRowId);
			if (detailRow) {
				explanation = detailRow.querySelector('[data-risk-explanation]');
				if (explanation) {
					clearElement(explanation);
					appendText(explanation, riskExplanation(risk));
				}
			}
		}
	}

	function applyRowVisibility() {
		var table = document.getElementById('cws-core-file-changes-table');

		if (!table) {
			return;
		}

		table.querySelectorAll('tbody tr[data-checksum-path]').forEach(function (row) {
			var risk = row.getAttribute('data-risk') || 'pending';
			var detailRowId = row.getAttribute('data-row-id');
			var detailRow = detailRowId ? document.getElementById(detailRowId) : null;
			var visible;

			// Always show the fixed watchlist unless a Risk filter is selected.
			if (filterState.risk && risk !== 'pending') {
				visible = filterState.risk === risk;
			} else {
				visible = true;
			}

			row.hidden = !visible;

			if (detailRow && !visible) {
				detailRow.hidden = true;
				row.querySelectorAll('.cws-report-eye').forEach(function (eye) {
					eye.setAttribute('aria-expanded', 'false');
				});
			}
		});
	}

	function showScanStatus(message) {
		var statusNode = document.getElementById('cws-core-file-changes-checksum-status');

		if (!statusNode) {
			return;
		}

		clearElement(statusNode);

		if (!message) {
			statusNode.hidden = true;
			return;
		}

		statusNode.hidden = false;
		statusNode.className = 'cws-checksum-scan-status is-error';
		appendText(statusNode, message);
	}

	function applyChecksumResults(paths) {
		var table = document.getElementById('cws-core-file-changes-table');

		if (!table || !paths) {
			return;
		}

		table.querySelectorAll('tbody tr[data-checksum-path]').forEach(function (row) {
			var checksumPath = row.getAttribute('data-checksum-path');
			var status = Object.prototype.hasOwnProperty.call(paths, checksumPath)
				? paths[checksumPath]
				: 'unavailable';

			updateRowRisk(row, status);
		});

		applyRowVisibility();
	}

	function bindFilters() {
		var riskSelect = document.getElementById('cws-file-changes-risk-filter');

		if (riskSelect) {
			riskSelect.addEventListener('change', function () {
				filterState.risk = riskSelect.value || '';
				applyRowVisibility();
			});
		}
	}

	function runChecksumVerification() {
		var table = document.getElementById('cws-core-file-changes-table');

		if (!table || !config.ajaxUrl || !config.nonce) {
			return;
		}

		var body = new window.FormData();

		body.append('action', 'choctaw_wp_security_file_changes_checksum');
		body.append('nonce', config.nonce);

		window.fetch(config.ajaxUrl, {
			method: 'POST',
			credentials: 'same-origin',
			body: body
		})
			.then(function (response) {
				return response.json();
			})
			.then(function (payload) {
				if (!payload || !payload.success || !payload.data) {
					throw new Error(strings.scanError || 'Unable to verify checksums for these files.');
				}

				applyChecksumResults(payload.data.paths || {});

				if (payload.data.errors && payload.data.errors.length) {
					showScanStatus(payload.data.errors.join(' '));
				}
			})
			.catch(function () {
				showScanStatus(strings.scanError || 'Unable to verify checksums for these files.');

				(table.querySelectorAll('tbody tr[data-checksum-path]') || []).forEach(function (row) {
					updateRowRisk(row, 'unavailable');
				});
				applyRowVisibility();
			});
	}

	ready(function () {
		bindFilters();
		runChecksumVerification();
	});
}());
