(function () {
	'use strict';

	var config = window.choctawWpSecurityFileChanges || {};
	var strings = config.strings || {};

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

	function renderStatusElement(status) {
		var wrapper = document.createElement('span');
		var label;

		switch (status) {
			case 'verified':
				wrapper.className = 'cws-checksum-status is-verified';
				label = strings.verified || 'Checksum verified';
				wrapper.setAttribute('aria-label', label);
				wrapper.setAttribute('title', label);
				wrapper.appendChild(createDashicon('dashicons-yes-alt'));
				break;
			case 'failed':
			case 'missing':
				wrapper.className = 'cws-checksum-status is-failed';
				label = status === 'missing'
					? (strings.missing || 'File missing')
					: (strings.failed || 'Checksum mismatch');
				wrapper.setAttribute('aria-label', label);
				wrapper.setAttribute('title', label);
				wrapper.appendChild(createDashicon('dashicons-dismiss'));
				break;
			case 'not_applicable':
				wrapper.className = 'cws-checksum-status is-not-applicable';
				label = strings.notApplicable || 'Not included in WordPress core checksums';
				wrapper.setAttribute('aria-label', label);
				wrapper.setAttribute('title', label);
				appendText(wrapper, strings.notApplicableAbbr || 'N/A');
				break;
			default:
				wrapper.className = 'cws-checksum-status is-unavailable';
				label = strings.unavailable || 'Checksum unavailable';
				wrapper.setAttribute('aria-label', label);
				wrapper.setAttribute('title', label);
				appendText(wrapper, '—');
				break;
		}

		return wrapper;
	}

	function updateRowStatus(row, status) {
		var cell = row.querySelector('.cws-checksum-verified-cell');

		if (!cell) {
			return;
		}

		clearElement(cell);
		cell.appendChild(renderStatusElement(status));
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

			updateRowStatus(row, status);
		});
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
					updateRowStatus(row, 'unavailable');
				});
			});
	}

	ready(runChecksumVerification);
}());
