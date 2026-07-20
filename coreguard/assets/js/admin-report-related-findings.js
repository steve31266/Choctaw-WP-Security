/**
 * Related-findings detail block for Sassh Findings reports.
 *
 * Loads related items on detail expand (cap 10). Hidden when empty.
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

	function findingId(finding) {
		if (!finding || typeof finding !== 'object') {
			return '';
		}
		if (finding.finding_id) {
			return text(finding.finding_id);
		}
		return '';
	}

	function comparisonLabel(cmp) {
		if (cmp === 'same') {
			return strings.relatedSameFp || 'Same file contents fingerprint';
		}
		if (cmp === 'different') {
			return strings.relatedDiffFp || 'Different file contents fingerprint';
		}
		return strings.relatedUnknownFp || 'Object fingerprint comparison unavailable';
	}

	function scannerLabel(scannerId) {
		var id = text(scannerId);
		if (id === 'uploads-folder') {
			return 'Uploads Folder';
		}
		if (id === 'mu-plugins') {
			return 'MU-Plugins';
		}
		if (id === 'verify-checksums') {
			return 'Verify Checksums';
		}
		if (id === 'exposed-files') {
			return 'Exposed Files';
		}
		return id || '—';
	}

	function postRelated(findingIdValue) {
		var body = new window.FormData();
		body.append('action', 'sassh_finding_related');
		body.append('nonce', config.sasshNonce || '');
		body.append('finding_id', findingIdValue);

		return window.fetch(config.ajaxUrl || (window.ajaxurl || ''), {
			method: 'POST',
			credentials: 'same-origin',
			body: body
		}).then(function (response) {
			return response.json().then(function (payload) {
				if (!response.ok || !payload || !payload.success) {
					var message = payload && payload.data && payload.data.message
						? text(payload.data.message)
						: (strings.relatedLoadError || 'Related findings could not be loaded.');
					throw new Error(message);
				}
				return payload.data || {};
			});
		});
	}

	function renderRelatedList(items) {
		var list = createElement('ul', 'cws-related-findings-list');

		items.forEach(function (item) {
			var li = createElement('li', 'cws-related-findings-item');
			var title = text(item.title || item.object_key || item.finding_id);
			var meta = [
				scannerLabel(item.scanner_id),
				text(item.risk_label || item.risk_level),
				text(item.status_label || item.effective_status)
			];

			if (item.detection_state === 'not_detected') {
				meta.push(strings.notDetected || 'No Longer Detected');
			}

			li.appendChild(createElement('strong', '', title));
			li.appendChild(createElement('span', 'cws-related-findings-meta', meta.filter(Boolean).join(' · ')));
			li.appendChild(createElement('span', 'cws-related-findings-fp', comparisonLabel(item.object_fingerprint_comparison)));

			if (item.effective_status === 'dismissed' && item.object_fingerprint_comparison === 'same') {
				var hintTemplate = strings.relatedDismissedHint || 'This file was previously reported by %s and dismissed while its contents had the same fingerprint.';
				var hint = hintTemplate.indexOf('%s') !== -1
					? hintTemplate.replace('%s', scannerLabel(item.scanner_id))
					: hintTemplate;
				li.appendChild(createElement('p', 'cws-related-findings-hint', hint));
			}

			list.appendChild(li);
		});

		return list;
	}

	/**
	 * Append related-findings block to a detail panel parent.
	 * Fetches on expand; removes itself when empty.
	 *
	 * @param {HTMLElement} parent
	 * @param {Object} finding
	 * @return {HTMLElement|null}
	 */
	function appendRelatedFindings(parent, finding) {
		var id = findingId(finding);
		var block;

		if (!parent || !id) {
			return null;
		}

		block = createElement('div', 'cws-related-findings');
		block.hidden = true;
		parent.appendChild(block);

		postRelated(id)
			.then(function (data) {
				var items = (data && data.related_findings) ? data.related_findings : [];
				if (!items.length) {
					if (block.parentNode) {
						block.parentNode.removeChild(block);
					}
					return;
				}
				clearElement(block);
				block.appendChild(createElement('h4', '', strings.relatedFindings || 'Related findings'));
				block.appendChild(renderRelatedList(items));
				block.hidden = false;
			})
			.catch(function () {
				if (block.parentNode) {
					block.parentNode.removeChild(block);
				}
			});

		return block;
	}

	function clearElement(element) {
		while (element.firstChild) {
			element.removeChild(element.firstChild);
		}
	}

	window.CwsReportRelatedFindings = {
		appendRelatedFindings: appendRelatedFindings
	};
}(window, document));
