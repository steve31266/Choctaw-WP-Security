(function () {
	'use strict';

	var config = window.choctawWpSecurityCoreChecksum || {};
	var strings = config.strings || {};
	var categoryLabels = config.categoryLabels || {};
	var pageSize = parseInt(config.pageSize, 10) || 20;
	var resultState = null;
	var uiState = {
		page: 1,
		sortKey: 'path',
		sortDir: 'asc',
		risk: '',
		status: 'needs_review',
		category: '',
		search: '',
		expandedId: ''
	};

	var riskOrder = {
		critical: 4,
		warning: 3,
		suspicious: 2,
		alert: 2,
		safe: 1,
		info: 0
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

	function format(template) {
		var args = Array.prototype.slice.call(arguments, 1);
		return text(template).replace(/%(\d+\$)?s/g, function (match, position) {
			var index = position ? parseInt(position, 10) - 1 : 0;
			var value = typeof args[index] === 'undefined' ? '' : args[index];
			if (!position) {
				args.shift();
			}
			return text(value);
		});
	}

	function numberFormat(value) {
		var number = parseInt(value, 10);
		if (isNaN(number)) {
			return '0';
		}
		return number.toLocaleString();
	}

	function clearElement(element) {
		while (element.firstChild) {
			element.removeChild(element.firstChild);
		}
	}

	function appendText(parent, value) {
		parent.appendChild(document.createTextNode(text(value)));
	}

	function createCoreGuardMark() {
		var html = (window.choctawWpSecurityAdmin && window.choctawWpSecurityAdmin.coreGuardMarkHtml) || '';
		var holder;
		var mark;

		if (!html) {
			mark = document.createElement('span');
			mark.className = 'dashicons dashicons-shield';
			mark.setAttribute('aria-hidden', 'true');
			return mark;
		}

		holder = document.createElement('span');
		holder.innerHTML = html;
		mark = holder.firstElementChild;

		if (!mark) {
			mark = document.createElement('span');
			mark.className = 'dashicons dashicons-shield';
			mark.setAttribute('aria-hidden', 'true');
		}

		return mark;
	}

	function createElement(tagName, className, content) {
		var element = document.createElement(tagName);
		if (className) {
			element.className = className;
		}
		if (typeof content !== 'undefined') {
			appendText(element, content);
		}
		return element;
	}

	function showNotice(message, type) {
		var notices = document.getElementById('cws-core-checksum-js-notices');
		if (!notices) {
			return;
		}
		clearElement(notices);
		if (!message) {
			return;
		}
		var notice = createElement('div', 'notice notice-' + (type || 'info') + ' is-dismissible');
		notice.appendChild(createElement('p', '', message));
		notices.appendChild(notice);
	}

	function setBusy(isBusy, message) {
		var form = document.getElementById('cws-core-checksum-form');
		var resultsEl = document.getElementById('cws-core-checksum-js-results');
		if (!form) {
			return;
		}
		form.querySelectorAll('button, input[type="submit"]').forEach(function (button) {
			button.disabled = isBusy;
		});
		if (resultsEl) {
			resultsEl.querySelectorAll('button, select, input').forEach(function (control) {
				control.disabled = isBusy;
			});
		}
		if (isBusy) {
			showNotice(message, 'info');
		}
	}

	function request(action) {
		var body = new window.FormData();
		body.append('action', action);
		body.append('nonce', config.nonce || '');
		return window.fetch(config.ajaxUrl, {
			method: 'POST',
			credentials: 'same-origin',
			body: body
		}).then(function (response) {
			return response.json();
		}).then(function (payload) {
			if (!payload || !payload.success) {
				throw new Error(payload && payload.data && payload.data.message ? payload.data.message : '');
			}
			return payload.data || {};
		});
	}

	function riskLabel(risk) {
		var map = {
			critical: strings.riskCritical || 'Critical',
			warning: strings.riskWarning || 'Warning',
			suspicious: strings.riskSuspicious || 'Suspicious',
			alert: strings.riskAlert || 'Alert',
			safe: strings.riskSafe || 'Safe',
			info: strings.riskInfo || 'Info'
		};
		return map[risk] || risk || 'Info';
	}

	function collectFindings(result) {
		return result && Array.isArray(result.findings) ? result.findings : [];
	}

	function filteredFindings(findings) {
		var search = text(uiState.search).toLowerCase().trim();
		return findings.filter(function (finding) {
			if (uiState.risk && text(finding.risk || finding.risk_level) !== uiState.risk) {
				return false;
			}
			if (window.CwsReportStatus && !window.CwsReportStatus.matchesStatusFilter(finding, uiState.status)) {
				return false;
			}
			if (uiState.category && finding.category !== uiState.category) {
				return false;
			}
			if (search) {
				var haystack = (
					text(finding.path) + ' ' +
					text(finding.author) + ' ' +
					text(finding.description) + ' ' +
					text(finding.version)
				).toLowerCase();
				if (haystack.indexOf(search) === -1) {
					return false;
				}
			}
			return true;
		});
	}

	function sortedFindings(findings) {
		var list = findings.slice();
		var key = uiState.sortKey;
		var dir = uiState.sortDir === 'asc' ? 1 : -1;

		list.sort(function (left, right) {
			var a;
			var b;
			if (key === 'risk') {
				a = riskOrder[left.risk] || 0;
				b = riskOrder[right.risk] || 0;
				return (a - b) * dir;
			}
			if (key === 'category') {
				a = text(left.category_label || left.category).toLowerCase();
				b = text(right.category_label || right.category).toLowerCase();
			} else {
				a = text(left[key] || '').toLowerCase();
				b = text(right[key] || '').toLowerCase();
			}
			if (a < b) {
				return -1 * dir;
			}
			if (a > b) {
				return 1 * dir;
			}
			return 0;
		});
		return list;
	}

	function paginate(items) {
		var pagination = window.CwsReportPagination.paginate(items, uiState.page, pageSize);
		uiState.page = pagination.page;
		return pagination;
	}

	function renderPagination(parent, pagination) {
		window.CwsReportPagination.render(parent, pagination, {
			itemLabel: config.itemNoun || 'findings',
			onPageChange: function (page) {
				uiState.page = page;
				uiState.expandedId = '';
				renderResult(resultState);
			}
		});
	}

	function renderRiskCell(finding) {
		var wrap = createElement('div', 'cws-risk is-' + text(finding.risk || 'info'));
		var label = createElement('span', 'cws-risk-label');
		label.appendChild(createCoreGuardMark());
		appendText(label, finding.risk_label || riskLabel(finding.risk));
		wrap.appendChild(label);
		return wrap;
	}

	function sortableHeader(label, sortKey) {
		var th = document.createElement('th');
		var button = createElement('button', 'button-link', label);
		th.scope = 'col';
		button.type = 'button';
		button.addEventListener('click', function () {
			if (uiState.sortKey === sortKey) {
				uiState.sortDir = uiState.sortDir === 'asc' ? 'desc' : 'asc';
			} else {
				uiState.sortKey = sortKey;
				uiState.sortDir = sortKey === 'risk' ? 'desc' : 'asc';
			}
			uiState.page = 1;
			renderResult(resultState);
		});
		if (uiState.sortKey === sortKey) {
			button.appendChild(createElement('span', 'cws-sort-indicator', uiState.sortDir === 'asc' ? ' ▲' : ' ▼'));
		}
		th.appendChild(button);
		return th;
	}

	function renderToolbar(parent) {
		var toolbar = createElement('div', 'cws-report-toolbar');
		var riskLabelEl = document.createElement('label');
		var riskSelect = document.createElement('select');
		var categoryLabelEl = document.createElement('label');
		var categorySelect = document.createElement('select');
		var searchLabel = document.createElement('label');
		var searchInput = document.createElement('input');

		riskLabelEl.appendChild(createElement('span', 'screen-reader-text', strings.risk || 'Risk'));
		riskSelect.appendChild(new Option(strings.allRisks || 'All risks', ''));
		riskSelect.appendChild(new Option(strings.riskCritical || 'Critical', 'critical'));
		riskSelect.appendChild(new Option(strings.riskSuspicious || 'Suspicious', 'suspicious'));
		riskSelect.value = uiState.risk;
		riskSelect.addEventListener('change', function () {
			uiState.risk = riskSelect.value;
			uiState.page = 1;
			uiState.expandedId = '';
			renderResult(resultState);
		});
		riskLabelEl.appendChild(riskSelect);
		toolbar.appendChild(riskLabelEl);

		if (window.CwsReportStatus) {
			window.CwsReportStatus.appendStatusFilter(toolbar, uiState, function () {
				uiState.page = 1;
				renderResult(resultState);
			});
		}

		categoryLabelEl.appendChild(createElement('span', 'screen-reader-text', strings.category || 'Category'));
		categorySelect.appendChild(new Option(strings.allCategories || 'All categories', ''));
		Object.keys(categoryLabels).forEach(function (key) {
			categorySelect.appendChild(new Option(categoryLabels[key], key));
		});
		categorySelect.value = uiState.category;
		categorySelect.addEventListener('change', function () {
			uiState.category = categorySelect.value;
			uiState.page = 1;
			uiState.expandedId = '';
			renderResult(resultState);
		});
		categoryLabelEl.appendChild(categorySelect);
		toolbar.appendChild(categoryLabelEl);

		searchLabel.appendChild(createElement('span', 'screen-reader-text', strings.search || 'Search'));
		searchInput.type = 'search';
		searchInput.placeholder = strings.searchPlaceholder || 'Search files…';
		searchInput.value = uiState.search;
		searchInput.addEventListener('input', function () {
			uiState.search = searchInput.value;
			uiState.page = 1;
			uiState.expandedId = '';
			renderResult(resultState);
		});
		searchLabel.appendChild(searchInput);
		toolbar.appendChild(searchLabel);

		parent.appendChild(toolbar);
	}

	function appendInfoField(dl, label, value) {
		var dt = document.createElement('dt');
		var dd = document.createElement('dd');
		appendText(dt, label);
		appendText(dd, value || '—');
		dl.appendChild(dt);
		dl.appendChild(dd);
	}

	function displayValue(value) {
		var trimmed = text(value).trim();
		return trimmed ? trimmed : '—';
	}

	function renderDetailPanel(finding) {
		var grid = createElement('div', 'cws-report-detail-grid cws-core-checksum-detail-grid');
		var left = createElement('div', 'cws-core-checksum-detail-left');
		var right = createElement('div', 'cws-core-checksum-detail-right');
		var infoPanel = createElement('div', 'cws-core-checksum-info-panel');
		var infoList = document.createElement('dl');
		var contentsBlock = createElement('div', 'cws-core-checksum-contents');
		var textarea = document.createElement('textarea');
		var whyBlock = createElement('div', 'cws-core-checksum-why-block');
		var howBlock = createElement('div', 'cws-core-checksum-how-block');

		infoPanel.appendChild(createElement('h4', '', strings.infoPanel || 'Info'));
		appendInfoField(infoList, strings.modifiedDateTime || 'Modified Date/Time', displayValue(finding.modified_label));
		appendInfoField(infoList, strings.fileSize || 'File Size', displayValue(finding.size_label));
		appendInfoField(infoList, strings.permissions || 'Permissions', displayValue(finding.permissions));
		appendInfoField(infoList, strings.owner || 'Owner', displayValue(finding.owner));
		if (finding.confirmed_this_run === false) {
			appendInfoField(infoList, strings.confirmation || 'Confirmation', strings.notConfirmedThisRun || 'Not reconfirmed by this incomplete scan');
		}
		infoPanel.appendChild(infoList);

		contentsBlock.appendChild(createElement('h4', '', strings.contentsHeading || 'Contents'));
		textarea.readOnly = true;
		textarea.rows = 14;
		textarea.className = 'cws-file-contents-textarea large-text code';
		textarea.value = window.CwsReportPagination && typeof window.CwsReportPagination.withContentsFooter === 'function'
			? window.CwsReportPagination.withContentsFooter(finding.contents || '', !!finding.contents_truncated)
			: text(finding.contents || '');
		contentsBlock.appendChild(textarea);

		left.appendChild(infoPanel);
		left.appendChild(contentsBlock);

		whyBlock.appendChild(createElement('h4', '', strings.whySeeingThis || 'Why you are seeing this'));
		whyBlock.appendChild(createElement('p', '', finding.why_seeing_this || strings.whySeeingThisFallback || ''));
		howBlock.appendChild(createElement('h4', '', strings.howToProceed || 'How to proceed'));
		howBlock.appendChild(createElement('p', '', finding.how_to_proceed || strings.howToProceedFallback || ''));

		right.appendChild(whyBlock);
		right.appendChild(howBlock);

		if (window.CwsReportStatus) {
			window.CwsReportStatus.appendDismissControls(right, finding, config.scanType || 'verify-checksums', function () {
				uiState.expandedId = '';
				renderResult(resultState);
			});
		}

		if (window.CwsReportRelatedFindings) {
			window.CwsReportRelatedFindings.appendRelatedFindings(right, finding);
		}

		grid.appendChild(left);
		grid.appendChild(right);
		return grid;
	}

	function pathDirectory(path) {
		var value = text(path);
		var idx = value.lastIndexOf('/');
		// Root-relative files (e.g. agents.txt) show "/" like the legacy PHP report.
		if (idx === -1) {
			return value ? '/' : '';
		}
		return value.substring(0, idx + 1);
	}

	function pathBasename(path) {
		var value = text(path);
		var idx = value.lastIndexOf('/');
		return idx === -1 ? value : value.substring(idx + 1);
	}

	function renderFindingRow(tbody, finding) {
		var row = document.createElement('tr');
		var riskTd = document.createElement('td');
		var statusTd = document.createElement('td');
		var categoryTd = document.createElement('td');
		var pathTd = document.createElement('td');
		var fileTd = document.createElement('td');
		var actionsTd = document.createElement('td');
		var eye = createElement('button', 'cws-report-eye');
		var eyeIcon = createElement('span', 'dashicons dashicons-visibility');
		var rowKey = finding.finding_id || finding.id || finding.fingerprint || '';
		var isExpanded = uiState.expandedId === rowKey;

		if (isExpanded) {
			row.className = 'is-expanded';
		}
		if (finding.confirmed_this_run === false) {
			row.className = (row.className ? row.className + ' ' : '') + 'cws-finding-not-confirmed';
		}

		riskTd.appendChild(renderRiskCell(finding));
		row.appendChild(riskTd);
		if (window.CwsReportStatus) {
			statusTd.appendChild(window.CwsReportStatus.renderStatusCell(finding));
		}
		row.appendChild(statusTd);
		categoryTd.appendChild(createElement('span', 'cws-report-pill', finding.category_label || finding.category || ''));
		row.appendChild(categoryTd);
		pathTd.appendChild(createElement('code', 'cws-file-path', pathDirectory(finding.path)));
		row.appendChild(pathTd);
		fileTd.appendChild(createElement('code', 'cws-file-path', pathBasename(finding.path)));
		row.appendChild(fileTd);

		eye.type = 'button';
		eye.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
		eye.setAttribute('aria-label', isExpanded ? (strings.hideDetails || 'Hide details') : (strings.viewDetails || 'View details'));
		eyeIcon.setAttribute('aria-hidden', 'true');
		eye.appendChild(eyeIcon);
		eye.addEventListener('click', function () {
			uiState.expandedId = isExpanded ? '' : rowKey;
			renderResult(resultState);
		});
		actionsTd.appendChild(eye);
		row.appendChild(actionsTd);
		tbody.appendChild(row);

		if (isExpanded) {
			var detailRow = createElement('tr', 'cws-report-detail-row');
			var detailTd = document.createElement('td');
			detailTd.colSpan = 6;
			detailTd.appendChild(renderDetailPanel(finding));
			detailRow.appendChild(detailTd);
			tbody.appendChild(detailRow);
		}
	}

	function renderTable(parent, findings) {
		var section = createElement('div', 'cws-report-section cws-core-checksum-section');
		var sorted = sortedFindings(filteredFindings(findings));
		var pagination = paginate(sorted);
		var table = createElement('table', 'widefat striped cws-core-checksum-table cws-core-checksum-table');
		var thead = document.createElement('thead');
		var headerRow = document.createElement('tr');
		var tbody = document.createElement('tbody');
		var actionsTh = document.createElement('th');

		renderToolbar(section);

		if (!sorted.length) {
			section.appendChild(createElement('p', '', strings.noFindings || 'No findings matched the current filters.'));
			parent.appendChild(section);
			return;
		}

		headerRow.appendChild(sortableHeader(strings.risk || 'Risk', 'risk'));
		headerRow.appendChild(createElement('th', '', strings.status || 'Status'));
		headerRow.appendChild(sortableHeader(strings.category || 'Category', 'category'));
		headerRow.appendChild(sortableHeader(strings.path || 'Path', 'path'));
		headerRow.appendChild(createElement('th', '', strings.file || 'File'));
		actionsTh.scope = 'col';
		appendText(actionsTh, strings.actions || 'Action');
		headerRow.appendChild(actionsTh);
		thead.appendChild(headerRow);
		table.appendChild(thead);

		pagination.items.forEach(function (finding) {
			renderFindingRow(tbody, finding);
		});
		table.appendChild(tbody);
		section.appendChild(table);
		renderPagination(section, pagination);
		parent.appendChild(section);
	}

	function renderSummary(resultsEl, result) {
		var summary = result.summary || {};
		var criticalCount = parseInt(summary.critical, 10) || 0;
		var suspiciousCount = parseInt(summary.suspicious, 10) || 0;
		var incomplete = !!result.scan_incomplete || result.coverage_complete === false || (result.completion_status && result.completion_status !== 'success');
		var className = incomplete ? 'cws-core-checksum-results is-warning' : (criticalCount > 0 ? 'cws-core-checksum-results is-error' : (suspiciousCount > 0 ? 'cws-core-checksum-results is-warning' : 'cws-core-checksum-results is-success'));
		var panel = createElement('div', className);
		var message;
		var localeNote;

		if (incomplete) {
			message = strings.scanIncomplete || 'Scan coverage was incomplete. Previously detected findings were not cleared.';
		} else if (criticalCount > 0 || suspiciousCount > 0) {
			message = format(
				strings.scanCompleteIssues || 'Scan complete. %1$s critical and %2$s suspicious core checksum finding(s). %3$s file(s) checked for WordPress %4$s (%5$s).',
				numberFormat(criticalCount),
				numberFormat(suspiciousCount),
				numberFormat(result.checked || 0),
				text(result.version || ''),
				text(result.locale_effective || result.locale || '')
			);
		} else {
			message = format(
				strings.scanCompleteClean || 'Scan complete. All checked WordPress core files match official checksums for version %1$s (%2$s). %3$s files verified.',
				text(result.version || ''),
				text(result.locale_effective || result.locale || ''),
				numberFormat(result.checked || 0)
			);
		}

		panel.appendChild(createElement('p', 'cws-core-checksum-summary', message));

		if (incomplete && result.prior_findings_only) {
			panel.appendChild(createElement('p', 'description', strings.priorFindingsNote || 'Active findings below are from earlier successful scans and were not reconfirmed by this run.'));
		}

		if (result.locale_requested && result.locale_effective && result.locale_requested !== result.locale_effective) {
			localeNote = format(
				strings.localeFallback || 'Requested checksum locale %1$s; used %2$s.',
				text(result.locale_requested),
				text(result.locale_effective)
			);
			panel.appendChild(createElement('p', 'description', localeNote));
		}

		if (Array.isArray(result.errors) && result.errors.length) {
			result.errors.forEach(function (errorMessage) {
				panel.appendChild(createElement('p', 'description', errorMessage));
			});
		}

		resultsEl.appendChild(panel);
	}

	function renderResult(result) {
		var resultsEl = document.getElementById('cws-core-checksum-js-results');
		var fallback = document.getElementById('cws-core-checksum-fallback-results');
		if (!resultsEl || !result) {
			return;
		}
		resultState = result;
		clearElement(resultsEl);
		if (fallback) {
			fallback.style.display = 'none';
		}
		renderSummary(resultsEl, result);
		renderTable(resultsEl, collectFindings(result));
		var button = document.querySelector('#cws-core-checksum-form input[name="choctaw_wp_security_core_checksum_scan"]');
		if (button && resultState) {
			button.value = strings.rescanButton || button.value;
		}
	}

	function handleScan() {
		setBusy(true, strings.scanning);
		request('choctaw_wp_security_core_checksum_scan').then(function (data) {
			uiState.page = 1;
			uiState.expandedId = '';
			showNotice('', 'success');
			renderResult(data.result);
		}).catch(function (error) {
			showNotice(error.message || strings.scanError, 'error');
		}).finally(function () {
			setBusy(false);
		});
	}

	function init() {
		var form = document.getElementById('cws-core-checksum-form');
		if (!form || !config.ajaxUrl) {
			return;
		}
		form.addEventListener('submit', function (event) {
			event.preventDefault();
			handleScan();
		});
		if (config.initialResult && typeof config.initialResult === 'object') {
			renderResult(config.initialResult);
		}
	}

	ready(init);
})();
