(function () {
	'use strict';

	var config = window.choctawWpSecurityDirectoryBrowsing || {};
	var strings = config.strings || {};
	var pageSize = parseInt(config.pageSize, 10) || 20;
	var resultState = null;
	var uiState = {
		page: 1,
		sortKey: 'risk',
		sortDir: 'desc',
		risk: '',
		status: '',
		search: '',
		expandedId: ''
	};

	var riskOrder = {
		critical: 5,
		review: 4,
		info: 2,
		safe: 1
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
		var notices = document.getElementById('cws-directory-browsing-js-notices');
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
		var form = document.getElementById('cws-directory-browsing-form');
		var resultsEl = document.getElementById('cws-directory-browsing-js-results');
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
			review: strings.riskReview || 'Review',
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
			if (uiState.risk && finding.risk !== uiState.risk) {
				return false;
			}
			if (window.CwsReportStatus && !window.CwsReportStatus.matchesStatusFilter(finding, uiState.status)) {
				return false;
			}
			if (search) {
				var haystack = (
					text(finding.path) + ' ' +
					text(finding.test_url) + ' ' +
					text(finding.server_type_label) + ' ' +
					text(finding.testing_method)
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
			a = text(left[key] || left.path || '').toLowerCase();
			b = text(right[key] || right.path || '').toLowerCase();
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

	function renderBrowsingCell(finding) {
		var state = text(finding.browsing || 'unknown');
		var wrap = createElement('span', 'cws-browsing-status is-' + state);
		wrap.appendChild(createElement('span', 'cws-browsing-status-label', finding.browsing_label || state));
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
		var searchLabel = document.createElement('label');
		var searchInput = document.createElement('input');

		riskLabelEl.appendChild(createElement('span', 'screen-reader-text', strings.risk || 'Risk'));
		riskSelect.appendChild(new Option(strings.allRisks || 'All risks', ''));
		riskSelect.appendChild(new Option(strings.riskCritical || 'Critical', 'critical'));
		riskSelect.appendChild(new Option(strings.riskReview || 'Review', 'review'));
		riskSelect.appendChild(new Option(strings.riskSafe || 'Safe', 'safe'));
		riskSelect.appendChild(new Option(strings.riskInfo || 'Info', 'info'));
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

		searchLabel.appendChild(createElement('span', 'screen-reader-text', strings.search || 'Search'));
		searchInput.type = 'search';
		searchInput.placeholder = strings.searchPlaceholder || 'Search path…';
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

	function infoPath(finding) {
		return text(finding.test_url) || text(finding.path) || '—';
	}

	function renderDetailPanel(finding) {
		var grid = createElement('div', 'cws-report-detail-grid cws-directory-browsing-detail-grid');
		var left = createElement('div', 'cws-directory-browsing-detail-left');
		var right = createElement('div', 'cws-directory-browsing-detail-right');
		var infoPanel = createElement('div', 'cws-directory-browsing-info-panel');
		var infoList = document.createElement('dl');
		var contentsBlock = createElement('div', 'cws-directory-browsing-contents');
		var textarea = document.createElement('textarea');
		var whyBlock = createElement('div', 'cws-directory-browsing-why-block');
		var howBlock = createElement('div', 'cws-directory-browsing-how-block');

		infoPanel.appendChild(createElement('h4', '', strings.infoPanel || 'Info'));
		appendInfoField(infoList, strings.testingMethod || 'Testing Method', finding.testing_method || '—');
		appendInfoField(infoList, strings.path || 'Path', infoPath(finding));
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
			window.CwsReportStatus.appendDismissControls(right, finding, config.scanType || 'directory-browsing', function () {
				uiState.expandedId = '';
				renderResult(resultState);
			});
		}

		grid.appendChild(left);
		grid.appendChild(right);
		return grid;
	}

	function renderFindingRow(tbody, finding) {
		var row = document.createElement('tr');
		var riskTd = document.createElement('td');
		var statusTd = document.createElement('td');
		var serverTd = document.createElement('td');
		var pathTd = document.createElement('td');
		var browsingTd = document.createElement('td');
		var actionsTd = document.createElement('td');
		var pathCode = createElement('code', 'cws-file-path', finding.path || '');
		var eye = createElement('button', 'cws-report-eye');
		var eyeIcon = createElement('span', 'dashicons dashicons-visibility');
		var isExpanded = uiState.expandedId === finding.id;

		if (isExpanded) {
			row.className = 'is-expanded';
		}

		riskTd.appendChild(renderRiskCell(finding));
		row.appendChild(riskTd);
		if (window.CwsReportStatus) {
			statusTd.appendChild(window.CwsReportStatus.renderStatusCell(finding));
		}
		row.appendChild(statusTd);
		appendText(serverTd, finding.server_type_label || '—');
		row.appendChild(serverTd);
		pathTd.appendChild(pathCode);
		row.appendChild(pathTd);
		browsingTd.appendChild(renderBrowsingCell(finding));
		row.appendChild(browsingTd);

		eye.type = 'button';
		eye.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
		eye.setAttribute('aria-label', isExpanded ? (strings.hideDetails || 'Hide details') : (strings.viewDetails || 'View details'));
		eyeIcon.setAttribute('aria-hidden', 'true');
		eye.appendChild(eyeIcon);
		eye.addEventListener('click', function () {
			uiState.expandedId = isExpanded ? '' : finding.id;
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
		var section = createElement('div', 'cws-report-section cws-directory-browsing-section');
		var sorted = sortedFindings(filteredFindings(findings));
		var pagination = paginate(sorted);
		var table = createElement('table', 'widefat striped cws-core-checksum-table cws-directory-browsing-table');
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
		headerRow.appendChild(sortableHeader(strings.serverType || 'Server Type', 'server_type_label'));
		headerRow.appendChild(sortableHeader(strings.path || 'Path', 'path'));
		headerRow.appendChild(sortableHeader(strings.directoryBrowsing || 'Directory Browsing', 'browsing'));
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
		var critical = parseInt(summary.critical, 10) || 0;
		var review = parseInt(summary.review, 10) || 0;
		var safe = parseInt(summary.safe, 10) || 0;
		var info = parseInt(summary.info, 10) || 0;
		var className = (critical > 0 || review > 0) ? 'cws-core-checksum-results is-error' : 'cws-core-checksum-results is-success';
		var panel = createElement('div', className);
		var message;

		if (critical > 0 || review > 0) {
			message = format(
				strings.scanCompleteIssues || 'Scan complete. %1$s critical, %2$s review, %3$s safe, and %4$s informational finding(s).',
				numberFormat(critical),
				numberFormat(review),
				numberFormat(safe),
				numberFormat(info)
			);
		} else {
			message = format(
				strings.scanCompleteClean || 'Scan complete. No critical or review findings. %1$s safe and %2$s informational item(s) reported.',
				numberFormat(safe),
				numberFormat(info)
			);
		}

		panel.appendChild(createElement('p', 'cws-core-checksum-summary', message));
		resultsEl.appendChild(panel);
	}

	function renderResult(result) {
		var resultsEl = document.getElementById('cws-directory-browsing-js-results');
		var fallback = document.getElementById('cws-directory-browsing-fallback-results');
		var helpBoxes = document.getElementById('cws-directory-browsing-help-boxes');
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
		if (helpBoxes) {
			helpBoxes.hidden = false;
		}
		var button = document.querySelector('#cws-directory-browsing-form input[name="choctaw_wp_security_exposed_folders_scan"]');
		if (button && resultState) {
			button.value = strings.rescanButton || button.value;
		}
	}

	function handleScan() {
		setBusy(true, strings.scanning);
		request('choctaw_wp_security_directory_browsing_scan').then(function (data) {
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
		var form = document.getElementById('cws-directory-browsing-form');
		if (!form || !config.ajaxUrl) {
			return;
		}
		form.addEventListener('submit', function (event) {
			event.preventDefault();
			handleScan();
		});
		if (window.CwsReportStatus && typeof window.CwsReportStatus.bindPhpDismissControls === 'function') {
			window.CwsReportStatus.bindPhpDismissControls(document.getElementById('cws-directory-browsing-fallback-results'));
		}
		if (config.initialResult && typeof config.initialResult === 'object') {
			renderResult(config.initialResult);
		}
	}

	ready(init);
})();
