(function () {
	'use strict';

	var config = window.choctawWpSecurityDatabaseScan || {};
	var strings = config.strings || {};
	var pageSize = parseInt(config.pageSize, 10) || 20;
	var resultState = null;
	var sectionState = {};

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

	function sizeFormat(bytes) {
		var size = parseInt(bytes, 10);
		var units = ['B', 'KB', 'MB', 'GB'];
		var index = 0;

		if (isNaN(size) || size <= 0) {
			return '-';
		}

		while (size >= 1024 && index < units.length - 1) {
			size = size / 1024;
			index++;
		}

		return (index === 0 ? Math.round(size) : size.toFixed(size >= 10 ? 1 : 2)) + ' ' + units[index];
	}

	function clearElement(element) {
		while (element.firstChild) {
			element.removeChild(element.firstChild);
		}
	}

	function appendText(parent, value) {
		parent.appendChild(document.createTextNode(text(value)));
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
		var notices = document.getElementById('cws-database-scan-js-notices');
		var notice;
		var paragraph;

		if (!notices) {
			return;
		}

		clearElement(notices);

		if (!message) {
			return;
		}

		notice = createElement('div', 'notice notice-' + (type || 'info') + ' is-dismissible');
		paragraph = createElement('p', '', message);
		notice.appendChild(paragraph);
		notices.appendChild(notice);
	}

	function getSelectedTable() {
		var selected = document.querySelector('input[name="database_scan_options_table"]:checked');

		return selected ? selected.value : '';
	}

	function selectTable(tableName) {
		var inputs;

		if (!tableName) {
			return;
		}

		inputs = document.querySelectorAll('input[name="database_scan_options_table"]');
		inputs.forEach(function (input) {
			if (input.value === tableName) {
				input.checked = true;
			}
		});
	}

	function setBusy(isBusy, message) {
		var form = document.getElementById('cws-database-scan-form');
		var resultsEl = document.getElementById('cws-database-scan-js-results');
		var buttons;

		if (!form) {
			return;
		}

		buttons = form.querySelectorAll('button, input[type="submit"]');
		buttons.forEach(function (button) {
			button.disabled = isBusy;
		});

		if (resultsEl) {
			resultsEl.querySelectorAll('button').forEach(function (button) {
				button.disabled = isBusy;
			});
		}

		if (isBusy) {
			showNotice(message, 'info');
		}
	}

	function request(action, tableName) {
		var body = new window.FormData();

		body.append('action', action);
		body.append('nonce', config.nonce || '');
		body.append('database_scan_options_table', tableName || '');

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

	function severityLabel(severity) {
		if (severity === 'critical') {
			return 'Critical';
		}

		if (severity === 'warning') {
			return 'Warning';
		}

		return 'Info';
	}

	function severityRank(severity) {
		if (severity === 'critical') {
			return 0;
		}

		if (severity === 'warning') {
			return 1;
		}

		return 2;
	}

	function optionIdLabel(finding) {
		var optionId = parseInt(finding.option_id, 10);

		if (finding.option_id_label) {
			return text(finding.option_id_label);
		}

		if (!isNaN(optionId) && optionId > 0) {
			return text(optionId);
		}

		return '-';
	}

	function getSortValue(finding, key) {
		if (key === 'severity') {
			return severityRank(finding.severity || 'info');
		}

		if (key === 'option_id') {
			return parseInt(finding.option_id, 10) || 0;
		}

		if (key === 'size') {
			return parseInt(finding.size, 10) || 0;
		}

		return text(finding[key] || '').toLowerCase();
	}

	function sortedFindings(sectionKey, findings) {
		var state = sectionState[sectionKey] || {};
		var sorted = findings.slice();

		if (!state.sortKey) {
			return sorted;
		}

		sorted.sort(function (left, right) {
			var leftValue = getSortValue(left, state.sortKey);
			var rightValue = getSortValue(right, state.sortKey);
			var result = 0;

			if (leftValue < rightValue) {
				result = -1;
			} else if (leftValue > rightValue) {
				result = 1;
			}

			return state.sortDirection === 'desc' ? result * -1 : result;
		});

		return sorted;
	}

	function setSort(sectionKey, sortKey) {
		var state = sectionState[sectionKey] || {};

		if (state.sortKey === sortKey) {
			state.sortDirection = state.sortDirection === 'asc' ? 'desc' : 'asc';
		} else {
			state.sortKey = sortKey;
			state.sortDirection = 'asc';
		}

		state.page = 1;
		sectionState[sectionKey] = state;
		renderResult(resultState);
	}

	function defaultSectionState(sectionKey) {
		if (sectionKey === 'large_autoload') {
			return {
				page: 1,
				sortKey: 'size',
				sortDirection: 'desc'
			};
		}

		return {
			page: 1,
			sortKey: 'severity',
			sortDirection: 'asc'
		};
	}

	function paginate(items, sectionKey) {
		var state = sectionState[sectionKey] || {};
		var total = items.length;
		var totalPages = Math.max(1, Math.ceil(total / pageSize));
		var page = Math.min(Math.max(parseInt(state.page, 10) || 1, 1), totalPages);
		var offset = (page - 1) * pageSize;

		state.page = page;
		sectionState[sectionKey] = state;

		return {
			items: items.slice(offset, offset + pageSize),
			page: page,
			total: total,
			totalPages: totalPages
		};
	}

	function pageButton(label, screenReaderText, disabled, callback) {
		var button = createElement('button', disabled ? 'button disabled' : 'button');
		var hidden = createElement('span', 'screen-reader-text', screenReaderText);
		var visible = createElement('span', '', label);

		button.type = 'button';
		button.disabled = disabled;
		visible.setAttribute('aria-hidden', 'true');
		button.appendChild(hidden);
		button.appendChild(visible);

		if (!disabled) {
			button.addEventListener('click', callback);
		}

		return button;
	}

	function renderPagination(parent, sectionKey, pagination) {
		var nav;
		var pages;
		var count;
		var links;
		var pageText;

		if (pagination.totalPages <= 1) {
			return;
		}

		nav = createElement('div', 'tablenav bottom cws-report-pagination');
		pages = createElement('div', 'tablenav-pages');
		count = createElement(
			'span',
			'displaying-num',
			format(pagination.total === 1 ? strings.item : strings.items, numberFormat(pagination.total))
		);
		links = createElement('span', 'pagination-links');
		pageText = createElement(
			'span',
			'paging-input',
			format(strings.pageOf, numberFormat(pagination.page), numberFormat(pagination.totalPages))
		);

		function goTo(page) {
			sectionState[sectionKey].page = page;
			renderResult(resultState);
		}

		links.appendChild(pageButton('«', strings.firstPage, pagination.page <= 1, function () {
			goTo(1);
		}));
		links.appendChild(pageButton('‹', strings.previousPage, pagination.page <= 1, function () {
			goTo(pagination.page - 1);
		}));
		links.appendChild(pageText);
		links.appendChild(pageButton('›', strings.nextPage, pagination.page >= pagination.totalPages, function () {
			goTo(pagination.page + 1);
		}));
		links.appendChild(pageButton('»', strings.lastPage, pagination.page >= pagination.totalPages, function () {
			goTo(pagination.totalPages);
		}));

		pages.appendChild(count);
		pages.appendChild(links);
		nav.appendChild(pages);
		parent.appendChild(nav);
	}

	function sortableHeader(label, sectionKey, sortKey) {
		var th = document.createElement('th');
		var button = createElement('button', 'cws-sortable-column', label);
		var state = sectionState[sectionKey] || {};

		th.scope = 'col';
		button.type = 'button';
		button.setAttribute('aria-label', label + ': ' + (state.sortKey === sortKey && state.sortDirection === 'asc' ? strings.sortDescending : strings.sortAscending));
		button.addEventListener('click', function () {
			setSort(sectionKey, sortKey);
		});

		if (state.sortKey === sortKey) {
			button.appendChild(createElement('span', 'cws-sort-indicator', state.sortDirection === 'asc' ? ' ▲' : ' ▼'));
		}

		th.appendChild(button);
		return th;
	}

	function renderFindingRow(tbody, finding, sectionKey) {
		var row = document.createElement('tr');
		var excerptCell;
		var optionCell;
		var code;

		row.appendChild(createElement('td', '', severityLabel(finding.severity || 'info')));
		row.appendChild(createElement('td', '', optionIdLabel(finding)));

		optionCell = document.createElement('td');
		code = createElement('code', 'cws-file-path', finding.option_name || '');
		optionCell.appendChild(code);
		row.appendChild(optionCell);

		row.appendChild(createElement('td', '', sizeFormat(finding.size || 0)));
		row.appendChild(createElement('td', '', finding.detail || ''));

		excerptCell = createElement('td', sectionKey === 'large_autoload' ? 'cws-database-scan-excerpt' : '', finding.excerpt || '');
		row.appendChild(excerptCell);
		tbody.appendChild(row);
	}

	function renderSection(resultsEl, sectionKey, section) {
		var findings = Array.isArray(section.findings) ? section.findings : [];
		var sorted = sortedFindings(sectionKey, findings);
		var pagination = paginate(sorted, sectionKey);
		var sectionEl = createElement('div', 'cws-report-section cws-database-scan-section' + (sectionKey === 'large_autoload' ? ' cws-database-scan-section-full-width' : ''));
		var heading = document.createElement('h3');
		var table;
		var thead;
		var headerRow;
		var tbody;

		appendText(heading, section.title || '');
		heading.appendChild(createElement('span', 'cws-database-scan-count', '(' + numberFormat(findings.length) + ')'));
		sectionEl.appendChild(heading);
		sectionEl.appendChild(createElement('p', 'description', section.guidance || ''));

		if (section.info_message) {
			var info = createElement('div', 'cws-core-checksum-results is-success');
			info.appendChild(createElement('p', 'cws-core-checksum-summary', section.info_message));
			sectionEl.appendChild(info);
			resultsEl.appendChild(sectionEl);
			return;
		}

		if (!findings.length) {
			sectionEl.appendChild(createElement('p', '', strings.noFindings));
			resultsEl.appendChild(sectionEl);
			return;
		}

		table = createElement('table', 'widefat striped cws-core-checksum-table');
		thead = document.createElement('thead');
		headerRow = document.createElement('tr');
		tbody = document.createElement('tbody');

		headerRow.appendChild(sortableHeader(strings.severity, sectionKey, 'severity'));
		headerRow.appendChild(sortableHeader(strings.optionId, sectionKey, 'option_id'));
		headerRow.appendChild(sortableHeader(strings.option, sectionKey, 'option_name'));
		headerRow.appendChild(sortableHeader(strings.size, sectionKey, 'size'));
		headerRow.appendChild(sortableHeader(strings.detail, sectionKey, 'detail'));
		headerRow.appendChild(sortableHeader(strings.excerpt, sectionKey, 'excerpt'));

		thead.appendChild(headerRow);
		table.appendChild(thead);

		pagination.items.forEach(function (finding) {
			renderFindingRow(tbody, finding, sectionKey);
		});

		table.appendChild(tbody);
		sectionEl.appendChild(table);
		renderPagination(sectionEl, sectionKey, pagination);
		resultsEl.appendChild(sectionEl);
	}

	function renderSummary(resultsEl, result) {
		var summary = result.summary || {};
		var critical = parseInt(summary.critical, 10) || 0;
		var warning = parseInt(summary.warning, 10) || 0;
		var info = parseInt(summary.info, 10) || 0;
		var hasProblems = critical + warning > 0;
		var className = critical > 0 ? 'cws-core-checksum-results is-error' : (warning > 0 ? 'cws-core-checksum-results is-warning' : 'cws-core-checksum-results is-success');
		var panel = createElement('div', className);
		var message = hasProblems ?
			format(strings.scanCompleteIssues, numberFormat(critical), numberFormat(warning), numberFormat(info)) :
			format(strings.scanCompleteClean, numberFormat(info));

		panel.appendChild(createElement('p', 'cws-core-checksum-summary', message));

		if (result.scan_incomplete) {
			panel.appendChild(createElement('p', '', strings.incomplete));
		}

		if (result.options_table) {
			panel.appendChild(createElement('p', '', format(strings.scannedTable, result.options_table)));
		}

		if (result.wordpress_configured_table && result.options_table && result.wordpress_configured_table !== result.options_table) {
			panel.appendChild(createElement('p', '', format(strings.configuredTable, result.wordpress_configured_table)));
		}

		resultsEl.appendChild(panel);
	}

	function renderBottomActions(resultsEl) {
		var actions = createElement('div', 'cws-database-scan-report-actions');
		var button = createElement('button', 'button button-secondary', strings.rescanButton);

		button.type = 'button';
		button.addEventListener('click', handleScan);
		actions.appendChild(button);
		resultsEl.appendChild(actions);
	}

	function renderResult(result) {
		var resultsEl = document.getElementById('cws-database-scan-js-results');
		var fallback = document.getElementById('cws-database-scan-fallback-results');
		var sections;

		if (!resultsEl || !result) {
			return;
		}

		resultState = result;
		clearElement(resultsEl);

		if (fallback) {
			fallback.style.display = 'none';
		}

		if (result.options_table) {
			selectTable(result.options_table);
		}

		renderSummary(resultsEl, result);

		sections = result.sections || {};
		Object.keys(sections).forEach(function (sectionKey) {
			if (!sectionState[sectionKey]) {
				sectionState[sectionKey] = defaultSectionState(sectionKey);
			}

			renderSection(resultsEl, sectionKey, sections[sectionKey]);
		});

		renderBottomActions(resultsEl);
		updateScanButtonLabel();
	}

	function updateScanButtonLabel() {
		var button = document.querySelector('#cws-database-scan-form input[name="choctaw_wp_security_database_scan"]');

		if (button && resultState) {
			button.value = strings.rescanButton || button.value;
		}
	}

	function handleScan() {
		setBusy(true, strings.scanning);

		request('choctaw_wp_security_database_scan', getSelectedTable()).then(function (data) {
			sectionState = {};
			showNotice('', 'success');
			renderResult(data.result);
		}).catch(function (error) {
			showNotice(error.message || strings.scanError, 'error');
		}).finally(function () {
			setBusy(false);
		});
	}

	function handleBaselineReset() {
		setBusy(true, strings.resettingBaseline);

		request('choctaw_wp_security_database_scan_baseline_reset', getSelectedTable()).then(function (data) {
			showNotice(data.message || '', 'success');
			if (data.options_table) {
				selectTable(data.options_table);
			}
		}).catch(function (error) {
			showNotice(error.message || strings.resetError, 'error');
		}).finally(function () {
			setBusy(false);
		});
	}

	function init() {
		var form = document.getElementById('cws-database-scan-form');

		if (!form || !config.ajaxUrl) {
			return;
		}

		form.addEventListener('submit', function (event) {
			var submitter = event.submitter || document.activeElement;
			var isBaselineReset = submitter && submitter.name === 'choctaw_wp_security_database_scan_baseline_reset';

			event.preventDefault();

			if (isBaselineReset) {
				handleBaselineReset();
				return;
			}

			handleScan();
		});

		if (config.initialResult && typeof config.initialResult === 'object') {
			renderResult(config.initialResult);
		}
	}

	ready(init);
}());
