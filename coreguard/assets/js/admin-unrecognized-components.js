(function () {
	'use strict';

	var config = window.choctawWpSecurityUnrecognizedComponents || {};
	var strings = config.strings || {};
	var pageSize = parseInt(config.pageSize, 10) || 20;
	var resultState = null;
	var uiState = {
		page: 1,
		sortKey: 'name',
		sortDir: 'asc',
		risk: '',
		status: 'needs_review',
		category: '',
		search: '',
		expandedId: ''
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
			if (uiState.category && finding.category !== uiState.category) {
				return false;
			}
			if (search && text(finding.name).toLowerCase().indexOf(search) === -1) {
				return false;
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

			if (key === 'category') {
				a = text(left.category_label || left.category).toLowerCase();
				b = text(right.category_label || right.category).toLowerCase();
			} else if (key === 'state') {
				a = text(left.state_label || left.state).toLowerCase();
				b = text(right.state_label || right.state).toLowerCase();
			} else if (key === 'name') {
				a = text(left.name).toLowerCase();
				b = text(right.name).toLowerCase();
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
			itemLabel: config.itemNoun || 'components',
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
		appendText(label, finding.risk_label || strings.riskInfo || 'Info');
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
				uiState.sortDir = 'asc';
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
		var toolbar = createElement('div', 'cws-report-toolbar cws-unrecognized-components-toolbar');
		var riskLabelEl = document.createElement('label');
		var riskSelect = document.createElement('select');
		var categoryLabelEl = document.createElement('label');
		var categorySelect = document.createElement('select');
		var searchLabel = document.createElement('label');
		var searchInput = document.createElement('input');

		riskLabelEl.appendChild(createElement('span', 'screen-reader-text', strings.risk || 'Risk'));
		riskSelect.appendChild(new Option(strings.allRisks || 'All risks', ''));
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
				uiState.expandedId = '';
				renderResult(resultState);
			});
		}

		categoryLabelEl.appendChild(createElement('span', 'screen-reader-text', strings.category || 'Category'));
		categorySelect.appendChild(new Option(strings.allCategories || 'All categories', ''));
		categorySelect.appendChild(new Option(strings.categoryPlugin || 'Plugin', 'plugin'));
		categorySelect.appendChild(new Option(strings.categoryTheme || 'Theme', 'theme'));
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
		searchInput.placeholder = strings.searchPlaceholder || 'Search name…';
		searchInput.value = uiState.search;
		searchInput.setAttribute('data-cws-report-search', '1');
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

	function appendInfoField(dl, label, value, asCode) {
		var dt = document.createElement('dt');
		var dd = document.createElement('dd');
		appendText(dt, label);
		if (asCode) {
			dd.appendChild(createElement('code', 'cws-file-path', value || '—'));
		} else {
			appendText(dd, value || '—');
		}
		dl.appendChild(dt);
		dl.appendChild(dd);
	}

	function renderDetailPanel(finding) {
		var grid = createElement('div', 'cws-report-detail-grid cws-unrecognized-components-detail-grid');
		var left = createElement('div', 'cws-unrecognized-components-detail-left');
		var right = createElement('div', 'cws-unrecognized-components-detail-right');
		var infoPanel = createElement('div', 'cws-unrecognized-components-info-panel');
		var infoList = document.createElement('dl');
		var contentsBlock = createElement('div', 'cws-unrecognized-components-contents');
		var textarea = document.createElement('textarea');
		var whyBlock = createElement('div', 'cws-unrecognized-components-why-block');
		var howBlock = createElement('div', 'cws-unrecognized-components-how-block');

		infoPanel.appendChild(createElement('h4', '', strings.infoPanel || 'Info'));
		appendInfoField(infoList, strings.slug || 'Slug', finding.slug || '', true);
		appendInfoField(infoList, strings.version || 'Version', finding.version || '—', false);
		infoPanel.appendChild(infoList);

		contentsBlock.appendChild(createElement('h4', '', strings.contentsHeading || 'Contents'));
		textarea.readOnly = true;
		textarea.rows = 14;
		textarea.className = 'cws-file-contents-textarea large-text code';
		textarea.value = text(finding.contents || '');
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
			window.CwsReportStatus.appendDismissControls(right, finding, config.scanType || 'unrecognized-components', function () {
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
		var categoryTd = document.createElement('td');
		var nameTd = document.createElement('td');
		var stateTd = document.createElement('td');
		var actionsTd = document.createElement('td');
		var eye = createElement('button', 'cws-report-eye');
		var eyeIcon = createElement('span', 'dashicons dashicons-visibility');
		var findingId = text(finding.fingerprint || finding.id || '');
		var isExpanded = uiState.expandedId === findingId;

		if (isExpanded) {
			row.className = 'is-expanded';
		}

		riskTd.appendChild(renderRiskCell(finding));
		row.appendChild(riskTd);

		if (window.CwsReportStatus) {
			statusTd.appendChild(window.CwsReportStatus.renderStatusCell(finding));
		}
		row.appendChild(statusTd);

		categoryTd.appendChild(createElement('span', 'cws-report-pill', finding.category_label || finding.category || ''));
		row.appendChild(categoryTd);

		appendText(nameTd, finding.name || '');
		row.appendChild(nameTd);

		appendText(stateTd, finding.state_label || finding.state || '');
		row.appendChild(stateTd);

		eye.type = 'button';
		eye.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
		eye.setAttribute('aria-label', isExpanded ? (strings.hideDetails || 'Hide details') : (strings.viewDetails || 'View details'));
		eyeIcon.setAttribute('aria-hidden', 'true');
		eye.appendChild(eyeIcon);
		eye.addEventListener('click', function () {
			uiState.expandedId = isExpanded ? '' : findingId;
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
		var section = createElement('div', 'cws-unrecognized-components-table-wrap');
		var allFindings = collectFindings(resultState);
		var sorted = sortedFindings(filteredFindings(findings));
		var pagination = paginate(sorted);
		var table = createElement('table', 'widefat striped cws-core-checksum-table cws-unrecognized-components-table');
		var thead = document.createElement('thead');
		var headerRow = document.createElement('tr');
		var tbody = document.createElement('tbody');
		var actionsTh = document.createElement('th');

		renderToolbar(section);

		if (!allFindings.length) {
			section.appendChild(createElement('p', '', strings.allRecognized || 'All installed plugins and themes were recognized by the API.'));
			parent.appendChild(section);
			return;
		}

		if (!sorted.length) {
			section.appendChild(createElement('p', '', strings.noFindings || 'No unrecognized components matched the current filters.'));
			parent.appendChild(section);
			return;
		}

		headerRow.appendChild(sortableHeader(strings.risk || 'Risk', 'risk'));
		headerRow.appendChild(createElement('th', '', strings.status || 'Status'));
		headerRow.appendChild(sortableHeader(strings.category || 'Category', 'category'));
		headerRow.appendChild(sortableHeader(strings.name || 'Name', 'name'));
		headerRow.appendChild(sortableHeader(strings.state || 'State', 'state'));
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

	function renderResult(result) {
		var resultsEl = document.getElementById('cws-unrecognized-components-js-results');
		var fallback = document.getElementById('cws-unrecognized-components-fallback-results');
		var active;
		var restoreSearch;
		var searchInput;

		if (!resultsEl || !result) {
			return;
		}

		active = document.activeElement;
		restoreSearch = active && active.getAttribute && active.getAttribute('data-cws-report-search') === '1';

		resultState = result;
		clearElement(resultsEl);
		if (fallback) {
			fallback.style.display = 'none';
		}
		renderTable(resultsEl, collectFindings(result));

		if (restoreSearch) {
			searchInput = resultsEl.querySelector('[data-cws-report-search="1"]');
			if (searchInput) {
				searchInput.focus();
				if (typeof searchInput.setSelectionRange === 'function') {
					searchInput.setSelectionRange(searchInput.value.length, searchInput.value.length);
				}
			}
		}
	}

	function init() {
		var resultsEl = document.getElementById('cws-unrecognized-components-js-results');
		if (!resultsEl) {
			return;
		}
		if (config.initialResult && typeof config.initialResult === 'object') {
			renderResult(config.initialResult);
		}
	}

	ready(init);
})();
