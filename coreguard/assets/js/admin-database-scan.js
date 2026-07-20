(function () {
	'use strict';

	var config = window.choctawWpSecurityDatabaseScan || {};
	var strings = config.strings || {};
	var categoryLabels = config.categoryLabels || {};
	var pageSize = parseInt(config.pageSize, 10) || 20;
	var resultState = null;
	var uiState = {
		page: 1,
		sortKey: 'size',
		sortDir: 'desc',
		risk: '',
		status: 'needs_review',
		category: '',
		search: '',
		expandedId: ''
	};

	var riskOrder = {
		critical: 5,
		warning: 4,
		suspicious: 3,
		info: 2,
		safe: 1,
		alert: 2
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

	function appendHighlighted(parent, value) {
		var raw = text(value);
		var query = text(uiState.search).trim();
		var lower;
		var needle;
		var start;
		var index;
		var mark;

		if (!query) {
			appendText(parent, raw);
			return;
		}

		lower = raw.toLowerCase();
		needle = query.toLowerCase();
		start = 0;
		index = lower.indexOf(needle);

		while (index !== -1) {
			if (index > start) {
				appendText(parent, raw.slice(start, index));
			}
			mark = document.createElement('mark');
			mark.className = 'cws-search-hit';
			appendText(mark, raw.slice(index, index + query.length));
			parent.appendChild(mark);
			start = index + query.length;
			index = lower.indexOf(needle, start);
		}

		if (start < raw.length) {
			appendText(parent, raw.slice(start));
		}
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

	function setBusy(isBusy, message) {
		var form = document.getElementById('cws-database-scan-form');
		var resultsEl = document.getElementById('cws-database-scan-js-results');
		var buttons;
		var controls;

		if (!form) {
			return;
		}

		buttons = form.querySelectorAll('button, input[type="submit"]');
		buttons.forEach(function (button) {
			button.disabled = isBusy;
		});

		if (resultsEl) {
			controls = resultsEl.querySelectorAll('button, select, input');
			Array.prototype.forEach.call(controls, function (control) {
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
			safe: strings.riskSafe || 'Safe',
			info: strings.riskInfo || 'Info'
		};
		return map[risk] || risk || strings.riskInfo || 'Info';
	}

	function findingRisk(finding) {
		return text(finding.risk_level || finding.risk || 'info');
	}

	function collectFindings(result) {
		if (result && Array.isArray(result.findings)) {
			return result.findings;
		}

		var findings = [];
		var sections = (result && result.sections) || {};
		Object.keys(sections).forEach(function (sectionKey) {
			var section = sections[sectionKey] || {};
			(Array.isArray(section.findings) ? section.findings : []).forEach(function (finding) {
				var copy = Object.assign({}, finding);
				if (!copy.section_key) {
					copy.section_key = sectionKey;
				}
				if (!copy.category) {
					copy.category = sectionKey;
				}
				if (!copy.category_label) {
					copy.category_label = categoryLabels[sectionKey] || sectionKey;
				}
				if (!copy.risk) {
					if (copy.risk_level) {
						copy.risk = copy.risk_level;
					} else if (copy.severity === 'critical') {
						copy.risk = 'critical';
					} else if (copy.severity === 'warning') {
						copy.risk = 'warning';
					} else if (sectionKey === 'large_autoload') {
						copy.risk = 'safe';
					} else {
						copy.risk = 'info';
					}
				}
				if (typeof copy.is_recognized === 'undefined') {
					copy.is_recognized = copy.risk === 'safe';
				}
				findings.push(copy);
			});
		});
		return findings;
	}

	function filteredFindings(findings) {
		var search = text(uiState.search).toLowerCase().trim();

		return findings.filter(function (finding) {
			if (uiState.risk && findingRisk(finding) !== uiState.risk) {
				return false;
			}

			if (window.CwsReportStatus && !window.CwsReportStatus.matchesStatusFilter(finding, uiState.status)) {
				return false;
			}

			if (uiState.category && finding.category !== uiState.category && finding.section_key !== uiState.category) {
				return false;
			}

			if (search) {
				var haystack = (
					text(finding.option_name) + ' ' +
					text(finding.excerpt) + ' ' +
					text(finding.full_value) + ' ' +
					text(finding.detail)
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
				a = riskOrder[findingRisk(left)] || 0;
				b = riskOrder[findingRisk(right)] || 0;
				if (a !== b) {
					return (a - b) * dir;
				}
				return ((parseInt(left.size, 10) || 0) - (parseInt(right.size, 10) || 0)) * -1;
			}

			if (key === 'option_id') {
				a = parseInt(left.option_id, 10) || 0;
				b = parseInt(right.option_id, 10) || 0;
				return (a - b) * dir;
			}

			if (key === 'size') {
				a = parseInt(left.size, 10) || 0;
				b = parseInt(right.size, 10) || 0;
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

	function renderRiskCell(finding) {
		var risk = findingRisk(finding);
		var wrap = createElement('div', 'cws-risk is-' + risk);
		var label = createElement('span', 'cws-risk-label');

		label.appendChild(createCoreGuardMark());
		appendText(label, finding.risk_label || riskLabel(risk));
		wrap.appendChild(label);
		return wrap;
	}

	function renderCategoryPill(finding) {
		var pills = createElement('div', 'cws-report-pills');
		var label = finding.category_label || categoryLabels[finding.category] || finding.category || '';
		pills.appendChild(createElement('span', 'cws-report-pill', label));
		return pills;
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
				uiState.sortDir = sortKey === 'size' || sortKey === 'risk' ? 'desc' : 'asc';
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
		var riskSelect = document.createElement('select');
		var categorySelect = document.createElement('select');
		var searchInput = document.createElement('input');
		var riskOptions = [
			{ value: '', label: strings.allRisks || 'All risks' },
			{ value: 'critical', label: strings.riskCritical || 'Critical' },
			{ value: 'warning', label: strings.riskWarning || 'Warning' },
			{ value: 'suspicious', label: strings.riskSuspicious || 'Suspicious' },
			{ value: 'info', label: strings.riskInfo || 'Info' }
		];
		var categoryKeys = Object.keys(categoryLabels);

		if (uiState.risk === 'safe') {
			uiState.risk = '';
		}

		riskSelect.setAttribute('aria-label', strings.risk || 'Risk');
		riskOptions.forEach(function (option) {
			var el = createElement('option', '', option.label);
			el.value = option.value;
			if (uiState.risk === option.value) {
				el.selected = true;
			}
			riskSelect.appendChild(el);
		});
		riskSelect.addEventListener('change', function () {
			uiState.risk = riskSelect.value;
			uiState.page = 1;
			renderResult(resultState);
		});

		categorySelect.setAttribute('aria-label', strings.category || 'Category');
		var allCat = createElement('option', '', strings.allCategories || 'All categories');
		allCat.value = '';
		categorySelect.appendChild(allCat);
		categoryKeys.forEach(function (key) {
			var el = createElement('option', '', categoryLabels[key]);
			el.value = key;
			if (uiState.category === key) {
				el.selected = true;
			}
			categorySelect.appendChild(el);
		});
		categorySelect.addEventListener('change', function () {
			uiState.category = categorySelect.value;
			uiState.page = 1;
			renderResult(resultState);
		});

		searchInput.type = 'search';
		searchInput.setAttribute('data-cws-report-search', '1');
		searchInput.placeholder = strings.searchPlaceholder || 'Search option name or value';
		searchInput.value = uiState.search;
		searchInput.addEventListener('input', function () {
			uiState.search = searchInput.value;
			uiState.page = 1;
			renderResult(resultState);
		});

		toolbar.appendChild(riskSelect);
		if (window.CwsReportStatus) {
			window.CwsReportStatus.appendStatusFilter(toolbar, uiState, function () {
				uiState.page = 1;
				renderResult(resultState);
			});
		}
		toolbar.appendChild(categorySelect);
		toolbar.appendChild(searchInput);
		parent.appendChild(toolbar);
	}

	function appendInfoField(dl, label, valueNode) {
		var dt = document.createElement('dt');
		var dd = document.createElement('dd');
		appendText(dt, label);
		if (typeof valueNode === 'string') {
			appendText(dd, valueNode);
		} else if (valueNode) {
			dd.appendChild(valueNode);
		} else {
			appendText(dd, '—');
		}
		dl.appendChild(dt);
		dl.appendChild(dd);
	}

	function pickGuidanceText(map, risk) {
		if (!map || typeof map !== 'object') {
			return '';
		}
		if (map[risk]) {
			return text(map[risk]);
		}
		if (map.default) {
			return text(map.default);
		}
		return '';
	}

	function guidanceForFinding(finding) {
		var category = text(finding.category || finding.section_key || '');
		var risk = findingRisk(finding);
		var why = text(finding.why_seeing_this || '');
		var how = text(finding.how_to_proceed || '');
		var entry;

		if (!why || !how) {
			entry = (config.detailGuidance || {})[category] || {};
			if (!why) {
				why = pickGuidanceText(entry.why, risk);
			}
			if (!how) {
				how = pickGuidanceText(entry.how, risk);
			}
		}

		return {
			why: why || text(strings.whySeeingThisFallback || ''),
			how: how || text(strings.howToProceedFallback || '')
		};
	}

	function renderDetailPanel(finding) {
		var grid = createElement('div', 'cws-report-detail-grid cws-database-scan-detail-grid');
		var left = createElement('div', 'cws-database-scan-detail-left');
		var right = createElement('div', 'cws-database-scan-detail-right');
		var infoPanel = createElement('div', 'cws-database-scan-info-panel');
		var infoList = document.createElement('dl');
		var valueBlock = createElement('div', 'cws-database-scan-option-value');
		var textarea = document.createElement('textarea');
		var whyBlock = createElement('div', 'cws-database-scan-why-block');
		var howBlock = createElement('div', 'cws-database-scan-how-block');
		var guidance = guidanceForFinding(finding);
		var detailNode = createElement('span', '');
		var optionNoun = (window.CwsReportPagination && window.CwsReportPagination.strings && window.CwsReportPagination.strings.contentsNounOptionValue) || 'Option Value';

		infoPanel.appendChild(createElement('h4', '', strings.infoPanel || 'Info'));
		appendInfoField(infoList, strings.size || 'Size', sizeFormat(finding.size || 0));
		appendHighlighted(detailNode, finding.detail || finding.description || '—');
		appendInfoField(infoList, strings.detail || 'Detail', detailNode);
		infoPanel.appendChild(infoList);

		valueBlock.appendChild(createElement('h4', '', strings.optionValue || 'Option Value'));
		textarea.readOnly = true;
		textarea.rows = 14;
		textarea.className = 'cws-file-contents-textarea large-text code';
		textarea.value = window.CwsReportPagination && typeof window.CwsReportPagination.withContentsFooter === 'function'
			? window.CwsReportPagination.withContentsFooter(finding.full_value || finding.excerpt || '', !!finding.contents_truncated, optionNoun)
			: text(finding.full_value || finding.excerpt || '');
		valueBlock.appendChild(textarea);

		left.appendChild(infoPanel);
		left.appendChild(valueBlock);

		whyBlock.appendChild(createElement('h4', '', strings.whySeeingThis || 'Why you are seeing this'));
		whyBlock.appendChild(createElement('p', '', guidance.why));

		howBlock.appendChild(createElement('h4', '', strings.howToProceed || 'How to proceed'));
		howBlock.appendChild(createElement('p', '', guidance.how));

		right.appendChild(whyBlock);
		right.appendChild(howBlock);

		if (window.CwsReportStatus) {
			window.CwsReportStatus.appendDismissControls(right, finding, config.scanType || 'database-scan', function () {
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

	function findingExpandKey(finding, index) {
		var key = text(finding && finding.fingerprint ? finding.fingerprint : '');
		if (!key) {
			key = text(finding && finding.id ? finding.id : '');
		}
		// Index keeps expand state unique even when older cached scans share fingerprints.
		return (key || 'row') + '::' + String(index);
	}

	function renderFindingRow(tbody, finding, index) {
		var row = document.createElement('tr');
		var riskTd = document.createElement('td');
		var statusTd = document.createElement('td');
		var categoryTd = document.createElement('td');
		var optionTd = document.createElement('td');
		var optionCode = createElement('code', 'cws-file-path');
		var actionsTd = document.createElement('td');
		var eye = createElement('button', 'cws-report-eye');
		var eyeIcon = createElement('span', 'dashicons dashicons-visibility');
		var expandKey = findingExpandKey(finding, index);
		var isExpanded = uiState.expandedId === expandKey;

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

		categoryTd.appendChild(renderCategoryPill(finding));
		row.appendChild(categoryTd);

		row.appendChild(createElement('td', '', optionIdLabel(finding)));

		appendHighlighted(optionCode, finding.option_name || '');
		optionTd.appendChild(optionCode);
		if (finding.confirmed_this_run === false) {
			optionTd.appendChild(createElement('p', 'description', strings.notConfirmedThisRun || 'Not reconfirmed by this incomplete scan'));
		}
		row.appendChild(optionTd);

		eye.type = 'button';
		eye.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
		eye.setAttribute('aria-label', isExpanded ? (strings.hideDetails || 'Hide details') : (strings.viewDetails || 'View details'));
		eyeIcon.setAttribute('aria-hidden', 'true');
		eye.appendChild(eyeIcon);
		eye.addEventListener('click', function () {
			uiState.expandedId = isExpanded ? '' : expandKey;
			renderResult(resultState);
		});
		actionsTd.appendChild(eye);
		row.appendChild(actionsTd);
		tbody.appendChild(row);

		if (isExpanded) {
			var detailRow = createElement('tr', 'cws-report-detail-row');
			var detailPanelTd = document.createElement('td');
			detailPanelTd.colSpan = 6;
			detailPanelTd.appendChild(renderDetailPanel(finding));
			detailRow.appendChild(detailPanelTd);
			tbody.appendChild(detailRow);
		}
	}

	function renderTable(parent, findings) {
		var section = createElement('div', 'cws-report-section cws-database-scan-section');
		var sorted = sortedFindings(filteredFindings(findings));
		var pagination = paginate(sorted);
		var table = createElement('table', 'widefat striped cws-core-checksum-table cws-database-scan-table');
		var thead = document.createElement('thead');
		var headerRow = document.createElement('tr');
		var tbody = document.createElement('tbody');
		var actionsTh = document.createElement('th');

		renderToolbar(section);

		if (!sorted.length) {
			section.appendChild(createElement('p', '', uiState.status === 'needs_review' ? (strings.noFlagged || strings.noFindings || 'No findings requiring review were found. Choose All risks, Safe, or Info to view inventory findings.') : (strings.noFindings || 'No findings matched the current filters.')));
			parent.appendChild(section);
			return;
		}

		headerRow.appendChild(sortableHeader(strings.risk || 'Risk', 'risk'));
		headerRow.appendChild(createElement('th', '', strings.status || 'Status'));
		headerRow.appendChild(sortableHeader(strings.category || 'Category', 'category'));
		headerRow.appendChild(sortableHeader(strings.optionId || 'Option ID', 'option_id'));
		headerRow.appendChild(sortableHeader(strings.option || 'Option', 'option_name'));
		actionsTh.scope = 'col';
		appendText(actionsTh, strings.actions || 'Action');
		headerRow.appendChild(actionsTh);

		thead.appendChild(headerRow);
		table.appendChild(thead);

		pagination.items.forEach(function (finding, index) {
			renderFindingRow(tbody, finding, index);
		});

		table.appendChild(tbody);
		section.appendChild(table);
		renderPagination(section, pagination);
		parent.appendChild(section);
	}

	function renderSummary(resultsEl, result) {
		var summary = result.summary || {};
		var critical = parseInt(summary.critical, 10) || 0;
		var warning = parseInt(summary.warning, 10) || 0;
		var suspicious = parseInt(summary.suspicious, 10) || 0;
		var incomplete = !result.rejected && (!!result.scan_incomplete || result.coverage_complete === false || (result.completion_status && result.completion_status !== 'success'));
		var hasProblems = critical + warning + suspicious > 0;
		var className;
		var panel;
		var message;

		if (result.rejected) {
			panel = createElement('div', 'cws-core-checksum-results is-error');
			message = (Array.isArray(result.errors) && result.errors.length) ? result.errors[0] : (strings.scanRejected || 'This options table cannot be scanned.');
			panel.appendChild(createElement('p', 'cws-core-checksum-summary', message));
			resultsEl.appendChild(panel);
			return;
		}

		className = incomplete
			? 'cws-core-checksum-results is-warning'
			: (critical > 0
				? 'cws-core-checksum-results is-error'
				: ((warning + suspicious) > 0 ? 'cws-core-checksum-results is-warning' : 'cws-core-checksum-results is-success'));
		panel = createElement('div', className);

		if (incomplete) {
			message = strings.scanIncomplete || strings.incomplete || 'Scan coverage was incomplete. Previously detected findings were not cleared.';
		} else if (hasProblems) {
			message = format(
				strings.scanCompleteIssues || 'Scan complete. %1$s critical, %2$s warning, %3$s suspicious findings.',
				numberFormat(critical),
				numberFormat(warning),
				numberFormat(suspicious)
			);
		} else {
			message = strings.scanCompleteClean || 'Scan complete. No critical, warning, or suspicious findings.';
		}

		panel.appendChild(createElement('p', 'cws-core-checksum-summary', message));

		if (incomplete && result.prior_findings_only) {
			panel.appendChild(createElement('p', 'description', strings.priorFindingsNote || 'Active findings below are from earlier successful scans and were not reconfirmed by this run.'));
		}

		if (Array.isArray(result.errors) && result.errors.length) {
			result.errors.forEach(function (errorMessage) {
				panel.appendChild(createElement('p', 'description', errorMessage));
			});
		}

		if (result.wordpress_configured_table && result.options_table && result.wordpress_configured_table !== result.options_table) {
			panel.appendChild(createElement('p', '', format(strings.configuredTable, result.wordpress_configured_table)));
		}

		resultsEl.appendChild(panel);
	}

	function renderResult(result) {
		var resultsEl = document.getElementById('cws-database-scan-js-results');
		var fallback = document.getElementById('cws-database-scan-fallback-results');
		var findings;
		var active = document.activeElement;
		var restoreSearch = active && active.getAttribute && active.getAttribute('data-cws-report-search') === '1';
		var selectionStart = restoreSearch ? active.selectionStart : null;
		var selectionEnd = restoreSearch ? active.selectionEnd : null;
		var searchInput;

		if (!resultsEl || !result) {
			return;
		}

		resultState = result;
		clearElement(resultsEl);

		if (fallback) {
			fallback.style.display = 'none';
		}

		renderSummary(resultsEl, result);
		findings = collectFindings(result);
		renderTable(resultsEl, findings);
		updateScanButtonLabel();

		if (restoreSearch) {
			searchInput = resultsEl.querySelector('[data-cws-report-search="1"]');
			if (searchInput) {
				searchInput.focus();
				if (selectionStart !== null && typeof searchInput.setSelectionRange === 'function') {
					try {
						searchInput.setSelectionRange(selectionStart, selectionEnd);
					} catch (e) {
						// Ignore selection errors on type=search in some browsers.
					}
				}
			}
		}
	}

	function updateScanButtonLabel() {
		var button = document.querySelector('#cws-database-scan-form input[name="choctaw_wp_security_database_scan"]');

		if (button && resultState) {
			button.value = strings.rescanButton || button.value;
		}
	}

	function handleScan() {
		setBusy(true, strings.scanning);

		request('choctaw_wp_security_database_scan').then(function (data) {
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
		var form = document.getElementById('cws-database-scan-form');

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
}());
