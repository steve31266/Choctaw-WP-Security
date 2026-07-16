(function () {
	'use strict';

	var config = window.choctawWpSecurityScheduledTasks || {};
	var strings = config.strings || {};
	var categoryLabels = config.categoryLabels || {};
	var pageSize = parseInt(config.pageSize, 10) || 20;
	var resultState = null;
	var uiState = {
		page: 1,
		sortKey: 'risk',
		sortDir: 'desc',
		risk: '',
		status: 'needs_review',
		category: '',
		source: '',
		search: '',
		expandedId: ''
	};

	var riskOrder = {
		critical: 4,
		suspicious: 3,
		review: 2,
		info: 1
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
		var notices = document.getElementById('cws-scheduled-tasks-js-notices');
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
		paragraph = document.createElement('p');
		appendText(paragraph, message);
		notice.appendChild(paragraph);
		notices.appendChild(notice);
	}

	function setBusy(isBusy, message) {
		var form = document.getElementById('cws-scheduled-tasks-form');
		var button = form ? form.querySelector('input[name="choctaw_wp_security_scheduled_tasks_scan"]') : null;
		var controls = document.querySelectorAll('#cws-scheduled-tasks-js-results button, #cws-scheduled-tasks-js-results select, #cws-scheduled-tasks-js-results input');

		if (button) {
			button.disabled = !!isBusy;
			if (isBusy && message) {
				button.value = message;
			} else if (!isBusy) {
				button.value = strings.scanButton || 'Scan Now';
			}
		}

		Array.prototype.forEach.call(controls, function (control) {
			control.disabled = !!isBusy;
		});
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
			return response.json().then(function (payload) {
				if (!response.ok || !payload || !payload.success) {
					var message = payload && payload.data && payload.data.message ? payload.data.message : strings.scanError;
					throw new Error(message);
				}
				return payload.data;
			});
		});
	}

	function riskLabel(risk) {
		var map = {
			critical: strings.riskCritical,
			suspicious: strings.riskSuspicious,
			review: strings.riskReview,
			info: strings.riskInfo
		};
		return map[risk] || risk || strings.riskInfo;
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

			if (uiState.category) {
				var rules = Array.isArray(finding.rules) ? finding.rules : [];
				if (rules.indexOf(uiState.category) === -1) {
					return false;
				}
			}

			if (uiState.source && finding.source_key !== uiState.source) {
				return false;
			}

			if (search) {
				var haystack = (text(finding.hook) + ' ' + text(finding.source)).toLowerCase();
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
				if (a !== b) {
					return (a - b) * dir;
				}
				a = parseInt(left.score, 10) || 0;
				b = parseInt(right.score, 10) || 0;
				if (a !== b) {
					return (a - b) * (uiState.sortDir === 'desc' ? 1 : -1);
				}
			} else if (key === 'next_run') {
				a = parseInt(left.next_run, 10) || 0;
				b = parseInt(right.next_run, 10) || 0;
				if (a !== b) {
					return (a - b) * dir;
				}
			} else if (key === 'category') {
				a = text((left.category_labels || [])[0]).toLowerCase();
				b = text((right.category_labels || [])[0]).toLowerCase();
				if (a !== b) {
					return a < b ? -1 * dir : 1 * dir;
				}
			} else if (key === 'source') {
				a = text(left.source).toLowerCase();
				b = text(right.source).toLowerCase();
				if (a !== b) {
					return a < b ? -1 * dir : 1 * dir;
				}
			} else if (key === 'hook') {
				a = text(left.hook).toLowerCase();
				b = text(right.hook).toLowerCase();
				if (a !== b) {
					return a < b ? -1 * dir : 1 * dir;
				}
			}

			a = parseInt(left.next_run, 10) || 0;
			b = parseInt(right.next_run, 10) || 0;
			return a - b;
		});

		return list;
	}

	function paginate(findings) {
		var pagination = window.CwsReportPagination.paginate(findings, uiState.page, pageSize);
		uiState.page = pagination.page;
		return pagination;
	}

	function sortableHeader(label, key) {
		var th = document.createElement('th');
		var button = createElement('button', 'button-link', label);
		button.type = 'button';
		button.setAttribute('aria-label', uiState.sortKey === key && uiState.sortDir === 'asc' ? strings.sortDescending : strings.sortAscending);
		if (uiState.sortKey === key) {
			button.appendChild(document.createTextNode(uiState.sortDir === 'asc' ? ' ▲' : ' ▼'));
		}
		button.addEventListener('click', function () {
			if (uiState.sortKey === key) {
				uiState.sortDir = uiState.sortDir === 'asc' ? 'desc' : 'asc';
			} else {
				uiState.sortKey = key;
				uiState.sortDir = key === 'risk' ? 'desc' : 'asc';
			}
			uiState.page = 1;
			renderResult(resultState);
		});
		th.appendChild(button);
		return th;
	}

	function createSelect(options, value, onChange) {
		var select = document.createElement('select');
		options.forEach(function (option) {
			var el = document.createElement('option');
			el.value = option.value;
			appendText(el, option.label);
			if (option.value === value) {
				el.selected = true;
			}
			select.appendChild(el);
		});
		select.addEventListener('change', function () {
			onChange(select.value);
		});
		return select;
	}

	function renderToolbar(container) {
		var toolbar = createElement('div', 'cws-scheduled-tasks-toolbar');
		var search = document.createElement('input');
		var refresh = createElement('button', 'button button-secondary', strings.refreshButton || 'Refresh');
		var categoryOptions = [{ value: '', label: strings.allCategories || 'All Categories' }];
		var riskOptions = [
			{ value: '', label: strings.allRisk || 'All Risk' },
			{ value: 'critical', label: strings.riskCritical },
			{ value: 'suspicious', label: strings.riskSuspicious },
			{ value: 'review', label: strings.riskReview },
			{ value: 'info', label: strings.riskInfo }
		];
		var sourceOptions = [
			{ value: '', label: strings.allSources || 'All Sources' },
			{ value: 'plugin', label: strings.sourcePlugin },
			{ value: 'theme', label: strings.sourceTheme },
			{ value: 'unknown', label: strings.sourceUnknown }
		];

		Object.keys(categoryLabels).forEach(function (key) {
			// Recognized Core is inventory-only; use Risk = Info / All Risk instead.
			if (key === 'recognized_core') {
				return;
			}
			categoryOptions.push({ value: key, label: categoryLabels[key] });
		});

		toolbar.appendChild(createSelect(riskOptions, uiState.risk, function (value) {
			uiState.risk = value;
			uiState.page = 1;
			renderResult(resultState);
		}));

		if (window.CwsReportStatus) {
			window.CwsReportStatus.appendStatusFilter(toolbar, uiState, function () {
				uiState.page = 1;
				renderResult(resultState);
			});
		}

		toolbar.appendChild(createSelect(categoryOptions, uiState.category, function (value) {
			uiState.category = value;
			uiState.page = 1;
			renderResult(resultState);
		}));

		toolbar.appendChild(createSelect(sourceOptions, uiState.source, function (value) {
			uiState.source = value;
			uiState.page = 1;
			renderResult(resultState);
		}));

		search.type = 'search';
		search.setAttribute('data-cws-report-search', '1');
		search.placeholder = strings.searchPlaceholder || '';
		search.value = uiState.search;
		search.addEventListener('input', function () {
			uiState.search = search.value;
			uiState.page = 1;
			renderResult(resultState);
		});
		toolbar.appendChild(search);

		refresh.type = 'button';
		refresh.addEventListener('click', handleScan);
		toolbar.appendChild(refresh);

		container.appendChild(toolbar);
	}

	function renderRiskCell(finding) {
		var cell = createElement('div', 'cws-scheduled-tasks-risk is-' + text(finding.risk || 'info'));
		var label = createElement('span', 'cws-scheduled-tasks-risk-label');

		label.appendChild(createCoreGuardMark());
		appendText(label, finding.risk_label || riskLabel(finding.risk));
		cell.appendChild(label);
		cell.appendChild(createElement('span', 'cws-scheduled-tasks-confidence is-' + text(finding.confidence || 'low').replace(/_/g, '-'), format(strings.confidence || 'Confidence: %s', finding.confidence_label || finding.confidence || '')));
		return cell;
	}

	function renderCategoryPills(finding) {
		var wrap = createElement('div', 'cws-scheduled-tasks-pills');
		var rules = Array.isArray(finding.rules) ? finding.rules : [];
		var labels = Array.isArray(finding.category_labels) ? finding.category_labels : [];

		rules.forEach(function (rule, index) {
			wrap.appendChild(createElement('span', 'cws-scheduled-tasks-pill is-' + rule, labels[index] || categoryLabels[rule] || rule));
		});

		return wrap;
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

	function renderDetailPanel(finding) {
		var grid = createElement('div', 'cws-scheduled-tasks-detail-grid');
		var left = createElement('div', 'cws-scheduled-tasks-detail-left');
		var right = createElement('div', 'cws-scheduled-tasks-detail-right');
		var infoPanel = createElement('div', 'cws-scheduled-tasks-info-panel');
		var infoList = document.createElement('dl');
		var nextRunWrap = document.createElement('div');
		var argsBlock = createElement('div', 'cws-scheduled-tasks-raw-args');
		var textarea = document.createElement('textarea');
		var whyBlock = createElement('div', 'cws-scheduled-tasks-why-block');
		var howBlock = createElement('div', 'cws-scheduled-tasks-how-block');
		var whyList = document.createElement('ul');
		var howList = document.createElement('ul');
		var sourceNode = createElement('span', '');
		var argsNoun = (window.CwsReportPagination && window.CwsReportPagination.strings && window.CwsReportPagination.strings.contentsNounArguments) || 'Arguments';

		infoPanel.appendChild(createElement('h4', '', strings.infoPanel || 'Info'));
		appendInfoField(infoList, strings.schedule || 'Schedule', finding.schedule_label || finding.schedule || '—');

		appendText(nextRunWrap, finding.next_run_label || '—');
		if (finding.next_run_relative) {
			nextRunWrap.appendChild(createElement('span', 'cws-scheduled-tasks-next-run-relative' + (finding.is_overdue ? ' is-overdue' : ''), finding.next_run_relative));
		}
		appendInfoField(infoList, strings.nextRun || 'Next Run', nextRunWrap);

		appendHighlighted(sourceNode, finding.source || '—');
		appendInfoField(infoList, strings.source || 'Source', sourceNode);
		appendInfoField(infoList, strings.size || 'Size', finding.size_label || '—');
		appendInfoField(infoList, strings.details || 'Details', finding.detail || '—');
		infoPanel.appendChild(infoList);

		argsBlock.appendChild(createElement('h4', '', strings.rawArguments || 'Raw Arguments'));
		textarea.readOnly = true;
		textarea.rows = 14;
		textarea.className = 'cws-file-contents-textarea large-text code';
		textarea.value = window.CwsReportPagination && typeof window.CwsReportPagination.withContentsFooter === 'function'
			? window.CwsReportPagination.withContentsFooter(finding.args_pretty || '', !!finding.contents_truncated, argsNoun)
			: text(finding.args_pretty || '');
		argsBlock.appendChild(textarea);

		left.appendChild(infoPanel);
		left.appendChild(argsBlock);

		whyBlock.appendChild(createElement('h4', '', strings.whySeeingThis || 'Why you are seeing this'));
		(Array.isArray(finding.summary) ? finding.summary : []).forEach(function (line) {
			whyList.appendChild(createElement('li', '', line));
		});
		if (!whyList.childNodes.length) {
			whyList.appendChild(createElement('li', '', '—'));
		}
		whyBlock.appendChild(whyList);

		howBlock.appendChild(createElement('h4', '', strings.howToProceed || 'How to proceed'));
		(Array.isArray(finding.recommendations) ? finding.recommendations : []).forEach(function (line) {
			howList.appendChild(createElement('li', '', line));
		});
		if (!howList.childNodes.length) {
			howList.appendChild(createElement('li', '', '—'));
		}
		howBlock.appendChild(howList);

		right.appendChild(whyBlock);
		right.appendChild(howBlock);

		if (window.CwsReportStatus) {
			window.CwsReportStatus.appendDismissControls(right, finding, config.scanType || 'scheduled-tasks', function () {
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
		var hookTd = document.createElement('td');
		var hookCode = createElement('code', 'cws-file-path');
		var actionsTd = document.createElement('td');
		var eye = createElement('button', 'cws-scheduled-tasks-eye');
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

		categoryTd.appendChild(renderCategoryPills(finding));
		row.appendChild(categoryTd);

		appendHighlighted(hookCode, finding.hook || '');
		hookTd.appendChild(hookCode);
		row.appendChild(hookTd);

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
			var detailRow = document.createElement('tr');
			var detailTd = document.createElement('td');
			detailRow.className = 'cws-scheduled-tasks-detail-row';
			detailTd.colSpan = 5;
			detailTd.appendChild(renderDetailPanel(finding));
			detailRow.appendChild(detailTd);
			tbody.appendChild(detailRow);
		}
	}

	function renderPagination(container, pagination) {
		window.CwsReportPagination.render(container, pagination, {
			itemLabel: config.itemNoun || 'events',
			onPageChange: function (page) {
				uiState.page = page;
				renderResult(resultState);
			}
		});
	}

	function renderSummary(resultsEl, result) {
		var summary = result.summary || {};
		var critical = parseInt(summary.critical, 10) || 0;
		var suspicious = parseInt(summary.suspicious, 10) || 0;
		var review = parseInt(summary.review, 10) || 0;
		var info = parseInt(summary.info, 10) || 0;
		var flagged = parseInt(summary.flagged, 10) || 0;
		var hasProblems = critical + suspicious > 0;
		var className = critical > 0 ? 'cws-core-checksum-results is-error' : (suspicious > 0 ? 'cws-core-checksum-results is-warning' : 'cws-core-checksum-results is-success');
		var panel = createElement('div', className);
		var message = hasProblems ?
			format(strings.scanCompleteIssues, numberFormat(critical), numberFormat(suspicious), numberFormat(review), numberFormat(info), numberFormat(flagged)) :
			format(strings.scanCompleteClean, numberFormat(review), numberFormat(info), numberFormat(flagged));

		panel.appendChild(createElement('p', 'cws-core-checksum-summary', message));

		if (result.wordpress_configured_table && result.options_table && result.wordpress_configured_table !== result.options_table) {
			panel.appendChild(createElement('p', '', format(strings.configuredTable, result.wordpress_configured_table)));
		}

		resultsEl.appendChild(panel);
	}

	function renderTable(resultsEl, findings) {
		var sectionEl = createElement('div', 'cws-report-section cws-scheduled-tasks-section');
		var filtered = filteredFindings(findings);
		var sorted = sortedFindings(filtered);
		var pagination = paginate(sorted);
		var table = createElement('table', 'widefat striped cws-core-checksum-table cws-scheduled-tasks-table');
		var thead = document.createElement('thead');
		var headerRow = document.createElement('tr');
		var tbody = document.createElement('tbody');

		renderToolbar(sectionEl);

		if (!filtered.length) {
			sectionEl.appendChild(createElement('p', '', uiState.status === 'needs_review' ? (strings.noFlagged || strings.noFindings) : (strings.noFindings || 'No WP-Cron events matched the current filters.')));
			resultsEl.appendChild(sectionEl);
			return;
		}

		headerRow.appendChild(sortableHeader(strings.risk, 'risk'));
		headerRow.appendChild(createElement('th', '', strings.status || 'Status'));
		headerRow.appendChild(createElement('th', '', strings.category));
		headerRow.appendChild(sortableHeader(strings.hook, 'hook'));
		headerRow.appendChild(createElement('th', '', strings.actions));
		thead.appendChild(headerRow);
		table.appendChild(thead);

		pagination.items.forEach(function (finding) {
			renderFindingRow(tbody, finding);
		});

		table.appendChild(tbody);
		sectionEl.appendChild(table);
		renderPagination(sectionEl, pagination);
		resultsEl.appendChild(sectionEl);
	}

	function renderResult(result) {
		var resultsEl = document.getElementById('cws-scheduled-tasks-js-results');
		var fallback = document.getElementById('cws-scheduled-tasks-fallback-results');
		var helpBoxes = document.getElementById('cws-scheduled-tasks-help-boxes');
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

		if (helpBoxes) {
			helpBoxes.hidden = false;
		}

		renderSummary(resultsEl, result);
		findings = Array.isArray(result.findings) ? result.findings : [];
		renderTable(resultsEl, findings);

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

	function handleScan() {
		setBusy(true, strings.scanning);

		request('choctaw_wp_security_scheduled_tasks_scan').then(function (data) {
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
		var form = document.getElementById('cws-scheduled-tasks-form');

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
