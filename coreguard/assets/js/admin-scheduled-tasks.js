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
		critical: 5,
		warning: 4,
		suspicious: 3,
		info: 2,
		safe: 1
	};

	function findingRisk(finding) {
		return text(finding && (finding.risk_level || finding.risk) || 'info');
	}

	function findingId(finding) {
		return text(finding && (finding.finding_id || finding.id) || '');
	}

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
			warning: strings.riskWarning,
			suspicious: strings.riskSuspicious,
			info: strings.riskInfo
		};
		return map[risk] || risk || strings.riskInfo;
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

			if (uiState.category) {
				var rules = Array.isArray(finding.rules) ? finding.rules : [];
				var ruleId = text(finding.rule_id).replace(/-/g, '_');
				if (rules.indexOf(uiState.category) === -1 && ruleId !== uiState.category) {
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
				a = riskOrder[findingRisk(left)] || 0;
				b = riskOrder[findingRisk(right)] || 0;
				if (a !== b) {
					return (a - b) * dir;
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
		var categoryOptions = [{ value: '', label: strings.allCategories || 'All Categories' }];
		var riskOptions = [
			{ value: '', label: strings.allRisk || 'All Risk' },
			{ value: 'critical', label: strings.riskCritical },
			{ value: 'warning', label: strings.riskWarning },
			{ value: 'suspicious', label: strings.riskSuspicious }
		];
		var sourceOptions = [
			{ value: '', label: strings.allSources || 'All Sources' },
			{ value: 'plugin', label: strings.sourcePlugin },
			{ value: 'theme', label: strings.sourceTheme },
			{ value: 'unknown', label: strings.sourceUnknown }
		];

		Object.keys(categoryLabels).forEach(function (key) {
			// Recognized inventory is shown separately — not Findings categories.
			if (key === 'recognized_core' || key === 'recognized_plugin_theme') {
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

		container.appendChild(toolbar);
	}

	function renderRiskCell(finding) {
		var risk = findingRisk(finding);
		var cell = createElement('div', 'cws-scheduled-tasks-risk is-' + risk);
		var label = createElement('span', 'cws-scheduled-tasks-risk-label');

		label.appendChild(createCoreGuardMark());
		appendText(label, finding.risk_label || riskLabel(risk));
		cell.appendChild(label);
		return cell;
	}

	function renderCategoryPills(finding) {
		var wrap = createElement('div', 'cws-scheduled-tasks-pills');
		var display = text(finding.category_label_display || '');
		if (display) {
			wrap.appendChild(createElement('span', 'cws-scheduled-tasks-pill', display));
			return wrap;
		}
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
		var whyLines = Array.isArray(finding.why_seeing_this) && finding.why_seeing_this.length
			? finding.why_seeing_this
			: (Array.isArray(finding.summary) ? finding.summary : []);
		whyLines.forEach(function (line) {
			whyList.appendChild(createElement('li', '', line));
		});
		if (!whyList.childNodes.length) {
			whyList.appendChild(createElement('li', '', '—'));
		}
		whyBlock.appendChild(whyList);

		howBlock.appendChild(createElement('h4', '', strings.howToProceed || 'How to proceed'));
		var howLines = Array.isArray(finding.how_to_proceed) && finding.how_to_proceed.length
			? finding.how_to_proceed
			: (Array.isArray(finding.recommendations) ? finding.recommendations : []);
		howLines.forEach(function (line) {
			howList.appendChild(createElement('li', '', line));
		});
		if (!howList.childNodes.length) {
			howList.appendChild(createElement('li', '', '—'));
		}
		howBlock.appendChild(howList);

		right.appendChild(whyBlock);
		right.appendChild(howBlock);

		var cats = Array.isArray(finding.categories) ? finding.categories : [];
		if (cats.length) {
			var catBlock = createElement('div', 'cws-scheduled-tasks-categories-block');
			catBlock.appendChild(createElement('h4', '', strings.categories || 'Categories'));
			var catList = document.createElement('ul');
			cats.forEach(function (cat) {
				var label = text(cat.category_label || cat.title || cat.rule_id || '');
				var risk = text(cat.risk_level || cat.risk || '');
				catList.appendChild(createElement('li', '', label + (risk ? ' · ' + risk : '')));
			});
			catBlock.appendChild(catList);
			right.appendChild(catBlock);
		}

		if (window.CwsReportStatus) {
			window.CwsReportStatus.appendDismissControls(right, finding, config.scanType || 'scheduled-tasks', function () {
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
		var id = findingId(finding);
		var isExpanded = uiState.expandedId === id;

		if (isExpanded) {
			row.className = 'is-expanded';
		}

		if (finding.confirmed_this_run === false) {
			row.className = (row.className ? row.className + ' ' : '') + 'cws-finding-not-reconfirmed';
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
		if (finding.confirmed_this_run === false) {
			hookTd.appendChild(createElement('div', 'description', strings.notReconfirmed || 'Not reconfirmed by this incomplete run'));
		}
		row.appendChild(hookTd);

		eye.type = 'button';
		eye.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
		eye.setAttribute('aria-label', isExpanded ? (strings.hideDetails || 'Hide details') : (strings.viewDetails || 'View details'));
		eyeIcon.setAttribute('aria-hidden', 'true');
		eye.appendChild(eyeIcon);
		eye.addEventListener('click', function () {
			uiState.expandedId = isExpanded ? '' : id;
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
			message = strings.scanIncomplete || 'Scan coverage was incomplete. Previously detected findings were not cleared.';
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

	function renderInventory(resultsEl, inventory) {
		var section;
		var table;
		var thead;
		var headerRow;
		var tbody;
		var list = Array.isArray(inventory) ? inventory : [];

		section = createElement('div', 'cws-report-section cws-scheduled-tasks-inventory');
		section.appendChild(createElement('h3', '', strings.inventoryHeading || 'Recognized scheduled tasks (inventory)'));
		section.appendChild(createElement('p', 'description', strings.inventoryHelp || 'Informational only — not Findings.'));

		if (!list.length) {
			section.appendChild(createElement('p', '', strings.noInventory || 'No recognized scheduled tasks in the scanned cron option.'));
			resultsEl.appendChild(section);
			return;
		}

		table = createElement('table', 'widefat striped cws-scheduled-tasks-inventory-table');
		thead = document.createElement('thead');
		headerRow = document.createElement('tr');
		headerRow.appendChild(createElement('th', '', strings.hook || 'Hook'));
		headerRow.appendChild(createElement('th', '', strings.source || 'Source'));
		headerRow.appendChild(createElement('th', '', strings.schedule || 'Schedule'));
		headerRow.appendChild(createElement('th', '', strings.nextRun || 'Next Run'));
		thead.appendChild(headerRow);
		table.appendChild(thead);

		tbody = document.createElement('tbody');
		list.forEach(function (item) {
			var row = document.createElement('tr');
			var hookTd = document.createElement('td');
			var sourceTd = document.createElement('td');
			var scheduleTd = document.createElement('td');
			var nextTd = document.createElement('td');
			var hookCode = createElement('code', 'cws-file-path');

			appendText(hookCode, item.hook || '');
			hookTd.appendChild(hookCode);
			appendText(sourceTd, item.source || item.source_key || '');
			appendText(scheduleTd, item.schedule_label || item.schedule || '');
			appendText(nextTd, item.next_run_label || '');
			if (item.next_run_relative) {
				nextTd.appendChild(document.createElement('br'));
				nextTd.appendChild(createElement('span', 'cws-scheduled-tasks-next-run-relative', item.next_run_relative));
			}

			row.appendChild(hookTd);
			row.appendChild(sourceTd);
			row.appendChild(scheduleTd);
			row.appendChild(nextTd);
			tbody.appendChild(row);
		});

		table.appendChild(tbody);
		section.appendChild(table);
		resultsEl.appendChild(section);
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

		if (!result.rejected) {
			findings = Array.isArray(result.findings) ? result.findings : [];
			renderTable(resultsEl, findings);
			renderInventory(resultsEl, result.inventory);
		}

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
