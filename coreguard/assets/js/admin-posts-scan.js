(function () {
	'use strict';

	var config = window.choctawWpSecurityPostsScan || {};
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
		var notices = document.getElementById('cws-posts-scan-js-notices');
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
		var form = document.getElementById('cws-posts-scan-form');
		var resultsEl = document.getElementById('cws-posts-scan-js-results');
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
			safe: strings.riskSafe || 'Safe',
			info: strings.riskInfo || 'Info'
		};
		return map[risk] || risk || 'Info';
	}

	function collectFindings(result) {
		if (result && Array.isArray(result.findings) && result.findings.length) {
			return result.findings;
		}
		var findings = [];
		var sections = (result && result.sections) || {};
		Object.keys(sections).forEach(function (sectionKey) {
			var mappedKey = sectionKey;
			if (sectionKey === 'script_iframe_injection' || sectionKey === 'high_confidence_scripts') {
				mappedKey = 'scripts';
			}
			(Array.isArray(sections[sectionKey].findings) ? sections[sectionKey].findings : []).forEach(function (finding) {
				var copy = Object.assign({}, finding);
				copy.section_key = mappedKey;
				copy.category = mappedKey;
				copy.category_label = categoryLabels[mappedKey] || mappedKey;
				if (!copy.risk) {
					if (copy.severity === 'critical') {
						copy.risk = 'critical';
					} else if (copy.severity === 'warning') {
						copy.risk = 'suspicious';
					} else {
						copy.risk = 'info';
					}
				}
				copy.is_recognized = copy.risk === 'safe';
				findings.push(copy);
			});
		});
		return findings;
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
			if (uiState.category && finding.category !== uiState.category && finding.section_key !== uiState.category) {
				return false;
			}
			if (search) {
				var haystack = (
					text(finding.post_title) + ' ' +
					text(finding.excerpt) + ' ' +
					text(finding.matched_snippet) + ' ' +
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
				a = riskOrder[left.risk] || 0;
				b = riskOrder[right.risk] || 0;
				return (a - b) * dir;
			}
			if (key === 'post_id' || key === 'user_id' || key === 'size') {
				a = parseInt(left[key], 10) || 0;
				b = parseInt(right[key], 10) || 0;
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
		appendText(label, riskLabel(finding.risk));
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
				uiState.sortDir = sortKey === 'risk' || sortKey === 'size' ? 'desc' : 'asc';
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

		riskSelect.setAttribute('aria-label', strings.risk || 'Risk');
		[
			{ value: '', label: strings.allRisks || 'All risks' },
			{ value: 'critical', label: strings.riskCritical || 'Critical' },
			{ value: 'warning', label: strings.riskWarning || 'Warning' },
			{ value: 'suspicious', label: strings.riskSuspicious || 'Suspicious' },
			{ value: 'safe', label: strings.riskSafe || 'Safe' },
			{ value: 'info', label: strings.riskInfo || 'Info' }
		].forEach(function (option) {
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

		var allCat = createElement('option', '', strings.allCategories || 'All categories');
		allCat.value = '';
		categorySelect.appendChild(allCat);
		Object.keys(categoryLabels).forEach(function (key) {
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

		toolbar.appendChild(riskSelect);
		if (window.CwsReportStatus) {
			window.CwsReportStatus.appendStatusFilter(toolbar, uiState, function () {
				uiState.page = 1;
				renderResult(resultState);
			});
		}
		toolbar.appendChild(categorySelect);
		parent.appendChild(toolbar);
	}

	function renderPostIdCell(finding) {
		var postId = parseInt(finding.post_id, 10);
		var cell = document.createElement('td');
		if (isNaN(postId) || postId <= 0) {
			appendText(cell, '-');
			return cell;
		}
		var link = document.createElement('a');
		link.href = 'post.php?action=edit&post=' + postId;
		link.target = '_blank';
		link.rel = 'noopener noreferrer';
		appendText(link, text(postId));
		cell.appendChild(link);
		return cell;
	}

	function renderUserIdLink(finding) {
		var userId = parseInt(finding.user_id, 10);
		var displayName = text(finding.user_display_name || '');
		var wrap = document.createElement('span');
		var link;

		if (isNaN(userId) || userId <= 0) {
			appendText(wrap, '0');
			return wrap;
		}

		link = document.createElement('a');
		link.href = 'user-edit.php?user_id=' + userId;
		link.target = '_blank';
		link.rel = 'noopener noreferrer';
		appendText(link, text(userId));
		if (displayName) {
			link.title = displayName;
			link.setAttribute('aria-label', format(strings.userIdLabel || 'User ID %1$s (%2$s)', text(userId), displayName));
		}
		wrap.appendChild(link);
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

	function guidanceLines(value, fallback) {
		var lines = [];
		var i;
		if (Array.isArray(value)) {
			for (i = 0; i < value.length; i++) {
				if (text(value[i])) {
					lines.push(text(value[i]));
				}
			}
		} else if (text(value)) {
			lines.push(text(value));
		}
		if (!lines.length && fallback) {
			lines.push(text(fallback));
		}
		return lines;
	}

	function appendGuidanceParagraphs(parent, lines) {
		var i;
		for (i = 0; i < lines.length; i++) {
			parent.appendChild(createElement('p', '', lines[i]));
		}
	}

	function guidanceForFinding(finding) {
		return {
			why: guidanceLines(finding.why_seeing_this, strings.whySeeingThisFallback || ''),
			how: guidanceLines(finding.how_to_proceed, strings.howToProceedFallback || '')
		};
	}

	function renderDetailPanel(finding) {
		var grid = createElement('div', 'cws-report-detail-grid cws-posts-scan-detail-grid');
		var left = createElement('div', 'cws-posts-scan-detail-left');
		var right = createElement('div', 'cws-posts-scan-detail-right');
		var infoPanel = createElement('div', 'cws-posts-scan-info-panel');
		var infoList = document.createElement('dl');
		var snippetBlock = createElement('div', 'cws-posts-scan-matched-snippet');
		var textarea = document.createElement('textarea');
		var whyBlock = createElement('div', 'cws-posts-scan-why-block');
		var howBlock = createElement('div', 'cws-posts-scan-how-block');
		var guidance = guidanceForFinding(finding);
		var snippetNoun = (window.CwsReportPagination && window.CwsReportPagination.strings && window.CwsReportPagination.strings.contentsNounSnippet) || 'Snippet';

		infoPanel.appendChild(createElement('h4', '', strings.infoPanel || 'Info'));
		appendInfoField(infoList, strings.userId || 'User ID', renderUserIdLink(finding));
		appendInfoField(infoList, strings.userDisplayName || 'User Display Name', finding.user_display_name || '—');
		appendInfoField(infoList, strings.status || 'Status', finding.post_status || '—');
		appendInfoField(infoList, strings.size || 'Size', sizeFormat(finding.size || 0));
		appendInfoField(infoList, strings.detail || 'Detail', finding.detail || '—');
		if (finding.confirmed_this_run === false) {
			appendInfoField(infoList, strings.status || 'Status', strings.notConfirmedThisRun || 'Not reconfirmed by this incomplete scan');
		}
		infoPanel.appendChild(infoList);

		snippetBlock.appendChild(createElement('h4', '', strings.matchedSnippet || 'Matched Snippet'));
		textarea.readOnly = true;
		textarea.rows = 14;
		textarea.className = 'cws-file-contents-textarea large-text code';
		textarea.value = window.CwsReportPagination && typeof window.CwsReportPagination.withContentsFooter === 'function'
			? window.CwsReportPagination.withContentsFooter(finding.matched_snippet || finding.excerpt || '', !!finding.contents_truncated, snippetNoun)
			: text(finding.matched_snippet || finding.excerpt || '');
		snippetBlock.appendChild(textarea);

		left.appendChild(infoPanel);
		left.appendChild(snippetBlock);

		whyBlock.appendChild(createElement('h4', '', strings.whySeeingThis || 'Why you are seeing this'));
		appendGuidanceParagraphs(whyBlock, guidance.why);
		howBlock.appendChild(createElement('h4', '', strings.howToProceed || 'How to proceed'));
		appendGuidanceParagraphs(howBlock, guidance.how);

		right.appendChild(whyBlock);
		right.appendChild(howBlock);

		if (window.CwsReportStatus) {
			window.CwsReportStatus.appendDismissControls(right, finding, config.scanType || 'wp-posts', function () {
				uiState.expandedId = '';
				renderResult(resultState);
			});
		}

		if (window.CwsReportRelatedFindings && typeof window.CwsReportRelatedFindings.appendRelatedFindings === 'function') {
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
		var titleTd = document.createElement('td');
		var actionsTd = document.createElement('td');
		var eye = createElement('button', 'cws-report-eye');
		var eyeIcon = createElement('span', 'dashicons dashicons-visibility');
		var findingKey = text(finding.finding_id || finding.id);
		var isExpanded = uiState.expandedId === findingKey;

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
		row.appendChild(renderPostIdCell(finding));
		appendText(titleTd, finding.post_title || '');
		row.appendChild(titleTd);
		row.appendChild(createElement('td', '', finding.post_type || ''));

		eye.type = 'button';
		eye.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
		eye.setAttribute('aria-label', isExpanded ? (strings.hideDetails || 'Hide details') : (strings.viewDetails || 'View details'));
		eyeIcon.setAttribute('aria-hidden', 'true');
		eye.appendChild(eyeIcon);
		eye.addEventListener('click', function () {
			uiState.expandedId = isExpanded ? '' : findingKey;
			renderResult(resultState);
		});
		actionsTd.appendChild(eye);
		row.appendChild(actionsTd);
		tbody.appendChild(row);

		if (isExpanded) {
			var detailRow = createElement('tr', 'cws-report-detail-row');
			var detailTd = document.createElement('td');
			detailTd.colSpan = 7;
			detailTd.appendChild(renderDetailPanel(finding));
			detailRow.appendChild(detailTd);
			tbody.appendChild(detailRow);
		}
	}

	function renderTable(parent, findings) {
		var section = createElement('div', 'cws-report-section cws-posts-scan-section');
		var sorted = sortedFindings(filteredFindings(findings));
		var pagination = paginate(sorted);
		var table = createElement('table', 'widefat striped cws-core-checksum-table cws-posts-scan-table');
		var thead = document.createElement('thead');
		var headerRow = document.createElement('tr');
		var tbody = document.createElement('tbody');
		var actionsTh = document.createElement('th');

		renderToolbar(section);

		if (!sorted.length) {
			section.appendChild(createElement('p', '', uiState.status === 'needs_review' ? (strings.noFlagged || strings.noFindings) : (strings.noFindings || 'No findings matched the current filters.')));
			parent.appendChild(section);
			return;
		}

		headerRow.appendChild(sortableHeader(strings.risk || 'Risk', 'risk'));
		headerRow.appendChild(createElement('th', '', strings.status || 'Status'));
		headerRow.appendChild(sortableHeader(strings.category || 'Category', 'category'));
		headerRow.appendChild(sortableHeader(strings.postId || 'Post ID', 'post_id'));
		headerRow.appendChild(sortableHeader(strings.title || 'Title', 'post_title'));
		headerRow.appendChild(sortableHeader(strings.type || 'Type', 'post_type'));
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
		var warning = parseInt(summary.warning, 10) || 0;
		var suspicious = parseInt(summary.suspicious, 10) || 0;
		var incomplete = !result.rejected && (!!result.scan_incomplete || result.coverage_complete === false || (result.completion_status && result.completion_status !== 'success'));
		var hasProblems = critical + warning + suspicious > 0;
		var className;
		var panel;
		var message;
		var i;

		if (result.rejected) {
			message = (Array.isArray(result.errors) && result.errors.length) ? result.errors[0] : (strings.scanRejected || 'This posts table cannot be scanned.');
			panel = createElement('div', 'cws-core-checksum-results is-error');
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
			panel.appendChild(createElement('p', '', strings.priorFindingsOnly || 'Showing previously detected findings that were not reconfirmed by this incomplete run.'));
		}

		if (Array.isArray(result.errors) && result.errors.length) {
			for (i = 0; i < result.errors.length; i++) {
				panel.appendChild(createElement('p', '', result.errors[i]));
			}
		}

		if (result.wordpress_configured_table && result.posts_table && result.wordpress_configured_table !== result.posts_table) {
			panel.appendChild(createElement('p', '', format(strings.configuredTable, result.wordpress_configured_table)));
		}
		resultsEl.appendChild(panel);
	}

	function renderResult(result) {
		var resultsEl = document.getElementById('cws-posts-scan-js-results');
		var fallback = document.getElementById('cws-posts-scan-fallback-results');
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
		var button = document.querySelector('#cws-posts-scan-form input[name="choctaw_wp_security_posts_scan"]');
		if (button && resultState) {
			button.value = strings.rescanButton || button.value;
		}
	}

	function handleScan() {
		setBusy(true, strings.scanning);
		request('choctaw_wp_security_posts_scan').then(function (data) {
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
		var form = document.getElementById('cws-posts-scan-form');
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
