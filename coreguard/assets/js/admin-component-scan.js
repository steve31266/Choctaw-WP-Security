(function () {
	'use strict';

	var config = window.choctawWpSecurityComponentScan || {};
	var strings = config.strings || {};
	var pageSize = parseInt(config.pageSize, 10) || 20;
	var resultState = null;
	var uiState = {
		page: 1,
		sortKey: 'risk',
		sortDir: 'desc',
		risk: '',
		status: 'needs_review',
		type: '',
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
		var notices = document.getElementById('cws-component-scan-js-notices');
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
		var form = document.getElementById('cws-component-scan-form');
		var resultsEl = document.getElementById('cws-component-scan-js-results');
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
			warning: strings.riskWarning || 'Warning',
			suspicious: strings.riskSuspicious || 'Suspicious'
		};
		return map[risk] || risk || 'Info';
	}

	function kindLabel(kind) {
		var map = {
			core: strings.kindCore || 'WordPress Core',
			theme: strings.kindTheme || 'Theme',
			plugin: strings.kindPlugin || 'Plugin'
		};
		return map[text(kind)] || (strings.kindPlugin || 'Plugin');
	}

	function findingRowKey(finding) {
		return text(finding.finding_id || finding.id || finding.fingerprint || '');
	}

	function collectFindings(result) {
		return result && Array.isArray(result.findings) ? result.findings : [];
	}

	function primaryCategory(finding) {
		var cats = Array.isArray(finding.categories) ? finding.categories : [];
		var primaryId = text(finding.primary_rule_id);
		var found = null;

		cats.forEach(function (cat) {
			if (!found && text(cat.rule_id) === primaryId) {
				found = cat;
			}
		});

		return found || cats[0] || null;
	}

	function vulnCategories(finding) {
		var cats = Array.isArray(finding.categories) ? finding.categories : [];
		return cats.filter(function (cat) {
			return text(cat.rule_id).indexOf('vuln:') === 0;
		});
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
			if (uiState.type === 'vulnerability' && !finding.has_vulnerabilities) {
				return false;
			}
			if (uiState.type === 'unrecognized' && !finding.is_unrecognized) {
				return false;
			}
			if (search) {
				var meta = finding.metadata || {};
				var haystack = (
					text(finding.title) + ' ' +
					text(meta.slug) + ' ' +
					text(meta.file) + ' ' +
					text(meta.stylesheet)
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
				a = text(left.category_label_display || left.category_label).toLowerCase();
				b = text(right.category_label_display || right.category_label).toLowerCase();
			} else {
				a = text(left.title).toLowerCase();
				b = text(right.title).toLowerCase();
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
		var category = primaryCategory(finding);
		var severity = category ? text(category.cvss_severity_label || category.severity) : '';
		var score = category ? text(category.score) : '';

		label.appendChild(createCoreGuardMark());
		appendText(label, finding.risk_label || riskLabel(finding.risk));
		wrap.appendChild(label);

		if (finding.has_vulnerabilities && severity) {
			var cvss = score
				? format(strings.cvssWithScore || 'CVSS %1$s (%2$s)', severity, score)
				: format(strings.cvssWithoutScore || 'CVSS %s', severity);
			wrap.appendChild(createElement('span', 'cws-component-scan-cvss', cvss));
		}

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
		var toolbar = createElement('div', 'cws-report-toolbar cws-component-scan-toolbar');
		var riskLabelEl = document.createElement('label');
		var riskSelect = document.createElement('select');
		var typeLabelEl = document.createElement('label');
		var typeSelect = document.createElement('select');
		var searchLabel = document.createElement('label');
		var searchInput = document.createElement('input');

		riskLabelEl.appendChild(createElement('span', 'screen-reader-text', strings.risk || 'Risk'));
		riskSelect.appendChild(new Option(strings.allRisks || 'All risks', ''));
		riskSelect.appendChild(new Option(strings.riskWarning || 'Warning', 'warning'));
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

		typeLabelEl.appendChild(createElement('span', 'screen-reader-text', strings.type || 'Type'));
		typeSelect.appendChild(new Option(strings.allTypes || 'All types', ''));
		typeSelect.appendChild(new Option(strings.typeVulnerability || 'Known Vulnerability', 'vulnerability'));
		typeSelect.appendChild(new Option(strings.typeUnrecognized || 'Unrecognized Component', 'unrecognized'));
		typeSelect.value = uiState.type;
		typeSelect.addEventListener('change', function () {
			uiState.type = typeSelect.value;
			uiState.page = 1;
			uiState.expandedId = '';
			renderResult(resultState);
		});
		typeLabelEl.appendChild(typeSelect);
		toolbar.appendChild(typeLabelEl);

		searchLabel.appendChild(createElement('span', 'screen-reader-text', strings.search || 'Search'));
		searchInput.type = 'search';
		searchInput.placeholder = strings.searchPlaceholder || 'Search components…';
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

	function appendInfoCodeField(dl, label, value) {
		var dt = document.createElement('dt');
		var dd = document.createElement('dd');
		var code;
		appendText(dt, label);
		if (!value) {
			appendText(dd, '—');
		} else {
			code = document.createElement('code');
			code.className = 'cws-file-path';
			appendText(code, value);
			dd.appendChild(code);
		}
		dl.appendChild(dt);
		dl.appendChild(dd);
	}

	/**
	 * Accept only http(s) URLs for external links (mirror PHP sanitizer).
	 */
	function sanitizeExternalHttpUrl(raw) {
		var value = text(raw).trim();
		var parsed;
		var scheme;

		if (!value) {
			return '';
		}

		if (/^(javascript|data|vbscript|file|about):/i.test(value)) {
			return '';
		}

		try {
			parsed = new URL(value);
		} catch (err) {
			return '';
		}

		scheme = String(parsed.protocol || '').replace(/:$/, '').toLowerCase();
		if (scheme !== 'http' && scheme !== 'https') {
			return '';
		}

		if (!parsed.hostname) {
			return '';
		}

		return parsed.href;
	}

	function appendExternalLink(parent, href, label) {
		var safe = sanitizeExternalHttpUrl(href);
		var link;
		var iconWrap;
		var icon;
		var sr;

		if (!safe) {
			appendText(parent, label || '—');
			return;
		}

		link = document.createElement('a');
		link.href = safe;
		link.target = '_blank';
		link.rel = 'noopener noreferrer';
		appendText(link, label || safe);

		sr = document.createElement('span');
		sr.className = 'screen-reader-text';
		appendText(sr, strings.opensInNewTab || ' (opens in a new tab)');
		link.appendChild(sr);

		iconWrap = document.createElement('sup');
		iconWrap.className = 'cws-external-link-icon';
		iconWrap.setAttribute('aria-hidden', 'true');
		icon = document.createElement('span');
		icon.className = 'dashicons dashicons-external';
		icon.setAttribute('aria-hidden', 'true');
		iconWrap.appendChild(icon);
		link.appendChild(iconWrap);

		parent.appendChild(link);
	}

	function appendInfoUriField(dl, label, href) {
		var dt = document.createElement('dt');
		var dd = document.createElement('dd');
		var safe = sanitizeExternalHttpUrl(href);

		appendText(dt, label);
		if (!safe) {
			appendText(dd, '—');
		} else {
			appendExternalLink(dd, safe, safe);
		}
		dl.appendChild(dt);
		dl.appendChild(dd);
	}

	function appendComponentIdentityFields(infoList, meta, kind) {
		if (kind === 'plugin') {
			if (meta.plugin_uri) {
				appendInfoUriField(infoList, strings.pluginUri || 'Plugin URI', meta.plugin_uri);
			}
			if (meta.author) {
				appendInfoField(infoList, strings.author || 'Author', meta.author);
			}
			if (meta.author_uri) {
				appendInfoUriField(infoList, strings.authorUri || 'Author URI', meta.author_uri);
			}
			if (meta.update_uri) {
				appendInfoUriField(infoList, strings.updateUri || 'Update URI', meta.update_uri);
			}
			if (meta.update_hostname) {
				appendInfoField(infoList, strings.updateHostname || 'Update Host', meta.update_hostname);
			}
			if (meta.installed_path) {
				appendInfoCodeField(infoList, strings.installedPath || 'Installed Path', meta.installed_path);
			}
			appendInfoField(infoList, strings.active || 'Active', meta.active ? (strings.yes || 'Yes') : (strings.no || 'No'));
			appendInfoField(
				infoList,
				strings.networkActive || 'Network Active',
				meta.network_active ? (strings.yes || 'Yes') : (strings.no || 'No')
			);
			return;
		}

		if (kind === 'theme') {
			if (meta.theme_uri) {
				appendInfoUriField(infoList, strings.themeUri || 'Theme URI', meta.theme_uri);
			}
			if (meta.author) {
				appendInfoField(infoList, strings.author || 'Author', meta.author);
			}
			if (meta.author_uri) {
				appendInfoUriField(infoList, strings.authorUri || 'Author URI', meta.author_uri);
			}
			if (meta.update_uri) {
				appendInfoUriField(infoList, strings.updateUri || 'Update URI', meta.update_uri);
			}
			if (meta.update_hostname) {
				appendInfoField(infoList, strings.updateHostname || 'Update Host', meta.update_hostname);
			}
			if (meta.installed_path) {
				appendInfoCodeField(infoList, strings.installedPath || 'Installed Path', meta.installed_path);
			}
			appendInfoField(infoList, strings.active || 'Active', meta.active ? (strings.yes || 'Yes') : (strings.no || 'No'));
			if ( meta.via_child_theme ) {
				appendInfoField(infoList, strings.activeVia || 'Active Via', format(strings.activeViaChildTheme || 'Child theme "%s"', meta.via_child_theme));
			}
		}

		if (meta.recognition_source_label || meta.recognition_source) {
			appendInfoField(
				infoList,
				strings.recognitionSource || 'Recognition Source',
				meta.recognition_source_label || meta.recognition_source
			);
		}
		if (meta.registry_name) {
			appendInfoField(infoList, strings.registryName || 'Registry Name', meta.registry_name);
		}
		if (meta.registry_vendor) {
			appendInfoField(infoList, strings.registryVendor || 'Registry Vendor', meta.registry_vendor);
		}
	}

	function renderAdvisories(finding) {
		var vulns = vulnCategories(finding);
		if (!vulns.length && !finding.is_unrecognized) {
			return null;
		}

		var block = createElement('div', 'cws-component-scan-advisories');
		block.appendChild(createElement('h4', '', strings.advisories || 'Advisories'));

		if (finding.is_unrecognized) {
			block.appendChild(createElement('p', 'description', strings.unrecognizedNote || 'This component was not recognized by the WPVulnerability API.'));
		}

		vulns.forEach(function (category) {
			var item = createElement('div', 'cws-component-scan-advisory-item');
			var titleLine = createElement('p', 'cws-component-scan-advisory-title');
			var severity = text(category.cvss_severity_label || category.severity);
			var score = text(category.score);
			var description = text(category.description);
			var versionRange = text(category.version_range);
			var sources = Array.isArray(category.sources) ? category.sources : [];
			var list;

			titleLine.appendChild(createElement('strong', '', category.advisory_name || category.title || ''));
			if (severity) {
				var cvss = score
					? format(strings.cvssWithScore || 'CVSS %1$s (%2$s)', severity, score)
					: format(strings.cvssWithoutScore || 'CVSS %s', severity);
				titleLine.appendChild(createElement('span', 'cws-component-scan-cvss', cvss));
			}
			item.appendChild(titleLine);

			if (description) {
				item.appendChild(createElement('p', '', description));
			}

			if (versionRange || category.unfixed || category.closed) {
				list = document.createElement('ul');
				if (versionRange) {
					list.appendChild(createElement('li', '', format(strings.affectedVersions || 'Affected versions: %s', versionRange)));
				}
				if (category.unfixed) {
					list.appendChild(createElement('li', '', strings.unfixedNote || 'No fixed version has been published yet for this advisory.'));
				}
				if (category.closed) {
					list.appendChild(createElement('li', '', strings.closedNote || 'This advisory record is marked closed by the provider.'));
				}
				item.appendChild(list);
			}

			if (sources.length) {
				var sourcesLine = createElement('p', 'cws-component-scan-advisory-sources');
				appendText(sourcesLine, (strings.sources || 'Sources:') + ' ');
				sources.forEach(function (source, index) {
					if (!source || !source.link) {
						return;
					}
					if (index > 0) {
						appendText(sourcesLine, ', ');
					}
					appendExternalLink(sourcesLine, source.link, source.name || source.link);
				});
				item.appendChild(sourcesLine);
			}

			block.appendChild(item);
		});

		if (vulns.length) {
			block.appendChild(createElement('p', 'description', strings.exposureNote || 'This reflects a known public vulnerability advisory for the installed version (exposure / unpatched risk) — it is not confirmation that this site has been compromised or that malware is present.'));
		}

		return block;
	}

	function renderDetailPanel(finding) {
		var grid = createElement('div', 'cws-report-detail-grid cws-component-scan-detail-grid');
		var left = createElement('div', 'cws-component-scan-detail-left');
		var right = createElement('div', 'cws-component-scan-detail-right');
		var infoPanel = createElement('div', 'cws-component-scan-info-panel');
		var infoList = document.createElement('dl');
		var whyBlock = createElement('div', 'cws-component-scan-why-block');
		var howBlock = createElement('div', 'cws-component-scan-how-block');
		var whyList = document.createElement('ul');
		var howList = document.createElement('ul');
		var meta = finding.metadata || {};
		var kind = text(meta.kind);
		var advisories;

		infoPanel.appendChild(createElement('h4', '', strings.infoPanel || 'Info'));
		if (kind === 'plugin' || kind === 'theme') {
			infoPanel.appendChild(createElement('p', 'description', strings.identityInformational || 'Header and path fields below are informational only. They help you review the component and are not used by themselves to recognize or whitelist it.'));
		}
		appendInfoField(infoList, strings.kind || 'Kind', kindLabel(kind));
		if (meta.slug) {
			appendInfoCodeField(infoList, strings.slug || 'Slug', meta.slug);
		}
		if (meta.file) {
			appendInfoCodeField(infoList, strings.file || 'File', meta.file);
		}
		if (meta.stylesheet) {
			appendInfoCodeField(infoList, strings.stylesheet || 'Stylesheet', meta.stylesheet);
		}
		appendInfoField(infoList, strings.version || 'Version', meta.version || '—');
		appendComponentIdentityFields(infoList, meta, kind);
		infoPanel.appendChild(infoList);

		left.appendChild(infoPanel);

		advisories = renderAdvisories(finding);
		if (advisories) {
			left.appendChild(advisories);
		}

		whyBlock.appendChild(createElement('h4', '', strings.whySeeingThis || 'Why you are seeing this'));
		var whyLines = Array.isArray(finding.why_seeing_this) ? finding.why_seeing_this : [];
		whyLines.forEach(function (line) {
			whyList.appendChild(createElement('li', '', line));
		});
		if (!whyList.childNodes.length) {
			whyList.appendChild(createElement('li', '', '—'));
		}
		whyBlock.appendChild(whyList);

		howBlock.appendChild(createElement('h4', '', strings.howToProceed || 'How to proceed'));
		var howLines = Array.isArray(finding.how_to_proceed) ? finding.how_to_proceed : [];
		howLines.forEach(function (line) {
			howList.appendChild(createElement('li', '', line));
		});
		if (!howList.childNodes.length) {
			howList.appendChild(createElement('li', '', '—'));
		}
		howBlock.appendChild(howList);

		right.appendChild(whyBlock);
		right.appendChild(howBlock);

		if (window.CwsReportStatus) {
			window.CwsReportStatus.appendDismissControls(right, finding, config.scanType || 'component-scan', function () {
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
		var componentTd = document.createElement('td');
		var actionsTd = document.createElement('td');
		var rowKey = findingRowKey(finding);
		var eye = createElement('button', 'cws-report-eye');
		var eyeIcon = createElement('span', 'dashicons dashicons-visibility');
		var isExpanded = uiState.expandedId === rowKey;
		var meta = finding.metadata || {};

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
		categoryTd.appendChild(createElement('span', 'cws-report-pill', finding.category_label_display || finding.category_label || ''));
		row.appendChild(categoryTd);

		appendText(componentTd, finding.title || '');
		if (meta.version) {
			componentTd.appendChild(createElement('p', 'description', format(strings.componentVersion || 'Version %s', meta.version)));
		}
		if (finding.confirmed_this_run === false) {
			componentTd.appendChild(createElement('p', 'description', strings.notConfirmedThisRun || 'Not reconfirmed by this incomplete scan'));
		}
		row.appendChild(componentTd);

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
			detailTd.colSpan = 5;
			detailTd.appendChild(renderDetailPanel(finding));
			detailRow.appendChild(detailTd);
			tbody.appendChild(detailRow);
		}
	}

	function renderTable(parent, findings) {
		var section = createElement('div', 'cws-report-section cws-component-scan-section');
		var sorted = sortedFindings(filteredFindings(findings));
		var pagination = paginate(sorted);
		var table = createElement('table', 'widefat striped cws-core-checksum-table cws-component-scan-table');
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
		headerRow.appendChild(sortableHeader(strings.component || 'Component', 'component'));
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

	function appendInventoryRecognitionNote(li, entry) {
		var note;
		var parts;
		var label;

		if (!entry || (!entry.recognition_source && !entry.recognition_source_label)) {
			return;
		}

		label = entry.recognition_source_label || entry.recognition_source || '';
		parts = [format(strings.inventoryRegistryNote || 'Recognition Source: %s', label)];
		if (entry.registry_name) {
			parts.push((strings.registryName || 'Registry Name') + ': ' + text(entry.registry_name));
		}
		if (entry.registry_vendor) {
			parts.push((strings.registryVendor || 'Registry Vendor') + ': ' + text(entry.registry_vendor));
		}

		note = createElement('span', 'description', parts.join(' — '));
		li.appendChild(document.createElement('br'));
		li.appendChild(note);
	}

	function renderInventory(parent, inventory) {
		var core = inventory && inventory.core;
		var plugins = (inventory && Array.isArray(inventory.plugins)) ? inventory.plugins : [];
		var themes = (inventory && Array.isArray(inventory.themes)) ? inventory.themes : [];

		if (!core && !plugins.length && !themes.length) {
			return;
		}

		var section = createElement('div', 'cws-report-section cws-component-scan-inventory');
		var list = document.createElement('ul');
		list.className = 'cws-component-scan-clean-list';

		section.appendChild(createElement('h3', '', strings.inventoryHeading || 'Recognized, No Known Vulnerabilities'));
		section.appendChild(createElement('p', 'description', strings.inventoryDescription || 'These components were recognized by the WPVulnerability API or the Sassh recognized-components registry and have no known vulnerability advisories for the installed version. Recognition is not a safety or integrity guarantee. This inventory is informational and cannot be dismissed.'));

		if (core) {
			list.appendChild(createElement('li', '', format(strings.inventoryCore || '%s (core)', core.version || '')));
		}
		themes.forEach(function (theme) {
			var li = createElement('li', '', format(strings.inventoryTheme || '%1$s %2$s (theme)', theme.name || '', theme.version || ''));
			appendInventoryRecognitionNote(li, theme);
			list.appendChild(li);
		});
		plugins.forEach(function (plugin) {
			var li = createElement('li', '', format(strings.inventoryPlugin || '%1$s %2$s (plugin)', plugin.name || '', plugin.version || ''));
			appendInventoryRecognitionNote(li, plugin);
			list.appendChild(li);
		});

		section.appendChild(list);
		parent.appendChild(section);
	}

	function renderSummary(resultsEl, result) {
		var summary = result.summary || {};
		var warning = parseInt(summary.warning, 10) || 0;
		var suspicious = parseInt(summary.suspicious, 10) || 0;
		var total = parseInt(summary.total, 10) || 0;
		var incomplete = !!result.scan_incomplete || result.coverage_complete === false || (result.completion_status && result.completion_status !== 'success');
		var className = incomplete
			? 'cws-core-checksum-results is-warning'
			: (((warning + suspicious) > 0) ? 'cws-core-checksum-results is-warning' : 'cws-core-checksum-results is-success');
		var panel = createElement('div', className);
		var message;

		if (incomplete) {
			message = strings.scanIncomplete || 'Scan coverage was incomplete. Previously detected findings were not cleared.';
		} else if (total === 0) {
			message = strings.scanCompleteClean || 'Scan complete. No known vulnerabilities or unrecognized components were found.';
		} else {
			message = format(
				strings.scanCompleteIssues || 'Scan complete. %1$s warning and %2$s suspicious finding(s) among %3$s component(s).',
				numberFormat(warning),
				numberFormat(suspicious),
				numberFormat(total)
			);
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

		resultsEl.appendChild(panel);
	}

	function renderResult(result) {
		var resultsEl = document.getElementById('cws-component-scan-js-results');
		var fallback = document.getElementById('cws-component-scan-fallback-results');
		var helpBoxes = document.getElementById('cws-component-scan-help-boxes');
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
		renderInventory(resultsEl, result.inventory);
		if (helpBoxes) {
			helpBoxes.hidden = false;
		}
		var button = document.querySelector('#cws-component-scan-form input[name="choctaw_wp_security_component_scan"]');
		if (button && resultState) {
			button.value = strings.rescanButton || button.value;
		}
	}

	function handleScan() {
		setBusy(true, strings.scanning);
		request('choctaw_wp_security_component_scan').then(function (data) {
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
		var form = document.getElementById('cws-component-scan-form');
		if (!form || !config.ajaxUrl) {
			return;
		}
		form.addEventListener('submit', function (event) {
			event.preventDefault();
			handleScan();
		});
		if (config.initialResult && typeof config.initialResult === 'object' && config.initialResult.findings_backend === 'sassh') {
			renderResult(config.initialResult);
		}
	}

	ready(init);
})();
