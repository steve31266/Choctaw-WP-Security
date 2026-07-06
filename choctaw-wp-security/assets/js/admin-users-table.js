(function () {
	'use strict';

	var config = window.choctawWpSecurityUsersTable || {};
	var strings = config.strings || {};
	var pageSize = parseInt(config.pageSize, 10) || 20;
	var resultState = null;
	var listState = {
		page: 1,
		sortKey: 'ID',
		sortDirection: 'asc'
	};
	var activityState = {};
	var activityCache = {};
	var expandedUserId = null;

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
		var notices = document.getElementById('cws-users-table-js-notices');
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
		var selected = document.querySelector('input[name="database_scan_users_table"]:checked');

		return selected ? selected.value : '';
	}

	function selectTable(tableName) {
		var inputs;

		if (!tableName) {
			return;
		}

		inputs = document.querySelectorAll('input[name="database_scan_users_table"]');
		inputs.forEach(function (input) {
			input.checked = input.value === tableName;
		});
	}

	function setBusy(isBusy, message) {
		var form = document.getElementById('cws-users-table-form');
		var resultsEl = document.getElementById('cws-users-table-js-results');
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

	function request(action, extraFields) {
		var body = new window.FormData();

		body.append('action', action);
		body.append('nonce', config.nonce || '');
		body.append('database_scan_users_table', getSelectedTable() || '');

		if (extraFields) {
			Object.keys(extraFields).forEach(function (key) {
				body.append(key, extraFields[key]);
			});
		}

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

	function getListSortValue(user, key) {
		if (key === 'ID') {
			return parseInt(user.ID, 10) || 0;
		}

		if (key === 'user_registered') {
			return text(user.user_registered || '');
		}

		return text(user[key] || '').toLowerCase();
	}

	function sortedUsers(users) {
		var sorted = users.slice();

		if (!listState.sortKey) {
			return sorted;
		}

		sorted.sort(function (left, right) {
			var leftValue = getListSortValue(left, listState.sortKey);
			var rightValue = getListSortValue(right, listState.sortKey);
			var result = 0;

			if (leftValue < rightValue) {
				result = -1;
			} else if (leftValue > rightValue) {
				result = 1;
			}

			return listState.sortDirection === 'desc' ? result * -1 : result;
		});

		return sorted;
	}

	function setListSort(sortKey) {
		if (listState.sortKey === sortKey) {
			listState.sortDirection = listState.sortDirection === 'asc' ? 'desc' : 'asc';
		} else {
			listState.sortKey = sortKey;
			listState.sortDirection = 'asc';
		}

		listState.page = 1;
		renderResult(resultState);
	}

	function paginateItems(items, page) {
		var total = items.length;
		var totalPages = Math.max(1, Math.ceil(total / pageSize));
		var currentPage = Math.min(Math.max(parseInt(page, 10) || 1, 1), totalPages);
		var offset = (currentPage - 1) * pageSize;

		return {
			items: items.slice(offset, offset + pageSize),
			page: currentPage,
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

	function renderPagination(parent, pagination, onPageChange) {
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

		links.appendChild(pageButton('«', strings.firstPage, pagination.page <= 1, function () {
			onPageChange(1);
		}));
		links.appendChild(pageButton('‹', strings.previousPage, pagination.page <= 1, function () {
			onPageChange(pagination.page - 1);
		}));
		links.appendChild(pageText);
		links.appendChild(pageButton('›', strings.nextPage, pagination.page >= pagination.totalPages, function () {
			onPageChange(pagination.page + 1);
		}));
		links.appendChild(pageButton('»', strings.lastPage, pagination.page >= pagination.totalPages, function () {
			onPageChange(pagination.totalPages);
		}));

		pages.appendChild(count);
		pages.appendChild(links);
		nav.appendChild(pages);
		parent.appendChild(nav);
	}

	function sortableHeader(label, sortKey, state, onSort) {
		var th = document.createElement('th');
		var button = createElement('button', 'cws-sortable-column', label);

		th.scope = 'col';
		button.type = 'button';
		button.setAttribute(
			'aria-label',
			label + ': ' + (state.sortKey === sortKey && state.sortDirection === 'asc' ? strings.sortDescending : strings.sortAscending)
		);
		button.addEventListener('click', function () {
			onSort(sortKey);
		});

		if (state.sortKey === sortKey) {
			button.appendChild(createElement('span', 'cws-sort-indicator', state.sortDirection === 'asc' ? ' ▲' : ' ▼'));
		}

		th.appendChild(button);
		return th;
	}

	function getActivityState(userId) {
		if (!activityState[userId]) {
			activityState[userId] = {
				page: 1,
				sortKey: 'date',
				sortDirection: 'desc',
				loading: false,
				error: ''
			};
		}

		return activityState[userId];
	}

	function getActivitySortValue(item, key) {
		if (key === 'date') {
			return text(item.date || '');
		}

		return text(item[key] || '').toLowerCase();
	}

	function sortedActivities(userId, activities) {
		var state = getActivityState(userId);
		var sorted = activities.slice();

		if (!state.sortKey) {
			return sorted;
		}

		sorted.sort(function (left, right) {
			var leftValue = getActivitySortValue(left, state.sortKey);
			var rightValue = getActivitySortValue(right, state.sortKey);
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

	function setActivitySort(userId, sortKey) {
		var state = getActivityState(userId);

		if (state.sortKey === sortKey) {
			state.sortDirection = state.sortDirection === 'asc' ? 'desc' : 'asc';
		} else {
			state.sortKey = sortKey;
			state.sortDirection = 'asc';
		}

		state.page = 1;
		renderResult(resultState);
	}

	function renderActivityPanel(container, userId) {
		var cache = activityCache[userId];
		var state = getActivityState(userId);
		var panel = createElement('div', 'cws-users-activity-panel');
		var notice;

		clearElement(container);
		panel.appendChild(createElement('p', '', strings.activityLimitations || ''));

		if (state.loading) {
			panel.appendChild(createElement('p', 'cws-users-activity-loading', strings.activityLoading || ''));
			container.appendChild(panel);
			return;
		}

		if (state.error) {
			panel.appendChild(createElement('p', '', state.error));
			container.appendChild(panel);
			return;
		}

		if (!cache || !cache.success) {
			panel.appendChild(createElement('p', 'cws-users-activity-loading', strings.activityLoading || ''));
			container.appendChild(panel);
			return;
		}

		if (cache.capped) {
			notice = createElement('p', '', format(strings.activityCapped || '', numberFormat(cache.cap || 500)));
			panel.appendChild(notice);
		}

		if (!cache.activities || !cache.activities.length) {
			panel.appendChild(createElement('p', '', strings.noActivity || ''));
			container.appendChild(panel);
			return;
		}

		var sorted = sortedActivities(userId, cache.activities);
		var pagination = paginateItems(sorted, state.page);
		var table = createElement('table', 'widefat striped cws-core-checksum-table');
		var thead = document.createElement('thead');
		var headerRow = document.createElement('tr');
		var tbody = document.createElement('tbody');

		headerRow.appendChild(sortableHeader(strings.activityDate || 'Date', 'date', state, function (sortKey) {
			setActivitySort(userId, sortKey);
		}));
		headerRow.appendChild(sortableHeader(strings.activityLabel || 'Activity', 'activity_label', state, function (sortKey) {
			setActivitySort(userId, sortKey);
		}));
		headerRow.appendChild(sortableHeader(strings.activityType || 'Type', 'object_subtype', state, function (sortKey) {
			setActivitySort(userId, sortKey);
		}));
		headerRow.appendChild(sortableHeader(strings.activityTitle || 'Title', 'title', state, function (sortKey) {
			setActivitySort(userId, sortKey);
		}));
		headerRow.appendChild(sortableHeader(strings.activityDetail || 'Status/Detail', 'detail', state, function (sortKey) {
			setActivitySort(userId, sortKey);
		}));

		thead.appendChild(headerRow);
		table.appendChild(thead);

		pagination.items.forEach(function (item) {
			var row = document.createElement('tr');

			row.appendChild(createElement('td', '', item.date || ''));
			row.appendChild(createElement('td', '', item.activity_label || ''));
			row.appendChild(createElement('td', '', item.object_subtype || ''));
			row.appendChild(createElement('td', '', item.title || ''));
			row.appendChild(createElement('td', '', item.detail || item.status || ''));
			tbody.appendChild(row);
		});

		table.appendChild(tbody);
		panel.appendChild(table);
		renderPagination(panel, pagination, function (page) {
			getActivityState(userId).page = page;
			renderResult(resultState);
		});
		container.appendChild(panel);
	}

	function loadUserActivity(userId) {
		var state = getActivityState(userId);

		if (activityCache[userId]) {
			renderResult(resultState);
			return;
		}

		state.loading = true;
		state.error = '';
		renderResult(resultState);

		request('choctaw_wp_security_user_activity_load', {
			user_id: userId
		}).then(function (data) {
			activityCache[userId] = data;
			state.loading = false;
			renderResult(resultState);
		}).catch(function (error) {
			state.loading = false;
			state.error = error.message || strings.activityError || '';
			renderResult(resultState);
		});
	}

	function toggleActivity(userId) {
		if (expandedUserId === userId) {
			expandedUserId = null;
			renderResult(resultState);
			return;
		}

		expandedUserId = userId;
		loadUserActivity(userId);
	}

	function renderSummary(resultsEl, result) {
		var summary = result.summary || {};
		var total = parseInt(summary.total, 10) || 0;
		var panel = createElement('div', 'cws-core-checksum-results is-success');

		panel.appendChild(createElement('p', 'cws-core-checksum-summary', format(strings.usersLoaded || '%s user(s) loaded.', numberFormat(total))));

		if (result.users_table) {
			panel.appendChild(createElement('p', '', format(strings.loadedTable || 'Loaded table: %s', result.users_table)));
		}

		if (result.wordpress_configured_table && result.users_table && result.wordpress_configured_table !== result.users_table) {
			panel.appendChild(createElement('p', '', format(strings.configuredTable || 'WordPress configured table: %s', result.wordpress_configured_table)));
		}

		resultsEl.appendChild(panel);
	}

	function renderUserTable(resultsEl, users) {
		var sorted = sortedUsers(users);
		var pagination = paginateItems(sorted, listState.page);
		var section = createElement('div', 'cws-report-section');
		var table = createElement('table', 'widefat striped cws-core-checksum-table');
		var thead = document.createElement('thead');
		var headerRow = document.createElement('tr');
		var tbody = document.createElement('tbody');

		headerRow.appendChild(sortableHeader(strings.id || 'ID', 'ID', listState, setListSort));
		headerRow.appendChild(sortableHeader(strings.userLogin || 'user_login', 'user_login', listState, setListSort));
		headerRow.appendChild(sortableHeader(strings.userEmail || 'user_email', 'user_email', listState, setListSort));
		headerRow.appendChild(sortableHeader(strings.userRegistered || 'user_registered', 'user_registered', listState, setListSort));
		headerRow.appendChild(sortableHeader(strings.userStatus || 'user_status', 'user_status', listState, setListSort));
		headerRow.appendChild(sortableHeader(strings.displayName || 'display_name', 'display_name', listState, setListSort));

		var actionsHeader = document.createElement('th');
		actionsHeader.scope = 'col';
		appendText(actionsHeader, strings.actions || 'Actions');
		headerRow.appendChild(actionsHeader);

		thead.appendChild(headerRow);
		table.appendChild(thead);

		pagination.items.forEach(function (user) {
			var row = document.createElement('tr');
			var loginCell = document.createElement('td');
			var actionsCell = document.createElement('td');
			var button;
			var userId = parseInt(user.ID, 10) || 0;
			var isExpanded = expandedUserId === userId;

			row.appendChild(createElement('td', '', user.ID || ''));
			loginCell.appendChild(createElement('code', 'cws-file-path', user.user_login || ''));
			row.appendChild(loginCell);
			row.appendChild(createElement('td', '', user.user_email || ''));
			row.appendChild(createElement('td', '', user.user_registered || ''));
			row.appendChild(createElement('td', '', user.user_status || ''));
			row.appendChild(createElement('td', '', user.display_name || ''));

			button = createElement('button', 'button button-secondary', isExpanded ? (strings.hideActivity || 'Hide activity') : (strings.viewActivity || 'View activity'));
			button.type = 'button';
			button.addEventListener('click', function () {
				toggleActivity(userId);
			});
			actionsCell.appendChild(button);
			row.appendChild(actionsCell);
			tbody.appendChild(row);

			if (isExpanded) {
				var activityRow = document.createElement('tr');
				var activityCell = document.createElement('td');

				activityCell.colSpan = 7;
				activityRow.appendChild(activityCell);
				renderActivityPanel(activityCell, userId);
				tbody.appendChild(activityRow);
			}
		});

		table.appendChild(tbody);
		section.appendChild(table);
		renderPagination(section, pagination, function (page) {
			listState.page = page;
			renderResult(resultState);
		});
		resultsEl.appendChild(section);
	}

	function renderBottomActions(resultsEl) {
		var actions = createElement('div', 'cws-database-scan-report-actions');
		var button = createElement('button', 'button button-secondary', strings.reloadButton || strings.loadButton || 'Load Users');

		button.type = 'button';
		button.addEventListener('click', handleLoad);
		actions.appendChild(button);
		resultsEl.appendChild(actions);
	}

	function renderResult(result) {
		var resultsEl = document.getElementById('cws-users-table-js-results');
		var fallback = document.getElementById('cws-users-table-fallback-results');
		var users;

		if (!resultsEl || !result) {
			return;
		}

		resultState = result;
		clearElement(resultsEl);

		if (fallback) {
			fallback.style.display = 'none';
		}

		if (result.users_table) {
			selectTable(result.users_table);
		}

		renderSummary(resultsEl, result);

		users = Array.isArray(result.users) ? result.users : [];

		if (!users.length) {
			resultsEl.appendChild(createElement('p', '', strings.noUsers || ''));
			updateLoadButtonLabel();
			return;
		}

		renderUserTable(resultsEl, users);
		renderBottomActions(resultsEl);
		updateLoadButtonLabel();
	}

	function updateLoadButtonLabel() {
		var button = document.querySelector('#cws-users-table-form input[name="choctaw_wp_security_users_table_load"]');

		if (button && resultState) {
			button.value = strings.reloadButton || button.value;
		}
	}

	function handleLoad() {
		setBusy(true, strings.loading || '');

		request('choctaw_wp_security_users_table_load').then(function (data) {
			listState.page = 1;
			activityState = {};
			activityCache = {};
			expandedUserId = null;
			showNotice('', 'success');
			renderResult(data.result);
		}).catch(function (error) {
			showNotice(error.message || strings.loadError || '', 'error');
		}).finally(function () {
			setBusy(false);
		});
	}

	function init() {
		var form = document.getElementById('cws-users-table-form');

		if (!form || !config.ajaxUrl) {
			return;
		}

		form.addEventListener('submit', function (event) {
			event.preventDefault();
			handleLoad();
		});

		if (config.initialResult && typeof config.initialResult === 'object') {
			renderResult(config.initialResult);
		}
	}

	ready(init);
}());
