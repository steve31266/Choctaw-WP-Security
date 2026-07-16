(function () {
	'use strict';

	function setExpanded(toggle, expanded) {
		toggle.setAttribute('aria-expanded', expanded ? 'true' : 'false');
	}

	function closePanel(toggle, panel) {
		panel.hidden = true;
		setExpanded(toggle, false);
	}

	function openPanel(toggle, panel) {
		panel.hidden = false;
		setExpanded(toggle, true);
	}

	function togglePanel(toggle) {
		var panelId = toggle.getAttribute('aria-controls');
		var panel;

		if (!panelId) {
			return;
		}

		panel = document.getElementById(panelId);

		if (!panel) {
			return;
		}

		if (panel.hidden) {
			openPanel(toggle, panel);
			return;
		}

		closePanel(toggle, panel);
	}

	function toggleReportEye(button) {
		var targetId = button.getAttribute('data-expand-target');
		var panel;
		var expanded;

		if (!targetId) {
			return;
		}

		panel = document.getElementById(targetId);

		if (!panel) {
			return;
		}

		expanded = button.getAttribute('aria-expanded') === 'true';
		panel.hidden = expanded;
		button.setAttribute('aria-expanded', expanded ? 'false' : 'true');
	}

	function handleDocumentClick(event) {
		var target = event.target;
		var eye;

		if (!(target instanceof Element)) {
			return;
		}

		if (target.closest('.cws-help-toggle')) {
			event.preventDefault();
			togglePanel(target.closest('.cws-help-toggle'));
			return;
		}

		eye = target.closest('.cws-report-eye[data-expand-target]');
		if (eye) {
			event.preventDefault();
			toggleReportEye(eye);
		}
	}

	function handleDocumentKeydown(event) {
		if ('Escape' !== event.key) {
			return;
		}

		document.querySelectorAll('.cws-help-toggle[aria-expanded="true"]').forEach(function (toggle) {
			var panelId = toggle.getAttribute('aria-controls');
			var panel = panelId ? document.getElementById(panelId) : null;

			if (panel && !panel.hidden) {
				closePanel(toggle, panel);
			}
		});
	}

	function bindSimpleTableSorting(tableId, defaultKey, defaultDir) {
		var table = document.getElementById(tableId);
		var tbody;
		var sortKey = defaultKey || '';
		var sortDir = defaultDir || 'asc';

		if (!table) {
			return;
		}

		tbody = table.querySelector('tbody');
		if (!tbody) {
			return;
		}

		table.querySelectorAll('th[data-sort-key]').forEach(function (th) {
			var button = th.querySelector('button');
			if (!button) {
				return;
			}

			button.addEventListener('click', function () {
				var key = th.getAttribute('data-sort-key');
				var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
				var indicator;

				if (sortKey === key) {
					sortDir = sortDir === 'asc' ? 'desc' : 'asc';
				} else {
					sortKey = key;
					sortDir = key === 'time' || key === 'duration' ? 'desc' : 'asc';
				}

				rows.sort(function (left, right) {
					var a = left.getAttribute('data-' + sortKey) || '';
					var b = right.getAttribute('data-' + sortKey) || '';
					var result = 0;

					if (sortKey === 'time' || sortKey === 'duration') {
						result = (parseInt(a, 10) || 0) - (parseInt(b, 10) || 0);
					} else {
						a = a.toLowerCase();
						b = b.toLowerCase();
						if (a < b) {
							result = -1;
						} else if (a > b) {
							result = 1;
						}
					}

					return sortDir === 'desc' ? result * -1 : result;
				});

				rows.forEach(function (row) {
					tbody.appendChild(row);
				});

				table.querySelectorAll('.cws-sort-indicator').forEach(function (node) {
					if (node.parentNode) {
						node.parentNode.removeChild(node);
					}
				});
				indicator = document.createElement('span');
				indicator.className = 'cws-sort-indicator';
				indicator.appendChild(document.createTextNode(sortDir === 'asc' ? ' ▲' : ' ▼'));
				button.appendChild(indicator);
			});
		});
	}

	function bindLockoutSorting() {
		bindSimpleTableSorting('cws-recent-lockouts-table', 'time', 'desc');
	}

	function bindReportTableSorting() {
		bindLockoutSorting();
	}

	document.addEventListener('click', handleDocumentClick);
	document.addEventListener('keydown', handleDocumentKeydown);

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', bindReportTableSorting);
	} else {
		bindReportTableSorting();
	}

	function syncLoginRateLimitPolicyFields() {
		var checkbox = document.getElementById('login_rate_limit_enabled');

		if (!checkbox) {
			return;
		}

		var fields = document.querySelectorAll('.cws-rate-limit-policy-field');
		var enabled = checkbox.checked;

		fields.forEach(function (field) {
			var input = field.querySelector('input[type="number"]');

			field.classList.toggle('cws-rate-limit-policy-field-is-disabled', !enabled);

			if (input) {
				input.disabled = !enabled;
			}
		});
	}

	function initLoginRateLimitPolicyToggle() {
		var checkbox = document.getElementById('login_rate_limit_enabled');

		if (!checkbox) {
			return;
		}

		checkbox.addEventListener('change', syncLoginRateLimitPolicyFields);
		syncLoginRateLimitPolicyFields();
	}

	function syncFeatureStatusBanner(banner) {
		var checkboxId = banner.getAttribute('data-checkbox-id');
		var checkbox = checkboxId ? document.getElementById(checkboxId) : null;

		if (!checkbox) {
			return;
		}

		var icon = banner.querySelector('.dashicons');
		var title = banner.querySelector('.cws-server-status-banner-title');
		var activeLabel = banner.getAttribute('data-active-label') || '';
		var disabledLabel = banner.getAttribute('data-disabled-label') || '';
		var activeIcon = banner.getAttribute('data-active-icon') || 'dashicons-yes-alt';
		var disabledIcon = banner.getAttribute('data-disabled-icon') || 'dashicons-warning';
		var isActive = checkbox.checked;

		banner.classList.toggle('is-active', isActive);
		banner.classList.toggle('is-disabled-risk', !isActive);

		if (title) {
			title.textContent = isActive ? activeLabel : disabledLabel;
		}

		if (icon) {
			icon.className = 'dashicons ' + (isActive ? activeIcon : disabledIcon);
		}
	}

	function initFeatureStatusToggles() {
		document.querySelectorAll('[data-cws-feature-status="1"]').forEach(function (banner) {
			var checkboxId = banner.getAttribute('data-checkbox-id');
			var checkbox = checkboxId ? document.getElementById(checkboxId) : null;

			if (!checkbox) {
				return;
			}

			checkbox.addEventListener('change', function () {
				syncFeatureStatusBanner(banner);
			});
			syncFeatureStatusBanner(banner);
		});
	}

	function initAdminHelpExtras() {
		initLoginRateLimitPolicyToggle();
		initFeatureStatusToggles();
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', initAdminHelpExtras);
	} else {
		initAdminHelpExtras();
	}
})();
