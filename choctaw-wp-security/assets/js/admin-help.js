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

	function handleDocumentClick(event) {
		var target = event.target;

		if (!(target instanceof Element)) {
			return;
		}

		if (target.closest('.cws-help-toggle')) {
			event.preventDefault();
			togglePanel(target.closest('.cws-help-toggle'));
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

	document.addEventListener('click', handleDocumentClick);
	document.addEventListener('keydown', handleDocumentKeydown);

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

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', initLoginRateLimitPolicyToggle);
	} else {
		initLoginRateLimitPolicyToggle();
	}
})();
