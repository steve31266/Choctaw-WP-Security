(function () {
	'use strict';

	var DESKTOP_MIN_WIDTH = 1100;
	var PHONE_MAX_WIDTH = 782;

	function isDesktop() {
		return window.matchMedia('(min-width: ' + DESKTOP_MIN_WIDTH + 'px)').matches;
	}

	function isPhone() {
		return window.matchMedia('(max-width: ' + PHONE_MAX_WIDTH + 'px)').matches;
	}

	/**
	 * Sync drawer left offset to the live WordPress admin menu width.
	 *
	 * WordPress can collapse via body.folded or auto-fold CSS (≤960px) without
	 * always reflecting that in a class we can rely on alone.
	 */
	function syncWpMenuOffset() {
		var width = 0;

		if (!isPhone()) {
			var menu = document.getElementById('adminmenuwrap');
			width = menu ? menu.offsetWidth : 0;
		}

		document.documentElement.style.setProperty('--cws-wp-menu-width', width + 'px');
	}

	function getFocusable(container) {
		return Array.prototype.slice.call(
			container.querySelectorAll(
				'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
			)
		).filter(function (el) {
			return el.offsetWidth > 0 || el.offsetHeight > 0 || el.getClientRects().length > 0;
		});
	}

	function initNavigation() {
		var toggle = document.querySelector('.cws-menu-toggle');
		var drawer = document.getElementById('cws-admin-nav');
		var closeButton = document.querySelector('.cws-menu-close');
		var backdrop = document.querySelector('.cws-menu-backdrop');
		var collapseButton = document.getElementById('collapse-button');

		if (!toggle || !drawer || !closeButton || !backdrop) {
			return;
		}

		syncWpMenuOffset();

		var openDrawer = function () {
			if (isDesktop()) {
				return;
			}

			syncWpMenuOffset();
			drawer.classList.add('is-open');
			backdrop.hidden = false;
			toggle.setAttribute('aria-expanded', 'true');
			document.body.classList.add('cws-menu-open');
			closeButton.focus();
		};

		var closeDrawer = function (options) {
			var restoreFocus = !options || options.restoreFocus !== false;

			drawer.classList.remove('is-open');
			backdrop.hidden = true;
			toggle.setAttribute('aria-expanded', 'false');
			document.body.classList.remove('cws-menu-open');

			if (restoreFocus && !isDesktop()) {
				toggle.focus();
			}
		};

		toggle.addEventListener('click', function () {
			if (drawer.classList.contains('is-open')) {
				closeDrawer();
				return;
			}

			openDrawer();
		});

		closeButton.addEventListener('click', function () {
			closeDrawer();
		});

		backdrop.addEventListener('click', function () {
			closeDrawer();
		});

		document.addEventListener('keydown', function (event) {
			if (!drawer.classList.contains('is-open') || isDesktop()) {
				return;
			}

			if (event.key === 'Escape') {
				closeDrawer();
				return;
			}

			if (event.key !== 'Tab') {
				return;
			}

			var focusable = getFocusable(drawer);

			if (!focusable.length) {
				return;
			}

			var first = focusable[0];
			var last = focusable[focusable.length - 1];

			if (event.shiftKey && document.activeElement === first) {
				event.preventDefault();
				last.focus();
				return;
			}

			if (!event.shiftKey && document.activeElement === last) {
				event.preventDefault();
				first.focus();
			}
		});

		drawer.addEventListener('click', function (event) {
			if (event.target.closest('a')) {
				closeDrawer({ restoreFocus: false });
			}
		});

		window.addEventListener('resize', function () {
			syncWpMenuOffset();

			if (isDesktop() && drawer.classList.contains('is-open')) {
				closeDrawer({ restoreFocus: false });
			}
		});

		if (collapseButton) {
			collapseButton.addEventListener('click', function () {
				window.setTimeout(syncWpMenuOffset, 50);
			});
		}

		if (typeof MutationObserver === 'function') {
			var observer = new MutationObserver(function () {
				syncWpMenuOffset();
			});

			observer.observe(document.body, {
				attributes: true,
				attributeFilter: ['class'],
			});
		}
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', initNavigation);
	} else {
		initNavigation();
	}
})();
