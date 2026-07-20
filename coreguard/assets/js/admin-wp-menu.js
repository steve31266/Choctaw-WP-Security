(function () {
	'use strict';

	/**
	 * WordPress mobile/responsive admin treats items with submenus as toggles.
	 * Sassh keeps those submenu pages registered for capabilities but hides
	 * the flyout in CSS, so a phone tap would otherwise do nothing. Force the
	 * top-level Sassh link to navigate to its href instead.
	 */
	function bindCoreGuardMenuLink() {
		var link = document.querySelector('#toplevel_page_sassh > a.menu-top');

		if (!link) {
			return;
		}

		link.addEventListener(
			'click',
			function (event) {
				var href = link.getAttribute('href');

				if (!href) {
					return;
				}

				event.preventDefault();
				event.stopImmediatePropagation();
				window.location.href = href;
			},
			true
		);
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', bindCoreGuardMenuLink);
	} else {
		bindCoreGuardMenuLink();
	}
})();
