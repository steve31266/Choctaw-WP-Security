(function () {
	'use strict';

	/**
	 * Wrap report tables so narrow viewports can scroll horizontally.
	 *
	 * @param {ParentNode} [root]
	 */
	function wrapReportTables(root) {
		var scope = root && root.querySelectorAll ? root : document;
		var tables = scope.querySelectorAll('table.cws-core-checksum-table');
		var i;
		var table;
		var parent;
		var wrap;

		for (i = 0; i < tables.length; i++) {
			table = tables[i];
			parent = table.parentElement;

			if (!parent || parent.classList.contains('cws-report-table-scroll')) {
				continue;
			}

			wrap = document.createElement('div');
			wrap.className = 'cws-report-table-scroll';
			parent.insertBefore(wrap, table);
			wrap.appendChild(table);
		}
	}

	function observeReportTables() {
		var target = document.querySelector('.cws-admin-layout-main') || document.body;

		if (typeof MutationObserver !== 'function' || !target) {
			return;
		}

		var observer = new MutationObserver(function (mutations) {
			var m;
			var nodes;
			var n;
			var node;

			for (m = 0; m < mutations.length; m++) {
				nodes = mutations[m].addedNodes;

				for (n = 0; n < nodes.length; n++) {
					node = nodes[n];

					if (node.nodeType !== 1) {
						continue;
					}

					if (node.matches && node.matches('table.cws-core-checksum-table')) {
						wrapReportTables(node.parentNode || document);
						continue;
					}

					if (node.querySelector && node.querySelector('table.cws-core-checksum-table')) {
						wrapReportTables(node);
					}
				}
			}
		});

		observer.observe(target, {
			childList: true,
			subtree: true,
		});
	}

	function init() {
		wrapReportTables(document);
		observeReportTables();
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', init);
	} else {
		init();
	}
})();
