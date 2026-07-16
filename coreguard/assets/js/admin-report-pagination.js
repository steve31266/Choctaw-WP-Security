/**
 * Shared report pagination chrome (far-right controls + range text).
 *
 * Expects window.choctawWpSecurityReportPagination from wp_localize_script.
 *
 * Always renders the footer when total > 0, including a single page
 * (controls disabled). Omit the footer when there are no rows.
 */
(function (window, document) {
	'use strict';

	var config = window.choctawWpSecurityReportPagination || {};
	var defaultStrings = config.strings || {};

	function text(value) {
		if (value === null || typeof value === 'undefined') {
			return '';
		}
		return String(value);
	}

	function format(template) {
		var args = Array.prototype.slice.call(arguments, 1);
		return text(template).replace(/%(\d+)\$s/g, function (match, index) {
			var position = parseInt(index, 10) - 1;
			return typeof args[position] === 'undefined' ? match : text(args[position]);
		});
	}

	function numberFormat(value) {
		var number = Number(value) || 0;
		if (window.Intl && typeof window.Intl.NumberFormat === 'function') {
			return new window.Intl.NumberFormat().format(number);
		}
		return String(number);
	}

	function createElement(tag, className, content) {
		var el = document.createElement(tag);
		if (className) {
			el.className = className;
		}
		if (typeof content !== 'undefined' && content !== null && content !== '') {
			el.appendChild(document.createTextNode(text(content)));
		}
		return el;
	}

	function mergeStrings(overrides) {
		var merged = {};
		var key;
		for (key in defaultStrings) {
			if (Object.prototype.hasOwnProperty.call(defaultStrings, key)) {
				merged[key] = defaultStrings[key];
			}
		}
		if (overrides && typeof overrides === 'object') {
			for (key in overrides) {
				if (Object.prototype.hasOwnProperty.call(overrides, key)) {
					merged[key] = overrides[key];
				}
			}
		}
		return merged;
	}

	/**
	 * Slice items into a page of results.
	 *
	 * @param {Array} items
	 * @param {number} page
	 * @param {number} [perPage]
	 * @returns {{items: Array, page: number, total: number, totalPages: number, perPage: number, from: number, to: number}}
	 */
	function paginate(items, page, perPage) {
		var list = Array.isArray(items) ? items : [];
		var size = parseInt(perPage, 10) || parseInt(config.pageSize, 10) || 20;
		var total = list.length;
		var totalPages = Math.max(1, Math.ceil(total / size) || 1);
		var currentPage = Math.min(Math.max(parseInt(page, 10) || 1, 1), totalPages);
		var offset = (currentPage - 1) * size;
		var from = total === 0 ? 0 : offset + 1;
		var to = Math.min(offset + size, total);

		return {
			items: list.slice(offset, offset + size),
			page: currentPage,
			total: total,
			totalPages: totalPages,
			perPage: size,
			from: from,
			to: to
		};
	}

	function pageButton(label, title, disabled, page, onPageChange) {
		var button = createElement('button', 'button button-small', label);
		button.type = 'button';
		button.title = title || '';
		button.disabled = !!disabled;
		if (!disabled && typeof onPageChange === 'function') {
			button.addEventListener('click', function () {
				onPageChange(page);
			});
		}
		return button;
	}

	/**
	 * Render the shared pagination bar.
	 *
	 * @param {HTMLElement} parent
	 * @param {{page: number, total: number, totalPages: number, from?: number, to?: number, perPage?: number}} pagination
	 * @param {{itemLabel?: string, onPageChange?: Function, strings?: Object}} [options]
	 */
	function render(parent, pagination, options) {
		var opts = options || {};
		var strings = mergeStrings(opts.strings);
		var total = pagination && typeof pagination.total !== 'undefined' ? parseInt(pagination.total, 10) || 0 : 0;
		var page;
		var totalPages;
		var perPage;
		var from;
		var to;
		var itemLabel;
		var bar;
		var info;
		var controls;
		var onPageChange;

		if (!parent || total <= 0) {
			return;
		}

		page = parseInt(pagination.page, 10) || 1;
		totalPages = Math.max(1, parseInt(pagination.totalPages, 10) || 1);
		perPage = parseInt(pagination.perPage, 10) || parseInt(config.pageSize, 10) || 20;
		from = typeof pagination.from !== 'undefined'
			? parseInt(pagination.from, 10) || 0
			: ((page - 1) * perPage) + 1;
		to = typeof pagination.to !== 'undefined'
			? parseInt(pagination.to, 10) || 0
			: Math.min(page * perPage, total);
		itemLabel = text(opts.itemLabel || strings.items || 'items');
		onPageChange = typeof opts.onPageChange === 'function' ? opts.onPageChange : null;

		bar = createElement('div', 'cws-report-pagination-bar');
		info = createElement('div', 'cws-report-pagination-info');
		controls = createElement('div', 'cws-report-pagination-controls');

		info.appendChild(
			createElement(
				'span',
				'',
				format(
					strings.showingRange || 'Showing %1$s to %2$s of %3$s %4$s.',
					numberFormat(from),
					numberFormat(to),
					numberFormat(total),
					itemLabel
				)
			)
		);
		info.appendChild(document.createTextNode(' '));
		info.appendChild(
			createElement(
				'span',
				'',
				format(
					strings.pageOf || 'Page %1$s of %2$s',
					numberFormat(page),
					numberFormat(totalPages)
				)
			)
		);

		controls.appendChild(
			pageButton('«', strings.firstPage || 'First page', page <= 1, 1, onPageChange)
		);
		controls.appendChild(
			pageButton('‹', strings.previousPage || 'Previous page', page <= 1, page - 1, onPageChange)
		);
		controls.appendChild(
			pageButton('›', strings.nextPage || 'Next page', page >= totalPages, page + 1, onPageChange)
		);
		controls.appendChild(
			pageButton('»', strings.lastPage || 'Last page', page >= totalPages, totalPages, onPageChange)
		);

		bar.appendChild(info);
		bar.appendChild(controls);
		parent.appendChild(bar);
	}

	/**
	 * Footer text for inside a Contents textarea (end-of / truncated).
	 *
	 * @param {boolean} truncated Whether contents were truncated to 16K.
	 * @param {string} [noun] Content noun (File, Arguments, Snippet, Option Value).
	 * @param {Object} [stringOverrides] Optional string overrides.
	 * @returns {string}
	 */
	function contentsFooterLabel(truncated, noun, stringOverrides) {
		var s = mergeStrings(stringOverrides);

		if (truncated) {
			return s.contentsTruncatedFooter || '---Contents truncated, first 16K displayed.';
		}

		return format(s.contentsEndOf || '---End of %1$s', noun || s.contentsNounFile || 'File');
	}

	/**
	 * Append the end-of / truncated marker inside Contents textarea text.
	 *
	 * @param {string} contents Preview contents.
	 * @param {boolean} truncated Whether contents were truncated to 16K.
	 * @param {string} [noun] Content noun (File, Arguments, Snippet, Option Value).
	 * @param {Object} [stringOverrides] Optional string overrides.
	 * @returns {string}
	 */
	function withContentsFooter(contents, truncated, noun, stringOverrides) {
		return text(contents) + '\n\n' + contentsFooterLabel(truncated, noun, stringOverrides);
	}

	window.CwsReportPagination = {
		paginate: paginate,
		render: render,
		contentsFooterLabel: contentsFooterLabel,
		withContentsFooter: withContentsFooter,
		strings: defaultStrings
	};
}(window, document));
