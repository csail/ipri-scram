// modules are defined as an array
// [ module function, map of requires ]
//
// map of requires is short require name -> numeric require
//
// anything defined in a previous bundle is accessed via the
// orig method which is the require for previous bundles

// eslint-disable-next-line no-global-assign
require = (function (modules, cache, entry) {
  // Save the require from previous bundle to this closure if any
  var previousRequire = typeof require === "function" && require;

  function newRequire(name, jumped) {
    if (!cache[name]) {
      if (!modules[name]) {
        // if we cannot find the module within our internal map or
        // cache jump to the current global require ie. the last bundle
        // that was added to the page.
        var currentRequire = typeof require === "function" && require;
        if (!jumped && currentRequire) {
          return currentRequire(name, true);
        }

        // If there are other bundles on this page the require from the
        // previous one is saved to 'previousRequire'. Repeat this as
        // many times as there are bundles until the module is found or
        // we exhaust the require chain.
        if (previousRequire) {
          return previousRequire(name, true);
        }

        var err = new Error('Cannot find module \'' + name + '\'');
        err.code = 'MODULE_NOT_FOUND';
        throw err;
      }

      localRequire.resolve = resolve;

      var module = cache[name] = new newRequire.Module(name);

      modules[name][0].call(module.exports, localRequire, module, module.exports);
    }

    return cache[name].exports;

    function localRequire(x){
      return newRequire(localRequire.resolve(x));
    }

    function resolve(x){
      return modules[name][1][x] || x;
    }
  }

  function Module(moduleName) {
    this.id = moduleName;
    this.bundle = newRequire;
    this.exports = {};
  }

  newRequire.isParcelRequire = true;
  newRequire.Module = Module;
  newRequire.modules = modules;
  newRequire.cache = cache;
  newRequire.parent = previousRequire;

  for (var i = 0; i < entry.length; i++) {
    newRequire(entry[i]);
  }

  // Override the current require with this new one
  return newRequire;
})({47:[function(require,module,exports) {
/**
 * uiProgressButton.js v1.0.0
 * http://www.codrops.com
 *
 * Licensed under the MIT license.
 * http://www.opensource.org/licenses/mit-license.php
 *
 * Copyright 2014, Codrops
 * http://www.codrops.com
 */
;(function (window) {

	'use strict';

	var transEndEventNames = {
		'WebkitTransition': 'webkitTransitionEnd',
		'MozTransition': 'transitionend',
		'OTransition': 'oTransitionEnd',
		'msTransition': 'MSTransitionEnd',
		'transition': 'transitionend'
	},
	    transEndEventName = transEndEventNames[Modernizr.prefixed('transition')],
	    support = { transitions: Modernizr.csstransitions };

	function extend(a, b) {
		for (var key in b) {
			if (b.hasOwnProperty(key)) {
				a[key] = b[key];
			}
		}
		return a;
	}

	function SVGEl(el) {
		this.el = el;
		// the path elements
		this.paths = [].slice.call(this.el.querySelectorAll('path'));
		// we will save both paths and its lengths in arrays
		this.pathsArr = new Array();
		this.lengthsArr = new Array();
		this._init();
	}

	SVGEl.prototype._init = function () {
		var self = this;
		this.paths.forEach(function (path, i) {
			self.pathsArr[i] = path;
			path.style.strokeDasharray = self.lengthsArr[i] = path.getTotalLength();
		});
		// undraw stroke
		this.draw(0);
	};

	// val in [0,1] : 0 - no stroke is visible, 1 - stroke is visible
	SVGEl.prototype.draw = function (val) {
		for (var i = 0, len = this.pathsArr.length; i < len; ++i) {
			this.pathsArr[i].style.strokeDashoffset = this.lengthsArr[i] * (1 - val);
		}
	};

	function UIProgressButton(el, options) {
		this.el = el;
		this.options = extend({}, this.options);
		extend(this.options, options);
		this._init();
	}

	UIProgressButton.prototype.options = {
		// time in ms that the status (success or error will be displayed) - should be at least higher than the transition-duration value defined for the stroke-dashoffset transition of both checkmark and cross strokes
		statusTime: 1500
	};

	UIProgressButton.prototype._init = function () {
		// the button
		this.button = this.el.querySelector('button');
		// progress el
		this.progressEl = new SVGEl(this.el.querySelector('svg.progress-circle'));
		// the success/error elems
		this.successEl = new SVGEl(this.el.querySelector('svg.checkmark'));
		this.errorEl = new SVGEl(this.el.querySelector('svg.cross'));
		// init events
		this._initEvents();
		// enable button
		// this._enable();
		this._disable();
	};

	UIProgressButton.prototype._initEvents = function () {
		var self = this;
		this.button.addEventListener('click', function () {
			self._submit();
		});
	};

	UIProgressButton.prototype._submit = function () {
		// by adding the loading class the button will transition to a "circle"
		// classie.addClass( this.el, 'loading' );

		var self = this,
		    onEndBtnTransitionFn = function onEndBtnTransitionFn(ev) {
			if (support.transitions) {
				if (ev.propertyName !== 'width') return false;
				this.removeEventListener(transEndEventName, onEndBtnTransitionFn);
			}

			// disable the button - this should have been the first thing to do when clicking the button.
			// however if we do so Firefox does not seem to fire the transitionend event.
			this.setAttribute('disabled', '');

			if (typeof self.options.callback === 'function') {
				self.options.callback(self);
			} else {
				// fill it (time will be the one defined in the CSS transition-duration property)
				self.setProgress(1);
				self.stop();
			}
		};

		if (support.transitions) {
			this.button.addEventListener(transEndEventName, onEndBtnTransitionFn);
		} else {
			onEndBtnTransitionFn();
		}
	};

	// runs after the progress reaches 100%
	UIProgressButton.prototype.stop = function (status) {
		var self = this,
		    endLoading = function endLoading() {
			// first undraw progress stroke.
			// self.progressEl.draw(0);

			if (typeof status === 'number') {
				var statusClass = status >= 0 ? 'success' : 'error',
				    statusEl = status >= 0 ? self.successEl : self.errorEl;

				// draw stroke of success (checkmark) or error (cross).
				statusEl.draw(1);
				// add respective class to the element
				classie.addClass(self.el, statusClass);
				// after options.statusTime remove status and undraw the respective stroke. Also enable the button.
				setTimeout(function () {
					classie.remove(self.el, statusClass);
					statusEl.draw(0);
					self._enable();
				}, self.options.statusTime);
			} else {
				self._enable();
			}
			// finally remove class loading.
			classie.removeClass(self.el, 'loading');
		};

		// give it a time (ideally the same like the transition time) so that the last progress increment animation is still visible.
		setTimeout(endLoading, 0); // 300 );
	};

	UIProgressButton.prototype.setProgress = function (val) {
		this.progressEl.draw(val);
	};

	// enable button
	UIProgressButton.prototype._enable = function () {
		this.button.removeAttribute('disabled');
	};

	UIProgressButton.prototype._disable = function () {
		this.button.setAttribute('disabled', true);
	};

	// add to global namespace
	window.UIProgressButton = UIProgressButton;
})(window);
},{}],55:[function(require,module,exports) {

var global = (1, eval)('this');
var OldModule = module.bundle.Module;
function Module(moduleName) {
  OldModule.call(this, moduleName);
  this.hot = {
    accept: function (fn) {
      this._acceptCallback = fn || function () {};
    },
    dispose: function (fn) {
      this._disposeCallback = fn;
    }
  };
}

module.bundle.Module = Module;

var parent = module.bundle.parent;
if ((!parent || !parent.isParcelRequire) && typeof WebSocket !== 'undefined') {
  var hostname = '' || location.hostname;
  var protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
  var ws = new WebSocket(protocol + '://' + hostname + ':' + '56600' + '/');
  ws.onmessage = function (event) {
    var data = JSON.parse(event.data);

    if (data.type === 'update') {
      data.assets.forEach(function (asset) {
        hmrApply(global.require, asset);
      });

      data.assets.forEach(function (asset) {
        if (!asset.isNew) {
          hmrAccept(global.require, asset.id);
        }
      });
    }

    if (data.type === 'reload') {
      ws.close();
      ws.onclose = function () {
        location.reload();
      };
    }

    if (data.type === 'error-resolved') {
      console.log('[parcel] ✨ Error resolved');
    }

    if (data.type === 'error') {
      console.error('[parcel] 🚨  ' + data.error.message + '\n' + 'data.error.stack');
    }
  };
}

function getParents(bundle, id) {
  var modules = bundle.modules;
  if (!modules) {
    return [];
  }

  var parents = [];
  var k, d, dep;

  for (k in modules) {
    for (d in modules[k][1]) {
      dep = modules[k][1][d];
      if (dep === id || Array.isArray(dep) && dep[dep.length - 1] === id) {
        parents.push(+k);
      }
    }
  }

  if (bundle.parent) {
    parents = parents.concat(getParents(bundle.parent, id));
  }

  return parents;
}

function hmrApply(bundle, asset) {
  var modules = bundle.modules;
  if (!modules) {
    return;
  }

  if (modules[asset.id] || !bundle.parent) {
    var fn = new Function('require', 'module', 'exports', asset.generated.js);
    asset.isNew = !modules[asset.id];
    modules[asset.id] = [fn, asset.deps];
  } else if (bundle.parent) {
    hmrApply(bundle.parent, asset);
  }
}

function hmrAccept(bundle, id) {
  var modules = bundle.modules;
  if (!modules) {
    return;
  }

  if (!modules[id] && bundle.parent) {
    return hmrAccept(bundle.parent, id);
  }

  var cached = bundle.cache[id];
  if (cached && cached.hot._disposeCallback) {
    cached.hot._disposeCallback();
  }

  delete bundle.cache[id];
  bundle(id);

  cached = bundle.cache[id];
  if (cached && cached.hot && cached.hot._acceptCallback) {
    cached.hot._acceptCallback();
    return true;
  }

  return getParents(global.require, id).some(function (id) {
    return hmrAccept(global.require, id);
  });
}
},{}]},{},[55,47])
//# sourceMappingURL=/dist/4e21b07b96f296b131ae21464f2482e7.map