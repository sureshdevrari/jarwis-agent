// jest-dom adds custom jest matchers for asserting on DOM nodes.
// allows you to do things like:
// expect(element).toHaveTextContent(/react/i)
// learn more: https://github.com/testing-library/jest-dom
import '@testing-library/jest-dom';

// Polyfill IntersectionObserver for jsdom tests
if (!global.IntersectionObserver) {
	global.IntersectionObserver = class {
		constructor() {}
		observe() {}
		unobserve() {}
		disconnect() {}
	};
}

// Silence window.scrollTo in jsdom (override even if defined)
window.scrollTo = () => {};

// Mock canvas getContext to prevent jsdom errors
if (window.HTMLCanvasElement) {
	window.HTMLCanvasElement.prototype.getContext = () => ({
		clearRect: () => {},
		fillRect: () => {},
		beginPath: () => {},
		moveTo: () => {},
		lineTo: () => {},
		stroke: () => {},
		closePath: () => {},
		fill: () => {},
		save: () => {},
		restore: () => {},
		translate: () => {},
		rotate: () => {},
		scale: () => {},
		setTransform: () => {},
	});
}
