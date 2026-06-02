'use strict';

window.addEventListener('load', () => {
    if (typeof window.Chart === 'undefined' && window.hasOwnProperty('Chart')) {
        console.log('Chart module exists, exposing globally');
    }
    if (typeof window.Chart === 'undefined') {
        console.warn('Chart.js failed to load as window.Chart, trying alternative approaches');
        if (typeof Chart !== 'undefined') window.Chart = Chart;
    }
});
