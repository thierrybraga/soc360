'use strict';

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('wishlist-form');
    const submitBtn = document.getElementById('submit-btn');
    const btnText = submitBtn?.querySelector('.btn-text');
    const btnLoading = submitBtn?.querySelector('.btn-loading');
    const emailInput = document.getElementById('email');
    const targetDate = new Date('2025-06-01T00:00:00').getTime();

    function updateCountdown() {
        const distance = targetDate - Date.now();
        const values = distance > 0 ? {
            days: Math.floor(distance / (1000 * 60 * 60 * 24)),
            hours: Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60)),
            minutes: Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60)),
            seconds: Math.floor((distance % (1000 * 60)) / 1000)
        } : { days: 0, hours: 0, minutes: 0, seconds: 0 };

        Object.entries(values).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) element.textContent = String(value).padStart(2, '0');
        });
    }

    updateCountdown();
    setInterval(updateCountdown, 1000);

    form?.addEventListener('submit', () => {
        if (form.checkValidity()) {
            submitBtn.disabled = true;
            btnText?.classList.add('d-none');
            btnLoading?.classList.remove('d-none');
        }
    });

    emailInput?.addEventListener('input', () => {
        const email = emailInput.value.trim();
        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (email && emailPattern.test(email)) {
            emailInput.classList.remove('is-invalid');
            emailInput.classList.add('is-valid');
        } else if (email) {
            emailInput.classList.add('is-invalid');
            emailInput.classList.remove('is-valid');
        } else {
            emailInput.classList.remove('is-invalid', 'is-valid');
        }
    });
});
