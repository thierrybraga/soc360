'use strict';

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-simple-form-validation]').forEach(form => {
        const submitBtn = form.querySelector('[type="submit"]');
        const btnText = submitBtn?.querySelector('.btn-text');
        const btnLoading = submitBtn?.querySelector('.btn-loading');

        form.addEventListener('submit', () => {
            if (form.checkValidity()) {
                if (submitBtn) submitBtn.disabled = true;
                btnText?.classList.add('d-none');
                btnLoading?.classList.remove('d-none');
            }
        });

        form.querySelectorAll('input, select, textarea').forEach(input => {
            input.addEventListener('blur', () => validateField(input));
            input.addEventListener('input', () => {
                if (input.classList.contains('is-invalid')) {
                    validateField(input);
                }
            });
        });
    });

    function validateField(field) {
        const value = field.value.trim();
        const isRequired = field.hasAttribute('required') || field.labels?.[0]?.classList.contains('required');

        if (isRequired && !value) {
            field.classList.add('is-invalid');
            field.classList.remove('is-valid');
        } else if (value) {
            field.classList.remove('is-invalid');
            field.classList.add('is-valid');
        } else {
            field.classList.remove('is-invalid', 'is-valid');
        }
    }
});
