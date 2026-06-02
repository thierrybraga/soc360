'use strict';

document.addEventListener('DOMContentLoaded', () => {
    const ipInput = document.getElementById('ip_address');
    ipInput?.addEventListener('blur', () => {
        const ipPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const value = ipInput.value.trim();

        if (value && !ipPattern.test(value)) {
            ipInput.classList.add('is-invalid');
            ipInput.classList.remove('is-valid');

            let feedback = ipInput.parentNode.querySelector('.invalid-feedback');
            if (!feedback) {
                feedback = document.createElement('div');
                feedback.className = 'invalid-feedback';
                ipInput.parentNode.appendChild(feedback);
            }
            feedback.textContent = 'Por favor, insira um endereço IP válido';
        } else if (value) {
            ipInput.classList.remove('is-invalid');
            ipInput.classList.add('is-valid');
        }
    });

});
