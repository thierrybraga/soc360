'use strict';

(function () {
    function setTestEmailVisible(visible) {
        const testEmailDiv = document.getElementById('testEmailDiv');
        const sendBtnText = document.getElementById('sendBtnText');
        testEmailDiv?.classList.toggle('is-hidden', !visible);
        if (testEmailDiv) {
            testEmailDiv.style.display = visible ? 'block' : 'none';
        }
        if (sendBtnText) {
            sendBtnText.textContent = visible ? 'Enviar Teste' : 'Enviar Newsletter';
        }
    }

    function previewNewsletter() {
        const subject = document.getElementById('subject')?.value || '';
        const content = document.getElementById('content')?.value || '';

        if (!subject || !content) {
            window.OpenMonitor?.showToast?.('Preencha o assunto e o conteúdo antes de visualizar.', 'warning');
            return;
        }

        document.getElementById('previewSubject').textContent = subject;
        document.getElementById('previewContent').innerHTML = content;
        bootstrap.Modal.getOrCreateInstance(document.getElementById('previewModal')).show();
    }

    function clearForm() {
        if (!window.confirm('Tem certeza que deseja limpar todos os campos?')) {
            return;
        }

        document.getElementById('newsletterForm')?.reset();
        setTestEmailVisible(false);
    }

    function submitFromPreview() {
        bootstrap.Modal.getOrCreateInstance(document.getElementById('previewModal')).hide();
        document.getElementById('sendBtn')?.click();
    }

    document.addEventListener('DOMContentLoaded', () => {
        document.getElementById('send_test')?.addEventListener('change', event => {
            setTestEmailVisible(event.target.checked);
        });

        document.getElementById('previewNewsletterBtn')?.addEventListener('click', previewNewsletter);
        document.getElementById('clearNewsletterBtn')?.addEventListener('click', clearForm);
        document.getElementById('sendPreviewBtn')?.addEventListener('click', submitFromPreview);

        document.getElementById('newsletterForm')?.addEventListener('submit', () => {
            const sendBtn = document.getElementById('sendBtn');
            if (!sendBtn) return;

            const originalText = sendBtn.innerHTML;
            sendBtn.disabled = true;
            sendBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Enviando...';

            setTimeout(() => {
                sendBtn.disabled = false;
                sendBtn.innerHTML = originalText;
            }, 10000);
        });

        document.querySelectorAll('.toast').forEach(toast => {
            setTimeout(() => bootstrap.Toast.getOrCreateInstance(toast).hide(), 5000);
        });
    });
}());
