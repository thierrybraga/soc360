'use strict';

// Simple copy to clipboard function
    function copyToClipboard(elementId) {
      const element = document.getElementById(elementId);
      if (element) {
        navigator.clipboard.writeText(element.innerText || element.textContent)
          .then(() => {
            const btn = element.nextElementSibling;
            const originalTitle = btn.getAttribute('data-bs-title') || 'Copy Email';
            // Check if the tooltip has already been initialized
            let tooltip = bootstrap.Tooltip.getInstance(btn);
            if (!tooltip) { // Initialize if it doesn't exist
                 tooltip = new bootstrap.Tooltip(btn);
            }
            btn.setAttribute('data-bs-title', 'Copied!');
            tooltip.show();
            setTimeout(() => {
              tooltip.hide();
              btn.setAttribute('data-bs-title', originalTitle);
            }, 1500);
          })
          .catch(err => {
            console.error('Failed to copy text: ', err);
            // Optionally show an error message
          });
      }
    }
    // Initialize tooltips - Ensure Bootstrap JS has been loaded
    document.addEventListener('DOMContentLoaded', () => {
        document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => {
          new bootstrap.Tooltip(el);
        });
    });

document.addEventListener('DOMContentLoaded', function() {
      const form = document.getElementById('notification-form');
      const submitBtn = document.getElementById('submit-btn');
      const resetBtn = document.getElementById('reset-btn');
      const successMessage = document.getElementById('success-message');
      const emailInput = document.getElementById('email');
      const emailToggle = document.getElementById('emailToggle');

      // Email validation
      function validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
      }

      // Real-time email validation
      emailInput.addEventListener('input', function() {
        const email = this.value.trim();
        const isValid = email === '' || validateEmail(email);
        
        this.classList.toggle('is-invalid', !isValid && email !== '');
        this.classList.toggle('is-valid', isValid && email !== '');
        
        const feedback = document.getElementById('email-feedback');
        if (!isValid && email !== '') {
          feedback.textContent = 'Please enter a valid email address.';
        }
      });

      // Toggle email input based on switch
      emailToggle.addEventListener('change', function() {
        const method = emailInput.closest('.notification-method');
        method.classList.toggle('enabled', this.checked);
        
        if (this.checked) {
          emailInput.required = true;
          emailInput.focus();
        } else {
          emailInput.required = false;
          emailInput.classList.remove('is-invalid', 'is-valid');
        }
      });

      // Reset form
      resetBtn.addEventListener('click', function() {
        form.reset();
        document.querySelectorAll('.form-control').forEach(input => {
          input.classList.remove('is-valid', 'is-invalid');
        });
        document.querySelectorAll('.notification-method').forEach(method => {
          method.classList.remove('enabled');
        });
        successMessage.classList.add('d-none');
        showToast('Form reset successfully', 'info');
      });

      // Form submission
      form.addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Validate form
        let isValid = true;
        
        if (emailToggle.checked) {
          const email = emailInput.value.trim();
          if (!email || !validateEmail(email)) {
            emailInput.classList.add('is-invalid');
            isValid = false;
          }
        }
        
        if (!isValid) {
          showToast('Please fix the errors before submitting', 'error');
          return;
        }
        
        // Show loading state
        const btnText = submitBtn.querySelector('.btn-text');
        const btnLoading = submitBtn.querySelector('.btn-loading');
        
        btnText.classList.add('d-none');
        btnLoading.classList.remove('d-none');
        submitBtn.disabled = true;
        
        // Simulate form submission (replace with actual AJAX call)
        setTimeout(() => {
          // Reset button state
          btnText.classList.remove('d-none');
          btnLoading.classList.add('d-none');
          submitBtn.disabled = false;
          
          // Show success message
          successMessage.classList.remove('d-none');
          showToast('Notification preferences saved successfully!', 'success');
          
          // Hide success message after 3 seconds
          setTimeout(() => {
            successMessage.classList.add('d-none');
          }, 3000);
        }, 2000);
      });

      // showToast — delegates to global window.showToast (js/core/utils.js)

      // Initialize form state
      if (emailToggle.checked) {
        emailInput.closest('.notification-method').classList.add('enabled');
      }
    });
