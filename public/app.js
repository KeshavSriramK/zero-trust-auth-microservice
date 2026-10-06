document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('login-form');
  const alertBox = document.getElementById('alert-box');
  const submitBtn = document.getElementById('submit-btn');
  const btnText = submitBtn.querySelector('.btn-text');
  const spinner = submitBtn.querySelector('.spinner');

  const sanitizeInput = (str) => {
    const temp = document.createElement('div');
    temp.textContent = str;
    return temp.innerHTML.trim();
  };

  const showAlert = (message, type = 'error') => {
    alertBox.textContent = message;
    alertBox.className = `alert ${type}`;
  };

  const hideAlert = () => {
    alertBox.className = 'alert hidden';
  };

  const setLoading = (isLoading) => {
    submitBtn.disabled = isLoading;
    if (isLoading) {
      btnText.classList.add('hidden');
      spinner.classList.remove('hidden');
    } else {
      btnText.classList.remove('hidden');
      spinner.classList.add('hidden');
    }
  };

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const rawEmail = document.getElementById('email').value;
    const rawPassword = document.getElementById('password').value;

    const email = sanitizeInput(rawEmail);
    const password = sanitizeInput(rawPassword);

    if (!email || !password) {
      showAlert('Please complete all required fields.');
      return;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      showAlert('Please enter a valid email address.');
      return;
    }

    setLoading(true);

    try {
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || 'Authentication failed.');
      }

      showAlert('Authentication successful! Establishing session...', 'success');
      form.reset();
    } catch (err) {
      showAlert(err.message || 'Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  });
});