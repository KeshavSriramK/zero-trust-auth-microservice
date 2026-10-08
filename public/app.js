const authForm = document.getElementById('auth-form');
const alertBox = document.getElementById('alert-box');
const profileCard = document.getElementById('profile-card');

const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');

const btnLogin = document.getElementById('btn-login');
const btnRegister = document.getElementById('btn-register');
const btnLogout = document.getElementById('btn-logout');

function showAlert(message, isError = false) {
  alertBox.textContent = message;
  alertBox.className = `alert ${isError ? 'error' : 'success'}`;
  alertBox.classList.remove('hidden');
}

function clearAlert() {
  alertBox.textContent = '';
  alertBox.classList.add('hidden');
}

// Interceptor for API calls with auto-refresh logic
async function authenticatedFetch(url, options = {}) {
  let res = await fetch(url, options);

  // If token expired, attempt automatic refresh
  if (res.status === 401) {
    const refreshRes = await fetch('/api/refresh', { method: 'POST' });

    if (refreshRes.ok) {
      // Retry original request with newly set access token
      res = await fetch(url, options);
    } else {
      // Refresh failed, reset UI
      profileCard.classList.add('hidden');
      authForm.classList.remove('hidden');
    }
  }

  return res;
}

// Register User
btnRegister.addEventListener('click', async () => {
  clearAlert();
  try {
    const res = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: emailInput.value,
        password: passwordInput.value
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Registration failed');
    showAlert(data.message);
  } catch (err) {
    showAlert(err.message, true);
  }
});

// Login User
btnLogin.addEventListener('click', async () => {
  clearAlert();
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: emailInput.value,
        password: passwordInput.value
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Login failed');
    
    showAlert(data.message);
    checkSession();
  } catch (err) {
    showAlert(err.message, true);
  }
});

// Fetch Current Session
async function checkSession() {
  try {
    const res = await authenticatedFetch('/api/me');
    if (!res.ok) return;
    
    const data = await res.json();
    document.getElementById('user-id').textContent = data.user.id;
    document.getElementById('user-email').textContent = data.user.email;
    document.getElementById('user-role').textContent = data.user.role;
    
    authForm.classList.add('hidden');
    profileCard.classList.remove('hidden');
  } catch (err) {
    console.log('No active session.');
  }
}

// Logout User
btnLogout.addEventListener('click', async () => {
  await fetch('/api/logout', { method: 'POST' });
  profileCard.classList.add('hidden');
  authForm.classList.remove('hidden');
  showAlert('Signed out successfully.');
});

// Initial session check
checkSession();