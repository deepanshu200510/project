const oldPasswordInput = document.getElementById('old-password');
const newPasswordInput = document.getElementById('new-password');
const confirmPasswordInput = document.getElementById('confirm-password');
const changePasswordBtn = document.getElementById('change-password-btn');
const passwordInput = document.getElementById('password-input');
const showPasswordCheckbox = document.getElementById('show-password');
const notificationBtn = document.getElementById('notification-btn');

notificationBtn.addEventListener('click', () => {
  if ('Notification' in window) {
    Notification.requestPermission()
      .then(permission => {
        if (permission === 'granted') {
          const notification = new Notification('Notification Title', {
            body: 'This is a notification body.',
            icon: 'your-icon.png' // Replace with your icon URL
          });

          notification.onclick = () => {
            // Handle notification click
            console.log('Notification clicked');
          };
        }
      });
  } else {
    console.error('Notifications are not supported by your browser.');
  }
});

showPasswordCheckbox.addEventListener('change', () => {
  if (showPasswordCheckbox.checked) {
    passwordInput.type = 'text';
  } else {
    passwordInput.type = 'password';
  }
});

changePasswordBtn.addEventListener('click', async () => {
  const oldPassword = oldPasswordInput.value;
  const newPassword = newPasswordInput.value;
  const confirmPassword = confirmPasswordInput.value;

  // Basic validation
  if (!oldPassword || !newPassword || !confirmPassword) {
    alert('Please fill in all fields.');
    return;
  }

  if (newPassword !== confirmPassword) {
    alert('New passwords do not match.');
    return;
  }

  // Send a request to the server to change the password
  try {
    const response = await fetch('/change-password', { // Replace with your server endpoint
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        oldPassword,
        newPassword
      })
    });

    if (response.ok) {
      alert('Password changed successfully!');
      // Clear input fields
      oldPasswordInput.value = '';
      newPasswordInput.value = '';
      confirmPasswordInput.value = '';
    } else {
      const errorData = await response.json();
      alert(errorData.message || 'Password change failed. Please try again.');
    }
  } catch (error) {
    console.error('Error changing password:', error);
    alert('An error occurred. Please try again later.');
  }
});