// Custom JavaScript for Advanced Cybersecurity Course

document.addEventListener('DOMContentLoaded', function() {
  // Add custom initialization logic here if needed
  console.log('Advanced Cybersecurity Course loaded');

  // Optional: Add custom event handlers, analytics, or interactive features
});

// Example: Smooth scroll for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', function (e) {
    const targetId = this.getAttribute('href').substring(1);
    const target = document.getElementById(targetId);

    if (target) {
      e.preventDefault();
      target.scrollIntoView({
        behavior: 'smooth',
        block: 'start'
      });
    }
  });
});
