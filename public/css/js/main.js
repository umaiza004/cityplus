// Wait for the document to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
  // Check if user is authenticated
  function isAuthenticated() {
    const token = localStorage.getItem('jwtToken'); // Adjust based on where you store the token
    return token !== null; // Basic check; enhance with jwt.verify if needed
  }

  // Handle "Report an Issue" button click with authentication check
  const reportIssueBtn = document.getElementById('reportIssueBtn');
  if (reportIssueBtn) {
    reportIssueBtn.addEventListener('click', (e) => {
      e.preventDefault(); // Prevent default link behavior
      if (isAuthenticated()) {
        window.location.href = '/submit'; // Proceed to submit page if authenticated
      } else {
        if (confirm('You need to login or register to submit a complaint. Would you like to login now?')) {
          window.location.href = '/login'; // Redirect to login page
        }
      }
    });
  }

  // Add smooth scrolling for all anchor links
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
      e.preventDefault();
      
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        window.scrollTo({
          top: target.offsetTop - 70,
          behavior: 'smooth'
        });
      }
    });
  });

  // Animate elements when they come into view
  const animateOnScroll = () => {
    const elements = document.querySelectorAll('.animate-on-scroll');
    
    elements.forEach(element => {
      const elementPosition = element.getBoundingClientRect().top;
      const windowHeight = window.innerHeight;
      
      if (elementPosition < windowHeight - 100) {
        element.classList.add('animate__animated', 'animate__fadeInUp');
      }
    });
  };

  // Add animation class to all feature cards
  document.querySelectorAll('.feature-card').forEach(card => {
    card.classList.add('animate-on-scroll');
  });

  // Load recent successes on the homepage
  if (document.getElementById('recent-successes')) {
    loadRecentSuccesses();
  }

  // Initial call to animate elements
  animateOnScroll();
  
  // Add scroll event listener for animations
  window.addEventListener('scroll', animateOnScroll);
});

// Function to load recent successful complaints
async function loadRecentSuccesses() {
  try {
    const response = await fetch('/api/complaints');
    const data = await response.json();
    
    if (data.success) {
      const resolvedComplaints = data.complaints.filter(complaint => 
        complaint.status === 'Resolved'
      ).slice(0, 3);
      
      const successesContainer = document.getElementById('recent-successes');
      
      if (resolvedComplaints.length === 0) {
        successesContainer.innerHTML = '<p>No resolved issues yet. Be the first to report and help solve community problems!</p>';
        return;
      }
      
      let html = '';
      
      resolvedComplaints.forEach(complaint => {
        const date = new Date(complaint.createdAt).toLocaleDateString();
        
        html += `
          <div class="success-item mb-3 p-3 border-bottom">
            <h5>${complaint.title}</h5>
            <p class="small text-muted mb-2">${complaint.location.address} · Resolved on ${date}</p>
            <p class="mb-0">${complaint.solution || 'This issue has been successfully resolved.'}</p>
          </div>
        `;
      });
      
      successesContainer.innerHTML = html;
    } else {
      throw new Error(data.message || 'Failed to fetch successes');
    }
  } catch (error) {
    console.error('Error loading recent successes:', error);
    document.getElementById('recent-successes').innerHTML = '<p>Unable to load recent successes. Please try again later.</p>';
  }
}

// Add animation to navbar on scroll
window.addEventListener('scroll', function() {
  const navbar = document.querySelector('.navbar');
  
  if (window.scrollY > 50) {
    navbar.classList.add('shadow');
    navbar.style.padding = '0.5rem 1rem';
  } else {
    navbar.classList.remove('shadow');
    navbar.style.padding = '1rem';
  }
});

// Form validation functions
function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(String(email).toLowerCase());
}

// Initialize all tooltips
if (typeof bootstrap !== 'undefined') {
  const tooltips = document.querySelectorAll('[data-bs-toggle="tooltip"]');
  tooltips.forEach(tooltip => {
    new bootstrap.Tooltip(tooltip);
  });
}