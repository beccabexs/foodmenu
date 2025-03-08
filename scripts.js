// Toggle function for job sector details
function toggleJobSectorDropdown(id) {
  var content = document.getElementById(id);
  if (content.style.display === "none" || content.style.display === "") {
    content.style.display = "block";  // Show the content
  } else {
    content.style.display = "none";  // Hide the content
  }
}

// Navbar Dropdown toggle
function toggleNavDropdown(id) {
  var content = document.getElementById(id);
  if (content.style.display === "none" || content.style.display === "") {
    content.style.display = "block";
  } else {
    content.style.display = "none";
  }
}

// Get all accordion buttons (job sector buttons)
var acc = document.getElementsByClassName("accordion");

// Loop through each accordion button
for (var i = 0; i < acc.length; i++) {
  acc[i].addEventListener("click", function() {
    // Toggle between hiding and showing the active panel
    this.classList.toggle("active");
    var panel = this.nextElementSibling;
    if (panel.style.display === "block") {
      panel.style.display = "none";
    } else {
      panel.style.display = "block";
    }
  });
}
