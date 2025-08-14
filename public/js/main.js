// Toggle show/hide password
document.addEventListener("click", (e) => {
  if (e.target.classList.contains("showpwd")) {
    const id = e.target.getAttribute("data-target");
    const input = document.getElementById(id);
    if (!input) return;
    input.type = input.type === "password" ? "text" : "password";
  }
});

// Client-side empty input alert (basic UX)
document.addEventListener("submit", (e) => {
  const form = e.target.closest("form");
  if (!form) return;

  const requiredInputs = form.querySelectorAll("input[required]");
  for (const inp of requiredInputs) {
    if (!inp.value.trim()) {
      e.preventDefault();
      alert("Please fill all required fields.");
      inp.focus();
      break;
    }
  }
});

