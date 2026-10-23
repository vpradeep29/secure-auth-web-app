document.addEventListener("DOMContentLoaded", () => {
  const buttons = document.querySelectorAll(".section-link");
  const sections = document.querySelectorAll(".dashboard-section");

  buttons.forEach((button) => {
    button.addEventListener("click", () => {
      buttons.forEach((item) => {
        const selected = item === button;
        item.classList.toggle("active", selected);
        item.setAttribute("aria-current", selected ? "page" : "false");
      });

      sections.forEach((section) => {
        section.hidden = section.id !== button.dataset.section + "-section";
      });
    });
  });
});
