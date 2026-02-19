// Wait until DOM is loaded
document.addEventListener("DOMContentLoaded", () => {

    // Select all promote/demote links
    const actionLinks = document.querySelectorAll("td a");

    actionLinks.forEach(link => {
        link.addEventListener("click", (event) => {
            // Determine action type based on link text
            let actionText = link.textContent.trim();
            let confirmMsg = "";

            if (actionText.includes("Promote")) {
                confirmMsg = "Are you sure you want to promote this user to admin?";
            } else if (actionText.includes("Demote")) {
                confirmMsg = "Are you sure you want to demote this user to regular user?";
            }

            // Show confirmation popup
            if (confirmMsg) {
                const confirmed = window.confirm(confirmMsg);
                if (!confirmed) {
                    event.preventDefault(); // Stop navigation if canceled
                }
            }
        });
    });

    console.log("Admin actions JS loaded");
});
