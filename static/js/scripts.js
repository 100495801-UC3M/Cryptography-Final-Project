function redirect(route) {
    window.location.href = route;
}

function emailPopUp() {
    const popup = document.querySelector(".emailPopUp");

    popup.style.display = "block";

    setTimeout(() => {
        // Detectar clics fuera del popup
        window.addEventListener("click", closePopupOutside);
    }, 100);
}

// Función para cerrar popup al hacer clic fuera
function closePopupOutside(event) {
    const popup = document.querySelector(".emailPopUp");
    if (!popup.contains(event.target) && popup.style.display === "block") {
        closePopUp();
    }
}

// Ocultar PopUp
function closePopUp() {
    const change_password = document.getElementById("change_password")

    change_password.style.display = "none";

    window.removeEventListener("click", closePopupOutside);
    document.querySelector(".emailPopUp").style.display = "none";
}

function sendEmail() {
    const change_password = document.getElementById("change_password")

    change_password.style.display = "block";
}