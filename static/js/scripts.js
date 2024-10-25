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

function openConversation(userId) {
    document.querySelector('.conversation-list').style.display = 'none';
    document.querySelector('#conversationDetail').style.display = 'block';

    // Simular la carga de la conversación (aquí deberías hacer una llamada AJAX real)
    let conversationUser = document.querySelector('#conversationUser');
    let conversationMessages = document.querySelector('#conversationMessages');

    // Cargar el nombre del usuario (lo ideal sería cargar estos datos del servidor)
    conversationUser.innerText = userId; // Por simplicidad usamos userId, pero aquí podrías usar el nombre real

    // Simular mensajes (en una app real, obtendrás estos desde el servidor)
    conversationMessages.innerHTML = `
        <div class="message">Mensaje más reciente</div>
        <div class="message">Mensaje penúltimo</div>
        <div class="message">Mensaje anterior</div>
    `;
}

// Función para volver a la lista de conversaciones
function closeConversation() {
    document.querySelector('.conversation-list').style.display = 'block';
    document.querySelector('#conversationDetail').style.display = 'none';
}