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