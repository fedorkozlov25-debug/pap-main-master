$(document).ready(function () {
    const form = document.getElementById('registrationForm');

    ['togglePassword', 'toggleConfirmPassword'].forEach(function (id) {
        document.getElementById(id).addEventListener('click', function () {
            const field = this.parentElement.querySelector('input');
            field.type = field.type === 'password' ? 'text' : 'password';
            this.querySelector('i').classList.toggle('fa-eye');
            this.querySelector('i').classList.toggle('fa-eye-slash');
        });
    });

    $(form).on('submit', function (e) {
        e.preventDefault();
        $('.error-message, #successMessage').hide();

        const name = $('#fullName').val().trim();
        const email = $('#email').val().trim();
        const phone = $('#phone').val().trim();
        // Пробелы являются частью пароля, поэтому trim() здесь не используется.
        const password = $('#password').val();
        let isValid = true;

        if (name.length < 2) {
            $('#nameError').show();
            isValid = false;
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            $('#emailError').show();
            isValid = false;
        }
        if (password.length < 8 || password.length > 1024) {
            $('#passwordError').show();
            isValid = false;
        }
        if (password !== $('#confirmPassword').val()) {
            $('#confirmPasswordError').show();
            isValid = false;
        }
        if (!$('#terms').prop('checked')) {
            $('#termsError').show();
            isValid = false;
        }
        if (!isValid) {
            return;
        }

        const button = $(form).find('button[type="submit"]');
        button.prop('disabled', true);
        $.ajax({
            url: form.action,
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({name, email, phone, password})
        }).done(function () {
            form.reset();
            $('#successMessage').show();
        }).fail(function (xhr) {
            const message = xhr.responseJSON && xhr.responseJSON.error;
            $('#registrationError').text(
                message || 'Не удалось зарегистрироваться. Попробуйте позже.'
            ).show();
        }).always(function () {
            button.prop('disabled', false);
        });
    });
});
