function filterCategory(button) {
    var buttons = document.querySelectorAll('.category-filter');
    buttons.forEach(function(btn) {
        btn.classList.remove('active');
    });
    button.classList.add('active');
    document.getElementById('category-input').value = button.dataset.value;
    document.getElementById('category-form').submit(); // Submit the form
}
