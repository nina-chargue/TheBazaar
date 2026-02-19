function changeMainImage(element) {
    // Get the main image element
    var mainImage = document.getElementById('mainImage');
    // Set the src of the main image to the clicked thumbnail's src
    mainImage.src = element.src;

    // Remove the 'active' class from all thumbnails
    var thumbnails = document.querySelectorAll('.thumbnail');
    thumbnails.forEach(function(thumbnail) {
        thumbnail.classList.remove('active');
    });

    // Add the 'active' class to the clicked thumbnail
    element.classList.add('active');
}
