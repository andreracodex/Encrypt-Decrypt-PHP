    document.addEventListener('DOMContentLoaded', function() {
        var sidebarCollapse = document.getElementById('sidebarCollapse');
        var sidebar = document.getElementById('sidebar');
        var content = document.getElementById('content');

        sidebarCollapse.addEventListener('click', function() {
            sidebar.classList.toggle('active');
            content.classList.toggle('active');
        });
    });
