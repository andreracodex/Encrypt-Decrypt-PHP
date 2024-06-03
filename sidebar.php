<nav id="sidebar">
    <div class="p-4">
        <div class="sidebar-header text-center mb-4">
            <img src="images/logo.png" alt="Logo" class="img-fluid" style="max-width: 100px;">
        </div>
        <h4 class="text-white">Disk Crypt</h4>
        <ul class="list-unstyled components mb-5">
            <li>
                <a href="index.php">Home</a>
            </li>
            <li>
                <a href="#encryptSubmenu" data-toggle="collapse" aria-expanded="false" class="dropdown-toggle">ECC</a>
                <ul class="collapse list-unstyled" id="encryptSubmenu">
                    <li>
                        <a href="encrypt-ecc.php">Encrypt File</a>
                    </li>
                    <li>
                        <a href="decrypt-ecc.php">Decrypt File</a>
                    </li>
                </ul>
            </li>
            <li>
                <a href="#decryptSubmenu" data-toggle="collapse" aria-expanded="false" class="dropdown-toggle">AES</a>
                <ul class="collapse list-unstyled" id="decryptSubmenu">
                    <li>
                        <a href="encrypt-aes.php">Encrypt File</a>
                    </li>
                    <li>
                        <a href="decrypt-aes.php">Decrypt File</a>
                    </li>
                </ul>
            </li>
            <li>
                <a href="logout.php">Logout</a>
            </li>
        </ul>
    </div>
</nav>
