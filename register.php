<?php
// register.php
require_once 'config.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $password = $_POST['password'];
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    
    // Validaciones
    if (strlen($username) < 3 || strlen($username) > 32) {
        die("Usuario debe tener entre 3 y 32 caracteres");
    }
    
    if (strlen($password) < 6) {
        die("Contraseña muy corta (mínimo 6 caracteres)");
    }
    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        die("Email inválido");
    }
    
    // Conectar a BD
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    // Verificar si usuario existe
    $stmt = $conn->prepare("SELECT id FROM account WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();
    
    if ($stmt->num_rows > 0) {
        die("Usuario ya existe");
    }
    $stmt->close();
    
    // Generar salt y verifier (SRP6 para WoW 3.3.5a)
    function calculateSRP6($username, $password) {
        $salt = random_bytes(32);
        $username = strtoupper($username);
        $password = strtoupper($password);
        
        $h1 = sha1($username . ':' . $password, true);
        $h2 = sha1($salt . $h1, true);
        
        // WoW usa big-endian
        $verifier = '';
        for ($i = 0; $i < 20; $i += 4) {
            $verifier .= strrev(substr($h2, $i, 4));
        }
        
        return [
            'salt' => $salt,
            'verifier' => $verifier
        ];
    }
    
    $srp = calculateSRP6($username, $password);
    
    // Insertar cuenta
    $stmt = $conn->prepare("
        INSERT INTO account (username, salt, verifier, email, reg_mail, expansion, last_ip) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ");
    
    $ip = $_SERVER['REMOTE_ADDR'];
    $stmt->bind_param(
        "sssssis", 
        $username, 
        $srp['salt'], 
        $srp['verifier'], 
        $email, 
        $email, 
        EXPANSION, 
        $ip
    );
    
    if ($stmt->execute()) {
        echo "¡Cuenta creada exitosamente!";
        // Opcional: asignar 30 días de VIP automáticamente
        // account_access.php
    } else {
        echo "Error al crear cuenta: " . $conn->error;
    }
    
    $stmt->close();
    $conn->close();
}
?>
