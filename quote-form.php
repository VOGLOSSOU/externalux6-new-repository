<?php
// Configuration de la base de données
$dsn = "mysql:host=srv1580.hstgr.io;dbname=u433704782_ExternaLux6Web";
$username = "u433704782_externaLux6";
$password = "externalux6PassWord";

try {
    // Création de la connexion PDO
    $pdo = new PDO($dsn, $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Vérification si le formulaire a été soumis
    if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['submit'])) {
        // Initialisation des variables
        $name = isset($_POST['form-name']) ? htmlspecialchars(trim($_POST['form-name'])) : '';
        $email = isset($_POST['form-email']) ? htmlspecialchars(trim($_POST['form-email'])) : '';
        $service_type = isset($_POST['form-service']) ? htmlspecialchars(trim($_POST['form-service'])) : '';
        $message = isset($_POST['form-message']) ? htmlspecialchars(trim($_POST['form-message'])) : '';
        
        // Création du sujet personnalisé basé sur le type de service
        $service_labels = [
            'mobile-app' => 'Mobile App Development',
            'web-app' => 'Web Application',
            'extension' => 'Browser Extension',
            'custom-tool' => 'Custom Tool',
            'security-policy' => 'Security Policy Writing',
            'penetration-testing' => 'Penetration Testing',
            'incident-response' => 'Incident Response',
            'infrastructure-security' => 'Infrastructure Security',
            'multiple' => 'Multiple Services'
        ];
        
        $service_label = isset($service_labels[$service_type]) ? $service_labels[$service_type] : $service_type;
        $subject = "Quote Request - " . $service_label;
        
        $errors = [];
        
        // Validation
        if (empty($name)) {
            $errors[] = 'Name is required.';
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Invalid email address.';
        }
        if (empty($service_type)) {
            $errors[] = 'Service type is required.';
        }
        if (empty($message)) {
            $errors[] = 'Project description is required.';
        }
        
        if (!empty($errors)) {
            $errorMessage = htmlspecialchars(implode("\\n", $errors));
            echo "<script>alert('$errorMessage'); window.history.back();</script>";
        } else {
            // Préparation du message complet avec le type de service
            $fullMessage = "Service requested: " . $service_label . "\n\n" . $message;
            
            // Préparation de la requête SQL pour l'insertion
            $stmt = $pdo->prepare("INSERT INTO visitors_emails (name, email, subject, message) VALUES (:name, :email, :subject, :message)");
            $stmt->bindParam(':name', $name);
            $stmt->bindParam(':email', $email);
            $stmt->bindParam(':subject', $subject);
            $stmt->bindParam(':message', $fullMessage);
            
            // Exécution de la requête
            if ($stmt->execute()) {
                echo "<script>alert('Thank you for your quote request! We will respond within 24 hours.'); window.location.href='services.html';</script>";
            } else {
                error_log("Erreur lors de l'insertion dans la base de données : " . implode(", ", $stmt->errorInfo()));
                echo "<script>alert('An error occurred. Please try again.'); window.history.back();</script>";
            }
        }
    }
} catch (PDOException $e) {
    echo "<script>alert('Connection error: " . addslashes($e->getMessage()) . "'); window.history.back();</script>";
}
?>