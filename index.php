<?php
// L'application est servie depuis public/. Les autres dossiers ne sont pas accessibles par le web.
header('Location: public/', true, 302);
exit;
