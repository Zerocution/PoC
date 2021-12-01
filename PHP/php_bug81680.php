<?php

ini_set("from", "Hi\r\nInjected: I HAVE IT");
file_get_contents("http://localhost:3500");