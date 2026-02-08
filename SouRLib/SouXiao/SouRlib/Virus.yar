/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2026-02-07
   Identifier: Virus
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule Virus_Win32_Moiva {
   meta:
      description = "Virus - file Virus.Win32.Moiva.a-08c1857617a7b30f81a97a21c7b3cca99b8ad82ac868e932f8d7900f69c3d03e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "08c1857617a7b30f81a97a21c7b3cca99b8ad82ac868e932f8d7900f69c3d03e"
   strings:
      $x1 = "G*\\AC:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\Stub\\Project1.vbp" fullword wide
      $s2 = "C:\\Windows\\SysWow64\\MSDBRPTR.DLL" fullword ascii
      $s3 = "ZLIB.DLL" fullword ascii
      $s4 = "forvay.exe" fullword wide
      $s5 = "A processing error occured" fullword wide
      $s6 = "MSDataReportRuntimeLib.DataReport" fullword ascii
      $s7 = "cmdRemove" fullword ascii /* base64 encoded string 'rgQzj/' */
      $s8 = "frmLogin" fullword ascii
      $s9 = "rsLogin" fullword wide
      $s10 = "YXWVUT" fullword ascii /* reversed goodware string 'TUVWXY' */
      $s11 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s12 = "Invalid Password, Try Again" fullword wide
      $s13 = "Confirm password must be the same to password. . ." fullword wide
      $s14 = "Please enter correct password to edit this record. . ." fullword wide
      $s15 = "ReportHeader" fullword wide
      $s16 = "yyyyyyyyyyyyyyyyyyyyyy" fullword ascii
      $s17 = "Temporary Receipt" fullword ascii
      $s18 = "ZCompressByteArray >> ZLIB.Compress()" fullword wide
      $s19 = "A file system error has occured" fullword wide
      $s20 = "('.5>D&+-" fullword ascii /* hex encoded string ']' */
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule Virus_Win32_Moiva_2 {
   meta:
      description = "Virus - file Virus.Win32.Moiva.a-2986b0bd4774daf7ffbfa4f6fd239a3842e98c5774ea14ebf4726a4f8fca2a30"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "2986b0bd4774daf7ffbfa4f6fd239a3842e98c5774ea14ebf4726a4f8fca2a30"
   strings:
      $x1 = "F*\\AC:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\Stub\\Project1.vbp" fullword wide
      $s2 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s3 = "firehouses.exe" fullword wide
      $s4 = "http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:photosho" ascii
      $s5 = "//ns.adobe.com/xap/1.0/\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:st" ascii
      $s6 = "http://ns.adobe.com/photoshop/1.0/\" xmp:CreatorTool=\"Adobe Photoshop CS6 (Windows)\" xmp:CreateDate=\"2017-11-08T13:12:30+08:0" ascii
      $s7 = "frmLogin" fullword ascii
      $s8 = "LOGIN TO ACCESS THE SYSTEM" fullword ascii
      $s9 = "btnLogin" fullword ascii
      $s10 = "instanceID=\"xmp.iid:CDCDB61F0AC5E711B0EBB60B45ED057C\" stEvt:when=\"2017-11-09T12:56:45+08:00\" stEvt:softwareAgent=\"Adobe Pho" ascii
      $s11 = "YXWVUT" fullword ascii /* reversed goodware string 'TUVWXY' */
      $s12 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s13 = "C:\\Windows\\SysWOW64\\stdole2.tlb" fullword ascii
      $s14 = "floodboard" fullword wide
      $s15 = "RETYPE PASSWORD" fullword ascii
      $s16 = "lblPassword" fullword ascii
      $s17 = "PASSWORD :" fullword ascii
      $s18 = "Please enter valid username or password!" fullword wide
      $s19 = "Please fill up Password." fullword wide
      $s20 = "Please fill up Retype Password." fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule Virus_Win32_Moiva_3 {
   meta:
      description = "Virus - file Virus.Win32.Moiva.a-5167338e9391173e6017b1aa8a79bf23093f3673494199d6a92e5b77e0bd4aa2"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "5167338e9391173e6017b1aa8a79bf23093f3673494199d6a92e5b77e0bd4aa2"
   strings:
      $x1 = "G*\\AC:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\Stub\\Project1.vbp" fullword wide
      $s2 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s3 = "fireblende.exe" fullword wide
      $s4 = "floramour" fullword wide /* base64 encoded string '~Z+jj.' */
      $s5 = "http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:photosho" ascii
      $s6 = "//ns.adobe.com/xap/1.0/\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:st" ascii
      $s7 = "http://ns.adobe.com/photoshop/1.0/\" xmp:CreatorTool=\"Adobe Photoshop CS6 (Windows)\" xmp:CreateDate=\"2017-11-08T13:12:30+08:0" ascii
      $s8 = "frmLogin" fullword ascii
      $s9 = "LOGIN TO ACCESS THE SYSTEM" fullword ascii
      $s10 = "btnLogin" fullword ascii
      $s11 = "instanceID=\"xmp.iid:CDCDB61F0AC5E711B0EBB60B45ED057C\" stEvt:when=\"2017-11-09T12:56:45+08:00\" stEvt:softwareAgent=\"Adobe Pho" ascii
      $s12 = "YXWVUT" fullword ascii /* reversed goodware string 'TUVWXY' */
      $s13 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s14 = "FC:\\Windows\\SysWOW64\\stdole2.tlb" fullword ascii
      $s15 = "hamartiologist" fullword wide
      $s16 = "forwardly" fullword wide
      $s17 = "sophiologic" fullword wide
      $s18 = "RETYPE PASSWORD" fullword ascii
      $s19 = "lblPassword" fullword ascii
      $s20 = "PASSWORD :" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule Virus_Win32_Moiva_4 {
   meta:
      description = "Virus - file Virus.Win32.Moiva.a-5c523a295e64ca123dda4f517b1c9ee609af1f33ad3d8879c0e56505141a81d9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "5c523a295e64ca123dda4f517b1c9ee609af1f33ad3d8879c0e56505141a81d9"
   strings:
      $x1 = "E*\\AC:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\Stub\\Project1.vbp" fullword wide
      $s2 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s3 = "hayrides.exe" fullword wide
      $s4 = "http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:photosho" ascii
      $s5 = "//ns.adobe.com/xap/1.0/\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:st" ascii
      $s6 = "http://ns.adobe.com/photoshop/1.0/\" xmp:CreatorTool=\"Adobe Photoshop CS6 (Windows)\" xmp:CreateDate=\"2017-11-08T13:12:30+08:0" ascii
      $s7 = "frmLogin" fullword ascii
      $s8 = "LOGIN TO ACCESS THE SYSTEM" fullword ascii
      $s9 = "btnLogin" fullword ascii
      $s10 = "instanceID=\"xmp.iid:CDCDB61F0AC5E711B0EBB60B45ED057C\" stEvt:when=\"2017-11-09T12:56:45+08:00\" stEvt:softwareAgent=\"Adobe Pho" ascii
      $s11 = "YXWVUT" fullword ascii /* reversed goodware string 'TUVWXY' */
      $s12 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s13 = "FC:\\Windows\\SysWOW64\\stdole2.tlb" fullword ascii
      $s14 = "RETYPE PASSWORD" fullword ascii
      $s15 = "lblPassword" fullword ascii
      $s16 = "PASSWORD :" fullword ascii
      $s17 = "Please enter valid username or password!" fullword wide
      $s18 = "Please fill up Password." fullword wide
      $s19 = "Please fill up Retype Password." fullword wide
      $s20 = "Password is not correct!" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule Virus_Win32_Moiva_5 {
   meta:
      description = "Virus - file Virus.Win32.Moiva.a-60f7e26dce7596c24ce870eead6fabbbffd8f164f5c1ed09a23a460ae8363af1"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "60f7e26dce7596c24ce870eead6fabbbffd8f164f5c1ed09a23a460ae8363af1"
   strings:
      $x1 = "E*\\AC:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\Stub\\Project1.vbp" fullword wide
      $s2 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s3 = "firemanship.exe" fullword wide
      $s4 = "http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:photosho" ascii
      $s5 = "//ns.adobe.com/xap/1.0/\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:st" ascii
      $s6 = "http://ns.adobe.com/photoshop/1.0/\" xmp:CreatorTool=\"Adobe Photoshop CS6 (Windows)\" xmp:CreateDate=\"2017-11-08T13:12:30+08:0" ascii
      $s7 = "frmLogin" fullword ascii
      $s8 = "LOGIN TO ACCESS THE SYSTEM" fullword ascii
      $s9 = "btnLogin" fullword ascii
      $s10 = "instanceID=\"xmp.iid:CDCDB61F0AC5E711B0EBB60B45ED057C\" stEvt:when=\"2017-11-09T12:56:45+08:00\" stEvt:softwareAgent=\"Adobe Pho" ascii
      $s11 = "YXWVUT" fullword ascii /* reversed goodware string 'TUVWXY' */
      $s12 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s13 = "C:\\Windows\\SysWOW64\\stdole2.tlb" fullword ascii
      $s14 = "helminthologist" fullword wide
      $s15 = "floodometer" fullword wide
      $s16 = "flooded" fullword wide
      $s17 = "RETYPE PASSWORD" fullword ascii
      $s18 = "lblPassword" fullword ascii
      $s19 = "PASSWORD :" fullword ascii
      $s20 = "Please enter valid username or password!" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule Virus_Win32_Moiva_6 {
   meta:
      description = "Virus - file Virus.Win32.Moiva.a-6eb4bdd8ec2a01033803c139351d0fb38f919b7afda79afbc3a321609f5300b1"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "6eb4bdd8ec2a01033803c139351d0fb38f919b7afda79afbc3a321609f5300b1"
   strings:
      $x1 = "E*\\AC:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\Stub\\Project1.vbp" fullword wide
      $s2 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s3 = "forelaying.exe" fullword wide
      $s4 = "http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:photosho" ascii
      $s5 = "//ns.adobe.com/xap/1.0/\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:st" ascii
      $s6 = "http://ns.adobe.com/photoshop/1.0/\" xmp:CreatorTool=\"Adobe Photoshop CS6 (Windows)\" xmp:CreateDate=\"2017-11-08T13:12:30+08:0" ascii
      $s7 = "frmLogin" fullword ascii
      $s8 = "LOGIN TO ACCESS THE SYSTEM" fullword ascii
      $s9 = "btnLogin" fullword ascii
      $s10 = "instanceID=\"xmp.iid:CDCDB61F0AC5E711B0EBB60B45ED057C\" stEvt:when=\"2017-11-09T12:56:45+08:00\" stEvt:softwareAgent=\"Adobe Pho" ascii
      $s11 = "YXWVUT" fullword ascii /* reversed goodware string 'TUVWXY' */
      $s12 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s13 = "FC:\\Windows\\SysWOW64\\stdole2.tlb" fullword ascii
      $s14 = "RETYPE PASSWORD" fullword ascii
      $s15 = "lblPassword" fullword ascii
      $s16 = "PASSWORD :" fullword ascii
      $s17 = "Please enter valid username or password!" fullword wide
      $s18 = "Please fill up Password." fullword wide
      $s19 = "Please fill up Retype Password." fullword wide
      $s20 = "Password is not correct!" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule Virus_Win32_Moiva_7 {
   meta:
      description = "Virus - file Virus.Win32.Moiva.a-7d430bdeccbced4e2edfaecf2854fc4a89b6002d8bcc63a0bfab14c0e03b1060"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "7d430bdeccbced4e2edfaecf2854fc4a89b6002d8bcc63a0bfab14c0e03b1060"
   strings:
      $x1 = "F*\\AC:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\Stub\\Project1.vbp" fullword wide
      $s2 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s3 = "firefly.exe" fullword wide
      $s4 = "http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:photosho" ascii
      $s5 = "//ns.adobe.com/xap/1.0/\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:st" ascii
      $s6 = "http://ns.adobe.com/photoshop/1.0/\" xmp:CreatorTool=\"Adobe Photoshop CS6 (Windows)\" xmp:CreateDate=\"2017-11-08T13:12:30+08:0" ascii
      $s7 = "frmLogin" fullword ascii
      $s8 = "LOGIN TO ACCESS THE SYSTEM" fullword ascii
      $s9 = "btnLogin" fullword ascii
      $s10 = "instanceID=\"xmp.iid:CDCDB61F0AC5E711B0EBB60B45ED057C\" stEvt:when=\"2017-11-09T12:56:45+08:00\" stEvt:softwareAgent=\"Adobe Pho" ascii
      $s11 = "YXWVUT" fullword ascii /* reversed goodware string 'TUVWXY' */
      $s12 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s13 = "C:\\Windows\\SysWOW64\\stdole2.tlb" fullword ascii
      $s14 = "hypostomial" fullword wide
      $s15 = "hepatology" fullword wide
      $s16 = "RETYPE PASSWORD" fullword ascii
      $s17 = "lblPassword" fullword ascii
      $s18 = "PASSWORD :" fullword ascii
      $s19 = "Please enter valid username or password!" fullword wide
      $s20 = "Please fill up Password." fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule Virus_Win32_Moiva_8 {
   meta:
      description = "Virus - file Virus.Win32.Moiva.a-2a3e8a6fdf05fe48498cba64aed2ed84caff1c140b9a2c18737f4ba734df390f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "2a3e8a6fdf05fe48498cba64aed2ed84caff1c140b9a2c18737f4ba734df390f"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
      $s2 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"*\" processorArchitec" ascii
      $s3 = "/AutoIt3ExecuteScript" fullword wide
      $s4 = "/AutoIt3ExecuteLine" fullword wide
      $s5 = "PROCESSGETSTATS" fullword wide
      $s6 = "WINGETPROCESS" fullword wide
      $s7 = "SCRIPTNAME" fullword wide /* base64 encoded string 'H$H=3@0' */
      $s8 = "SHELLEXECUTEWAIT" fullword wide
      $s9 = "SHELLEXECUTE" fullword wide
      $s10 = "*Unable to get a list of running processes." fullword wide
      $s11 = "PROCESSSETPRIORITY" fullword wide
      $s12 = "HTTPSETUSERAGENT" fullword wide
      $s13 = "PROCESSWAITCLOSE" fullword wide
      $s14 = "PROCESSEXISTS" fullword wide
      $s15 = "PROCESSCLOSE" fullword wide
      $s16 = "PROCESSWAIT" fullword wide
      $s17 = "PROCESSLIST" fullword wide
      $s18 = "PROCESSORARCH" fullword wide
      $s19 = "STRINGREVERSE" fullword wide /* base64 encoded string 'I4H4dDTDR' */
      $s20 = "Error parsing function call.0Incorrect number of parameters in function call.'\"ReDim\" used without an array variable.>Illegal " wide
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule Virus_Win32_Moiva_9 {
   meta:
      description = "Virus - file Virus.Win32.Moiva.a-768a6767c853674899b69ac9a73f4f613d91c28ec414720baf65136569d654a3"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "768a6767c853674899b69ac9a73f4f613d91c28ec414720baf65136569d654a3"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
      $s2 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"*\" processorArchitec" ascii
      $s3 = "/AutoIt3ExecuteScript" fullword wide
      $s4 = "/AutoIt3ExecuteLine" fullword wide
      $s5 = "PROCESSGETSTATS" fullword wide
      $s6 = "WINGETPROCESS" fullword wide
      $s7 = "SCRIPTNAME" fullword wide /* base64 encoded string 'H$H=3@0' */
      $s8 = "SHELLEXECUTEWAIT" fullword wide
      $s9 = "SHELLEXECUTE" fullword wide
      $s10 = "*Unable to get a list of running processes." fullword wide
      $s11 = "PROCESSSETPRIORITY" fullword wide
      $s12 = "HTTPSETUSERAGENT" fullword wide
      $s13 = "PROCESSWAITCLOSE" fullword wide
      $s14 = "PROCESSEXISTS" fullword wide
      $s15 = "PROCESSCLOSE" fullword wide
      $s16 = "PROCESSWAIT" fullword wide
      $s17 = "PROCESSLIST" fullword wide
      $s18 = "PROCESSORARCH" fullword wide
      $s19 = "STRINGREVERSE" fullword wide /* base64 encoded string 'I4H4dDTDR' */
      $s20 = "Error parsing function call.0Incorrect number of parameters in function call.'\"ReDim\" used without an array variable.>Illegal " wide
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule Virus_Win32_Renamer {
   meta:
      description = "Virus - file Virus.Win32.Renamer.j-539237581e29cd00713ff5d0c1db24e647a95a2d65371b6602b9a72266dca94d"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "539237581e29cd00713ff5d0c1db24e647a95a2d65371b6602b9a72266dca94d"
   strings:
      $s1 = "Alt+ Clipboard does not support Icons/Menu '%s' is already being used by another formDocked control must have a name%Error remo" wide
      $s2 = "clWebDarkMagenta" fullword ascii
      $s3 = "Stream write error\"Unable to find a Table of Contents" fullword wide
      $s4 = "GlassFrame.Top" fullword ascii
      $s5 = "TCommonDialog@" fullword ascii
      $s6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes" fullword ascii
      $s7 = "\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\" fullword ascii
      $s8 = "        <requestedExecutionLevel" fullword ascii
      $s9 = "0J1t1N3U3" fullword ascii /* base64 encoded string ''[u7u7' */
      $s10 = "GlassFrame.SheetOfGlass" fullword ascii
      $s11 = "        processorArchitecture=\"*\"/>" fullword ascii
      $s12 = "    processorArchitecture=\"*\"/>" fullword ascii
      $s13 = "GlassFrame.Right" fullword ascii
      $s14 = "GlassFrame.Enabled" fullword ascii
      $s15 = "EComponentErrorl`A" fullword ascii
      $s16 = "GlassFrame.Left" fullword ascii
      $s17 = "GlassFrame.Bottom" fullword ascii
      $s18 = "C:\\Windows\\Ground" fullword ascii
      $s19 = "Write$Error creating variant or safe array!'%s' is not a valid integer value" fullword wide
      $s20 = ">.>6>>>F>" fullword ascii /* hex encoded string 'o' */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule Virus_Win32_Neshta {
   meta:
      description = "Virus - file Virus.Win32.Neshta.a-0ecf3547251601ff8fe19f49b499afcc2ad311c529475cfa69b9946a9411fb57"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "0ecf3547251601ff8fe19f49b499afcc2ad311c529475cfa69b9946a9411fb57"
   strings:
      $s1 = "iiiiiiiiiiii" fullword wide /* reversed goodware string 'iiiiiiiiiiii' */
      $s2 = "\\2,) 5*  " fullword ascii /* hex encoded string '%' */
      $s3 = "!+ _6A@<#" fullword ascii /* hex encoded string 'j' */
      $s4 = "48\" -<*!" fullword ascii /* hex encoded string 'H' */
      $s5 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii
      $s6 = "* -\"*V" fullword ascii
      $s7 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii
      $s8 = "$#,.'2%D[*\\" fullword ascii /* hex encoded string '-' */
      $s9 = " >=7Q%!!!" fullword ascii
      $s10 = "\\2D\"+&@**" fullword ascii /* hex encoded string '-' */
      $s11 = "\\>3\\4(-" fullword ascii /* hex encoded string '4' */
      $s12 = "\\+ -,0H" fullword ascii
      $s13 = "U\\.\"8)0!." fullword ascii
      $s14 = "\\\")?-\"40" fullword ascii /* hex encoded string '@' */
      $s15 = "\\'#)7E+]" fullword ascii /* hex encoded string '~' */
      $s16 = "-)?@!!!+ A" fullword ascii
      $s17 = "\\:=%3\"6" fullword ascii /* hex encoded string '6' */
      $s18 = "\\\"\\#&)69" fullword ascii /* hex encoded string 'i' */
      $s19 = "\\\"?#2@E" fullword ascii /* hex encoded string '.' */
      $s20 = "\\ +24='=" fullword ascii /* hex encoded string '$' */
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _Virus_Win32_Moiva_Virus_Win32_Moiva_0 {
   meta:
      description = "Virus - from files Virus.Win32.Moiva.a-2a3e8a6fdf05fe48498cba64aed2ed84caff1c140b9a2c18737f4ba734df390f, Virus.Win32.Moiva.a-768a6767c853674899b69ac9a73f4f613d91c28ec414720baf65136569d654a3"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "2a3e8a6fdf05fe48498cba64aed2ed84caff1c140b9a2c18737f4ba734df390f"
      hash2 = "768a6767c853674899b69ac9a73f4f613d91c28ec414720baf65136569d654a3"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
      $s2 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"*\" processorArchitec" ascii
      $s3 = "/AutoIt3ExecuteScript" fullword wide
      $s4 = "/AutoIt3ExecuteLine" fullword wide
      $s5 = "PROCESSGETSTATS" fullword wide
      $s6 = "WINGETPROCESS" fullword wide
      $s7 = "SCRIPTNAME" fullword wide /* base64 encoded string 'H$H=3@0' */
      $s8 = "SHELLEXECUTEWAIT" fullword wide
      $s9 = "SHELLEXECUTE" fullword wide
      $s10 = "*Unable to get a list of running processes." fullword wide
      $s11 = "PROCESSSETPRIORITY" fullword wide
      $s12 = "HTTPSETUSERAGENT" fullword wide
      $s13 = "PROCESSWAITCLOSE" fullword wide
      $s14 = "PROCESSEXISTS" fullword wide
      $s15 = "PROCESSCLOSE" fullword wide
      $s16 = "PROCESSWAIT" fullword wide
      $s17 = "PROCESSLIST" fullword wide
      $s18 = "PROCESSORARCH" fullword wide
      $s19 = "STRINGREVERSE" fullword wide /* base64 encoded string 'I4H4dDTDR' */
      $s20 = "Error parsing function call.0Incorrect number of parameters in function call.'\"ReDim\" used without an array variable.>Illegal " wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "0b768923437678ce375719e30b21693e" and ( 8 of them )
      ) or ( all of them )
}

rule _Virus_Win32_Moiva_Virus_Win32_Moiva_Virus_Win32_Moiva_Virus_Win32_Moiva_Virus_Win32_Moiva_Virus_Win32_Moiva_Virus_Win32_Moi_1 {
   meta:
      description = "Virus - from files Virus.Win32.Moiva.a-08c1857617a7b30f81a97a21c7b3cca99b8ad82ac868e932f8d7900f69c3d03e, Virus.Win32.Moiva.a-2986b0bd4774daf7ffbfa4f6fd239a3842e98c5774ea14ebf4726a4f8fca2a30, Virus.Win32.Moiva.a-5167338e9391173e6017b1aa8a79bf23093f3673494199d6a92e5b77e0bd4aa2, Virus.Win32.Moiva.a-5c523a295e64ca123dda4f517b1c9ee609af1f33ad3d8879c0e56505141a81d9, Virus.Win32.Moiva.a-60f7e26dce7596c24ce870eead6fabbbffd8f164f5c1ed09a23a460ae8363af1, Virus.Win32.Moiva.a-6eb4bdd8ec2a01033803c139351d0fb38f919b7afda79afbc3a321609f5300b1, Virus.Win32.Moiva.a-7d430bdeccbced4e2edfaecf2854fc4a89b6002d8bcc63a0bfab14c0e03b1060"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "08c1857617a7b30f81a97a21c7b3cca99b8ad82ac868e932f8d7900f69c3d03e"
      hash2 = "2986b0bd4774daf7ffbfa4f6fd239a3842e98c5774ea14ebf4726a4f8fca2a30"
      hash3 = "5167338e9391173e6017b1aa8a79bf23093f3673494199d6a92e5b77e0bd4aa2"
      hash4 = "5c523a295e64ca123dda4f517b1c9ee609af1f33ad3d8879c0e56505141a81d9"
      hash5 = "60f7e26dce7596c24ce870eead6fabbbffd8f164f5c1ed09a23a460ae8363af1"
      hash6 = "6eb4bdd8ec2a01033803c139351d0fb38f919b7afda79afbc3a321609f5300b1"
      hash7 = "7d430bdeccbced4e2edfaecf2854fc4a89b6002d8bcc63a0bfab14c0e03b1060"
   strings:
      $s1 = "frmLogin" fullword ascii
      $s2 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s3 = "ozjptsz" fullword ascii
      $s4 = "txtAddress" fullword ascii
      $s5 = "sI:\"Pv" fullword ascii
      $s6 = "cSR.YGf" fullword ascii
      $s7 = "RAt]K}" fullword ascii
      $s8 = ">* O?V" fullword ascii
      $s9 = "%Y%X}+t" fullword ascii
      $s10 = "Module2" fullword ascii
      $s11 = "Picture3" fullword ascii
      $s12 = "qUtPRA56" fullword ascii
      $s13 = "Module1" fullword ascii
      $s14 = "PPqvno3" fullword ascii
      $s15 = "WKzICZ3" fullword ascii
      $s16 = "YjtJ?Z" fullword ascii
      $s17 = "lblDate" fullword ascii
      $s18 = "jXAMMgC'Y" fullword ascii
      $s19 = "~SK#Erun" fullword ascii
      $s20 = "?xjtZGpS" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Virus_Win32_Moiva_Virus_Win32_Moiva_Virus_Win32_Moiva_Virus_Win32_Moiva_Virus_Win32_Moiva_Virus_Win32_Moiva_2 {
   meta:
      description = "Virus - from files Virus.Win32.Moiva.a-2986b0bd4774daf7ffbfa4f6fd239a3842e98c5774ea14ebf4726a4f8fca2a30, Virus.Win32.Moiva.a-5167338e9391173e6017b1aa8a79bf23093f3673494199d6a92e5b77e0bd4aa2, Virus.Win32.Moiva.a-5c523a295e64ca123dda4f517b1c9ee609af1f33ad3d8879c0e56505141a81d9, Virus.Win32.Moiva.a-60f7e26dce7596c24ce870eead6fabbbffd8f164f5c1ed09a23a460ae8363af1, Virus.Win32.Moiva.a-6eb4bdd8ec2a01033803c139351d0fb38f919b7afda79afbc3a321609f5300b1, Virus.Win32.Moiva.a-7d430bdeccbced4e2edfaecf2854fc4a89b6002d8bcc63a0bfab14c0e03b1060"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "2986b0bd4774daf7ffbfa4f6fd239a3842e98c5774ea14ebf4726a4f8fca2a30"
      hash2 = "5167338e9391173e6017b1aa8a79bf23093f3673494199d6a92e5b77e0bd4aa2"
      hash3 = "5c523a295e64ca123dda4f517b1c9ee609af1f33ad3d8879c0e56505141a81d9"
      hash4 = "60f7e26dce7596c24ce870eead6fabbbffd8f164f5c1ed09a23a460ae8363af1"
      hash5 = "6eb4bdd8ec2a01033803c139351d0fb38f919b7afda79afbc3a321609f5300b1"
      hash6 = "7d430bdeccbced4e2edfaecf2854fc4a89b6002d8bcc63a0bfab14c0e03b1060"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s2 = "http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:photosho" ascii
      $s3 = "//ns.adobe.com/xap/1.0/\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:st" ascii
      $s4 = "http://ns.adobe.com/photoshop/1.0/\" xmp:CreatorTool=\"Adobe Photoshop CS6 (Windows)\" xmp:CreateDate=\"2017-11-08T13:12:30+08:0" ascii
      $s5 = "LOGIN TO ACCESS THE SYSTEM" fullword ascii
      $s6 = "btnLogin" fullword ascii
      $s7 = "instanceID=\"xmp.iid:CDCDB61F0AC5E711B0EBB60B45ED057C\" stEvt:when=\"2017-11-09T12:56:45+08:00\" stEvt:softwareAgent=\"Adobe Pho" ascii
      $s8 = "RETYPE PASSWORD" fullword ascii
      $s9 = "lblPassword" fullword ascii
      $s10 = "PASSWORD :" fullword ascii
      $s11 = "Please enter valid username or password!" fullword wide
      $s12 = "Please fill up Password." fullword wide
      $s13 = "Please fill up Retype Password." fullword wide
      $s14 = "Password is not correct!" fullword wide
      $s15 = "56:27        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmp=" ascii
      $s16 = "t:instanceID=\"xmp.iid:C475C16B43C4E711B2FCF9216879E3CA\" stEvt:when=\"2017-11-08T13:12:30+08:00\" stEvt:softwareAgent=\"Adobe P" ascii
      $s17 = "btnSystemUser" fullword ascii
      $s18 = "SYSTEM USER" fullword wide
      $s19 = "REPORTS" fullword ascii
      $s20 = "1-08T14:33:57+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CS6 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"saved\"" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

