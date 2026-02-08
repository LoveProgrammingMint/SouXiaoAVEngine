/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2026-02-07
   Identifier: Worm
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule HEUR_Email_Worm_Win32_LovGate {
   meta:
      description = "Worm - file HEUR-Email-Worm.Win32.LovGate.gen-26b441b6ac06968d8029babb90fba7927e1d21c9cb84b0492c4890bca5dd2660"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "26b441b6ac06968d8029babb90fba7927e1d21c9cb84b0492c4890bca5dd2660"
   strings:
      $s1 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s2 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s4 = "%s.com" fullword ascii
      $s5 = "<Jenny@gsd.com>" fullword ascii
      $s6 = "http://icanhazip.com/" fullword ascii
      $s7 = "Received: from %s ([%d.%d.%d.%d]) by %s with MailEnable ESMTP; %s" fullword ascii
      $s8 = "Content-Type: multipart/mixed; boundary= \"%s\"" fullword ascii
      $s9 = "Content-Disposition: attachment; filename= \"Document.zip\"" fullword ascii
      $s10 = "%s%d.txt" fullword wide
      $s11 = "Received: (qmail %s invoked by uid %s); %s" fullword ascii
      $s12 = "%s\\%d%d%d.jpg" fullword wide
      $s13 = "%s, %u %s %u %.2u:%.2u:%.2u %s%.2u%.2u" fullword ascii
      $s14 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" fullword wide
      $s15 = "%u %s %u %.2u:%.2u:%.2u %s%.2u%.2u" fullword ascii
      $s16 = "%sn.txt" fullword wide
      $s17 = "Message-ID: <%s.%s@%s>" fullword ascii
      $s18 = "Kind regards, GSD Support." fullword ascii
      $s19 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s20 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      8 of them
}

rule HEUR_Email_Worm_Win32_LovGate_2 {
   meta:
      description = "Worm - file HEUR-Email-Worm.Win32.LovGate.gen-3a2dcd6c86a8b789c5f07eec531fd9a3d9268288d8cf47e9f324dacd55bb6cfc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "3a2dcd6c86a8b789c5f07eec531fd9a3d9268288d8cf47e9f324dacd55bb6cfc"
   strings:
      $s1 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s2 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s4 = "%s.com" fullword ascii
      $s5 = "<Jenny@gsd.com>" fullword ascii
      $s6 = "http://icanhazip.com/" fullword ascii
      $s7 = "Received: from %s ([%d.%d.%d.%d]) by %s with MailEnable ESMTP; %s" fullword ascii
      $s8 = "Content-Type: multipart/mixed; boundary= \"%s\"" fullword ascii
      $s9 = "Content-Disposition: attachment; filename= \"Document.zip\"" fullword ascii
      $s10 = "%s%d.txt" fullword wide
      $s11 = "Received: (qmail %s invoked by uid %s); %s" fullword ascii
      $s12 = "%s\\%d%d%d.jpg" fullword wide
      $s13 = "%s, %u %s %u %.2u:%.2u:%.2u %s%.2u%.2u" fullword ascii
      $s14 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" fullword wide
      $s15 = "%u %s %u %.2u:%.2u:%.2u %s%.2u%.2u" fullword ascii
      $s16 = "%sn.txt" fullword wide
      $s17 = "Message-ID: <%s.%s@%s>" fullword ascii
      $s18 = "Kind regards, GSD Support." fullword ascii
      $s19 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s20 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      8 of them
}

rule HEUR_Email_Worm_Win32_LovGate_3 {
   meta:
      description = "Worm - file HEUR-Email-Worm.Win32.LovGate.gen-75e5535a7b6aa384097fcb990c3ea85f8cbd1db87593dbf4f3d7fe7a619ba3ca"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "75e5535a7b6aa384097fcb990c3ea85f8cbd1db87593dbf4f3d7fe7a619ba3ca"
   strings:
      $s1 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s2 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s4 = "%s.com" fullword ascii
      $s5 = "<Jenny@gsd.com>" fullword ascii
      $s6 = "http://icanhazip.com/" fullword ascii
      $s7 = "Received: from %s ([%d.%d.%d.%d]) by %s with MailEnable ESMTP; %s" fullword ascii
      $s8 = "Content-Type: multipart/mixed; boundary= \"%s\"" fullword ascii
      $s9 = "Content-Disposition: attachment; filename= \"Document.zip\"" fullword ascii
      $s10 = "%s%d.txt" fullword wide
      $s11 = "Received: (qmail %s invoked by uid %s); %s" fullword ascii
      $s12 = "%s\\%d%d%d.jpg" fullword wide
      $s13 = "%s, %u %s %u %.2u:%.2u:%.2u %s%.2u%.2u" fullword ascii
      $s14 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" fullword wide
      $s15 = "%u %s %u %.2u:%.2u:%.2u %s%.2u%.2u" fullword ascii
      $s16 = "%sn.txt" fullword wide
      $s17 = "Message-ID: <%s.%s@%s>" fullword ascii
      $s18 = "Kind regards, GSD Support." fullword ascii
      $s19 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s20 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      8 of them
}

rule HEUR_Email_Worm_Win32_LovGate_4 {
   meta:
      description = "Worm - file HEUR-Email-Worm.Win32.LovGate.gen-a0f9d89853963fa2ead2a079952d1d321a60058a3e1198f445162489fa656615"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "a0f9d89853963fa2ead2a079952d1d321a60058a3e1198f445162489fa656615"
   strings:
      $s1 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s2 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s4 = "%s.com" fullword ascii
      $s5 = "<Jenny@gsd.com>" fullword ascii
      $s6 = "http://icanhazip.com/" fullword ascii
      $s7 = "Received: from %s ([%d.%d.%d.%d]) by %s with MailEnable ESMTP; %s" fullword ascii
      $s8 = "Content-Type: multipart/mixed; boundary= \"%s\"" fullword ascii
      $s9 = "Content-Disposition: attachment; filename= \"Document.zip\"" fullword ascii
      $s10 = "%s%d.txt" fullword wide
      $s11 = "Received: (qmail %s invoked by uid %s); %s" fullword ascii
      $s12 = "%s\\%d%d%d.jpg" fullword wide
      $s13 = "%s, %u %s %u %.2u:%.2u:%.2u %s%.2u%.2u" fullword ascii
      $s14 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" fullword wide
      $s15 = "%u %s %u %.2u:%.2u:%.2u %s%.2u%.2u" fullword ascii
      $s16 = "%sn.txt" fullword wide
      $s17 = "Message-ID: <%s.%s@%s>" fullword ascii
      $s18 = "Kind regards, GSD Support." fullword ascii
      $s19 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s20 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      8 of them
}

rule HEUR_Email_Worm_Win32_LovGate_5 {
   meta:
      description = "Worm - file HEUR-Email-Worm.Win32.LovGate.gen-b9b52cc15fa1c03663a49c10af56e8f7aaa786d7688a75176d6fbfb779e8faca"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "b9b52cc15fa1c03663a49c10af56e8f7aaa786d7688a75176d6fbfb779e8faca"
   strings:
      $s1 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s2 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s4 = "%s.com" fullword ascii
      $s5 = "<Jenny@gsd.com>" fullword ascii
      $s6 = "http://icanhazip.com/" fullword ascii
      $s7 = "Received: from %s ([%d.%d.%d.%d]) by %s with MailEnable ESMTP; %s" fullword ascii
      $s8 = "Content-Type: multipart/mixed; boundary= \"%s\"" fullword ascii
      $s9 = "Content-Disposition: attachment; filename= \"Document.zip\"" fullword ascii
      $s10 = "%s%d.txt" fullword wide
      $s11 = "Received: (qmail %s invoked by uid %s); %s" fullword ascii
      $s12 = "%s\\%d%d%d.jpg" fullword wide
      $s13 = "%s, %u %s %u %.2u:%.2u:%.2u %s%.2u%.2u" fullword ascii
      $s14 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" fullword wide
      $s15 = "%u %s %u %.2u:%.2u:%.2u %s%.2u%.2u" fullword ascii
      $s16 = "%sn.txt" fullword wide
      $s17 = "Message-ID: <%s.%s@%s>" fullword ascii
      $s18 = "Kind regards, GSD Support." fullword ascii
      $s19 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s20 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      8 of them
}

rule Worm_Win32_AutoRun {
   meta:
      description = "Worm - file Worm.Win32.AutoRun.fem-c35d3d00df7a0e8151ed013a202796cf453830dd9b40c8e23b0f0eb49ea42c0c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "c35d3d00df7a0e8151ed013a202796cf453830dd9b40c8e23b0f0eb49ea42c0c"
   strings:
      $s1 = "untime " fullword ascii
      $s2 = ";vCxhzp|q~s" fullword ascii
      $s3 = "WSsQ2RVvv" fullword ascii
      $s4 = "w`printcf" fullword ascii
      $s5 = "*yI:kerf$<^" fullword ascii
      $s6 = "MpTCdHp" fullword ascii
      $s7 = "Back En^" fullword ascii
      $s8 = "Strin5gXu" fullword ascii
      $s9 = "E\\Borla<Ln<" fullword ascii
      $s10 = "dBBscx`" fullword ascii
      $s11 = "zePp>dou" fullword ascii
      $s12 = "Wdpq9jlJ" fullword ascii
      $s13 = "SOFTWA" fullword ascii
      $s14 = "\\<~XY\\~" fullword ascii
      $s15 = "LvzP29" fullword ascii
      $s16 = "{v)?pi" fullword ascii
      $s17 = "piR?fl" fullword ascii
      $s18 = "S{1n}U" fullword ascii
      $s19 = "d]HYVG" fullword ascii
      $s20 = "HZ'?>j" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _HEUR_Email_Worm_Win32_LovGate_HEUR_Email_Worm_Win32_LovGate_HEUR_Email_Worm_Win32_LovGate_HEUR_Email_Worm_Win32_LovGate_HEU_0 {
   meta:
      description = "Worm - from files HEUR-Email-Worm.Win32.LovGate.gen-26b441b6ac06968d8029babb90fba7927e1d21c9cb84b0492c4890bca5dd2660, HEUR-Email-Worm.Win32.LovGate.gen-3a2dcd6c86a8b789c5f07eec531fd9a3d9268288d8cf47e9f324dacd55bb6cfc, HEUR-Email-Worm.Win32.LovGate.gen-75e5535a7b6aa384097fcb990c3ea85f8cbd1db87593dbf4f3d7fe7a619ba3ca, HEUR-Email-Worm.Win32.LovGate.gen-a0f9d89853963fa2ead2a079952d1d321a60058a3e1198f445162489fa656615, HEUR-Email-Worm.Win32.LovGate.gen-b9b52cc15fa1c03663a49c10af56e8f7aaa786d7688a75176d6fbfb779e8faca"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "26b441b6ac06968d8029babb90fba7927e1d21c9cb84b0492c4890bca5dd2660"
      hash2 = "3a2dcd6c86a8b789c5f07eec531fd9a3d9268288d8cf47e9f324dacd55bb6cfc"
      hash3 = "75e5535a7b6aa384097fcb990c3ea85f8cbd1db87593dbf4f3d7fe7a619ba3ca"
      hash4 = "a0f9d89853963fa2ead2a079952d1d321a60058a3e1198f445162489fa656615"
      hash5 = "b9b52cc15fa1c03663a49c10af56e8f7aaa786d7688a75176d6fbfb779e8faca"
   strings:
      $s1 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s2 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s4 = "%s.com" fullword ascii
      $s5 = "<Jenny@gsd.com>" fullword ascii
      $s6 = "http://icanhazip.com/" fullword ascii
      $s7 = "Received: from %s ([%d.%d.%d.%d]) by %s with MailEnable ESMTP; %s" fullword ascii
      $s8 = "Content-Type: multipart/mixed; boundary= \"%s\"" fullword ascii
      $s9 = "Content-Disposition: attachment; filename= \"Document.zip\"" fullword ascii
      $s10 = "%s%d.txt" fullword wide
      $s11 = "Received: (qmail %s invoked by uid %s); %s" fullword ascii
      $s12 = "%s\\%d%d%d.jpg" fullword wide
      $s13 = "%s, %u %s %u %.2u:%.2u:%.2u %s%.2u%.2u" fullword ascii
      $s14 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" fullword wide
      $s15 = "%u %s %u %.2u:%.2u:%.2u %s%.2u%.2u" fullword ascii
      $s16 = "%sn.txt" fullword wide
      $s17 = "Message-ID: <%s.%s@%s>" fullword ascii
      $s18 = "Kind regards, GSD Support." fullword ascii
      $s19 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s20 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and ( 8 of them )
      ) or ( all of them )
}

rule _HEUR_Email_Worm_Win32_LovGate_HEUR_Email_Worm_Win32_LovGate_HEUR_Email_Worm_Win32_LovGate_HEUR_Email_Worm_Win32_LovGate_1 {
   meta:
      description = "Worm - from files HEUR-Email-Worm.Win32.LovGate.gen-26b441b6ac06968d8029babb90fba7927e1d21c9cb84b0492c4890bca5dd2660, HEUR-Email-Worm.Win32.LovGate.gen-3a2dcd6c86a8b789c5f07eec531fd9a3d9268288d8cf47e9f324dacd55bb6cfc, HEUR-Email-Worm.Win32.LovGate.gen-75e5535a7b6aa384097fcb990c3ea85f8cbd1db87593dbf4f3d7fe7a619ba3ca, HEUR-Email-Worm.Win32.LovGate.gen-b9b52cc15fa1c03663a49c10af56e8f7aaa786d7688a75176d6fbfb779e8faca"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-07"
      hash1 = "26b441b6ac06968d8029babb90fba7927e1d21c9cb84b0492c4890bca5dd2660"
      hash2 = "3a2dcd6c86a8b789c5f07eec531fd9a3d9268288d8cf47e9f324dacd55bb6cfc"
      hash3 = "75e5535a7b6aa384097fcb990c3ea85f8cbd1db87593dbf4f3d7fe7a619ba3ca"
      hash4 = "b9b52cc15fa1c03663a49c10af56e8f7aaa786d7688a75176d6fbfb779e8faca"
   strings:
      $s1 = "0#0`0j0p0z0" fullword ascii
      $s2 = "6(6.646D6J6P6V6\\6b6i6p6w6~6" fullword ascii
      $s3 = "30353T3" fullword ascii
      $s4 = ";+;1;F;Q;\\;~;" fullword ascii
      $s5 = "t'hTG@" fullword ascii
      $s6 = ">+>8>K>U>i>z>" fullword ascii
      $s7 = "71787@7F7L7" fullword ascii
      $s8 = "?,?C?_?i?" fullword ascii
      $s9 = "<`=e=o={=" fullword ascii
      $s10 = "1!1j1p1x1" fullword ascii
      $s11 = "162<2F2M2X2^2r2" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and pe.imphash() == "51c161c9913a4b650517329371c6046d" and ( 8 of them )
      ) or ( all of them )
}

