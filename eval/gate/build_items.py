"""Writes eval/gate/labeled_items.csv, the stress set for the keyword gate.

All items are short fictional advisory titles and summaries written for this
audit. It oversamples hard cases on purpose, so the rates describe the gate's
behavior on those cases, not its performance on a real feed. One author wrote
the labels; a second labeler should review them before publication.
Odd items are dev (used to pick new terms), even items are held out.
"""
import csv
import os

R, N = 1, 0
ITEMS = [
 # plain, explicit space-segment reporting
 ("explicit", "en", R, "Satellite ground station modem default password", "Internet-exposed ground station modems ship with a default login."),
 ("explicit", "en", R, "GPS spoofing near commercial ports", "Vessels report GPS position jumps during transit."),
 ("explicit", "en", R, "GNSS receiver firmware flaw", "A firmware flaw lets crafted signals crash GNSS receivers."),
 ("explicit", "en", R, "Spacecraft flight software vulnerability", "A flaw in open flight software affects spacecraft command handling."),
 ("explicit", "en", R, "VSAT terminal hard-coded credentials", "VSAT terminals contain a hard-coded maintenance account."),
 ("explicit", "en", R, "Orbital imaging provider breach", "An orbital imaging provider reports a compromise of its customer portal."),
 # names and aliases that a reader would recognize
 ("alias", "en", R, "Starlink terminal denial of service", "Researchers crash user terminals with malformed frames."),
 ("alias", "en", R, "Viasat KA-SAT style modem wiper", "Wiper malware targets modems in a broadband network."),
 ("alias", "en", R, "Iridium pager traffic exposed", "Unencrypted Iridium traffic can be read with commodity receivers."),
 ("alias", "en", R, "Inmarsat maritime terminal flaw", "A flaw in shipboard terminals allows configuration changes."),
 ("alias", "en", R, "BeiDou receiver parsing bug", "Crafted navigation messages crash BeiDou receivers."),
 ("alias", "en", R, "GLONASS timing anomaly advisory", "Operators report timing errors in GLONASS-dependent equipment."),
 ("alias", "en", R, "SATCOM terminal authentication bypass", "An authentication bypass affects SATCOM terminals used at sea."),
 ("alias", "en", R, "TT&C software privilege escalation", "A flaw in TT&C software permits privilege escalation on operator consoles."),
 ("alias", "en", R, "CubeSat bus command injection", "A CubeSat command parser accepts unauthenticated uplinked commands."),
 ("alias", "en", R, "LEO constellation operator phishing", "A LEO constellation operator's engineers are targeted by phishing."),
 ("alias", "en", R, "ADS-B message injection", "Forged ADS-B messages appear on air traffic displays."),
 ("alias", "en", R, "Mission control system exposed", "A mission control system for earth observation is reachable from the internet."),
 ("alias", "en", R, "Telemetry downlink decoder overflow", "A decoder overflow affects telemetry downlink processing at teleports."),
 ("alias", "en", R, "Teleport antenna controller flaw", "A flaw affects antenna control units at a commercial teleport."),
 # relevant, but the text never uses a space word
 ("no_keyword", "en", R, "Payload operations center ransomware", "Ransomware disrupted a payload operations center during a contact window."),
 ("no_keyword", "en", R, "Launch range safety network intrusion", "Attackers reached a network at a launch range."),
 ("no_keyword", "en", R, "Timing receiver leap second bug", "A bug in timing receivers disrupts telecom synchronization."),
 ("no_keyword", "en", R, "Earth observation imagery tampering", "Tampered imagery entered an analysis pipeline."),
 # multilingual
 ("language", "fr", R, "Vulnérabilité dans un terminal satellite", "Une faille affecte des terminaux de communication par satellite."),
 ("language", "fr", R, "Brouillage GNSS signalé en mer", "Des navires signalent un brouillage du GNSS."),
 ("language", "es", R, "Vulnerabilidad en estación terrestre de satélites", "Una falla afecta a módems de estaciones terrestres."),
 ("language", "es", R, "Suplantación de señales GPS", "Buques informan suplantación de señales de navegación por satélite."),
 ("language", "ar", R, "ثغرة في محطة أرضية للأقمار الصناعية", "تؤثر الثغرة على أجهزة المودم في المحطات الأرضية."),
 ("language", "ar", R, "تشويش على إشارات نظام تحديد المواقع", "أبلغت السفن عن تشويش على إشارات الأقمار الصناعية."),
 ("language", "de", R, "Schwachstelle in Satellitenterminals", "Eine Lücke betrifft Bodenstationen und Satellitenmodems."),
 ("language", "ru", R, "Уязвимость в спутниковых терминалах", "Ошибка затрагивает наземные станции спутниковой связи."),
 ("language", "zh", R, "卫星地面站调制解调器漏洞", "该漏洞影响暴露在互联网上的地面站设备。"),
 ("language", "ja", R, "衛星通信端末の脆弱性", "地上局の機器に影響する脆弱性が報告された。"),
 # the evidence is an image, so the feed text is nearly empty
 ("image_only", "en", R, "Advisory attached", ""),
 ("image_only", "en", R, "See graphic for affected terminals", "Figure 1."),
 ("image_only", "en", R, "Bulletin 2026-114", "Details in the attached scan."),
 ("image_only", "en", R, "Weekly threat map", "Map only."),
 # look relevant, are not
 ("false_friend", "en", N, "Orbit project management app flaw", "A flaw in the Orbit task manager exposes shared boards."),
 ("false_friend", "en", N, "GPS dog collar app leaks location", "A pet tracker app exposes owners' accounts."),
 ("false_friend", "en", N, "Satellite office VPN outage", "A company's satellite office lost VPN access after an update."),
 ("false_friend", "en", N, "Phone navigation app crash", "A navigation app on phones crashes on malformed map files, GPS unaffected."),
 ("false_friend", "en", N, "Disk space exhaustion in backup tool", "A backup tool fails when disk space runs out."),
 ("false_friend", "en", N, "SDR meeting tool data exposure", "A sales development (SDR) tool exposes contact lists."),
 ("false_friend", "en", N, "Fitness watch GPS trail privacy", "A fitness watch publishes GPS trails by default."),
 ("false_friend", "en", N, "Orbital sander recall portal hacked", "A power tool maker's orbital sander recall site was defaced."),
 ("false_friend", "en", N, "Satellite TV streaming app account takeover", "Accounts on a satellite TV streaming app were taken over."),
 ("false_friend", "en", N, "Spatial database SQL injection", "A spatial extension for a database allows SQL injection."),
 # ordinary IT reporting
 ("unrelated", "en", N, "Web framework remote code execution", "A remote code execution vulnerability affects a web framework."),
 ("unrelated", "en", N, "Email server authentication bypass", "An authentication flaw affects a mail server."),
 ("unrelated", "en", N, "Router firmware exploit in the wild", "An exploit for home router firmware is being used."),
 ("unrelated", "en", N, "Supply chain attack on npm package", "A vendor package was tampered with."),
 ("unrelated", "en", N, "Hospital network ransomware", "Ransomware disrupted hospital network services."),
 ("unrelated", "en", N, "Critical infrastructure water utility alert", "A water utility's control network was scanned."),
 ("unrelated", "en", N, "VPN appliance zero-day", "A vulnerability in a VPN appliance is being exploited."),
 ("unrelated", "en", N, "Cloud identity misconfiguration", "A misconfiguration exposes tokens."),
 ("unrelated", "fr", N, "Vulnérabilité dans un navigateur", "Exécution de code arbitraire à distance dans un navigateur web."),
 ("unrelated", "es", N, "Vulnerabilidad en servidor de correo", "Una falla afecta a un servidor de correo."),
]


def main():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "labeled_items.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "split", "group", "lang", "relevant", "title", "summary"])
        counts = {}
        for i, (group, lang, label, title, summary) in enumerate(ITEMS, 1):
            counts[group] = counts.get(group, 0) + 1
            w.writerow([f"G{i:03d}", "dev" if counts[group] % 2 else "heldout", group, lang, label, title, summary])
    print(len(ITEMS), "items")


if __name__ == "__main__":
    main()
