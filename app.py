from flask import Flask, render_template_string, jsonify, request, send_from_directory
import sqlite3, os, json, re
from datetime import datetime, timedelta
import random

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME  = os.path.join(BASE_DIR, "cyber_salama_v4.db")

# ══════════════════════════════════════════════
# NETWORK PREFIX DETECTION
# ══════════════════════════════════════════════
NETWORK_PREFIXES = {
    "Vodacom":  ["074","075","076","25574","25575","25576","+25574","+25575","+25576"],
    "Airtel":   ["068","069","078","25568","25569","255786","255787","255788","+25568","+25569","+25578"],
    "Halotel":  ["062","0621","0629","25562","+25562"],
    "TTCL":     ["0022","073","25573","+25573"],
    "YAS":      ["0065","065","25565","+25565"],
    "M-Pesa":   ["0255"],
    "Zantel":   ["077","25577","+25577"],
}
MONEY_AGENTS = ["M-Pesa","Airtel Money","mixx by yas","Halotel Pesa","TTCL Pesa","NMB","CRDB","Equity Bank","NBC","Stanbic","Absa"]

def detect_network(number):
    clean = number.replace(" ","").replace("-","")
    for net, prefixes in NETWORK_PREFIXES.items():
        for p in prefixes:
            if clean.startswith(p):
                return net
    # fallback by length / country code
    if clean.startswith("+255") or clean.startswith("255"):
        return "Tanzania (Unknown)"
    return "Unknown"

# ══════════════════════════════════════════════
# THREAT KEYWORDS (from pasted list + extras)
# ══════════════════════════════════════════════
THREAT_PHRASES = [
    "tuma kwenye namba hii","ile ya zamani ina shida","nimekukosea muamala","nirudishie",
    "umeshinda zawadi","bofya link","akaunti yako imezuiwa","sasisha taarifa zako",
    "namba yako ya siri","nipe otp","kadi yako imefungwa","kitengo cha ulinzi wa benki",
    "fanya haraka sasa hivi","ndani ya saa 24","usimwambie mtu yeyote","hii ni siri kubwa",
    "usikate hii simu","ruzuku ya serikali","ajira mpya za dharura","mkopo wa haraka bila dhamana",
    "ada ya usajili wa mkopo","ingiza namba ya kadi","namba ya nyuma ya kadi","cvv",
    "tarehe ya kuisha kwa kadi","muamala usio wa kawaida","laini yako itafungwa",
    "mchango wa matibabu ya haraka","ndugu yako amepata ajali","tuma mchango sasa hivi hospitalini",
    "wekeza kidogo upate faida kubwa","fursa ya biashara mtandaoni","jaza fomu hii kupokea pesa",
    "usalama wa akaunti yako uko hatarini","badilisha namba yako ya siri sasa",
    "mshindi wa droo ya bahati nasibu","utajiri wa haraka bila kufanya kazi",
    "sarafu za kidijitali za siri","kuongeza salio la simu bure","namba ya siri ya mtandao",
    "thibitisha muamala uliokwama","simu kutoka makao makuu ya polisi",
    "ndugu yako amekamatwa na polisi","tuma hela ya dhamana haraka",
    "faini ya makosa ya mtandaoni","kuzuia akaunti isifutwe","ofa maalum ya leo pekee",
    "usikose nafasi hii ya kipekee","virusi vimegundulika kwenye simu yako",
    "safisha simu yako kwa kubofya","mwaliko wa kikundi cha uwekezaji wa siri",
    "kupanda ngazi kwa kuleta watu","upatu wa pesa mtandaoni",
    "ahadi ya kupata asilimia mia mbili","msaada wa kifedha kutoka kwa mfadhili wa kigeni",
    "mirathi ya marehemu tajiri","mwanasheria anayetafuta ndugu wa marehemu",
    "fungua kiambatisho hiki haraka","ombi la urafiki kutoka kwa mwanajeshi wa kigeni",
    "ada ya kutoa mzigo bandarini","wakala wa forodha feki",
    "nitasambaza video yako usiponilipa","usaliti wa kimapenzi mtandaoni",
    "kuomba namba ya siri ya kuingia whatsapp","namba ya uhakiki ya namba sita",
    "akaunti yako ya mitandao imedukuliwa","mtaalamu wa utajiri wa kishirikina",
    "dawa ya kupata utajiri haraka","kuuza viwanja kwa bei ya kutupwa",
    "kulipia fomu ya usaili wa kazi","tiketi ya uongo ya ndege","bima ya afya ya uongo",
    "kuomba picha ya kitambulisho cha nida","kuomba picha ya leseni",
    "mfumo unaokulazimisha kuleta watu","kuahidiwa laptop ya bure",
    "mteja wako wa cloud imejaa","kuuza antivirus ambayo ni malware",
    "parcel yako imekamatwa","barua ya wito wa mahakamani feki",
    "kuruhusu ufikiaji wa mbali","anydesk","teamviewer",
    "mkopo wa asilimia sifuri","app ya mkopo inayovuna mawasiliano",
    "kutishiwa siri zako zitafichuliwa","ofa ya kupata leseni bila mtihani",
    "kuuza majibu ya mitihani feki","daktari feki","dereva wa ambulansi anayeomba hela",
    "mwalimu mkuu feki","punguzo la hoteli ambalo halipo",
    "mamlaka inayoomba malipo binafsi","kuhamisha fedha kwenda akaunti salama",
    "tokeni za uongo za umeme","mita ya luku yenye hitilafu",
    "mawakala wa kusafisha majina crb","kufuta madeni ya mikopo",
    "fursa ya kusoma nje ya nchi bure","visa ya haraka ya kwenda ulaya",
    "mchezo wa kubahatisha isiyo na kibali","utabiri wa matokeo ya mpira fixed",
    "kulipia kujiunga na chama cha siri","usajili wa mashindano ya uongo",
    "kubadilisha fedha za kigeni mtaani","dhahabu feki","madini ya uongo",
    "mwekezaji wa kilimo cha uongo","kununua hisa za kampuni hewa",
    "majaribio ya kliniki ya uongo","ombi la kubadilisha nywila",
    "namba inayopiga na kukata wangiri","mtoto wako wa shule ana dharura",
    "pop up window ya kompyuta","barua pepe yenye nembo iliyofifia",
    "namba ya siri ya sasa hivi otp","thibitisha jina lako",
    "huduma kwa wateja namba mpya","usajili wa laini kwa vidole",
    "bando la bure","ajira ya kufanya ukiwa nyumbani",
    "nunua bidhaa hii kwa punguzo kubwa","lipia kabla ya kutumishiwa mzigo",
    "akaunti yako imeteuliwa","kuahidiwa","droo","bahati nasibu",
    "http://","https://bit.ly","tinyurl","t.me/","wa.me/",
    "otp","pin yako","namba ya siri",
]

WARNING_PHRASES = [
    "tuma namba","nipigie simu haraka","wasiliana haraka","kupata job",
    "ajira wasiliana","free","bure pata","promo","offer leo",
    "kukuomba msaada","tuma pesa","pesa haraka","faida","zawadi",
    "mkopo","bofya","link hii","thibitisha","verify",
    "namba yako","usisahau","haraka","sasa hivi","kabla ya",
    "pumzika usiku","risiti","malipo","amani","omba",
]

def analyze_sms(sender, recipients, message, conn):
    msg_lower = message.lower()
    reasons = []
    threat_level = "Safe"

    # 1. MASS SMS to new contacts
    if len(recipients) > 1:
        c = conn.cursor()
        new_contacts = []
        for recipient in recipients:
            c.execute("""SELECT COUNT(*) FROM sms_logs
                WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?)""",
                (sender, recipient, recipient, sender))
            if c.fetchone()[0] == 0:
                new_contacts.append(recipient)
        if len(new_contacts) >= 2:
            reasons.append("Mass SMS kwa {} watu wasio na mawasiliano ya awali".format(len(new_contacts)))
            threat_level = "Threat"

    # 2. Threat phrases
    for phrase in THREAT_PHRASES:
        if phrase.lower() in msg_lower:
            reasons.append("Neno hatari: '{}'".format(phrase[:40]))
            threat_level = "Threat"
            break

    # 3. Warning phrases (only if not already threat)
    if threat_level != "Threat":
        for phrase in WARNING_PHRASES:
            if phrase.lower() in msg_lower:
                reasons.append("Maudhui ya kutiliwa shaka: '{}'".format(phrase[:30]))
                threat_level = "Warning"
                break

    # 4. Suspicious long numbers (account/card numbers)
    if re.search(r'\b\d{10,}\b', message):
        reasons.append("Namba ndefu ya tuhuma (kadi/akaunti?)")
        if threat_level == "Safe":
            threat_level = "Warning"

    # 5. URLs
    if re.search(r'https?://|bit\.ly|tinyurl|t\.me/', msg_lower):
        reasons.append("Kiungo cha mtandao kimegunduliwa")
        threat_level = "Threat"

    if not reasons:
        return "Safe", "Hakuna viashiria vya utapeli"
    return threat_level, " | ".join(reasons[:3])


# ══════════════════════════════════════════════
# DATABASE INIT
# ══════════════════════════════════════════════
def get_db():
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS phone_numbers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        number TEXT UNIQUE, name TEXT, network TEXT, registered_at TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS sms_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT, recipient TEXT, message TEXT,
        status TEXT, threat_reason TEXT, timestamp TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS network_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        company TEXT, source TEXT, content TEXT, status TEXT, timestamp TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS network_partners (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE, type TEXT, contact TEXT, joined_at TEXT, active INTEGER DEFAULT 1
    )''')
    conn.commit()

    c.execute("SELECT COUNT(*) FROM phone_numbers")
    if c.fetchone()[0] == 0:
        numbers = [
            ("+255712000001","Juma Mwangi","Vodacom"),
            ("+255754000002","Amina Hassan","Airtel"),
            ("+255768000003","Peter Kimaro","Halotel"),
            ("+255622000004","Fatuma Ally","TTCL"),
            ("+255789000005","Said Omar","YAS"),
            ("+255712000006","Grace Mushi","Vodacom"),
            ("+255754000007","Ali Juma","Airtel"),
            ("+255768000008","Rehema Banda","Halotel"),
            ("+255712000009","Frank Ngowi","Vodacom"),
            ("+255754000010","Zainab Msoma","Airtel"),
            ("+255741000011","Baraka Msigwa","M-Pesa"),
            ("+255786000012","Neema Chande","Airtel Money"),
            ("+255716000013","Hassan Kileo","mixx by yas"),
        ]
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for n in numbers:
            c.execute("INSERT INTO phone_numbers (number,name,network,registered_at) VALUES (?,?,?,?)",
                      (n[0],n[1],n[2],now))

    c.execute("SELECT COUNT(*) FROM network_partners")
    if c.fetchone()[0] == 0:
        partners = [
            ("Vodacom Tanzania","Telecom","info@vodacom.co.tz"),
            ("Airtel Tanzania","Telecom","info@airtel.co.tz"),
            ("Halotel","Telecom","support@halotel.co.tz"),
            ("TTCL","Telecom","info@ttcl.co.tz"),
            ("YAS Tanzania","Telecom","support@yas.co.tz"),
            ("M-Pesa (Vodacom)","Money Agent","mpesa@vodacom.co.tz"),
            ("Airtel Money","Money Agent","airtelmoney@airtel.co.tz"),
            ("mixx by yas","Money Agent","tigopesa@tigo.co.tz"),
            ("Halotel Pesa","Money Agent","halopesa@halotel.co.tz"),
            ("NMB Bank","Bank","info@nmbtz.com"),
            ("CRDB Bank","Bank","info@crdbbank.com"),
            ("NBC Bank","Bank","info@nbctz.com"),
        ]
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for p in partners:
            c.execute("INSERT INTO network_partners (name,type,contact,joined_at) VALUES (?,?,?,?)",
                      (p[0],p[1],p[2],now))

    c.execute("SELECT COUNT(*) FROM network_logs")
    if c.fetchone()[0] == 0:
        mitandao = ["Vodacom","Airtel","Halotel","TTCL","YAS","Tigo"]
        msgs = [
            ("Gateway firewall packet integrity approved","Safe"),
            ("Session token validation check routing","Safe"),
            ("Unauthorized remote proxy execution intercepted","Threat"),
            ("Malicious payload deployment injection failed","Threat"),
            ("Anomalous traffic pattern under monitoring","Warning"),
            ("Bulk SMS flagged: no prior contact detected","Threat"),
            ("OTP keyword detected in outbound message","Warning"),
        ]
        now = datetime.now()
        entries = []
        for i in range(30):
            kp = random.choice(mitandao)
            msg = random.choice(msgs)
            muda = (now - timedelta(hours=i*2)).strftime("%Y-%m-%d %H:%M:%S")
            entries.append((kp,f"172.16.{random.randint(0,255)}.{random.randint(1,254)}",
                            f"[{kp.upper()}] {msg[0]}",msg[1],muda))
        c.executemany("INSERT INTO network_logs (company,source,content,status,timestamp) VALUES (?,?,?,?,?)", entries)

    conn.commit()
    conn.close()

init_db()

# ══════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════
@app.route('/logo.png')
def serve_logo():
    for jina in ['klogo cyber.jpeg','klogo cyber.jpg','logo.png','logo.jpg','logo.jpeg']:
        if os.path.exists(os.path.join(BASE_DIR, jina)):
            return send_from_directory(BASE_DIR, jina)
    return "Not Found", 404

@app.route('/')
def home():
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM network_logs"); t_net=c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM network_logs WHERE status='Threat'"); t_nt=c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM network_logs WHERE status='Warning'"); t_nw=c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM sms_logs"); t_sms=c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM sms_logs WHERE status='Threat'"); t_st=c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM sms_logs WHERE status='Warning'"); t_sw=c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM sms_logs WHERE status='Safe'"); t_ss=c.fetchone()[0]
    c.execute("SELECT number,name,network FROM phone_numbers ORDER BY id")
    numbers=[{"number":r[0],"name":r[1],"network":r[2]} for r in c.fetchall()]
    c.execute("SELECT sender,recipient,message,status,threat_reason,timestamp FROM sms_logs ORDER BY id DESC LIMIT 20")
    sms_recent=[{"sender":r[0],"recipient":r[1],"message":r[2],"status":r[3],"reason":r[4],"timestamp":r[5]} for r in c.fetchall()]
    c.execute("SELECT company,source,content,status,timestamp FROM network_logs ORDER BY id DESC LIMIT 15")
    net_recent=[{"company":r[0],"source":r[1],"content":r[2],"status":r[3],"timestamp":r[4]} for r in c.fetchall()]
    c.execute("SELECT name,type,contact,joined_at,active FROM network_partners ORDER BY type,name")
    partners=[{"name":r[0],"type":r[1],"contact":r[2],"joined_at":r[3],"active":r[4]} for r in c.fetchall()]

    # Graph data: last 7 days
    graph_data = []
    now = datetime.now()
    for i in range(6,-1,-1):
        day = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        c.execute("SELECT COUNT(*) FROM sms_logs WHERE timestamp LIKE ? AND status='Threat'", (day+"%",))
        t=c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM sms_logs WHERE timestamp LIKE ? AND status='Warning'", (day+"%",))
        w=c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM sms_logs WHERE timestamp LIKE ? AND status='Safe'", (day+"%",))
        s=c.fetchone()[0]
        graph_data.append({"day":day[-5:],"threats":t,"warnings":w,"safe":s})

    conn.close()
    return render_template_string(HTML,
        t_net=t_net,t_nt=t_nt,t_nw=t_nw,
        t_sms=t_sms,t_st=t_st,t_sw=t_sw,t_ss=t_ss,
        numbers=json.dumps(numbers),
        sms_recent=json.dumps(sms_recent),
        net_recent=json.dumps(net_recent),
        partners=json.dumps(partners),
        graph_data=json.dumps(graph_data)
    )

@app.route('/api/detect_network', methods=['POST'])
def api_detect_network():
    number = request.json.get('number','')
    net = detect_network(number)
    return jsonify({"network": net})

@app.route('/api/send_sms', methods=['POST'])
def send_sms():
    data=request.json
    sender=data.get('sender',''); recipients=data.get('recipients',[]); message=data.get('message','')
    if not sender or not recipients or not message:
        return jsonify({"error":"Taarifa hazikamiliki"}),400
    conn=get_db()
    status,reason=analyze_sms(sender,recipients,message,conn)
    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c=conn.cursor()
    for recipient in recipients:
        c.execute("INSERT INTO sms_logs (sender,recipient,message,status,threat_reason,timestamp) VALUES (?,?,?,?,?,?)",
                  (sender,recipient,message,status,reason,timestamp))
    c.execute("SELECT network FROM phone_numbers WHERE number=?",(sender,))
    row=c.fetchone(); snet=row[0] if row else "Unknown"
    c.execute("INSERT INTO network_logs (company,source,content,status,timestamp) VALUES (?,?,?,?,?)",
              (snet,sender,
               "[SMS] {} → {} recipient(s): \"{}\"".format(sender,len(recipients),message[:55]+"..." if len(message)>55 else message),
               status,timestamp))
    conn.commit()
    # Updated graph
    now=datetime.now()
    graph_data=[]
    for i in range(6,-1,-1):
        day=(now-timedelta(days=i)).strftime("%Y-%m-%d")
        c.execute("SELECT COUNT(*) FROM sms_logs WHERE timestamp LIKE ? AND status='Threat'",(day+"%",)); t=c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM sms_logs WHERE timestamp LIKE ? AND status='Warning'",(day+"%",)); w=c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM sms_logs WHERE timestamp LIKE ? AND status='Safe'",(day+"%",)); s=c.fetchone()[0]
        graph_data.append({"day":day[-5:],"threats":t,"warnings":w,"safe":s})
    conn.close()
    return jsonify({"status":status,"reason":reason,"timestamp":timestamp,"graph_data":graph_data})

@app.route('/api/numbers')
def get_numbers():
    conn=get_db(); c=conn.cursor()
    c.execute("SELECT number,name,network,registered_at FROM phone_numbers ORDER BY id")
    nums=[{"number":r[0],"name":r[1],"network":r[2],"registered_at":r[3]} for r in c.fetchall()]
    conn.close(); return jsonify(nums)

@app.route('/api/add_number', methods=['POST'])
def add_number():
    data=request.json
    number=data.get('number','').strip(); name=data.get('name','').strip(); network=data.get('network','').strip()
    if not number or not name or not network:
        return jsonify({"error":"Jaza taarifa zote"}),400
    if not network or network=="Unknown":
        network=detect_network(number)
    conn=get_db(); c=conn.cursor()
    try:
        c.execute("INSERT INTO phone_numbers (number,name,network,registered_at) VALUES (?,?,?,?)",
                  (number,name,network,datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit(); conn.close(); return jsonify({"success":True,"network":network})
    except sqlite3.IntegrityError:
        conn.close(); return jsonify({"error":"Namba hii tayari ipo"}),400

@app.route('/api/sms_logs')
def sms_logs_api():
    conn=get_db(); c=conn.cursor()
    c.execute("SELECT sender,recipient,message,status,threat_reason,timestamp FROM sms_logs ORDER BY id DESC LIMIT 50")
    logs=[{"sender":r[0],"recipient":r[1],"message":r[2],"status":r[3],"reason":r[4],"timestamp":r[5]} for r in c.fetchall()]
    c.execute("SELECT COUNT(*) FROM sms_logs"); t=c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM sms_logs WHERE status='Threat'"); th=c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM sms_logs WHERE status='Warning'"); w=c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM sms_logs WHERE status='Safe'"); s=c.fetchone()[0]
    conn.close(); return jsonify({"logs":logs,"total":t,"threats":th,"warnings":w,"safe":s})

@app.route('/api/network_logs')
def network_logs_api():
    kampuni=request.args.get('company','all'); timeframe=request.args.get('timeframe','year')
    conn=get_db(); c=conn.cursor()
    COMPANIES=["Vodacom","Airtel","Halotel","TTCL","YAS","Tigo"]
    MSGS=[
        ("Gateway Perimeter: Security integrity handshake passed","Safe"),
        ("Core backbone routing protocol verified","Safe"),
        ("Rapid packet distribution alert from unverified node","Warning"),
        ("High-risk transaction request blocked: Signature mismatch","Threat"),
        ("API authentication failure detected and isolated","Threat"),
        ("Phishing link injection attempt blocked at gateway","Threat"),
        ("Bulk SMS pattern detected from single source","Threat"),
        ("OTP solicitation keyword in outbound message","Warning"),
    ]
    kp=random.choice(COMPANIES) if kampuni=='all' else kampuni
    msg=random.choice(MSGS)
    ip="{}.{}.{}.{}".format(random.randint(10,192),random.randint(0,255),random.randint(0,255),random.randint(1,254))
    now_str=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO network_logs (company,source,content,status,timestamp) VALUES (?,?,?,?,?)",
              (kp,ip,"[{}] {}".format(kp.upper(),msg[0]),msg[1],now_str))
    conn.commit()
    now=datetime.now()
    if timeframe=='day': kikomo=(now-timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    elif timeframe=='week': kikomo=(now-timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    elif timeframe=='month': kikomo=(now-timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    else: kikomo="2026-01-01 00:00:00"
    q="SELECT company,source,content,status,timestamp FROM network_logs WHERE timestamp>=?"
    p=[kikomo]
    if kampuni!='all': q+=" AND company=?"; p.append(kampuni)
    q+=" ORDER BY id DESC LIMIT 15"
    base_p=tuple(p)
    filt=" AND company=?" if kampuni!='all' else ""
    filt_p=tuple([kikomo]+([kampuni] if kampuni!='all' else []))
    c.execute("SELECT COUNT(*) FROM network_logs WHERE timestamp>=?"+filt, filt_p); total=c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM network_logs WHERE status='Threat' AND timestamp>=?"+filt, filt_p); threats=c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM network_logs WHERE status='Warning' AND timestamp>=?"+filt, filt_p); warnings=c.fetchone()[0]
    c.execute(q,base_p)
    logs=[{"company":r[0],"source":r[1],"content":r[2],"status":r[3],"timestamp":r[4]} for r in c.fetchall()]
    conn.close()
    return jsonify({"logs":logs,"total":total,"threats":threats,"warnings":warnings})

@app.route('/api/partners')
def partners_api():
    conn=get_db(); c=conn.cursor()
    c.execute("SELECT name,type,contact,joined_at,active FROM network_partners ORDER BY type,name")
    partners=[{"name":r[0],"type":r[1],"contact":r[2],"joined_at":r[3],"active":r[4]} for r in c.fetchall()]
    conn.close(); return jsonify(partners)

@app.route('/api/graph')
def graph_api():
    conn=get_db(); c=conn.cursor()
    now=datetime.now(); graph_data=[]
    for i in range(6,-1,-1):
        day=(now-timedelta(days=i)).strftime("%Y-%m-%d")
        c.execute("SELECT COUNT(*) FROM sms_logs WHERE timestamp LIKE ? AND status='Threat'",(day+"%",)); t=c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM sms_logs WHERE timestamp LIKE ? AND status='Warning'",(day+"%",)); w=c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM sms_logs WHERE timestamp LIKE ? AND status='Safe'",(day+"%",)); s=c.fetchone()[0]
        graph_data.append({"day":day[-5:],"threats":t,"warnings":w,"safe":s})
    conn.close(); return jsonify(graph_data)

# ══════════════════════════════════════════════
# HTML
# ══════════════════════════════════════════════
HTML = """<!DOCTYPE html>
<html lang="sw">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>CYBER SALAMA TZ — National Command Dashboard v4</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@700;900&family=Exo+2:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
:root{
  --a:#00e5ff;--ag:rgba(0,229,255,.4);--ad:rgba(0,229,255,.1);
  --danger:#ff3b55;--warn:#ffc300;--safe:#00e096;
  --bg0:#030b16;--bg1:#071020;--bg2:#0b1a2e;--bg3:#0e2040;
  --bdr:rgba(0,229,255,.18);
  --txt:#e4f4ff;        /* bright white-blue — easy to read */
  --txt2:#b8d8f0;       /* secondary text */
  --mut:#4a7a9b;
  --mono:'Share Tech Mono',monospace;
  --disp:'Orbitron',sans-serif;
  --body:'Exo 2',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0;}
html{font-size:15px;}
body{
  background:var(--bg0);
  color:var(--txt);
  font-family:var(--body);
  font-size:15px;
  font-weight:500;
  line-height:1.65;
  min-height:100vh;
  display:flex;
  flex-direction:column;
  overflow-x:hidden;
}
body::before{
  content:'';position:fixed;inset:0;
  background-image:
    linear-gradient(rgba(0,229,255,.025) 1px,transparent 1px),
    linear-gradient(90deg,rgba(0,229,255,.025) 1px,transparent 1px);
  background-size:48px 48px;pointer-events:none;z-index:0;
}

/* ── NAVBAR ── */
.navbar{
  position:relative;z-index:100;
  background:linear-gradient(90deg,#030d1a 0%,#071628 50%,#030d1a 100%);
  padding:0 32px;
  display:flex;align-items:center;justify-content:space-between;
  border-bottom:2px solid var(--a);
  box-shadow:0 0 40px rgba(0,229,255,.18),0 4px 0 var(--a);
  height:68px;flex-wrap:wrap;gap:8px;
}
.brand{display:flex;align-items:center;gap:16px;}
.logo-box{
  width:48px;height:48px;border-radius:10px;
  border:2px solid var(--a);background:var(--bg0);
  display:flex;align-items:center;justify-content:center;
  overflow:hidden;box-shadow:0 0 20px var(--ag);flex-shrink:0;
}
.logo-box img{width:100%;height:100%;object-fit:cover;}
.logo-fb{font-family:var(--mono);color:var(--a);font-size:14px;font-weight:900;display:none;}
.brand-text{}
.brand-name{
  font-family:var(--disp);
  font-size:22px;
  font-weight:900;
  color:#ffffff;
  letter-spacing:5px;
  text-transform:uppercase;
  line-height:1.15;
  text-shadow:0 0 30px rgba(0,229,255,.5),0 0 60px rgba(0,229,255,.2);
}
.brand-name em{
  color:var(--a);
  font-style:normal;
  font-weight:900;
  text-shadow:0 0 20px rgba(0,229,255,.8);
}
.brand-tag{
  font-family:var(--mono);
  font-size:9px;color:var(--mut);
  letter-spacing:2.5px;text-transform:uppercase;margin-top:3px;
}
.nav-menu{display:flex;gap:5px;flex-wrap:wrap;}
.nb{
  background:transparent;
  border:1px solid rgba(0,229,255,.2);
  color:var(--txt2);
  padding:7px 14px;
  font-family:var(--body);
  font-weight:700;font-size:12px;
  border-radius:5px;cursor:pointer;
  transition:all .2s;
  text-transform:uppercase;letter-spacing:.5px;
  white-space:nowrap;
}
.nb:hover{border-color:var(--a);color:#fff;background:var(--ad);}
.nb.active{
  background:var(--a);color:var(--bg0);
  border-color:var(--a);
  box-shadow:0 0 18px var(--ag);
  font-weight:800;
}

/* ── MAIN ── */
.main{padding:24px 32px;flex:1;position:relative;z-index:1;}
.tab{display:none;}.tab.active{display:block;}
.sec-hd{
  font-family:var(--body);font-size:11px;font-weight:800;
  color:var(--mut);letter-spacing:3px;text-transform:uppercase;
  margin-bottom:18px;display:flex;align-items:center;gap:12px;
}
.sec-hd::after{content:'';flex:1;height:1px;background:var(--bdr);}

/* ── STAT CARDS ── */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:12px;margin-bottom:22px;}
.card{
  background:linear-gradient(135deg,var(--bg3) 0%,var(--bg2) 100%);
  border-radius:8px;padding:16px 18px;
  border:1px solid var(--bdr);border-left:4px solid var(--a);
  box-shadow:0 4px 16px rgba(0,0,0,.3);
}
.card h3{
  font-family:var(--body);font-size:10px;font-weight:700;
  color:var(--txt2);text-transform:uppercase;
  letter-spacing:1.5px;line-height:1.5;
}
.card p{
  font-family:var(--disp);font-size:32px;font-weight:900;
  margin-top:6px;color:var(--a);line-height:1;
}
.c-t{border-left-color:var(--danger);}.c-t p{color:var(--danger);}
.c-w{border-left-color:var(--warn);}.c-w p{color:var(--warn);}
.c-s{border-left-color:var(--safe);}.c-s p{color:var(--safe);}

/* ── CONTROL ── */
.ctrl{
  background:var(--bg2);padding:14px 20px;border-radius:8px;
  border:1px solid var(--bdr);margin-bottom:20px;
  display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap;
}
.ctrl label{
  font-family:var(--body);font-size:11px;font-weight:700;
  color:var(--txt2);letter-spacing:1px;white-space:nowrap;
  text-transform:uppercase;
}
select{
  background:var(--bg0);color:var(--txt);
  border:1.5px solid var(--a);padding:8px 14px;
  border-radius:5px;font-family:var(--body);
  font-weight:600;cursor:pointer;outline:none;font-size:14px;
}
.tf{display:flex;background:var(--bg0);padding:3px;border-radius:5px;border:1px solid var(--bdr);}
.tfb{
  background:transparent;border:none;color:var(--txt2);
  padding:6px 14px;font-family:var(--body);
  font-size:12px;font-weight:700;border-radius:3px;
  cursor:pointer;transition:all .2s;
  text-transform:uppercase;letter-spacing:.5px;
}
.tfb.active{background:var(--warn);color:var(--bg0);font-weight:800;}

/* ── LIVE ── */
.live-badge{
  display:inline-flex;align-items:center;gap:8px;
  background:rgba(0,229,255,.06);border:1px solid var(--a);
  padding:6px 16px;border-radius:20px;color:var(--a);
  font-family:var(--mono);font-size:10px;font-weight:bold;
  text-transform:uppercase;margin-bottom:16px;letter-spacing:1.5px;
}
.ld{width:7px;height:7px;background:var(--a);border-radius:50%;animation:blink 1.2s infinite;}
@keyframes blink{0%,100%{opacity:.15}50%{opacity:1}}

/* ── TABLE ── */
.tw{overflow-x:auto;border-radius:8px;margin-bottom:22px;box-shadow:0 4px 20px rgba(0,0,0,.3);}
table{width:100%;border-collapse:collapse;background:var(--bg3);border:1px solid var(--bdr);}
th{
  background:var(--bg0);
  color:var(--txt2);
  font-family:var(--body);font-size:11px;font-weight:800;
  text-transform:uppercase;letter-spacing:1.5px;
  border-bottom:2px solid var(--bdr);
  white-space:nowrap;padding:13px 16px;
}
td{
  padding:12px 16px;
  text-align:left;vertical-align:middle;
  color:var(--txt);
  font-size:13.5px;
  font-weight:500;
  line-height:1.55;
  border-bottom:1px solid rgba(0,229,255,.06);
}
tr:last-child td{border-bottom:none;}
tr:hover td{background:rgba(0,229,255,.05);}
.sS{
  color:var(--safe);font-family:var(--mono);font-size:11px;
  font-weight:bold;letter-spacing:1px;
  background:rgba(0,224,150,.1);padding:3px 8px;border-radius:3px;
  border:1px solid rgba(0,224,150,.3);white-space:nowrap;
}
.sW{
  color:var(--warn);font-family:var(--mono);font-size:11px;
  font-weight:bold;letter-spacing:1px;
  background:rgba(255,195,0,.1);padding:3px 8px;border-radius:3px;
  border:1px solid rgba(255,195,0,.3);white-space:nowrap;
}
.sT{
  color:var(--danger);font-family:var(--mono);font-size:11px;
  font-weight:bold;letter-spacing:1px;
  background:rgba(255,59,85,.1);padding:3px 8px;border-radius:3px;
  border:1px solid rgba(255,59,85,.4);white-space:nowrap;
  animation:pr 2s infinite;
}
@keyframes pr{0%,100%{opacity:1}50%{opacity:.5}}
.ts{font-family:var(--mono);font-size:11px;color:var(--mut);}
.msg-cell{font-size:13.5px;color:var(--txt);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.reason-cell{font-size:12px;color:var(--txt2);line-height:1.5;max-width:200px;}
code{
  background:rgba(255,195,0,.08);padding:3px 8px;
  border-radius:3px;font-family:var(--mono);
  color:var(--warn);font-size:11px;
  border:1px solid rgba(255,195,0,.25);
}

/* ── NETWORK BADGE ── */
.nbdg{
  display:inline-flex;align-items:center;gap:7px;
  padding:4px 11px;border-radius:5px;min-width:100px;
  border-left:4px solid #ccc;background:#fff;
  box-shadow:0 1px 4px rgba(0,0,0,.2);
}
.nbdg img{width:18px;height:18px;object-fit:contain;}
.nbdg span{font-family:var(--body);font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:.5px;}
.nv{border-left-color:#e60000;}.nv span{color:#c80000;}
.na{border-left-color:#0066cc;}.na span{color:#004fa3;}
.nh{border-left-color:#ff5500;}.nh span{color:#cc4400;}
.ny{border-left-color:#c8a800;}.ny span{color:#7a6500;}
.nt{border-left-color:#0044cc;}.nt span{color:#003399;}
.ng{border-left-color:#cc0066;}.ng span{color:#990044;}
.nm{border-left-color:#cc0000;}.nm span{color:#990000;}
.nz{border-left-color:#009977;}.nz span{color:#006655;}
.nu{border-left-color:#777;}.nu span{color:#444;}

/* ── SMS PANEL ── */
.panel{
  background:var(--bg2);border:1px solid var(--bdr);
  border-radius:10px;padding:24px;margin-bottom:22px;
  box-shadow:0 4px 20px rgba(0,0,0,.25);
}
.panel-title{
  font-family:var(--body);font-size:17px;font-weight:800;
  color:var(--a);text-transform:uppercase;letter-spacing:2px;
  margin-bottom:20px;display:flex;align-items:center;gap:10px;
  text-shadow:0 0 16px rgba(0,229,255,.4);
}
.fg{display:flex;flex-direction:column;gap:7px;margin-bottom:16px;}
.fg label{
  font-family:var(--body);font-size:11px;font-weight:800;
  color:var(--txt2);letter-spacing:1.5px;text-transform:uppercase;
}
.fg select,.fg input,.fg textarea{
  background:var(--bg0);color:var(--txt);
  border:1.5px solid rgba(0,229,255,.25);
  padding:11px 14px;border-radius:6px;
  font-family:var(--body);font-size:14px;font-weight:500;
  outline:none;transition:border-color .25s;width:100%;
}
.fg select:focus,.fg input:focus,.fg textarea:focus{border-color:var(--a);}
.fg textarea{resize:vertical;min-height:90px;line-height:1.7;}
.fg2{display:grid;grid-template-columns:1fr 1fr;gap:16px;}
.recip-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:9px;margin-bottom:16px;}
.rc{
  display:flex;align-items:center;gap:10px;
  background:var(--bg0);padding:10px 13px;
  border-radius:6px;border:1.5px solid rgba(0,229,255,.15);
  cursor:pointer;transition:border-color .2s;
}
.rc:hover{border-color:var(--a);}
.rc input[type=checkbox]{accent-color:var(--a);width:16px;height:16px;flex-shrink:0;}
.rc .rn{font-size:13.5px;font-weight:700;color:var(--txt);}
.rc .rnum{font-family:var(--mono);font-size:10px;color:var(--mut);margin-top:1px;}
.rc .rnet{
  font-family:var(--mono);font-size:9px;padding:2px 6px;
  border-radius:3px;background:var(--bg2);color:var(--a);
  border:1px solid var(--bdr);margin-left:auto;flex-shrink:0;font-weight:bold;
}
.btn{
  border:none;padding:12px 28px;border-radius:6px;
  font-family:var(--body);font-size:15px;font-weight:800;
  letter-spacing:1px;text-transform:uppercase;cursor:pointer;
  transition:all .2s;
}
.btn-primary{background:var(--a);color:var(--bg0);box-shadow:0 0 20px var(--ag);}
.btn-primary:hover{background:#00f2ff;transform:translateY(-2px);box-shadow:0 4px 24px var(--ag);}
.btn-primary:disabled{opacity:.45;cursor:not-allowed;transform:none;box-shadow:none;}
.btn-sec{background:var(--warn);color:var(--bg0);box-shadow:0 0 12px rgba(255,195,0,.3);}
.btn-sec:hover{background:#ffd633;transform:translateY(-1px);}
.res{
  display:none;margin-top:18px;padding:18px 20px;
  border-radius:8px;border:1px solid;
  font-family:var(--body);font-size:14.5px;
  font-weight:500;line-height:1.85;
}
.res.Safe{background:rgba(0,224,150,.07);border-color:var(--safe);color:#00e096;}
.res.Warning{background:rgba(255,195,0,.07);border-color:var(--warn);color:#ffc300;}
.res.Threat{background:rgba(255,59,85,.09);border-color:var(--danger);color:#ff3b55;}
.res strong{font-size:17px;font-family:var(--body);font-weight:900;letter-spacing:1px;display:block;margin-bottom:6px;}

/* ── GRAPH ── */
.graph-wrap{
  background:var(--bg2);border:1px solid var(--bdr);
  border-radius:10px;padding:22px;margin-bottom:22px;
  box-shadow:0 4px 20px rgba(0,0,0,.25);
}
.graph-wrap h3{
  font-family:var(--body);font-size:16px;font-weight:800;
  color:var(--a);text-transform:uppercase;letter-spacing:2px;
  margin-bottom:18px;
}
canvas#trend-chart{max-height:300px;}

/* ── NUMBERS GRID ── */
.num-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:11px;margin-bottom:22px;}
.num-card{
  background:linear-gradient(135deg,var(--bg3),var(--bg2));
  border:1px solid var(--bdr);border-radius:8px;
  padding:13px 16px;display:flex;align-items:center;gap:14px;
  box-shadow:0 2px 10px rgba(0,0,0,.25);
}
.avatar{
  width:42px;height:42px;border-radius:50%;
  background:var(--ad);border:2px solid var(--a);
  display:flex;align-items:center;justify-content:center;
  font-family:var(--disp);font-weight:900;font-size:16px;
  color:var(--a);flex-shrink:0;
}
.num-info .nname{font-weight:700;font-size:14.5px;color:var(--txt);}
.num-info .nnum{font-family:var(--mono);font-size:11px;color:var(--mut);margin-top:2px;}
.net-pill{
  margin-left:auto;font-family:var(--mono);font-size:10px;
  font-weight:bold;padding:4px 10px;border-radius:4px;
  background:var(--bg0);border:1px solid var(--bdr);
  color:var(--a);flex-shrink:0;
}

/* ── NETWORK DETECT ── */
.net-detect-result{
  font-family:var(--mono);font-size:12px;font-weight:bold;
  padding:6px 14px;border-radius:5px;background:var(--bg0);
  border:1.5px solid var(--a);color:var(--a);min-width:130px;text-align:center;
}

/* ── PARTNERS ── */
.partner-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:13px;margin-bottom:22px;}
.partner-card{
  background:linear-gradient(135deg,var(--bg3),var(--bg2));
  border:1px solid var(--bdr);border-radius:8px;
  padding:18px 20px;border-top:3px solid var(--a);
  transition:transform .2s;box-shadow:0 4px 16px rgba(0,0,0,.25);
}
.partner-card:hover{transform:translateY(-3px);}
.partner-card h4{
  font-family:var(--body);font-size:15.5px;font-weight:800;
  color:var(--txt);letter-spacing:.5px;margin-bottom:5px;
}
.partner-card .ptype{
  font-family:var(--mono);font-size:10px;color:var(--a);
  text-transform:uppercase;letter-spacing:1px;margin-bottom:9px;
}
.partner-card .pcontact{font-family:var(--mono);font-size:11px;color:var(--mut);}
.active-badge{
  display:inline-flex;align-items:center;gap:4px;
  background:rgba(0,224,150,.1);color:var(--safe);
  border:1px solid rgba(0,224,150,.4);
  padding:3px 10px;border-radius:10px;
  font-family:var(--mono);font-size:10px;font-weight:bold;margin-top:10px;
}
.money-badge{border-top-color:var(--warn);}
.bank-badge{border-top-color:var(--safe);}

/* ── AWARENESS ── */
.aw-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:14px;margin-bottom:22px;}
.aw-box{
  background:linear-gradient(135deg,var(--bg3),var(--bg2));
  padding:20px;border-radius:8px;
  border:1px solid var(--bdr);border-top:3px solid var(--a);
  transition:transform .2s;box-shadow:0 4px 16px rgba(0,0,0,.2);
}
.aw-box:hover{transform:translateY(-3px);}
.aw-box h4{
  font-family:var(--body);font-size:14px;font-weight:800;
  color:var(--warn);text-transform:uppercase;
  letter-spacing:1px;margin-bottom:10px;
}
.aw-box p{font-size:13.5px;font-weight:500;color:var(--txt2);line-height:1.75;}

/* ── FOOTER ── */
.footer{
  background:var(--bg1);padding:18px 32px;
  border-top:1px solid var(--bdr);position:relative;z-index:1;
}
.footer-inner{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;}
.footer-brand{font-family:var(--mono);font-size:11px;color:var(--mut);letter-spacing:1px;line-height:1.8;}
.footer-brand strong{color:var(--a);}
.footer-contact{font-family:var(--mono);font-size:11px;color:var(--mut);text-align:right;line-height:1.8;}
.footer-contact a{color:var(--a);text-decoration:none;}
.footer-contact a:hover{color:#fff;}

/* ── MOBILE ── */
@media(max-width:720px){
  .navbar{height:auto;padding:10px 16px;}
  .main{padding:14px 16px;}
  .fg2{grid-template-columns:1fr;}
  .cards{grid-template-columns:repeat(2,1fr);}
  .brand-name{font-size:17px;letter-spacing:3px;}
  th,td{padding:9px 11px;}
}
</style>
</head>
<body>

<!-- NAVBAR -->
<div class="navbar">
  <div class="brand">
    <div class="logo-box">
      <img src="/logo.png" alt="CS" onerror="this.style.display='none';document.querySelector('.logo-fb').style.display='block';">
      <span class="logo-fb">CS</span>
    </div>
    <div>
      <div class="brand-name">CYBER<em>SALAMA TZ</em></div>
      <div class="brand-tag">Elimu ya Usalama wa Mtandao · Tanzania · Est. 2026</div>
    </div>
  </div>
  <div class="nav-menu">
    <button class="nb active" onclick="sw(event,'t-net')">📡 Network Ops</button>
    <button class="nb" onclick="sw(event,'t-sms')">📱 SMS Detector</button>
    <button class="nb" onclick="sw(event,'t-nums')">👥 Namba</button>
    <button class="nb" onclick="sw(event,'t-partners')">🤝 Washirika</button>
    <button class="nb" onclick="sw(event,'t-graph')">📈 Takwimu</button>
    <button class="nb" onclick="sw(event,'t-aware')">💡 Uhamasishaji</button>
    <button class="nb" onclick="sw(event,'t-eng')">⚙️ Mfumo</button>
  </div>
</div>

<div class="main">

<!-- ══ TAB 1: NETWORK OPS ══ -->
<div id="t-net" class="tab active">
  <div class="sec-hd">📡 Chumba cha Operesheni za Vitisho — Taifa</div>
  <div class="cards">
    <div class="card"><h3>Packets Zilizochunguzwa</h3><p id="n-tot">{{ t_net }}</p></div>
    <div class="card c-t"><h3>Vitisho Vilivyozuiwa</h3><p id="n-thr">{{ t_nt }}</p></div>
    <div class="card c-w"><h3>Onyo Zilizorekodiwa</h3><p id="n-war">{{ t_nw }}</p></div>
    <div class="card c-s"><h3>SMS Zilizochunguzwa</h3><p id="n-sms">{{ t_sms }}</p></div>
    <div class="card c-t"><h3>SMS Vitisho</h3><p id="n-st">{{ t_st }}</p></div>
    <div class="card c-w"><h3>SMS Onyo</h3><p id="n-sw">{{ t_sw }}</p></div>
    <div class="card c-s"><h3>SMS Salama</h3><p id="n-ss">{{ t_ss }}</p></div>
  </div>
  <div class="ctrl">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
      <label>🚨 MTANDAO:</label>
      <select id="net-co" onchange="updNet()">
        <option value="all">🌐 Mtandao Wote wa Taifa</option>
        <option value="Vodacom">Vodacom</option>
        <option value="Airtel">Airtel</option>
        <option value="Halotel">Halotel</option>
        <option value="TTCL">TTCL</option>
        <option value="YAS">YAS</option>
      </select>
    </div>
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
      <label>KIPINDI:</label>
      <div class="tf">
        <button class="tfb" id="bd" onclick="chgT('day')">Leo</button>
        <button class="tfb" id="bw" onclick="chgT('week')">Wiki</button>
        <button class="tfb" id="bm" onclick="chgT('month')">Mwezi</button>
        <button class="tfb active" id="by" onclick="chgT('year')">2026</button>
      </div>
    </div>
  </div>
  <div class="live-badge"><div class="ld"></div>Mtiririko wa Moja kwa Moja — Sync 3s</div>
  <div class="tw">
    <table>
      <thead><tr>
        <th style="width:15%">Wakati</th>
        <th style="width:18%">Mtendaji</th>
        <th style="width:13%">IP Chanzo</th>
        <th style="width:40%">Taarifa ya Usalama</th>
        <th style="width:14%">Hali</th>
      </tr></thead>
      <tbody id="net-body"></tbody>
    </table>
  </div>
</div>

<!-- ══ TAB 2: SMS DETECTOR ══ -->
<div id="t-sms" class="tab">
  <div class="sec-hd">📱 Mfumo wa Kuchunguza SMS — Utapeli Detector</div>
  <div class="panel">
    <div class="panel-title">📤 Tuma SMS — Chunguza Maudhui</div>
    <div class="fg2">
      <div class="fg">
        <label>Mtumaji (Sender)</label>
        <select id="sms-from"><option value="">— Chagua Namba —</option></select>
      </div>
      <div class="fg">
        <label>Ujumbe wa SMS</label>
        <textarea id="sms-msg" placeholder="Andika ujumbe hapa... Mfumo utauchunguza moja kwa moja."></textarea>
      </div>
    </div>
    <div class="fg" style="margin-bottom:14px;">
      <label>Wapokeaji — Chagua Moja au Zaidi (Mass SMS kwa watu 2+ wapya = Threat)</label>
      <div class="recip-grid" id="recip-grid"></div>
    </div>
    <button class="btn btn-primary" id="btn-snd" onclick="doSend()">🚀 Tuma na Chunguza</button>
    <div class="res" id="res-box"></div>
  </div>

  <div class="sec-hd">📋 Kumbukumbu ya SMS — Hivi Karibuni</div>
  <div class="tw">
    <table>
      <thead><tr>
        <th style="width:13%">Wakati</th>
        <th style="width:13%">Mtumaji</th>
        <th style="width:13%">Mpokeaji</th>
        <th style="width:28%">Ujumbe</th>
        <th style="width:9%">Hali</th>
        <th style="width:24%">Sababu</th>
      </tr></thead>
      <tbody id="sms-body"></tbody>
    </table>
  </div>
</div>

<!-- ══ TAB 3: NUMBERS ══ -->
<div id="t-nums" class="tab">
  <div class="sec-hd">👥 Namba za Simu Zilizosajiliwa</div>
  <div class="panel">
    <div class="panel-title">➕ Sajili Namba Mpya — Mtandao Utatambuliwa Otomatiki</div>
    <div class="fg2">
      <div class="fg">
        <label>Jina Kamili</label>
        <input type="text" id="a-name" placeholder="Mfano: Juma Mwangi">
      </div>
      <div class="fg">
        <label>Namba ya Simu</label>
        <div class="net-detect-box">
          <input type="text" id="a-num" placeholder="+255712000001" oninput="autoDetect()" style="flex:1;">
        </div>
        <div style="margin-top:6px;display:flex;align-items:center;gap:8px;">
          <span style="font-family:var(--mono);font-size:10px;color:var(--mut);">MTANDAO:</span>
          <span class="net-detect-result" id="nd-result">—</span>
        </div>
      </div>
    </div>
    <div class="fg" style="margin-bottom:14px;max-width:260px;">
      <label>Mtandao (au acha mfumo uamue)</label>
      <select id="a-net">
        <option value="">🔍 Tambua Otomatiki</option>
        <option value="Vodacom">Vodacom</option>
        <option value="Airtel">Airtel</option>
        <option value="Halotel">Halotel</option>
        <option value="TTCL">TTCL</option>
        <option value="YAS">YAS</option>
        <option value="M-Pesa">M-Pesa Agent</option>
        <option value="Airtel Money">Airtel Money Agent</option>
        <option value="mixx by yas">mixx by yas Agent</option>
      </select>
    </div>
    <button class="btn btn-sec" onclick="doAdd()">➕ Sajili Namba</button>
    <span id="add-msg" style="font-family:var(--mono);font-size:11px;margin-left:12px;"></span>
  </div>
  <div class="num-grid" id="num-grid"></div>
</div>

<!-- ══ TAB 4: PARTNERS ══ -->
<div id="t-partners" class="tab">
  <div class="sec-hd">🤝 Washirika wa Taifa — Mkakati wa Kudhibiti Utapeli</div>
  <div style="background:var(--bg2);border:1px solid var(--bdr);border-radius:7px;padding:16px 20px;margin-bottom:18px;">
    <p style="font-size:14px;color:#85a8c0;line-height:1.8;">
      <strong style="color:var(--a);">CYBER SALAMA TZ</strong> inafanya kazi kwa ushirikiano na makampuni ya simu, mawakala wa pesa za mtandao, na taasisi za fedha ili kuhakikisha SMS zote zinachujwa kabla ya kufikia mtumiaji. Kila mshirika ana ufikiaji wa mfumo wa kugundua utapeli kwa wakati halisi.
    </p>
  </div>

  <div class="sec-hd" style="margin-top:8px;">📡 Makampuni ya Simu</div>
  <div class="partner-grid" id="pg-telecom"></div>

  <div class="sec-hd">💰 Mawakala wa Pesa za Mtandao</div>
  <div class="partner-grid" id="pg-money"></div>

  <div class="sec-hd">🏦 Taasisi za Fedha</div>
  <div class="partner-grid" id="pg-bank"></div>
</div>

<!-- ══ TAB 5: GRAPH ══ -->
<div id="t-graph" class="tab">
  <div class="sec-hd">📈 Takwimu — Mwenendo wa Utapeli kwa Wakati</div>
  <div class="graph-wrap">
    <h3>📊 Mwenendo wa SMS — Siku 7 Zilizopita</h3>
    <canvas id="trend-chart"></canvas>
  </div>
  <div class="cards" style="max-width:500px;">
    <div class="card c-t"><h3>Jumla Vitisho</h3><p id="g-t">{{ t_st }}</p></div>
    <div class="card c-w"><h3>Jumla Onyo</h3><p id="g-w">{{ t_sw }}</p></div>
    <div class="card c-s"><h3>Jumla Salama</h3><p id="g-s">{{ t_ss }}</p></div>
  </div>
</div>

<!-- ══ TAB 6: AWARENESS ══ -->
<div id="t-aware" class="tab">
  <div class="sec-hd">💡 Uhamasishaji wa Usalama wa Mtandao — Taifa 2026</div>
  <div class="aw-grid">
    <div class="aw-box"><h4>🔐 OTP / Namba ya Siri</h4><p>Kamwe usitoe OTP, PIN, au namba ya uthibitisho kwa mtu yeyote — hata akidai ni wa benki, NIDA, au mtandao wa simu.</p></div>
    <div class="aw-box"><h4>📱 WhatsApp Hijacking</h4><p>Rafiki yako akikuomba namba ya uhakiki uliyopokea SMS — USITUME. Account yake imeibiwa, mtapeli anatumia jina lake.</p></div>
    <div class="aw-box"><h4>📨 Mass SMS Scam</h4><p>Ukipata SMS kutoka namba isiyo na historia ya mawasiliano nawe, ikidai zawadi, faida, au dharura — ni Threat. Ripoti mara moja.</p></div>
    <div class="aw-box"><h4>🔗 Link za Utapeli</h4><p>Usibonyeze link zozote kwenye SMS zinazoahidi zawadi, mkopo, ajira, au zinazokulazimisha kuingia akaunti yako.</p></div>
    <div class="aw-box"><h4>💔 Romance Scam</h4><p>Mpenzi wa mtandao anayekuomba pesa za tiketi, visa, au dharura baada ya siku chache tu — ni mtego wa kimataifa.</p></div>
    <div class="aw-box"><h4>💰 Uwekezaji wa Uongo</h4><p>Hakuna biashara halali inayolipa faida ya 50%+ kwa wiki. Ahadi kama hizi ni wizi uliofunikwa na maneno mazuri.</p></div>
    <div class="aw-box"><h4>👮 Mamlaka Feki</h4><p>Simu inayodai ni polisi, benki, au serikali ikitaka pesa au taarifa za siri — kata simu na ripoti kwa mamlaka halisi.</p></div>
    <div class="aw-box"><h4>📦 Mzigo / Parcel Feki</h4><p>Ujumbe unaosema parcel yako imekamatwa na unahitaji kulipa ada ya kutoa — hii ni udanganyifu wa kawaida.</p></div>
    <div class="aw-box"><h4>💻 Ufikiaji wa Mbali</h4><p>Mtu anayekuomba ufungue AnyDesk, TeamViewer au programu yoyote ya ufikiaji wa mbali — kata mawasiliano haraka.</p></div>
  </div>
</div>

<!-- ══ TAB 7: ENGINEERING ══ -->
<div id="t-eng" class="tab">
  <div class="sec-hd">⚙️ Usanifu wa Mfumo</div>
  <div class="aw-grid">
    <div class="aw-box"><h4>Platform</h4><p>Python Flask + SQLite. Database ya kudumu — data haipotei kwenye restart. Live network feed kila sekunde 3. Port 5002.</p></div>
    <div class="aw-box"><h4>SMS Detection Engine</h4><p>Mfumo wa kugundua maneno 150+ ya utapeli (Kiswahili/Kiingereza), mass SMS detection, URL scanner, na prior contact analyzer.</p></div>
    <div class="aw-box"><h4>Network Auto-Detection</h4><p>Mfumo unagundua mtandao wa namba yoyote ya Tanzania (+255) otomatiki kwa kutumia prefix database.</p></div>
    <div class="aw-box"><h4>Viwango vya Hatari</h4><p><span style="color:var(--safe)">SAFE</span> — shughuli ya kawaida. <span style="color:var(--warn)">WARNING</span> — anomaly ya kutiliwa shaka. <span style="color:var(--danger)">THREAT</span> — shambulio halisi.</p></div>
    <div class="aw-box"><h4>Washirika wa Mfumo</h4><p>Makampuni ya simu 6, mawakala wa pesa 4, taasisi za fedha 3 — wote wameunganishwa kwenye mfumo wa uchujaji wa SMS.</p></div>
    <div class="aw-box"><h4>Version</h4><p>CYBER SALAMA TZ v4.0 — Campaign 2026. Mobile responsive. Chart.js analytics. Developed for Tanzania national security.</p></div>
  </div>
</div>

</div><!-- /main -->

<!-- FOOTER -->
<div class="footer">
  <div class="footer-inner">
    <div class="footer-brand">
      National Infrastructure Security Ecosystem ·
      Maintained by <strong>CYBER SALAMA TZ</strong> ·
      Campaign <strong>2026</strong> ·
      <strong>CEO:</strong> Founder & Director
    </div>
    <div class="footer-contact">
      📧 <a href="mailto:cybersecuritytz@gmail.com">cybersecuritytz@gmail.com</a><br>
      <span style="color:var(--mut);">© 2026 Cyber Salama TZ · All Rights Reserved</span>
    </div>
  </div>
</div>

<script>
var CUR_T='year';
var ALL_NUMS={{ numbers|safe }};
var SMS_LOG={{ sms_recent|safe }};
var NET_LOG={{ net_recent|safe }};
var PARTNERS={{ partners|safe }};
var GRAPH={{ graph_data|safe }};
var trendChart=null;

// Network badge mapping
var NET_LOGOS={
  vodacom:'https://upload.wikimedia.org/wikipedia/commons/thumb/a/a6/Vodacom_logo.svg/60px-Vodacom_logo.svg.png',
  airtel:'https://upload.wikimedia.org/wikipedia/commons/thumb/3/38/Airtel_logo.svg/60px-Airtel_logo.svg.png',
};
var NET_CLASS={vodacom:'nv',airtel:'na',halotel:'nh',yas:'ny',ttcl:'nt',
  'mixx by yas':'ng','m-pesa':'nm','airtel money':'na','unknown':'nu','tanzania (unknown)':'nu'};

function nbdg(company){
  var k=(company||'Unknown').toLowerCase();
  var cls=NET_CLASS[k]||'nu';
  var logo=NET_LOGOS[k]||'';
  var img=logo?'<img src="'+logo+'" onerror="this.remove();" alt="">':'';
  return '<div class="nbdg '+cls+'">'+img+'<span>'+company+'</span></div>';
}
function maskIP(ip){
  if(!ip||!ip.includes('.'))return ip;
  var p=ip.split('.');return p[0]+'.'+p[1]+'.***.***';
}

// ── TAB SWITCH
function sw(e,id){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.nb').forEach(b=>b.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  e.currentTarget.classList.add('active');
  if(id==='t-graph') drawChart(GRAPH);
}

// ── RENDER NET TABLE
function renderNet(logs){
  var h=''; var sc={'Safe':'sS','Warning':'sW','Threat':'sT'};
  logs.forEach(r=>{
    var cls=sc[r.status]||'sS';
    h+='<tr>'+
      '<td><span class="ts">'+(r.timestamp||'—')+'</span></td>'+
      '<td>'+nbdg(r.company)+'</td>'+
      '<td><code>'+maskIP(r.source)+'</code></td>'+
      '<td class="msg-cell" title="'+(r.content||'')+'">'+(r.content||'')+'</td>'+
      '<td><span class="'+cls+'">'+r.status+'</span></td>'+
      '</tr>';
  });
  document.getElementById('net-body').innerHTML=h;
}

// ── RENDER SMS TABLE
function renderSMS(logs){
  var h=''; var sc={'Safe':'sS','Warning':'sW','Threat':'sT'};
  logs.forEach(r=>{
    var cls=sc[r.status]||'sS';
    h+='<tr>'+
      '<td><span class="ts">'+(r.timestamp||'—')+'</span></td>'+
      '<td><span class="ts">'+(r.sender||'—')+'</span></td>'+
      '<td><span class="ts">'+(r.recipient||'—')+'</span></td>'+
      '<td class="msg-cell" title="'+(r.message||'')+'">'+(r.message||'')+'</td>'+
      '<td><span class="'+cls+'">'+r.status+'</span></td>'+
      '<td class="reason-cell">'+(r.reason||'—')+'</td>'+
      '</tr>';
  });
  document.getElementById('sms-body').innerHTML=h;
}

// ── RENDER NUMBERS
function renderNums(nums){
  var h='';
  nums.forEach(n=>{
    var init=(n.name||'?')[0].toUpperCase();
    h+='<div class="num-card">'+
       '<div class="avatar">'+init+'</div>'+
       '<div class="num-info"><div class="nname">'+n.name+'</div><div class="nnum">'+n.number+'</div></div>'+
       '<div class="net-pill">'+n.network+'</div>'+
       '</div>';
  });
  document.getElementById('num-grid').innerHTML=h;
}

// ── POPULATE SENDER / RECIPIENTS
function popNums(nums){
  var sel=document.getElementById('sms-from');
  sel.innerHTML='<option value="">— Chagua Namba —</option>';
  nums.forEach(n=>{ sel.innerHTML+='<option value="'+n.number+'">'+n.name+' ('+n.number+')</option>'; });
  var g=document.getElementById('recip-grid'); g.innerHTML='';
  nums.forEach(n=>{
    g.innerHTML+='<label class="rc">'+
      '<input type="checkbox" value="'+n.number+'">'+
      '<div><div class="rn">'+n.name+'</div><div class="rnum">'+n.number+'</div></div>'+
      '<div class="rnet">'+n.network+'</div>'+
      '</label>';
  });
}

// ── RENDER PARTNERS
function renderPartners(partners){
  var tel='',mon='',bank='';
  partners.forEach(p=>{
    var cls='partner-card';
    if(p.type==='Money Agent') cls+=' money-badge';
    else if(p.type==='Bank') cls+=' bank-badge';
    var card='<div class="'+cls+'">'+
      '<div class="ptype">'+p.type+'</div>'+
      '<h4>'+p.name+'</h4>'+
      '<div class="pcontact">📧 '+p.contact+'</div>'+
      '<div class="active-badge">✅ IMEUNGANISHWA</div>'+
      '</div>';
    if(p.type==='Telecom') tel+=card;
    else if(p.type==='Money Agent') mon+=card;
    else bank+=card;
  });
  document.getElementById('pg-telecom').innerHTML=tel;
  document.getElementById('pg-money').innerHTML=mon;
  document.getElementById('pg-bank').innerHTML=bank;
}

// ── AUTO DETECT NETWORK
function autoDetect(){
  var num=document.getElementById('a-num').value.trim();
  if(num.length<5){document.getElementById('nd-result').textContent='—';return;}
  fetch('/api/detect_network',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({number:num})})
  .then(r=>r.json()).then(d=>{
    var el=document.getElementById('nd-result');
    el.textContent=d.network;
    document.getElementById('a-net').value=d.network;
  }).catch(()=>{});
}

// ── SEND SMS
function doSend(){
  var sender=document.getElementById('sms-from').value;
  var message=document.getElementById('sms-msg').value.trim();
  var checked=document.querySelectorAll('#recip-grid input[type=checkbox]:checked');
  var recipients=Array.from(checked).map(c=>c.value).filter(v=>v!==sender);
  if(!sender){alert('Chagua mtumaji!');return;}
  if(!message){alert('Andika ujumbe!');return;}
  if(!recipients.length){alert('Chagua mpokeaji angalau mmoja!');return;}
  var btn=document.getElementById('btn-snd');
  btn.disabled=true; btn.textContent='⏳ Inachunguza...';
  fetch('/api/send_sms',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({sender,recipients,message})})
  .then(r=>r.json()).then(d=>{
    var box=document.getElementById('res-box');
    box.className='res '+d.status; box.style.display='block';
    var ic=d.status==='Safe'?'✅':d.status==='Warning'?'⚠️':'🚨';
    box.innerHTML='<strong>'+ic+' HALI: '+d.status+'</strong><br>'+
      '📅 Wakati: '+d.timestamp+'<br>'+
      '📤 Mtumaji: '+sender+'<br>'+
      '📥 Wapokeaji ('+recipients.length+'): '+recipients.join(', ')+'<br>'+
      '🔍 Sababu: '+d.reason;
    btn.disabled=false; btn.textContent='🚀 Tuma na Chunguza';
    refreshSMS(); updStats();
    if(d.graph_data){ GRAPH=d.graph_data; if(trendChart) drawChart(GRAPH); }
  }).catch(()=>{ btn.disabled=false; btn.textContent='🚀 Tuma na Chunguza'; });
}

// ── ADD NUMBER
function doAdd(){
  var name=document.getElementById('a-name').value.trim();
  var number=document.getElementById('a-num').value.trim();
  var network=document.getElementById('a-net').value;
  var msg=document.getElementById('add-msg');
  if(!name||!number){msg.style.color='var(--danger)';msg.textContent='Jaza jina na namba!';return;}
  fetch('/api/add_number',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name,number,network})})
  .then(r=>r.json()).then(d=>{
    if(d.success){
      msg.style.color='var(--safe)';
      msg.textContent='✅ Namba imesajiliwa! Mtandao: '+d.network;
      document.getElementById('a-name').value='';
      document.getElementById('a-num').value='';
      document.getElementById('nd-result').textContent='—';
      refreshNums();
    } else { msg.style.color='var(--danger)'; msg.textContent='❌ '+(d.error||'Hitilafu'); }
  });
}

// ── REFRESH
function refreshSMS(){ fetch('/api/sms_logs').then(r=>r.json()).then(d=>renderSMS(d.logs)); }
function refreshNums(){
  fetch('/api/numbers').then(r=>r.json()).then(nums=>{
    ALL_NUMS=nums; renderNums(nums); popNums(nums);
  });
}
function updStats(){
  fetch('/api/sms_logs').then(r=>r.json()).then(d=>{
    document.getElementById('n-sms').textContent=d.total;
    document.getElementById('n-st').textContent=d.threats;
    document.getElementById('n-sw').textContent=d.warnings;
    document.getElementById('n-ss').textContent=d.safe;
    document.getElementById('g-t').textContent=d.threats;
    document.getElementById('g-w').textContent=d.warnings;
    document.getElementById('g-s').textContent=d.safe;
  });
}

// ── NET FEED
function chgT(tf){
  CUR_T=tf;
  document.querySelectorAll('.tfb').forEach(b=>b.classList.remove('active'));
  document.getElementById('b'+tf[0]).classList.add('active');
  updNet();
}
function updNet(){
  var co=document.getElementById('net-co').value;
  fetch('/api/network_logs?company='+co+'&timeframe='+CUR_T+'&_t='+Date.now())
  .then(r=>r.json()).then(d=>{
    document.getElementById('n-tot').textContent=d.total;
    document.getElementById('n-thr').textContent=d.threats;
    document.getElementById('n-war').textContent=d.warnings;
    renderNet(d.logs);
  }).catch(()=>{});
}

// ── CHART
function drawChart(data){
  var ctx=document.getElementById('trend-chart').getContext('2d');
  if(trendChart) trendChart.destroy();
  trendChart=new Chart(ctx,{
    type:'bar',
    data:{
      labels:data.map(d=>d.day),
      datasets:[
        {label:'Vitisho',data:data.map(d=>d.threats),backgroundColor:'rgba(255,61,87,.7)',borderColor:'#ff3d57',borderWidth:1.5,borderRadius:4},
        {label:'Onyo',data:data.map(d=>d.warnings),backgroundColor:'rgba(255,183,3,.6)',borderColor:'#ffb703',borderWidth:1.5,borderRadius:4},
        {label:'Salama',data:data.map(d=>d.safe),backgroundColor:'rgba(0,200,150,.5)',borderColor:'#00c896',borderWidth:1.5,borderRadius:4},
      ]
    },
    options:{
      responsive:true,
      plugins:{
        legend:{labels:{color:'#85a8c0',font:{family:'Rajdhani',size:13,weight:'600'}}},
        tooltip:{
          backgroundColor:'#0c1c30',borderColor:'rgba(0,229,255,.3)',borderWidth:1,
          titleColor:'#00e5ff',bodyColor:'#dff0ff',
          titleFont:{family:'Share Tech Mono',size:12},
          bodyFont:{family:'Rajdhani',size:13}
        }
      },
      scales:{
        x:{ticks:{color:'#4e7a96',font:{family:'Share Tech Mono',size:11}},grid:{color:'rgba(0,229,255,.06)'}},
        y:{ticks:{color:'#4e7a96',font:{family:'Share Tech Mono',size:11}},grid:{color:'rgba(0,229,255,.06)'},beginAtZero:true}
      }
    }
  });
}

// ── INIT
renderNet(NET_LOG);
renderSMS(SMS_LOG);
renderNums(ALL_NUMS);
popNums(ALL_NUMS);
renderPartners(PARTNERS);
setInterval(updNet,3000);
setInterval(refreshSMS,5000);
setInterval(updStats,8000);
</script>
</body>
</html>"""

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)