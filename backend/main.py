
import io, json, os, re, socket, struct, subprocess, tempfile, traceback
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, Response
from pydantic import BaseModel

try:
    from scapy.all import rdpcap, TCP, IP, IPv6, Raw
except Exception:
    rdpcap = None
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
except Exception:
    x509 = None

app = FastAPI(title="Mail Vault API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

PORT_PROTOCOLS = {
    25:"SMTP", 465:"SMTP", 587:"SMTP", 110:"POP3", 995:"POP3", 143:"IMAP", 993:"IMAP"
}
WEAK_TLS = {"1.0","1.1","TLS 1.0","TLS 1.1","0x0301","0x0302"}
WEAK_CIPHERS = {"3DES","RC4","DES","NULL","EXPORT","MD5","_CBC_3DES","3DES_EDE_CBC"}
TLS_CIPHER_NAMES = {
    0x1301:"TLS_AES_128_GCM_SHA256",0x1302:"TLS_AES_256_GCM_SHA384",
    0x1303:"TLS_CHACHA20_POLY1305_SHA256",0xC02F:"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030:"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",0x009C:"TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x000A:"TLS_RSA_WITH_3DES_EDE_CBC_SHA",0x002F:"TLS_RSA_WITH_AES_128_CBC_SHA"
}

def proto_for(port):
    return PORT_PROTOCOLS.get(port)

def endpoint(pkt):
    if IP in pkt: return pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt: return pkt[IPv6].src, pkt[IPv6].dst
    return None, None

def tcp_streams(packets):
    streams = defaultdict(list)
    for p in packets:
        if TCP not in p: continue
        a,b=endpoint(p)
        if not a: continue
        sport,dport=int(p[TCP].sport),int(p[TCP].dport)
        proto=proto_for(sport) or proto_for(dport)
        if not proto: continue
        key=(min((a,sport),(b,dport)), max((a,sport),(b,dport)))
        streams[key].append(p)
    return streams

def payload_bytes(pkts):
    chunks=[]
    for p in sorted(pkts, key=lambda x:int(x[TCP].seq) if TCP in x else 0):
        if Raw in p:
            try: chunks.append(bytes(p[Raw].load))
            except: pass
    return b"".join(chunks)

def directional_payloads(pkts):
    directions=defaultdict(list)
    for p in pkts:
        if TCP not in p or Raw not in p: continue
        a,b=endpoint(p)
        if not a or not b: continue
        key=(a,int(p[TCP].sport),b,int(p[TCP].dport))
        try: directions[key].append((int(p[TCP].seq),bytes(p[Raw].load)))
        except: pass
    payloads=[]
    for chunks in directions.values():
        assembled=bytearray()
        next_seq=None
        for seq,payload in sorted(chunks,key=lambda item:item[0]):
            if next_seq is None:
                assembled.extend(payload); next_seq=seq+len(payload); continue
            if seq < next_seq:
                overlap=next_seq-seq
                if overlap < len(payload): assembled.extend(payload[overlap:])
            elif seq >= next_seq:
                assembled.extend(payload)
            next_seq=max(next_seq,seq+len(payload))
        payloads.append(bytes(assembled))
    return payloads

def tls_version(v):
    return {0x0301:"1.0",0x0302:"1.1",0x0303:"1.2",0x0304:"1.3"}.get(v, f"0x{v:04x}")

def parse_tls(data):
    out={"records":0,"version":None,"cipher":None,"cipher_id":None,"certificates":[],"handshake_types":[],"key_exchange":None}
    handshake_data=bytearray()
    i=0
    while i+5<=len(data) and out["records"]<100:
        ct=data[i]; ver=int.from_bytes(data[i+1:i+3],"big"); ln=int.from_bytes(data[i+3:i+5],"big")
        if ver & 0xff00 != 0x0300 or ln<=0 or i+5+ln>len(data):
            i+=1
            continue
        body=data[i+5:i+5+ln]; out["records"]+=1
        if ct==22:
            handshake_data.extend(body)
        i+=5+ln

    j=0
    while j+4<=len(handshake_data):
        ht=handshake_data[j]; hl=int.from_bytes(handshake_data[j+1:j+4],"big")
        if j+4+hl>len(handshake_data): break
        hb=handshake_data[j+4:j+4+hl]; out["handshake_types"].append(ht)
        if ht==2 and len(hb)>=38:
            sv=int.from_bytes(hb[0:2],"big")
            out["version"]=tls_version(sv)
            p=34
            if p<len(hb):
                sidlen=hb[p]; p+=1+sidlen
                if p+2<=len(hb):
                    cid=int.from_bytes(hb[p:p+2],"big")
                    out["cipher_id"]=cid; out["cipher"]=TLS_CIPHER_NAMES.get(cid, f"0x{cid:04x}")
                    if "ECDHE" in out["cipher"] or "DHE" in out["cipher"]: out["key_exchange"]="ECDHE/DHE"
                    elif "RSA" in out["cipher"]: out["key_exchange"]="RSA"
        elif ht==11 and len(hb)>=3:
            total=int.from_bytes(hb[:3],"big"); p=3; end=min(len(hb),3+total)
            while p+3<=end:
                cl=int.from_bytes(hb[p:p+3],"big"); p+=3
                cert=bytes(hb[p:p+cl]); p+=cl
                if cert: out["certificates"].append(cert)
        j+=4+hl
    return out

def cert_info(der):
    if not x509: return {"parse":"cryptography unavailable"}
    try:
        c=x509.load_der_x509_certificate(der)
        now=datetime.now(timezone.utc)
        nb=getattr(c,"not_valid_before_utc",c.not_valid_before.replace(tzinfo=timezone.utc))
        na=getattr(c,"not_valid_after_utc",c.not_valid_after.replace(tzinfo=timezone.utc))
        pub=c.public_key()
        if hasattr(pub,"key_size"): key=f"{pub.__class__.__name__.replace('PublicKey','')} {pub.key_size}"
        else: key=pub.__class__.__name__
        sig=c.signature_hash_algorithm.name if c.signature_hash_algorithm else "unknown"
        days=(na-now).days
        status="VALID" if nb<=now<=na else "EXPIRED"
        if days>=0 and days<=30: status="EXPIRING_SOON"
        if "sha1" in sig.lower() or (hasattr(pub,"key_size") and pub.key_size<2048): status="WEAK"
        return {"subject":c.subject.rfc4514_string(),"issuer":c.issuer.rfc4514_string(),
                "valid_from":nb.isoformat(),"valid_until":na.isoformat(),"days_remaining":days,
                "public_key":key,"signature":sig,"serial":str(c.serial_number),"status":status,
                "self_signed":c.subject==c.issuer}
    except Exception as e: return {"status":"PARSE_ERROR","error":str(e)}

def risk_label_for_score(score):
    score=max(0,min(100,int(score)))
    if score>=80: return "LOW RISK"
    if score>=50: return "MEDIUM RISK"
    return "HIGH RISK"


def build_findings_and_risk(sessions):
    findings=[]

    if not sessions:
        return {
            "findings": [{
                "severity": "HIGH",
                "category": "CAPTURE",
                "title": "No usable email/TLS sessions detected",
                "description": "The uploaded capture yielded no email-session evidence for TLS or certificate analysis.",
                "evidence": ["No TCP email streams were reconstructed from the uploaded capture."],
                "recommendation": "Verify the capture contains TCP traffic and supported SMTP, IMAP, or POP3 sessions before drawing a security conclusion.",
                "deduction": 100,
                "affected_sessions": 0,
            }],
            "posture_score": 0,
            "risk": "HIGH RISK",
            "high_count": 1,
            "medium_count": 0,
        }

    def add_finding(severity, category, title, description, evidence, recommendation, deduction, affected_sessions):
        if affected_sessions <= 0:
            return
        findings.append({
            "severity": severity,
            "category": category,
            "title": title,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
            "deduction": int(deduction),
            "affected_sessions": int(affected_sessions),
        })

    weak_tls_sessions=[s for s in sessions if s.get("tls_version") in {"1.0","1.1"}]
    if weak_tls_sessions:
        evidence=[f"Session {s['id']} negotiated {s.get('tls_version')}" for s in weak_tls_sessions]
        add_finding("HIGH","TLS","Legacy TLS version detected","Deprecated TLS versions were negotiated in active email sessions.",evidence,"Disable TLS 1.0/1.1 and require TLS 1.2 or newer.",20,len({s["id"] for s in weak_tls_sessions}))

    weak_cipher_sessions=[s for s in sessions if any(token in (s.get("cipher") or "").upper() for token in WEAK_CIPHERS)]
    if weak_cipher_sessions:
        evidence=[f"Session {s['id']} used {s.get('cipher')}" for s in weak_cipher_sessions]
        add_finding("HIGH","TLS","Legacy TLS and weak cipher detected","Weak legacy cryptography was used for email transport protection.",evidence,"Remove 3DES, RC4, NULL, export, MD5, and CBC-based legacy suites.",15,len({s["id"] for s in weak_cipher_sessions}))

    plaintext_sessions=[s for s in sessions if s.get("plaintext")]
    if plaintext_sessions:
        evidence=[f"Session {s['id']} was plaintext {s.get('protocol')} traffic" for s in plaintext_sessions]
        add_finding("HIGH","EMAIL","Plaintext email protocol observed","Email traffic was exposed without transport encryption.",evidence,"Require implicit TLS or successfully complete STARTTLS before transmitting email data.",20,len({s["id"] for s in plaintext_sessions}))

    smtp_auth_sessions=[s for s in sessions if s.get("smtp_auth_without_tls")]
    if smtp_auth_sessions:
        evidence=[f"Session {s['id']} exposed SMTP AUTH without TLS" for s in smtp_auth_sessions]
        add_finding("HIGH","SMTP","SMTP AUTH observed without encryption","Authentication credentials were observed without protective TLS encryption.",evidence,"Disable SMTP AUTH until TLS is active and rotate credentials observed in plaintext.",20,len({s["id"] for s in smtp_auth_sessions}))

    weak_cert_sessions=[]
    expired_sessions=[]
    expiring_sessions=[]
    for s in sessions:
        for cert in s.get("certificates",[]):
            status = cert.get("status")
            if status in {"WEAK","INVALID"}:
                weak_cert_sessions.append(s)
            if status == "EXPIRED":
                expired_sessions.append(s)
            if status == "EXPIRING_SOON":
                expiring_sessions.append(s)
    if weak_cert_sessions:
        evidence=[f"Session {s['id']} contained weak or invalid certificates" for s in weak_cert_sessions]
        add_finding("HIGH","CERTIFICATE","Certificate weakness detected","One or more certificates were weak, invalid, or failed trust assumptions.",evidence,"Replace weak or invalid certificates with a trusted certificate using current algorithms and key sizes.",15,len({s["id"] for s in weak_cert_sessions}))
    if expired_sessions:
        evidence=[f"Session {s['id']} contained an expired certificate" for s in expired_sessions]
        add_finding("HIGH","CERTIFICATE","Certificate expired","An expired certificate was observed in the capture.",evidence,"Renew the expired certificate and verify the complete chain before accepting email connections.",20,len({s["id"] for s in expired_sessions}))
    if expiring_sessions:
        evidence=[f"Session {s['id']} contained an expiring certificate" for s in expiring_sessions]
        add_finding("MEDIUM","CERTIFICATE","Certificate expires soon","A certificate is approaching expiry and requires renewal.",evidence,"Schedule certificate renewal before the observed validity window closes.",5,len({s["id"] for s in expiring_sessions}))

    no_fs_sessions=[s for s in sessions if s.get("tls_version") and not s.get("forward_secrecy")]
    if no_fs_sessions:
        evidence=[f"Session {s['id']} used {s.get('key_exchange') or 'non-forward-secret'} key exchange" for s in no_fs_sessions]
        add_finding("MEDIUM","TLS","No forward secrecy detected","TLS sessions were negotiated without forward secrecy where applicable.",evidence,"Prefer TLS 1.3 or ECDHE/DHE cipher suites and disable static RSA key exchange.",10,len({s["id"] for s in no_fs_sessions}))

    suspicious_sessions=[s for s in sessions if s.get("anomaly") or s.get("suspicious_email_behavior")]
    if suspicious_sessions:
        evidence=[f"Session {s['id']} showed suspicious email behavior" for s in suspicious_sessions]
        add_finding("MEDIUM","AI","Suspicious email connection behavior detected","The observed traffic profile deviates from the expected cryptographic baseline.",evidence,"Review the affected sessions and correlate the packet evidence with approved mail-client and server behavior.",10,len({s["id"] for s in suspicious_sessions}))

    posture_score=100 - sum(f["deduction"] for f in findings)
    posture_score=max(0,min(100,posture_score))
    high_count=sum(1 for f in findings if f["severity"]=="HIGH")
    medium_count=sum(1 for f in findings if f["severity"]=="MEDIUM")
    return {
        "findings": findings,
        "posture_score": posture_score,
        "risk": risk_label_for_score(posture_score),
        "high_count": high_count,
        "medium_count": medium_count,
    }


def analyze_pcap(raw):
    if rdpcap is None: raise HTTPException(500,"Scapy is not installed. Run pip install -r backend/requirements.txt")
    try: packets=rdpcap(io.BytesIO(raw))
    except Exception as e: raise HTTPException(400,f"Could not read PCAP: {e}")
    streams=tcp_streams(packets); sessions=[]; all_certs=[]; total_udp=0; total_tcp=0
    for p in packets:
        if TCP in p: total_tcp+=1
        elif IP in p or IPv6 in p: total_udp+=1
    for idx,(key,pkts) in enumerate(streams.items(),1):
        (a,ap),(b,bp)=key
        proto=proto_for(ap) or proto_for(bp) or "UNKNOWN"
        direction_payloads=directional_payloads(pkts)
        data=b"".join(direction_payloads)
        text=data[:200000].decode("latin1","ignore")
        tls_candidates=[parse_tls(payload) for payload in direction_payloads]
        tls=max(tls_candidates or [parse_tls(b"")], key=lambda item:(bool(item["version"]), bool(item["cipher"]), len(item["certificates"]), item["records"]))
        starttls= "YES" if re.search(r"\bSTARTTLS\b",text,re.I) else ("NO" if proto in {"SMTP","IMAP","POP3"} and tls["version"] is None else "NOT_DETECTED")
        certs=[cert_info(x) for x in tls["certificates"]]
        smtp_auth_without_tls = bool(proto == "SMTP" and re.search(r"\bAUTH\b", text, re.I) and starttls != "YES" and tls["version"] is None)
        plaintext = bool(proto in {"SMTP","IMAP","POP3"} and tls["version"] is None and starttls != "YES")
        s={"id":idx,"protocol":proto,"source":a,"source_port":ap,"destination":b,"destination_port":bp,
           "packets":len(pkts),"bytes":len(data),"starttls":starttls,
           "tls_version":tls["version"],"cipher":tls["cipher"],"cipher_id":tls["cipher_id"],
           "key_exchange":tls["key_exchange"],"handshake_types":tls["handshake_types"],
           "certificates":certs,"plaintext":plaintext,"smtp_auth_without_tls":smtp_auth_without_tls,
           "suspicious_email_behavior": False}
        s["forward_secrecy"]=bool(tls["version"] == "1.3" or tls["key_exchange"] in {"ECDHE/DHE"})
        sessions.append(s); all_certs.extend(certs)
    # AI/anomaly layer: unsupervised IsolationForest when sklearn is available, with a deterministic fallback.
    features=[]
    for s in sessions:
        features.append([
            1 if s["tls_version"]=="1.3" else 0,
            1 if s["tls_version"]=="1.2" else 0,
            1 if s["forward_secrecy"] else 0,
            1 if s["starttls"]=="YES" else 0,
            1 if s.get("plaintext") else 0,
            len(s["certificates"]),
        ])
    try:
        from sklearn.ensemble import IsolationForest
        if len(features)>=5:
            model=IsolationForest(random_state=42,contamination="auto").fit(features)
            pred=model.predict(features); vals=model.decision_function(features)
            for s,p,v in zip(sessions,pred,vals):
                s["anomaly"]=bool(p==-1); s["anomaly_confidence"]=round(max(0,min(1,0.5-v)),2)
        else:
            for s in sessions: s["anomaly"]=bool(s.get("tls_version") in {"1.0","1.1"} or s.get("plaintext")); s["anomaly_confidence"]=0.9 if s["anomaly"] else 0.2
    except Exception:
        for s in sessions: s["anomaly"]=bool(s.get("tls_version") in {"1.0","1.1"} or s.get("plaintext")); s["anomaly_confidence"]=0.9 if s["anomaly"] else 0.2
    for s in sessions:
        s["suspicious_email_behavior"]=bool(s.get("anomaly") or s.get("smtp_auth_without_tls") or s.get("plaintext"))
    risk_snapshot=build_findings_and_risk(sessions)
    findings=risk_snapshot["findings"]
    for s in sessions:
        s["risk"] = risk_label_for_score(100 - sum(f["deduction"] for f in findings if s["id"] in [session_id for item in f["evidence"] for session_id in [int(item.split()[1])] if item.startswith("Session ")]))
    summary_protocols={p:sum(s["protocol"]==p for s in sessions) for p in ["SMTP","IMAP","POP3"]}
    summary_tls={v:sum(s["tls_version"]==v for s in sessions) for v in ["1.3","1.2","1.1","1.0"]}
    applicable_tls=[s for s in sessions if s.get("tls_version")]
    forward_secret_sessions=sum(1 for s in applicable_tls if s.get("forward_secrecy"))
    forward_secrecy_percent = "N/A" if not applicable_tls else round((forward_secret_sessions/len(applicable_tls))*100)
    debug={
        "total_packets": len(packets),
        "tcp_packets": total_tcp,
        "udp_packets": total_udp,
        "tcp_streams": len(streams),
        "smtp_streams": sum(1 for s in sessions if s["protocol"]=="SMTP"),
        "imap_streams": sum(1 for s in sessions if s["protocol"]=="IMAP"),
        "pop3_streams": sum(1 for s in sessions if s["protocol"]=="POP3"),
        "tls_sessions": len(applicable_tls),
        "tls_1_0_sessions": summary_tls.get("1.0",0),
        "tls_1_1_sessions": summary_tls.get("1.1",0),
        "tls_1_2_sessions": summary_tls.get("1.2",0),
        "tls_1_3_sessions": summary_tls.get("1.3",0),
        "certificates_extracted": len(all_certs),
        "findings_generated": len(findings),
    }
    summary={
        "posture_score": risk_snapshot["posture_score"],
        "risk": risk_snapshot["risk"],
        "session_count": len(sessions),
        "high_count": risk_snapshot["high_count"],
        "medium_count": risk_snapshot["medium_count"],
        "certificate_count": len(all_certs),
        "protocols": summary_protocols,
        "tls_versions": summary_tls,
        "anomalies": sum(1 for s in sessions if s.get("anomaly")),
        "anomaly_confidence_percent": round(sum(s.get("anomaly_confidence",0) for s in sessions) / len(sessions) * 100) if sessions else 0,
        "forward_secrecy_percent": forward_secrecy_percent,
    }
    return {"product":"SecureMailScope","problem_statement":"SIH26159","generated_at":datetime.now(timezone.utc).isoformat(),
            "file_size":len(raw),"sessions":sessions,"summary":summary,"certificates":all_certs,"findings":findings,"debug":debug}

def demo_data():
    # A realistic demo dataset for judges before a real PCAP is uploaded.
    base={"protocols":{"SMTP":8,"IMAP":4,"POP3":2},"tls_versions":{"1.3":10,"1.2":2,"1.0":2}}
    sessions=[]
    for i in range(14):
        if i<2: p,t,c,k,r="SMTP","1.0","TLS_RSA_WITH_3DES_EDE_CBC_SHA","RSA","HIGH"
        elif i<4: p,t,c,k,r="SMTP","1.2","TLS_RSA_WITH_AES_128_GCM_SHA256","RSA","MEDIUM"
        elif i<6: p,t,c,k,r="IMAP","1.2","TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","ECDHE/DHE","LOW"
        else: p,t,c,k,r=("SMTP" if i%3 else "IMAP"),"1.3","TLS_AES_256_GCM_SHA384","ECDHE/DHE","LOW"
        sessions.append({"id":i+1,"protocol":p,"source":f"10.24.8.{15+i}","destination":"mail01.corp.local",
                         "source_port":40000+i,"destination_port":25 if p=="SMTP" else 993,"packets":18+i,
                         "bytes":1200+i*90,"starttls":"YES","tls_version":t,"cipher":c,"key_exchange":k,
                         "forward_secrecy":k!="RSA","certificates":[],"score":88 if r=="LOW" else 65 if r=="MEDIUM" else 28,
                         "risk":r,"reasons":[],"anomaly":r=="HIGH","anomaly_confidence":.96 if r=="HIGH" else .12})
    findings=[
      {"severity":"HIGH","title":"Deprecated TLS version detected","detail":"2 SMTP sessions negotiated TLS 1.0.","recommendation":"Disable TLS 1.0/1.1 and enforce TLS 1.2+.","affected_sessions":2},
      {"severity":"HIGH","title":"Weak 3DES cipher detected","detail":"2 sessions used TLS_RSA_WITH_3DES_EDE_CBC_SHA.","recommendation":"Remove legacy 3DES/CBC suites.","affected_sessions":2},
      {"severity":"MEDIUM","title":"Forward secrecy not guaranteed","detail":"2 sessions used RSA key exchange.","recommendation":"Prefer ECDHE/DHE or TLS 1.3.","affected_sessions":2},
      {"severity":"MEDIUM","title":"Certificate expires soon","detail":"1 certificate expires within 30 days.","recommendation":"Renew before expiry.","affected_sessions":1}]
    return {"product":"SecureMailScope","problem_statement":"SIH26159","generated_at":datetime.now(timezone.utc).isoformat(),
            "file_size":3800000,"sessions":sessions,"summary":{"posture_score":72,"risk":"MEDIUM","session_count":14,"high_count":2,"medium_count":3,"certificate_count":14,
            "protocols":base["protocols"],"tls_versions":base["tls_versions"],"anomalies":2,"forward_secrecy_percent":86},"certificates":[],"findings":findings}

DEMO=demo_data()

@app.get("/api/health")
def health(): return {"status":"ok","service":"SecureMailScope"}

@app.get("/api/demo")
def demo(): return DEMO

@app.post("/api/analyze")
async def analyze(file: UploadFile=File(...)):
    if not file.filename.lower().endswith((".pcap",".pcapng")): raise HTTPException(400,"Upload a .pcap or .pcapng file.")
    raw=await file.read()
    result=analyze_pcap(raw); result["filename"]=file.filename
    return result

@app.post("/api/report/html")
async def html_report(payload:dict):
    s=payload.get("summary",{}); f=payload.get("findings",[])
    rows="".join(f"<tr><td>{x.get('severity')}</td><td>{x.get('title')}</td><td>{x.get('description', x.get('detail', ''))}</td><td>{x.get('recommendation', '')}</td></tr>" for x in f)
    html=f"""<!doctype html><html><head><meta charset=utf-8><title>SecureMailScope Report</title>
    <style>body{{font-family:Arial;margin:45px;color:#17212b}}table{{border-collapse:collapse;width:100%}}td,th{{padding:10px;border-bottom:1px solid #ddd;text-align:left}}</style></head>
    <body><h1>SecureMailScope</h1><h2>Cryptographic Security Posture Assessment</h2>
    <h3>Posture Score: {s.get('posture_score','—')}/100</h3><p>Sessions analyzed: {s.get('session_count','—')} • High risk: {s.get('high_count','—')} • Medium: {s.get('medium_count','—')}</p>
    <h2>Prioritized Findings</h2><table><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Recommendation</th></tr>{rows}</table>
    <p>Generated by SecureMailScope — SIH 26159 prototype.</p></body></html>"""
    return HTMLResponse(html)

@app.post("/api/report/pdf")
async def pdf_report(payload:dict):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
        b=io.BytesIO(); doc=SimpleDocTemplate(b,pagesize=A4,rightMargin=36,leftMargin=36,topMargin=36,bottomMargin=36)
        st=getSampleStyleSheet(); s=payload.get("summary",{}); f=payload.get("findings",[])
        story=[Paragraph("SecureMailScope",st["Title"]),Paragraph("Cryptographic Security Posture Assessment — SIH 26159",st["Heading2"]),
               Paragraph(f"Posture score: {s.get('posture_score','—')}/100",st["Heading2"]),
               Paragraph(f"Sessions: {s.get('session_count','—')} | High risk: {s.get('high_count','—')} | Medium risk: {s.get('medium_count','—')}",st["BodyText"]),Spacer(1,18)]
        data=[["Severity","Finding","Evidence"]]+[[x.get("severity"),x.get("title"),x.get("detail")] for x in f]
        t=Table(data,colWidths=[65,180,270]); t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),.4,colors.grey),("BACKGROUND",(0,0),(-1,0),colors.HexColor("#eaf0f5")),("VALIGN",(0,0),(-1,-1),"TOP")]))
        story += [Paragraph("Prioritized Findings",st["Heading2"]),t,Spacer(1,20),Paragraph("Recommended workflow: validate evidence, remediate weak cryptography, and repeat the capture.",st["BodyText"])]
        doc.build(story); return Response(b.getvalue(),media_type="application/pdf",headers={"Content-Disposition":"attachment; filename=securemailscope-report.pdf"})
    except Exception as e:
        raise HTTPException(500,str(e))
