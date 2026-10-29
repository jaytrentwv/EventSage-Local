import os, re, json, csv, io, datetime, tempfile, hmac, base64
from collections import Counter, defaultdict
from flask import Flask, render_template, request, jsonify, Response
from defusedxml import ElementTree as ET
from xml.etree.ElementTree import ParseError
from urllib.parse import urlsplit

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 150 * 1024 * 1024
app.config['MAX_FORM_MEMORY_SIZE'] = 50 * 1024 * 1024

LEVELS = {'1':'Critical','2':'Error','3':'Warning','4':'Information','5':'Verbose'}


# Starter knowledge base. v2 emphasizes correlated incidents rather than isolated events.
EVENT_KB = {
    ('Ntfs',55): ('Storage / File System','NTFS detected file-system corruption or a damaged file record.'),
    ('Microsoft-Windows-Ntfs',98): ('Storage / File System','NTFS detected a volume state that may require repair or verification.'),
    ('Disk',51): ('Storage / Disk','A paging or disk I/O operation encountered an error.'),
    ('Disk',153): ('Storage / Disk','Windows retried an I/O operation after a storage timeout/error.'),
    ('Microsoft-Windows-Kernel-Power',41): ('Power / Stability','Windows restarted without a clean shutdown.'),
    ('EventLog',6008): ('Power / Stability','The previous shutdown was unexpected.'),
    ('Service Control Manager',7034): ('Services','A Windows service terminated unexpectedly.'),
    ('NETLOGON',5719): ('Active Directory / Domain','Netlogon could not establish a secure session with a domain controller.'),
    ('NetBT',4321): ('Network / Naming','A NetBIOS name could not be registered, usually because another device/interface already owns it.'),
    ('Microsoft-Windows-GroupPolicy',1129): ('Active Directory / Group Policy','Group Policy could not apply because domain/network connectivity was unavailable.'),
    ('Microsoft-Windows-WindowsUpdateClient',20): ('Windows Update','An update installation failed.'),
    ('Microsoft-Windows-Security-Kerberos',4): ('Authentication / Kerberos','Kerberos authentication reported a ticket/SPN/name mismatch or related failure.'),
}

def lname(tag):
    return tag.split('}',1)[-1]

def parse_event(elem):
    out = {'provider':'','event_id':0,'level':'','time':'','computer':'','channel':'','message':'','data':{}}
    sysnode = None; eventdata = None
    for c in elem:
        n=lname(c.tag)
        if n=='System': sysnode=c
        elif n in ('EventData','UserData'): eventdata=c
    if sysnode is not None:
        for c in sysnode:
            n=lname(c.tag)
            if n=='Provider': out['provider']=c.attrib.get('Name','')
            elif n=='EventID':
                try: out['event_id']=int((c.text or '0').strip())
                except: pass
            elif n=='Level': out['level']=LEVELS.get((c.text or '').strip(), (c.text or '').strip())
            elif n=='TimeCreated': out['time']=c.attrib.get('SystemTime','')
            elif n=='Computer': out['computer']=c.text or ''
            elif n=='Channel': out['channel']=c.text or ''
    vals=[]
    if eventdata is not None:
        for d in eventdata.iter():
            if lname(d.tag)=='Data':
                name=d.attrib.get('Name') or f'Data{len(vals)+1}'
                val=d.text or ''
                out['data'][name]=val
                vals.append(f'{name}: {val}')
    out['message']='\n'.join(vals)
    return out

def decode_xml_bytes(raw):
    # Windows / wevtutil commonly emits UTF-16 LE XML. Detect BOMs first,
    # then fall back to null-byte heuristics before trying UTF-8.
    if raw.startswith(b'\xff\xfe') or raw.startswith(b'\xfe\xff'):
        return raw.decode('utf-16')
    if raw.startswith(b'\xef\xbb\xbf'):
        return raw.decode('utf-8-sig')
    sample = raw[:200]
    # UTF-16 without a BOM usually contains a NUL byte every other byte.
    if sample.count(b'\x00') > max(4, len(sample)//6):
        try:
            return raw.decode('utf-16-le')
        except UnicodeDecodeError:
            try:
                return raw.decode('utf-16-be')
            except UnicodeDecodeError:
                pass
    return raw.decode('utf-8-sig', errors='replace')

def parse_xml_bytes(raw):
    text=decode_xml_bytes(raw).lstrip('\ufeff').strip()
    # Remove XML control characters that are illegal in XML 1.0 but can
    # occasionally leak into event payloads. Keep tabs/newlines/CR.
    text=''.join(ch for ch in text if ch in ('\t','\n','\r') or ord(ch) >= 0x20)
    # wevtutil can emit a stream of sibling <Event> elements without a single root.
    # Wrap the stream so ElementTree can parse it reliably.
    try:
        root=ET.fromstring(text)
        elems=[root] if lname(root.tag)=='Event' else [e for e in root.iter() if lname(e.tag)=='Event']
    except ParseError:
        text=re.sub(r'^\s*<\?xml[^>]*\?>','',text, count=1).strip()
        root=ET.fromstring('<Events>'+text+'</Events>')
        elems=[e for e in root if lname(e.tag)=='Event']
    if not elems: raise ValueError('No Event records found')
    return [parse_event(e) for e in elems]

def parse_json_bytes(raw):
    data=json.loads(raw.decode('utf-8-sig',errors='replace'))
    if isinstance(data,dict): data=data.get('events',[data])
    result=[]
    for x in data:
        try: eid=int(x.get('Id') or x.get('EventId') or x.get('event_id') or 0)
        except: eid=0
        result.append({
            'provider':str(x.get('ProviderName') or x.get('provider') or x.get('Provider') or ''),
            'event_id':eid,
            'level':str(x.get('LevelDisplayName') or x.get('level') or x.get('Level') or ''),
            'time':str(x.get('TimeCreated') or x.get('time') or ''),
            'computer':str(x.get('MachineName') or x.get('computer') or ''),
            'channel':str(x.get('LogName') or x.get('channel') or ''),
            'message':str(x.get('Message') or x.get('message') or ''),
            'data':x
        })
    return result

def parse_csv_bytes(raw):
    rows=list(csv.DictReader(io.StringIO(raw.decode('utf-8-sig',errors='replace'))))
    return parse_json_bytes(json.dumps(rows).encode())

def parse_evtx(path):
    from Evtx.Evtx import Evtx
    events=[]
    with Evtx(path) as log:
        for rec in log.records():
            try: events.append(parse_event(ET.fromstring(rec.xml())))
            except Exception: pass
    return events

def dt(s):
    if not s: return None
    try:
        value=datetime.datetime.fromisoformat(s.replace('Z','+00:00'))
        return value.replace(tzinfo=datetime.timezone.utc) if value.tzinfo is None else value.astimezone(datetime.timezone.utc)
    except: return None

def annotate(events):
    for i,e in enumerate(events):
        e['_id']=i
        e['_kb']=None
        key=(e['provider'],e['event_id'])
        if key in EVENT_KB:
            cat,desc=EVENT_KB[key]; e['_kb']={'category':cat,'summary':desc}
        else:
            # provider substring match for common names
            for (p,eid),(cat,desc) in EVENT_KB.items():
                if e['event_id']==eid and p.lower() in e['provider'].lower():
                    e['_kb']={'category':cat,'summary':desc}; break
    return events

def values_for(events, event_id, provider_contains=None):
    out=[]
    for e in events:
        if e['event_id']!=event_id: continue
        if provider_contains and provider_contains.lower() not in e['provider'].lower(): continue
        out.append(e)
    return out

def top_data_values(events, names, ip_only=False, limit=8):
    c=Counter()
    ip_re=re.compile(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)')
    for e in events:
        blob=' '.join(str(v) for v in list(e.get('data',{}).values())+[e.get('message','')])
        if ip_only:
            for m in ip_re.findall(blob): c[m]+=1
        else:
            for n in names:
                v=e.get('data',{}).get(n)
                if v: c[str(v)]+=1
    return c.most_common(limit)

def incident(title, category, severity, confidence, summary, evidence, recommendations, event_ids, details=None):
    return {'title':title,'category':category,'severity':severity,'confidence':confidence,
            'summary':summary,'evidence':evidence,'recommendations':recommendations,
            'event_ids':event_ids,'details':details or {}}

def correlate(events):
    incidents=[]
    netbt=values_for(events,4321,'NetBT')
    netlog=values_for(events,5719,'NETLOGON')
    gp=values_for(events,1129,'GroupPolicy')
    kerb=values_for(events,4,'Kerberos')
    dns=[e for e in events if 'DNS' in e['provider'].upper() and e['level'] in ('Error','Warning')]
    if netbt or netlog or gp:
        ips=top_data_values(netbt,[],ip_only=True,limit=10)
        incidents.append(incident(
            'Domain / Network Registration Cluster','Active Directory / Network','High','High',
            'Repeated NetBIOS registration conflicts occur alongside domain-controller/network connectivity failures. Treat these as one investigation, not hundreds of unrelated events.',
            [f'NetBT 4321: {len(netbt)}',f'NETLOGON 5719: {len(netlog)}',f'GroupPolicy 1129: {len(gp)}',f'DNS warning/error events: {len(dns)}',f'Kerberos event 4: {len(kerb)}'],
            ['Identify the most frequent conflicting IP addresses.','Map each conflicting IP to hostname/MAC/interface/VLAN.','Check local adapters and routes for multi-homed or virtual adapters.','Validate AD DNS and DC discovery from the affected machine.','Review whether NetBIOS over TCP/IP is required on every interface.'],
            [4321,5719,1129,4], {'top_ips':ips}
        ))

    ntfs55=values_for(events,55,'Ntfs')
    disk51=values_for(events,51,'Disk'); disk153=values_for(events,153,'Disk')
    if ntfs55 or disk51 or disk153:
        drives=Counter()
        for e in ntfs55:
            d=e.get('data',{}).get('DriveName')
            if d: drives[d]+=1
        incidents.append(incident(
            'Storage / File-System Findings','Storage','High' if disk51 or disk153 else 'Medium','High',
            'NTFS and/or disk I/O events were detected. Determine whether the affected volume is production storage, removable/test media, or an expected transient device.',
            [f'NTFS 55: {len(ntfs55)}',f'Disk 51: {len(disk51)}',f'Disk 153: {len(disk153)}'],
            ['Back up important data before repair operations.','Identify the physical device behind each drive letter.','Check device health/SMART/vendor diagnostics.','Only then decide whether CHKDSK or filesystem repair is appropriate.'],
            [55,51,153], {'drives':drives.most_common(8)}
        ))

    kp=values_for(events,41,'Kernel-Power'); shut=values_for(events,6008,'EventLog')
    if kp or shut:
        zero_bug=sum(1 for e in kp if str(e.get('data',{}).get('BugcheckCode','')).strip() in ('','0'))
        incidents.append(incident(
            'Unexpected Shutdown / Restart Cluster','Power / Stability','High','Medium',
            'The machine recorded unclean restarts. Kernel-Power 41 is a symptom; surrounding events must be used to determine the cause.',
            [f'Kernel-Power 41: {len(kp)}',f'EventLog 6008: {len(shut)}',f'Event 41 with BugcheckCode 0: {zero_bug}'],
            ['Inspect events 10 minutes before each restart.','Correlate disk/WHEA/driver/service failures with the restart.','Check dump files when BugcheckCode is non-zero.','Check power/UPS/firmware if no bugcheck exists.'],
            [41,6008]
        ))

    scm=values_for(events,7034,'Service Control Manager')
    if scm:
        names=Counter()
        for e in scm:
            n=e.get('data',{}).get('param1') or e.get('data',{}).get('Data1')
            if n: names[n]+=1
        incidents.append(incident(
            'Unexpected Service Terminations','Services','Medium','High',
            'One or more services terminated unexpectedly. Repeated failures during normal runtime deserve more attention than failures occurring only during reboot/update cycles.',
            [f'Service Control Manager 7034: {len(scm)}'],
            ['Rank services by repeat count.','Correlate each failure with Application log crashes.','Separate reboot/update-related stops from runtime crashes.'],
            [7034], {'services':names.most_common(10)}
        ))

    wu=values_for(events,20,'WindowsUpdateClient')
    if wu:
        codes=Counter(); titles=Counter()
        for e in wu:
            code=e.get('data',{}).get('errorCode'); title=e.get('data',{}).get('updateTitle')
            if code: codes[code]+=1
            if title: titles[title]+=1
        incidents.append(incident(
            'Windows Update Installation Failures','Windows Update','Low','High',
            'Windows Update recorded failed installs. App-package failures should be prioritized below domain, storage, or stability incidents unless they persist.',
            [f'WindowsUpdateClient 20: {len(wu)}'],
            ['Group failures by error code and package.','Retry after reboot if resources were in use.','Escalate recurring OS/security update failures above Store-app failures.'],
            [20], {'codes':codes.most_common(8),'updates':titles.most_common(8)}
        ))
    return incidents

def summary(events,incidents):
    sev=Counter(e.get('level') or 'Unknown' for e in events)
    providers=Counter(e.get('provider') or 'Unknown' for e in events)
    ids=Counter((e.get('provider') or 'Unknown',e.get('event_id') or 0) for e in events)
    times=[dt(e.get('time')) for e in events if dt(e.get('time'))]
    return {'total':len(events),'severity':dict(sev),'top_providers':providers.most_common(12),
            'top_ids':[{'provider':p,'event_id':i,'count':c} for (p,i),c in ids.most_common(20)],
            'start':min(times).isoformat() if times else '', 'end':max(times).isoformat() if times else '',
            'incident_count':len(incidents)}


def crash_investigation(events):
    """Evidence-based restart/bugcheck timeline; symptoms are not blamed on nearby events."""
    selected=[]
    for e in events:
        p=e.get('provider','').lower(); eid=e.get('event_id'); d=e.get('data',{})
        if (eid==41 and 'kernel-power' in p) or (eid==6008 and p=='eventlog') or (eid==1001 and ('wer' in p or 'bugcheck' in p or 'windows error reporting' in p)):
            selected.append(e)
    selected.sort(key=lambda e: e.get('time',''))
    restarts=[]
    for e in selected:
        if e['event_id']==6008: continue  # Event 6008 refers to a previous shutdown; don't double-count.
        if e['event_id']==1001: continue  # Attach crash reports to Kernel-Power whenever possible.
        t=dt(e.get('time'))
        if not t: continue
        near=[]
        for item in events:
            ti=dt(item.get('time'))
            if ti is None: continue
            diff=(ti-t).total_seconds()
            if -1800 <= diff <= 300 and item.get('level') in ('Error','Critical','Warning') and item is not e:
                near.append(item)
        near.sort(key=lambda x: x.get('time',''))
        raw=e.get('data',{}).get('BugcheckCode','0')
        try: code=int(str(raw),0)
        except ValueError:
            try: code=int(str(raw))
            except ValueError: code=0
        reports=[]
        for r in selected:
            if r.get('event_id')!=1001: continue
            tr=dt(r.get('time'))
            if tr and abs((tr-t).total_seconds())<=3600:
                reports.append({'time':r.get('time'),'message':r.get('message','')[:1000]})
        restarts.append({'time':e.get('time'),'bugcheck':('0x%08X'%code) if code else None,
                         'evidence':{'kernel_power_record':e.get('_id'), 'nearby_warning_error_count':len(near)},
                         'nearby':[{'time':x.get('time'),'provider':x.get('provider'),'id':x.get('event_id'),
                                    'level':x.get('level'),'detail':x.get('message','')[:250]} for x in near[-18:]],
                         'crash_reports':reports[:3]})
    return {'restarts':restarts[-40:],'count':len(restarts),
            'bugchecks':sum(bool(x['bugcheck']) for x in restarts),
            'note':'Kernel-Power 41 confirms an unclean restart, not its cause. Nearby events and bugcheck codes are evidence, not proof of a responsible driver.'}

def parse_windbg(raw):
    text=raw.decode('utf-8-sig',errors='replace')[:2_000_000]
    fields={}
    for key in ('BUGCHECK_CODE','BUGCHECK_STR','MODULE_NAME','IMAGE_NAME','SYMBOL_NAME',
                'FAILURE_BUCKET_ID','PROCESS_NAME','STACK_COMMAND','CUSTOMER_CRASH_COUNT'):
        m=re.search(r'(?im)^\s*'+key+r'\s*:\s*(.+?)\s*$',text)
        if m: fields[key]=m.group(1).strip()
    bug=re.search(r'(?im)^\s*BugCheck\s+([0-9a-fx]+)\s*,',text)
    if bug: fields['BugCheck']=bug.group(1)
    stack=re.search(r'(?ims)^\s*STACK_TEXT:\s*\n(.+?)(?:\n\s*\n|\n\s*SYMBOL_NAME:|\n\s*MODULE_NAME:)',text)
    if stack: fields['STACK_TEXT']=stack.group(1)[:7000]
    if not fields: return {'error':'No recognized WinDbg !analyze -v fields. Upload a text file containing the debugger output.'}
    return {'fields':fields,'caution':'MODULE_NAME/IMAGE_NAME can identify a crash-context module, not necessarily the underlying cause. Correlate the full stack and repeated dumps.'}

@app.before_request
def local_access_only():
    host=urlsplit('http://'+request.host).hostname
    if request.remote_addr not in ('127.0.0.1','::1') or host not in ('127.0.0.1','localhost','::1'):
        return Response('EventSage Local only accepts connections from this PC.',403)
    if request.method=='POST':
        origin=urlsplit(request.headers.get('Origin',''))
        if origin.scheme!='http' or origin.netloc.lower()!=request.host.lower():
            return jsonify({'error':'Origin not allowed'}),403

@app.after_request
def private_headers(response):
    response.headers['Cache-Control']='no-store'
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Referrer-Policy']='no-referrer'
    response.headers['Content-Security-Policy']="default-src 'self'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    return response

@app.errorhandler(413)
def too_large(error):
    return jsonify({'error':'Upload exceeds the 150 MB local application limit.'}),413

@app.post('/api/crash/windbg')
def windbg_upload():
    f=request.files.get('file')
    if not f: return jsonify({'error':'No text file uploaded'}),400
    raw=f.read(2_000_001)
    if len(raw)>2_000_000: return jsonify({'error':'Debugger text exceeds 2 MB.'}),413
    result=parse_windbg(raw)
    return jsonify(result), (400 if 'error' in result else 200)

@app.get('/')
def index(): return render_template('index.html')

@app.get('/api/health')
def health(): return jsonify({'ok':True,'version':'2.4-local','storage':'request-local'})

@app.post('/api/upload')
def upload():
    f=request.files.get('file')
    if not f: return jsonify({'error':'No file uploaded'}),400
    raw=f.read(); name=(f.filename or '').lower()
    try:
        if name.endswith('.evtx'):
            fd,path=tempfile.mkstemp(suffix='.evtx'); os.close(fd)
            try:
                with open(path,'wb') as stream: stream.write(raw)
                events=parse_evtx(path)
            finally:
                try: os.remove(path)
                except: pass
        elif name.endswith('.xml'): events=parse_xml_bytes(raw)
        elif name.endswith('.json'): events=parse_json_bytes(raw)
        elif name.endswith('.csv'): events=parse_csv_bytes(raw)
        else:
            try: events=parse_json_bytes(raw)
            except: events=parse_xml_bytes(raw)
        current_events=annotate(events)
        current_incidents=correlate(current_events)
        current_crashes=crash_investigation(current_events)
        return jsonify({'crashes':current_crashes,'summary':summary(current_events,current_incidents),'incidents':current_incidents,'events':current_events[-12000:]})
    except Exception as ex:
        return jsonify({'error':'Could not parse this log. Check the format and try a smaller export.'}),400

@app.post('/api/acknowledge')
def acknowledge():
    body=request.get_json(force=True)
    # v2 preview: front-end acknowledgment only; persistence comes next.
    return jsonify({'ok':True,'message':'Acknowledged for this analysis session. Persistent suppression profiles are planned for the next build.'})

if __name__=='__main__':
    app.run(host='127.0.0.1', port=8766, debug=False, use_reloader=False)
